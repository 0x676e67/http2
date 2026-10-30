use futures::channel::oneshot;
use futures::future::Either;
use futures::{FutureExt, StreamExt};
use h2_support::prelude::*;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::ReadBuf;

/// Write buffer of the TLS-like transport, as in tokio-btls.
const TRANSPORT_BUFFER: usize = 64 * 1024;
/// Bytes the peer drains from that buffer per step. Less than a DATA frame,
/// so the endpoint fills the buffer.
const DRAIN_STEP: usize = 4 * 1024;
const BODY_LEN: usize = 1024 * 1024;
/// DATA the peer may see before a control frame or the endpoint's reaction to
/// it; the body is much larger.
const DATA_LIMIT: usize = 2 * TRANSPORT_BUFFER;

/// Like a TLS stream: writes land in a bounded buffer, and `poll_flush` stays
/// pending until the peer has drained it.
struct BufferedIo {
    inner: mock::Mock,
    link: Arc<Mutex<Link>>,
}

struct Link {
    buf: Vec<u8>,
    cap: usize,
    /// Bytes the peer may still drain.
    credit: usize,
    waker: Option<Waker>,
}

/// Peer side of a `BufferedIo`.
struct Drain(Arc<Mutex<Link>>);

fn buffered_io(inner: mock::Mock) -> (BufferedIo, Drain) {
    let link = Arc::new(Mutex::new(Link {
        buf: Vec::new(),
        cap: usize::MAX,
        credit: usize::MAX,
        waker: None,
    }));
    let drain = Drain(link.clone());
    (BufferedIo { inner, link }, drain)
}

impl Link {
    fn forward(&mut self, inner: &mut mock::Mock, cx: &mut Context<'_>) -> io::Result<()> {
        let n = self.buf.len().min(self.credit);
        if n > 0 {
            match Pin::new(inner).poll_write(cx, &self.buf[..n]) {
                Poll::Ready(written) => {
                    let written = written?;
                    self.buf.drain(..written);
                    self.credit -= written;
                }
                Poll::Pending => unreachable!("mock writes are unbounded"),
            }
        }
        Ok(())
    }
}

impl Drain {
    /// Bounds the transport buffer; nothing drains until `release`.
    fn block(&self) {
        let mut link = self.0.lock().unwrap();
        link.cap = TRANSPORT_BUFFER;
        link.credit = 0;
    }

    fn buffered(&self) -> usize {
        self.0.lock().unwrap().buf.len()
    }

    fn release(&self, n: usize) {
        let mut link = self.0.lock().unwrap();
        link.credit += n;
        if let Some(waker) = link.waker.take() {
            waker.wake();
        }
    }
}

impl AsyncRead for BufferedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for BufferedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut link = this.link.lock().unwrap();
        link.forward(&mut this.inner, cx)?;

        let room = link.cap.saturating_sub(link.buf.len());
        if room == 0 {
            link.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let n = room.min(buf.len());
        link.buf.extend_from_slice(&buf[..n]);
        link.forward(&mut this.inner, cx)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut link = this.link.lock().unwrap();
        link.forward(&mut this.inner, cx)?;

        if !link.buf.is_empty() {
            link.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Drains one step from the endpoint's transport and returns the frames that
/// reached the peer.
async fn pump(peer: &mut mock::Handle, drain: &Drain) -> Vec<frame::Frame> {
    drain.release(DRAIN_STEP);
    for _ in 0..8 {
        util::yield_once().await;
    }

    let mut frames = Vec::new();
    while let Some(frame) = peer.next().now_or_never() {
        frames.push(frame.expect("unexpected EOF").expect("frame"));
    }
    frames
}

#[derive(Clone, Copy, Debug)]
enum Case {
    /// The client must acknowledge the peer's PING.
    PeerPing,
    /// The client must send a user PING and read its PONG.
    UserPing,
    /// The client must ACK the peer's SETTINGS and read the response HEADERS.
    SettingsAndResponse,
    /// The server must refuse a stream over its concurrency limit.
    ServerRefusal,
    /// The server must send a graceful GOAWAY and its PING.
    ServerGoAway,
}

/// Uploads a request body for the client cases.
async fn upload(io: BufferedIo, case: Case, trigger: oneshot::Receiver<()>, done: Arc<AtomicBool>) {
    let (mut client, mut conn) = client::handshake(io).await.unwrap();
    let request = Request::post("https://example.com/").body(()).unwrap();
    let (response, mut stream) = client.send_request(request, false).unwrap();
    stream
        .send_data(Bytes::from(vec![0; BODY_LEN]), true)
        .unwrap();

    match case {
        Case::UserPing => {
            let mut ping_pong = client::Connection::ping_pong(&mut conn).unwrap();
            conn.drive(trigger).await.unwrap();
            conn.drive(ping_pong.ping(Ping::opaque())).await.unwrap();
            done.store(true, Ordering::SeqCst);
        }
        Case::SettingsAndResponse => {
            conn.drive(response).await.unwrap();
            done.store(true, Ordering::SeqCst);
        }
        Case::PeerPing | Case::ServerRefusal | Case::ServerGoAway => {}
    }
    conn.await.unwrap();
}

/// Sends a response body for the server cases.
async fn download(io: BufferedIo, mut trigger: oneshot::Receiver<()>) {
    let mut conn = server::Builder::new()
        .max_concurrent_streams(1)
        .handshake::<_, Bytes>(io)
        .await
        .unwrap();
    let (_request, mut respond) = conn.next().await.unwrap().unwrap();
    let mut stream = respond.send_response(Response::new(()), false).unwrap();
    stream
        .send_data(Bytes::from(vec![0; BODY_LEN]), true)
        .unwrap();

    let mut shutdown = false;
    poll_fn(|cx| {
        if !shutdown && trigger.poll_unpin(cx).is_ready() {
            shutdown = true;
            conn.graceful_shutdown();
        }
        // The refused stream is never accepted.
        conn.poll_accept(cx).map(|stream| assert!(stream.is_none()))
    })
    .await;
}

/// Returns the DATA bytes seen by the peer if `case` stalls behind the body.
async fn run(case: Case) -> Result<(), usize> {
    let (io, mut peer) = mock::new();
    let (io, drain) = buffered_io(io);
    let (trigger_tx, trigger_rx) = oneshot::channel();
    let done = Arc::new(AtomicBool::new(false));

    let endpoint: Pin<Box<dyn Future<Output = ()>>> = match case {
        Case::ServerRefusal | Case::ServerGoAway => Box::pin(download(io, trigger_rx)),
        _ => Box::pin(upload(io, case, trigger_rx, done.clone())),
    };

    let peer = async move {
        // DATA waits for the WINDOW_UPDATEs sent once the transport is bounded.
        let settings = frames::settings().initial_window_size(0);
        if let Case::ServerRefusal | Case::ServerGoAway = case {
            peer.assert_server_handshake_with_settings(settings).await;
            peer.send_frame(
                frames::headers(1)
                    .request("GET", "https://example.com/")
                    .eos(),
            )
            .await;
            peer.recv_frame(frames::headers(1).response(200)).await;
        } else {
            peer.assert_client_handshake_with_settings(settings).await;
            peer.recv_frame(frames::headers(1).request("POST", "https://example.com/"))
                .await;
        }
        drain.block();
        peer.send_frame(frames::window_update(1, BODY_LEN as u32))
            .await;
        peer.send_frame(frames::window_update(0, BODY_LEN as u32))
            .await;

        // Let the body fill the transport buffer.
        while drain.buffered() < TRANSPORT_BUFFER {
            for frame in pump(&mut peer, &drain).await {
                assert!(matches!(frame, frame::Frame::Data(_)), "{:?}", frame);
            }
        }

        match case {
            Case::PeerPing => peer.send_frame(frames::ping([1; 8])).await,
            Case::UserPing | Case::ServerGoAway => trigger_tx.send(()).unwrap(),
            Case::SettingsAndResponse => {
                peer.send_frame(frames::settings().max_concurrent_streams(10))
                    .await;
                peer.send_frame(frames::headers(1).response(200)).await;
            }
            Case::ServerRefusal => {
                peer.send_frame(
                    frames::headers(3)
                        .request("GET", "https://example.com/")
                        .eos(),
                )
                .await;
            }
        }

        let mut sent = 0;
        let mut control = 0;
        loop {
            for frame in pump(&mut peer, &drain).await {
                match frame {
                    frame::Frame::Data(data) => sent += data.payload().len(),
                    frame::Frame::Ping(ping) if ping.is_ack() => {
                        assert_eq!(*ping.payload(), [1; 8]);
                        control += 1;
                    }
                    frame::Frame::Ping(ping) => {
                        peer.send_frame(frames::ping(*ping.payload()).pong()).await;
                        control += 1;
                    }
                    frame::Frame::Settings(settings) if settings.is_ack() => control += 1,
                    frame::Frame::Reset(reset) => {
                        assert_eq!(reset.stream_id(), 3);
                        assert_eq!(reset.reason(), Reason::REFUSED_STREAM);
                        control += 1;
                    }
                    frame::Frame::GoAway(go_away) => {
                        assert_eq!(go_away.reason(), Reason::NO_ERROR);
                        control += 1;
                    }
                    frame => panic!("unexpected frame: {:?}", frame),
                }
            }

            let finished = match case {
                Case::PeerPing | Case::ServerRefusal => control > 0,
                // The GOAWAY and the PING that follows it.
                Case::ServerGoAway => control > 1,
                Case::UserPing | Case::SettingsAndResponse => {
                    control > 0 && done.load(Ordering::SeqCst)
                }
            };
            if finished {
                return Ok(());
            }
            if sent > DATA_LIMIT {
                return Err(sent);
            }
        }
    };

    match select(Box::pin(peer), endpoint).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => panic!("{:?}: endpoint finished before the peer", case),
    }
}

#[tokio::test]
async fn control_frames_do_not_wait_for_backpressured_data() {
    h2_support::trace_init!();

    let mut stalled = Vec::new();
    for case in [
        Case::PeerPing,
        Case::UserPing,
        Case::SettingsAndResponse,
        Case::ServerRefusal,
        Case::ServerGoAway,
    ] {
        let result = tokio::time::timeout(Duration::from_secs(10), run(case))
            .await
            .unwrap_or_else(|_| panic!("{:?} timed out", case));
        if let Err(sent) = result {
            stalled.push(format!("{:?}: stalled behind {} DATA bytes", case, sent));
        }
    }
    assert!(stalled.is_empty(), "{:#?}", stalled);
}
