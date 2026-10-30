use futures::channel::oneshot;
use futures::future::Either;
use futures::{FutureExt, StreamExt};
use h2_support::prelude::*;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    /// Reads made after the input ended.
    reads_after_end: usize,
}

struct Link {
    buf: Vec<u8>,
    cap: usize,
    /// Bytes the peer may still drain.
    credit: usize,
    /// Writes to refuse, as if the socket became writable just after each.
    refusals: usize,
    waker: Option<Waker>,
    /// Bytes the endpoint has read.
    read: usize,
    /// Set once the input ends: reads then fail if `true`, else see EOF.
    end: Option<bool>,
}

/// Peer side of a `BufferedIo`.
struct Drain(Arc<Mutex<Link>>);

fn buffered_io(inner: mock::Mock) -> (BufferedIo, Drain) {
    let link = Arc::new(Mutex::new(Link {
        buf: Vec::new(),
        cap: usize::MAX,
        credit: usize::MAX,
        refusals: 0,
        waker: None,
        read: 0,
        end: None,
    }));
    let drain = Drain(link.clone());
    let io = BufferedIo {
        inner,
        link,
        reads_after_end: 0,
    };
    (io, drain)
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

    fn read(&self) -> usize {
        self.0.lock().unwrap().read
    }

    /// Makes every write wait until `resume`.
    fn pause(&self) {
        let mut link = self.0.lock().unwrap();
        link.cap = 0;
        link.credit = 0;
    }

    /// Lets writes through again after refusing the first `refusals`.
    fn resume(&self, refusals: usize) {
        let mut link = self.0.lock().unwrap();
        link.cap = usize::MAX;
        link.credit = usize::MAX;
        link.refusals = refusals;
        if let Some(waker) = link.waker.take() {
            waker.wake();
        }
    }

    fn release(&self, n: usize) {
        let mut link = self.0.lock().unwrap();
        link.credit += n;
        if let Some(waker) = link.waker.take() {
            waker.wake();
        }
    }

    /// Ends the input with an error, or with EOF if not `error`.
    fn end(&self, error: bool) {
        let mut link = self.0.lock().unwrap();
        link.end = Some(error);
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
        let this = self.get_mut();
        let end = this.link.lock().unwrap().end;
        if let Some(error) = end {
            this.reads_after_end += 1;
            // Reading must stop at the end rather than spin on it.
            assert!(this.reads_after_end <= 8, "read on after the end");
            return Poll::Ready(if error {
                Err(io::ErrorKind::ConnectionReset.into())
            } else {
                Ok(())
            });
        }

        let filled = buf.filled().len();
        futures::ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        this.link.lock().unwrap().read += buf.filled().len() - filled;
        Poll::Ready(Ok(()))
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
        if link.refusals > 0 {
            link.refusals -= 1;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
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

/// Yields until `done` holds, and returns whether it did.
async fn reached(done: impl Fn() -> bool) -> bool {
    for _ in 0..64 {
        if done() {
            return true;
        }
        util::yield_once().await;
    }
    false
}

/// Matches the PONG and SETTINGS ACK queues of the connection.
const MAX_QUEUED: u8 = 16;

/// Control frames the peer floods a client with while its writes are blocked.
#[derive(Clone, Copy, Debug)]
enum Flood {
    Pings,
    Settings,
}

async fn read_while_blocked(flood: Flood, refusals: usize) {
    let (io, mut peer) = mock::new();
    let (io, drain) = buffered_io(io);
    let (paused_tx, paused_rx) = oneshot::channel();
    let progress = Arc::new(AtomicUsize::new(0));

    let client = {
        let progress = progress.clone();
        async move {
            let (mut client, mut conn) = client::handshake(io).await.unwrap();
            let mut ping_pong = client::Connection::ping_pong(&mut conn).unwrap();
            conn.drive(paused_rx).await.unwrap();
            let request = Request::post("https://example.com/").body(()).unwrap();
            let (response, mut stream) = client.send_request(request, false).unwrap();
            stream
                .send_data(Bytes::from(vec![0; BODY_LEN]), true)
                .unwrap();
            // Our PING and SETTINGS wait behind the DATA stuck in the codec.
            conn.drive(util::yield_once()).await;
            ping_pong.send_ping(Ping::opaque()).unwrap();
            conn.set_initial_window_size(65_535).unwrap();

            let mut body = conn.drive(response).await.unwrap().into_body();
            // SETTINGS take effect before their ACK can be written.
            assert!(client.is_extended_connect_protocol_enabled());
            assert_eq!(conn.extended_connect_protocol(), Some(true));
            for step in 1..=2 {
                progress.store(step, Ordering::SeqCst);
                conn.drive(body.data()).await.unwrap().unwrap();
            }
            progress.store(3, Ordering::SeqCst);
            conn.await.unwrap();
        }
    };

    let peer = async move {
        peer.assert_client_handshake().await;
        peer.send_frame(frames::window_update(0, BODY_LEN as u32))
            .await;
        drain.pause();
        paused_tx.send(()).unwrap();
        for _ in 0..8 {
            util::yield_once().await;
        }

        // Nothing the client writes gets through, yet it reads past the PONG,
        // SETTINGS ACK, PING and SETTINGS it cannot write.
        peer.send_frame(frames::ping([1; 8])).await;
        let settings = frames::settings()
            .enable_connect_protocol(1)
            .initial_window_size(BODY_LEN as u32);
        peer.send_frame(settings).await;
        peer.send_frame(frames::headers(1).response(200)).await;
        assert!(
            reached(|| progress.load(Ordering::SeqCst) >= 1).await,
            "{:?}: stopped reading",
            flood
        );

        // Reading goes on until a flood fills a queue, and stops there until
        // writes drain.
        for i in 0..MAX_QUEUED - 1 {
            if i == MAX_QUEUED - 2 {
                peer.send_frame(frames::data(1, "a")).await;
                assert!(
                    reached(|| progress.load(Ordering::SeqCst) >= 2).await,
                    "{:?}: stopped early",
                    flood
                );
            }
            match flood {
                Flood::Pings => peer.send_frame(frames::ping([i + 2; 8])).await,
                Flood::Settings => peer.send_frame(frames::settings()).await,
            }
        }
        peer.send_frame(frames::data(1, "x").eos()).await;
        assert!(
            !reached(|| progress.load(Ordering::SeqCst) >= 3).await,
            "{:?}: read past a full queue",
            flood
        );
        drain.resume(refusals);

        let (pongs_due, acks_due) = match flood {
            Flood::Pings => (MAX_QUEUED, 1),
            Flood::Settings => (1, MAX_QUEUED),
        };
        // Our own PING and SETTINGS get written too.
        let (mut pongs, mut acks, mut ours, mut data) = (Vec::new(), 0, 0, 0);
        while pongs.len() < pongs_due as usize || acks < acks_due || ours < 2 {
            match peer.next().await.unwrap().unwrap() {
                frame::Frame::Data(frame) if acks == 0 => data += frame.payload().len(),
                frame::Frame::Settings(frame) if frame.is_ack() => acks += 1,
                frame::Frame::Ping(frame) if frame.is_ack() => pongs.push(frame.payload()[0]),
                frame::Frame::Ping(_) | frame::Frame::Settings(_) => ours += 1,
                _ => {}
            }
        }
        assert_eq!(pongs, (1..=pongs_due).collect::<Vec<_>>());
        // The peer widens its window only once it reads the ACK.
        assert!(
            data <= 65_535,
            "{:?}: {} DATA bytes before the ACK",
            flood,
            data
        );
        assert!(
            reached(|| progress.load(Ordering::SeqCst) >= 3).await,
            "{:?}: reading did not resume",
            flood
        );
    };

    match select(Box::pin(peer), Box::pin(client)).await {
        Either::Left(_) => {}
        Either::Right(_) => panic!("{:?}: client finished before the peer", flood),
    }
}

#[tokio::test]
async fn reads_while_control_frames_wait_to_be_written() {
    h2_support::trace_init!();

    // A second refusal hits the ACK buffered right before stream frames.
    for (flood, refusals) in [(Flood::Pings, 1), (Flood::Pings, 2), (Flood::Settings, 1)] {
        let run = read_while_blocked(flood, refusals);
        tokio::time::timeout(Duration::from_secs(10), run)
            .await
            .unwrap_or_else(|_| panic!("{:?} with {} refusals timed out", flood, refusals));
    }
}

/// How the server closes while nothing it writes gets through.
#[derive(Clone, Copy, Debug)]
enum Close {
    /// The GOAWAY and its PING wait behind DATA.
    Graceful,
    /// The GOAWAY waits behind DATA.
    Abrupt,
    /// The GOAWAY is buffered, and the final flush waits.
    AbruptFlush,
}

async fn close_while_blocked(close: Close) {
    let (io, mut peer) = mock::new();
    let (io, drain) = buffered_io(io);
    let (close_tx, mut close_rx) = oneshot::channel();
    let accepted = Arc::new(AtomicBool::new(false));

    let server = {
        let accepted = accepted.clone();
        async move {
            let mut conn = server::handshake(io).await.unwrap();
            let (_request, mut respond) = conn.next().await.unwrap().unwrap();
            let mut stream = respond.send_response(Response::new(()), false).unwrap();
            if !matches!(close, Close::AbruptFlush) {
                // Within the initial window, so stream 1 can end.
                stream
                    .send_data(Bytes::from_static(&[0; 16 * 1024]), true)
                    .unwrap();
            }

            let mut closing = false;
            poll_fn(|cx| {
                if !closing && close_rx.poll_unpin(cx).is_ready() {
                    closing = true;
                    match close {
                        Close::Graceful => conn.graceful_shutdown(),
                        Close::Abrupt | Close::AbruptFlush => {
                            conn.abrupt_shutdown(Reason::NO_ERROR)
                        }
                    }
                }
                while let Some(stream) = futures::ready!(conn.poll_accept(cx)) {
                    stream.unwrap();
                    accepted.store(true, Ordering::SeqCst);
                }
                Poll::Ready(())
            })
            .await;
        }
    };

    let peer = async move {
        peer.assert_server_handshake().await;
        drain.pause();
        peer.send_frame(
            frames::headers(1)
                .request("GET", "https://example.com/")
                .eos(),
        )
        .await;
        for _ in 0..8 {
            util::yield_once().await;
        }
        close_tx.send(()).unwrap();
        for _ in 0..8 {
            util::yield_once().await;
        }

        // Nothing the server writes gets through, yet it reads on.
        let expected: Vec<frame::Frame> = match close {
            Close::Graceful => {
                // Not the ACK of the shutdown PING, as that is not sent yet.
                peer.send_frame(frames::ping(frame::Ping::SHUTDOWN).pong())
                    .await;
                peer.send_frame(
                    frames::headers(3)
                        .request("GET", "https://example.com/")
                        .eos(),
                )
                .await;
                assert!(
                    reached(|| accepted.load(Ordering::SeqCst)).await,
                    "{:?}: stopped reading",
                    close
                );
                vec![
                    frames::go_away(StreamId::MAX).into(),
                    frames::ping(frame::Ping::SHUTDOWN).into(),
                ]
            }
            Close::Abrupt | Close::AbruptFlush => {
                let read = drain.read();
                for i in 0..32 {
                    if i == 16 {
                        // The rest must wake the server again.
                        for _ in 0..8 {
                            util::yield_once().await;
                        }
                    }
                    peer.send_frame(frames::ping([i; 8])).await;
                }
                // PING frames take 17 bytes each.
                assert!(
                    reached(|| drain.read() >= read + 32 * 17).await,
                    "{:?}: stopped reading",
                    close
                );
                // Then the input ends with an error or EOF.
                drain.end(matches!(close, Close::Abrupt));
                for _ in 0..8 {
                    util::yield_once().await;
                }
                vec![frames::go_away(1).into()]
            }
        };
        drain.resume(1);

        // A GOAWAY goes out before its PING.
        let mut control = Vec::new();
        while control.len() < expected.len() {
            let frame = peer.next().await.unwrap().unwrap();
            if let frame::Frame::GoAway(_) | frame::Frame::Ping(_) = frame {
                control.push(frame);
            }
        }
        assert_eq!(control, expected, "{:?}", close);
        peer
    };

    // Spawned, so the server only runs when woken.
    let server = tokio::spawn(server);
    let mut peer = peer.await;
    if let Close::Graceful = close {
        // No stream is left, yet the connection waits for the PING ACK.
        for _ in 0..8 {
            util::yield_once().await;
        }
        assert!(!server.is_finished(), "{:?}: closed early", close);
        peer.send_frame(frames::ping(frame::Ping::SHUTDOWN).pong())
            .await;
        peer.recv_frame(frames::go_away(3)).await;
    }
    server.await.unwrap();
}

#[tokio::test]
async fn reads_while_go_away_waits_to_be_written() {
    h2_support::trace_init!();

    for close in [Close::Graceful, Close::Abrupt, Close::AbruptFlush] {
        tokio::time::timeout(Duration::from_secs(10), close_while_blocked(close))
            .await
            .unwrap_or_else(|_| panic!("{:?} timed out", close));
    }
}

#[tokio::test]
async fn bytes_dropped_while_closing_count_as_read() {
    h2_support::trace_init!();
    let (io, mut peer) = mock::new();
    let (io, drain) = buffered_io(io);
    let (_client, mut conn) = client::handshake(io).await.unwrap();
    conn.drive(util::yield_once()).await;

    // The final flush waits, and the client drops what it reads.
    drain.pause();
    conn.abrupt_shutdown(Reason::NO_ERROR);
    conn.drive(util::yield_once()).await;
    assert!(!conn.take_read_activity());
    peer.send_frame(frames::ping([1; 8])).await;
    conn.drive(util::yield_once()).await;
    assert!(conn.take_read_activity());
}
