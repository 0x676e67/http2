use futures::FutureExt;
use h2_support::prelude::*;
use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::Notify;

const WINDOW: u32 = 65_535;

#[derive(Debug, PartialEq)]
enum IoEvent {
    Read(&'static str),
    Flush,
}

#[derive(Default)]
struct Peer {
    input: VecDeque<(&'static str, Bytes)>,
    written: Vec<u8>,
    events: Vec<IoEvent>,
    write_budget: Option<usize>,
    flush_blocked: bool,
    waker: Option<Waker>,
}

struct RecordingIo(Arc<Mutex<Peer>>);

impl AsyncRead for RecordingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut peer = self.0.lock().unwrap();
        let Some((label, mut bytes)) = peer.input.pop_front() else {
            peer.waker = Some(cx.waker().clone());
            return Poll::Pending;
        };
        let len = bytes.len().min(buf.remaining());
        buf.put_slice(&bytes.split_to(len));
        if bytes.is_empty() {
            peer.events.push(IoEvent::Read(label));
        } else {
            peer.input.push_front((label, bytes));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RecordingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut peer = self.0.lock().unwrap();
        if peer.write_budget == Some(0) {
            peer.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let len = peer.write_budget.unwrap_or(buf.len()).min(buf.len());
        peer.written.extend_from_slice(&buf[..len]);
        if let Some(budget) = &mut peer.write_budget {
            *budget -= len;
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut peer = self.0.lock().unwrap();
        if peer.flush_blocked {
            peer.waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            peer.events.push(IoEvent::Flush);
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

struct Harness {
    connection: client::Connection<RecordingIo, Bytes>,
    sender: client::SendRequest<Bytes>,
    peer: Arc<Mutex<Peer>>,
}

impl Harness {
    async fn new(limit: Option<u32>) -> Self {
        let mut builder = client::Builder::new();
        builder
            .initial_window_size(WINDOW)
            .initial_connection_window_size(WINDOW);
        if let Some(max_buffered_data) = limit {
            builder.window_update_policy(client::WindowUpdatePolicy::ReceiveDriven {
                max_buffered_data,
            });
        }
        Self::configured(builder).await
    }

    async fn configured(builder: client::Builder) -> Self {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let (sender, connection) = builder
            .handshake::<_, Bytes>(RecordingIo(peer.clone()))
            .await
            .unwrap();
        let mut harness = Self {
            connection,
            sender,
            peer,
        };
        harness.feed("settings", frame(4, 0, 0, &[]));
        harness.feed("settings ack", frame(4, 1, 0, &[]));
        harness.poll();
        harness.clear_output();
        harness
    }

    fn request(&mut self) -> (client::ResponseFuture, h2::SendStream<Bytes>) {
        let request = Request::get("https://example.com/").body(()).unwrap();
        let result = self.sender.send_request(request, true).unwrap();
        self.poll();
        self.clear_output();
        result
    }

    fn poll(&mut self) {
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut self.connection).poll(&mut cx).is_pending());
    }

    fn feed(&self, label: &'static str, bytes: Bytes) {
        let mut peer = self.peer.lock().unwrap();
        peer.input.push_back((label, bytes));
        if let Some(waker) = peer.waker.take() {
            waker.wake();
        }
    }

    fn clear_output(&self) {
        let mut peer = self.peer.lock().unwrap();
        peer.written.clear();
        peer.events.clear();
    }

    fn updates(&self) -> Vec<(u32, u32)> {
        let peer = self.peer.lock().unwrap();
        let mut bytes = peer.written.as_slice();
        if bytes.starts_with(MAGIC_PREFACE) {
            bytes = &bytes[MAGIC_PREFACE.len()..];
        }
        let mut updates = Vec::new();
        while !bytes.is_empty() {
            assert!(bytes.len() >= 9, "partial frame header: {:?}", bytes);
            let len = (usize::from(bytes[0]) << 16)
                | (usize::from(bytes[1]) << 8)
                | usize::from(bytes[2]);
            assert!(bytes.len() >= 9 + len, "partial frame payload");
            if bytes[3] == 8 {
                assert_eq!(len, 4);
                updates.push((
                    u32::from_be_bytes(bytes[5..9].try_into().unwrap()),
                    u32::from_be_bytes(bytes[9..13].try_into().unwrap()),
                ));
            }
            bytes = &bytes[9 + len..];
        }
        updates
    }
}

fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Bytes {
    let len = u32::try_from(payload.len()).unwrap();
    assert!(len <= 0x00ff_ffff);
    let mut bytes = Vec::with_capacity(9 + payload.len());
    bytes.extend_from_slice(&len.to_be_bytes()[1..]);
    bytes.extend_from_slice(&[kind, flags]);
    bytes.extend_from_slice(&stream_id.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.into()
}

#[tokio::test]
async fn receive_driven_budget_validation_and_large_stream_threshold() {
    const ACK: u32 = 4 * 1024 * 1024;
    const TARGET: u32 = 12 * 1024 * 1024;
    for (connection_window, limit) in [
        (WINDOW, 0),
        (WINDOW, WINDOW - 1),
        (TARGET, TARGET - 1),
        (WINDOW, 1 << 31),
    ] {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let result = client::Builder::new()
            .initial_connection_window_size(connection_window)
            .window_update_policy(client::WindowUpdatePolicy::ReceiveDriven {
                max_buffered_data: limit,
            })
            .handshake::<_, Bytes>(RecordingIo(peer.clone()))
            .await;
        assert!(result.is_err());
        let peer = peer.lock().unwrap();
        assert!(peer.written.is_empty());
        assert!(peer.events.is_empty());
    }

    // Changing the target after handshake must not bypass the budget on the
    // first connection write, before the receive driver has been polled.
    let peer = Arc::new(Mutex::new(Peer::default()));
    let (sender, mut connection) = client::Builder::new()
        .window_update_policy(client::WindowUpdatePolicy::ReceiveDriven {
            max_buffered_data: WINDOW,
        })
        .handshake::<_, Bytes>(RecordingIo(peer.clone()))
        .await
        .unwrap();
    connection.set_target_window_size(2 * WINDOW);
    let mut initial = Harness {
        connection,
        sender,
        peer,
    };
    initial.feed("settings", frame(4, 0, 0, &[]));
    initial.feed("settings ack", frame(4, 1, 0, &[]));
    initial.poll();
    assert!(initial
        .peer
        .lock()
        .unwrap()
        .written
        .starts_with(MAGIC_PREFACE));
    assert!(initial.updates().is_empty());

    // A blocked writer can fill both the codec and the bounded WU FIFO.
    // Keep every DATA byte within the original peer credit, and disable the
    // independent small-DATA limit so that only the new FIFO limit is tested.
    const LIMIT: u32 = 2 * WINDOW;
    const FRAME_COUNT: usize = LIMIT as usize / 13 + 2048;
    let mut builder = client::Builder::new();
    builder.data_frame_budget(usize::MAX).window_update_policy(
        client::WindowUpdatePolicy::ReceiveDriven {
            max_buffered_data: LIMIT,
        },
    );
    let mut bounded = Harness::configured(builder).await;
    let (response, _send) = bounded.request();
    bounded.feed("response", frame(1, 4, 1, &[0x88]));
    bounded.poll();
    let _body = response.now_or_never().unwrap().unwrap().into_body();
    bounded.clear_output();
    bounded.peer.lock().unwrap().write_budget = Some(0);
    for _ in 0..FRAME_COUNT {
        bounded.feed("queued data", frame(0, 0, 1, b"x"));
    }
    bounded.poll();
    let received = {
        let mut peer = bounded.peer.lock().unwrap();
        let received = peer
            .events
            .iter()
            .filter(|event| **event == IoEvent::Read("queued data"))
            .count();
        assert!(received > LIMIT as usize / 13);
        assert!(received < FRAME_COUNT && received < WINDOW as usize);
        assert!(peer.written.is_empty());
        peer.write_budget = None;
        peer.waker.take().unwrap().wake();
        received
    };
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let error = match Pin::new(&mut bounded.connection).poll(&mut cx) {
        Poll::Ready(Err(error)) => error,
        result => panic!("expected FIFO budget connection error, got {:?}", result),
    };
    assert_eq!(error.reason(), Some(h2::Reason::ENHANCE_YOUR_CALM));
    assert!(error.is_go_away() && error.is_library() && !error.is_io());
    // Shutdown must not emit credit for all received DATA after exhaustion.
    let granted: u32 = bounded
        .updates()
        .iter()
        .filter(|(id, _)| *id == 0)
        .map(|(_, increment)| increment)
        .sum();
    assert!(granted < received as u32);

    let mut builder = client::Builder::new();
    builder
        .initial_window_size(128 * 1024)
        .initial_stream_window_size(TARGET)
        .initial_connection_window_size(TARGET)
        .max_frame_size(ACK)
        .window_update_policy(client::WindowUpdatePolicy::ReceiveDriven {
            max_buffered_data: 4 * TARGET,
        });
    let mut harness = Harness::configured(builder).await;
    let (response, _send) = harness.request();
    harness.feed("response", frame(1, 4, 1, &[0x88]));
    let payload = vec![b'x'; ACK as usize];
    harness.feed("below threshold", frame(0, 0, 1, &payload[1..]));
    harness.poll();
    assert!(harness.updates().is_empty());
    let mut body = response.now_or_never().unwrap().unwrap().into_body();
    assert_eq!(
        body.data().await.unwrap().unwrap().len(),
        (ACK - 1) as usize
    );
    body.flow_control()
        .release_capacity((ACK - 1) as usize)
        .unwrap();
    harness.poll();
    assert!(harness.updates().is_empty());

    harness.feed("threshold", frame(0, 0, 1, &payload[..1]));
    harness.poll();
    assert_eq!(harness.updates(), vec![(1, ACK), (0, ACK)]);
    assert_eq!(body.data().await.unwrap().unwrap().len(), 1);
    body.flow_control().release_capacity(1).unwrap();
    harness.poll();
    assert_eq!(harness.updates(), vec![(1, ACK), (0, ACK)]);

    // Current-frame credit must still exclude earlier unconsumed payloads.
    harness.clear_output();
    for index in 0..2 {
        harness.feed("large data", frame(0, 0, 1, &payload));
        harness.poll();
        assert_eq!(
            body.flow_control().used_capacity(),
            (index + 1) * ACK as usize
        );
    }
    assert_eq!(harness.updates(), vec![(1, ACK), (0, ACK), (0, ACK)]);
    for _ in 0..2 {
        assert_eq!(body.data().await.unwrap().unwrap().len(), ACK as usize);
        body.flow_control().release_capacity(ACK as usize).unwrap();
        harness.poll();
    }
    assert_eq!(
        harness.updates(),
        vec![(1, ACK), (0, ACK), (0, ACK), (1, ACK)]
    );
}

#[tokio::test]
async fn receive_driven_updates_before_consumption_without_duplicate_credit() {
    for enabled in [false, true] {
        let mut harness = Harness::new(enabled.then_some(2 * WINDOW)).await;
        let (response, _send) = harness.request();
        harness.feed("response", frame(1, 4, 1, &[0x88]));
        harness.feed("first data", frame(0, 0, 1, b"abcd"));
        harness.feed("second data", frame(0, 0, 1, b"efgh"));
        harness.poll();

        assert_eq!(
            harness.updates(),
            if enabled {
                vec![(1, 4), (0, 4), (0, 4)]
            } else {
                vec![]
            }
        );

        let mut body = response.now_or_never().unwrap().unwrap().into_body();
        assert_eq!(body.flow_control().used_capacity(), 8);
        assert_eq!(
            body.data().now_or_never().unwrap().unwrap().unwrap(),
            "abcd"
        );
        assert_eq!(
            body.data().now_or_never().unwrap().unwrap().unwrap(),
            "efgh"
        );
        body.flow_control().release_capacity(8).unwrap();
        harness.poll();
        if enabled {
            assert_eq!(harness.updates(), vec![(1, 4), (0, 4), (0, 4), (1, 4)]);
        } else {
            assert!(harness.updates().is_empty());
        }
        assert_eq!(body.flow_control().used_capacity(), 0);
    }
}

#[tokio::test]
async fn padding_counts_once_and_terminal_streams_only_update_the_connection() {
    for reset in [false, true] {
        let mut harness = Harness::new(Some(2 * WINDOW)).await;
        let (response, mut send) = harness.request();
        harness.feed("response", frame(1, 4, 1, &[0x88]));
        // Three application bytes, one pad-length octet and two padding octets.
        let padded = &[2, b'a', b'b', b'c', 0, 0];
        harness.feed("padded data", frame(0, 8, 1, padded));
        harness.poll();
        assert_eq!(harness.updates(), vec![(1, 6), (0, 6)]);
        let mut body = response.now_or_never().unwrap().unwrap().into_body();
        assert_eq!(body.flow_control().used_capacity(), 3);
        assert_eq!(body.data().now_or_never().unwrap().unwrap().unwrap(), "abc");
        body.flow_control().release_capacity(3).unwrap();
        harness.poll();
        assert_eq!(harness.updates(), vec![(1, 6), (0, 6)]);

        if reset {
            send.send_reset(h2::Reason::CANCEL);
            harness.poll();
        }
        harness.feed("terminal data", frame(0, 8 | u8::from(!reset), 1, padded));
        harness.poll();
        assert_eq!(harness.updates(), vec![(1, 6), (0, 6), (0, 6)]);
        if !reset {
            assert_eq!(body.data().now_or_never().unwrap().unwrap().unwrap(), "abc");
            body.flow_control().release_capacity(3).unwrap();
            harness.poll();
            assert_eq!(harness.updates(), vec![(1, 6), (0, 6), (0, 6)]);
            assert!(body.data().now_or_never().unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn queued_and_unreleased_data_both_hold_the_connection_budget() {
    let mut harness = Harness::new(Some(WINDOW)).await;
    let (response, _send) = harness.request();
    harness.feed("response", frame(1, 4, 1, &[0x88]));
    harness.feed("data", frame(0, 0, 1, &[b'x'; 1024]));
    harness.poll();
    assert_eq!(harness.updates(), vec![(1, 1024)]);
    let mut body = response.now_or_never().unwrap().unwrap().into_body();

    // Returning capacity before polling does not remove the queued DATA.
    body.flow_control().release_capacity(1024).unwrap();
    harness.poll();
    assert_eq!(harness.updates(), vec![(1, 1024)]);
    assert_eq!(
        body.data().now_or_never().unwrap().unwrap().unwrap().len(),
        1024
    );
    harness.poll();
    assert_eq!(harness.updates(), vec![(1, 1024), (0, 1024)]);

    let (response, _send) = harness.request();
    harness.feed("second response", frame(1, 4, 3, &[0x88]));
    harness.feed("final data", frame(0, 1, 3, &[b'y'; 1024]));
    harness.poll();
    assert!(harness.updates().is_empty());
    let mut body = response.now_or_never().unwrap().unwrap().into_body();
    assert_eq!(body.flow_control().used_capacity(), 1024);
    // Final DATA must hold the same budget even though it needs no stream WU.
    drop(body);
    harness.poll();
    assert_eq!(harness.updates(), vec![(0, 1024)]);
}

#[tokio::test]
async fn receive_updates_try_each_flush_without_blocking_later_data_or_fin() {
    for blocked in [false, true] {
        let mut harness = Harness::new(Some(2 * WINDOW)).await;
        let (response, _send) = harness.request();
        harness.feed("response", frame(1, 4, 1, &[0x88]));
        harness.poll();
        let mut body = response.now_or_never().unwrap().unwrap().into_body();
        harness.clear_output();
        if blocked {
            let mut peer = harness.peer.lock().unwrap();
            peer.write_budget = Some(7);
            peer.flush_blocked = true;
        }
        harness.feed("first data", frame(0, 0, 1, b"abcd"));
        harness.feed("second data", frame(0, 0, 1, b"efgh"));
        harness.feed("final data", frame(0, 1, 1, b"ijkl"));
        harness.poll();
        {
            let mut peer = harness.peer.lock().unwrap();
            let reads: Vec<_> = ["first data", "second data", "final data"]
                .iter()
                .map(|label| {
                    peer.events
                        .iter()
                        .position(|event| *event == IoEvent::Read(label))
                        .unwrap()
                })
                .collect();
            if blocked {
                assert_eq!(peer.written.len(), 7);
                assert!(!peer.events.contains(&IoEvent::Flush));
                peer.write_budget = None;
                peer.waker.take().unwrap().wake();
            } else {
                for pair in reads.windows(2) {
                    assert!(peer.events[pair[0] + 1..pair[1]].contains(&IoEvent::Flush));
                }
                assert!(peer.events[reads[2] + 1..].contains(&IoEvent::Flush));
            }
        }
        let expected = vec![(1, 4), (0, 4), (0, 4), (0, 4)];
        if blocked {
            harness.poll();
            // FIN cannot discard the earlier stream update, even when its
            // bytes and the transport flush were both previously blocked.
            assert_eq!(harness.updates(), expected);
            let mut peer = harness.peer.lock().unwrap();
            assert!(!peer.events.contains(&IoEvent::Flush));
            peer.flush_blocked = false;
            peer.waker.take().unwrap().wake();
        }
        harness.poll();
        assert_eq!(harness.updates(), expected);
        for payload in ["abcd", "efgh", "ijkl"] {
            assert_eq!(body.data().await.unwrap().unwrap(), payload);
        }
        assert!(body.data().await.is_none());
        body.flow_control().release_capacity(12).unwrap();
        harness.poll();
        assert_eq!(harness.updates(), expected);
    }
}

struct ObserveBlockedWrite {
    io: DuplexStream,
    armed: Arc<AtomicBool>,
    blocked: Arc<Notify>,
}

impl AsyncRead for ObserveBlockedWrite {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for ObserveBlockedWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.io).poll_write(cx, buf);
        if result.is_pending() && this.armed.load(Ordering::SeqCst) {
            this.blocked.notify_one();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

async fn read_frame(io: &mut DuplexStream) -> (u8, usize) {
    let mut header = [0; 9];
    io.read_exact(&mut header).await.unwrap();
    let len =
        (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    let mut payload = vec![0; len];
    io.read_exact(&mut payload).await.unwrap();
    (header[3], len)
}

#[tokio::test]
async fn duplex_backpressure_does_not_make_response_reads_wait_for_request_writes() {
    const BODY_SIZE: usize = 32 * 1024;

    for receive_driven in [false, true] {
        let (io, mut peer) = tokio::io::duplex(256);
        let armed = Arc::new(AtomicBool::new(false));
        let blocked = Arc::new(Notify::new());
        let io = ObserveBlockedWrite {
            io,
            armed: armed.clone(),
            blocked: blocked.clone(),
        };
        let mut builder = client::Builder::new();
        if receive_driven {
            builder.window_update_policy(client::WindowUpdatePolicy::ReceiveDriven {
                max_buffered_data: 2 * WINDOW,
            });
        }
        let (mut sender, connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
        let (response, mut body) = sender
            .send_request(
                Request::post("https://example.com/").body(()).unwrap(),
                false,
            )
            .unwrap();
        let connection_task = tokio::spawn(connection);

        let progress = tokio::time::timeout(Duration::from_secs(2), async {
            let mut magic = [0; 24];
            peer.read_exact(&mut magic).await.unwrap();
            assert_eq!(&magic, MAGIC_PREFACE);
            assert_eq!(read_frame(&mut peer).await.0, 4);
            peer.write_all(&frame(4, 0, 0, &[])).await.unwrap();
            peer.write_all(&frame(4, 1, 0, &[])).await.unwrap();
            while read_frame(&mut peer).await.0 != 1 {}

            // Confirm actual request backpressure before the peer starts its
            // response. Both response frames fit within the original credit.
            armed.store(true, Ordering::SeqCst);
            body.send_data(Bytes::from(vec![b'q'; BODY_SIZE]), true)
                .unwrap();
            blocked.notified().await;
            armed.store(false, Ordering::SeqCst);
            peer.write_all(&frame(1, 4, 1, &[0x88])).await.unwrap();
            peer.write_all(&frame(0, 0, 1, &[b'r'; BODY_SIZE / 2]))
                .await
                .unwrap();
            peer.write_all(&frame(0, 1, 1, &[b'r'; BODY_SIZE / 2]))
                .await
                .unwrap();

            // The peer starts consuming the request only after its complete
            // response has been written. Waiting for an earlier WU flush here
            // would deadlock the two directions.
            let mut received = 0;
            while received < BODY_SIZE {
                let (kind, len) = read_frame(&mut peer).await;
                if kind == 0 {
                    received += len;
                }
            }
            assert_eq!(received, BODY_SIZE);
            let mut response = response.await.unwrap().into_body();
            let mut received = 0;
            while let Some(data) = response.data().await {
                received += data.unwrap().len();
            }
            assert_eq!(received, BODY_SIZE);
        })
        .await;

        connection_task.abort();
        let _ = connection_task.await;
        assert!(
            progress.is_ok(),
            "duplex stalled; receive_driven={}",
            receive_driven
        );
    }
}
