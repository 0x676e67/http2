use futures::FutureExt;
use h2_support::prelude::*;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use tokio::io::ReadBuf;

/// Takes every write whole and records it. Reads never complete.
struct Writes(Arc<Mutex<Vec<Bytes>>>);

impl AsyncRead for Writes {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Writes {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().unwrap().push(Bytes::copy_from_slice(buf));
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Counts the frames in a write of whole frames.
fn frame_count(mut write: &[u8]) -> usize {
    let mut frames = 0;
    while !write.is_empty() {
        let len = u32::from_be_bytes([0, write[0], write[1], write[2]]) as usize;
        write = &write[9 + len..];
        frames += 1;
    }
    frames
}

/// Sends two requests on a connection that waits to be woken, polling it
/// after each as a runtime would, and returns the frames in each write.
fn request_writes(coalesce: bool) -> (Vec<usize>, usize) {
    let writes = Arc::new(Mutex::new(Vec::new()));
    let (mut send_request, mut connection) = client::Builder::new()
        .coalesce_writes(coalesce)
        .handshake::<_, Bytes>(Writes(writes.clone()))
        .now_or_never()
        .expect("handshake attempted transport I/O")
        .unwrap();

    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);

    // The first poll writes the preface, held back or not, and registers.
    assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());
    let preface = writes.lock().unwrap().len();
    assert!(preface > 0);

    let mut streams = Vec::new();
    for _ in 0..2 {
        let request = Request::get("https://example.com/").body(()).unwrap();
        streams.push(send_request.send_request(request, true).unwrap());
        assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());
    }

    let writes = writes.lock().unwrap();
    let frames = writes[preface..].iter().map(|w| frame_count(w)).collect();
    (frames, wakes.0.load(Ordering::SeqCst))
}

#[test]
fn small_write_waits_once_for_streams_that_are_ready() {
    // Each request is written as soon as the connection is polled for it.
    assert_eq!(request_writes(false), (vec![1, 1], 2));

    // The first is held back for one more poll, which the connection asks
    // for itself, and shares its write with the second.
    assert_eq!(request_writes(true), (vec![2], 3));
}
