use futures::future::poll_fn;
use h2_support::prelude::{client, Request};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const CLIENT_MAGIC: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

struct RecordingIo {
    writes: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for RecordingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for RecordingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn client_handshake_selects_encoding_and_reuses_table_on_one_connection() {
    let writes = Arc::new(Mutex::new(Vec::new()));
    let io = RecordingIo {
        writes: writes.clone(),
    };
    let (mut sender, connection) = client::handshake(io).await.unwrap();

    let request = || {
        Request::builder()
            .uri("https://a/")
            .header("x", "a")
            .body(())
            .unwrap()
    };
    let (_response1, _send1) = sender.send_request(request(), true).unwrap();
    let (_response2, _send2) = sender.send_request(request(), true).unwrap();

    let mut connection = Box::pin(connection);
    for _ in 0..3 {
        poll_fn(|cx| {
            assert!(connection.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    let writes = writes.lock().unwrap();
    let headers: Vec<_> = frames(&writes).filter(|frame| frame.kind == 0x1).collect();
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].stream_id, 1);
    assert_eq!(headers[1].stream_id, 3);

    // One-byte strings are emitted raw because Huffman is not smaller. This
    // proves the public client handshake selected the client encoding route.
    assert_eq!(headers[0].payload, b"\x82\x87\x41\x01a\x84\x40\x01x\x01a");

    // The second request uses the dynamic :authority and ordinary-field
    // entries created by the first request on this same connection.
    assert_eq!(headers[1].payload, b"\x82\x87\xbf\x84\xbe");
}

struct WireFrame<'a> {
    kind: u8,
    stream_id: u32,
    payload: &'a [u8],
}

fn frames(src: &[u8]) -> impl Iterator<Item = WireFrame<'_>> {
    assert!(src.starts_with(CLIENT_MAGIC));
    let mut pos = CLIENT_MAGIC.len();

    std::iter::from_fn(move || {
        if pos == src.len() {
            return None;
        }

        assert!(src.len() - pos >= 9, "truncated HTTP/2 frame header");
        let payload_len =
            ((src[pos] as usize) << 16) | ((src[pos + 1] as usize) << 8) | src[pos + 2] as usize;
        let payload_start = pos + 9;
        let end = payload_start
            .checked_add(payload_len)
            .expect("frame length overflowed");
        assert!(end <= src.len(), "truncated HTTP/2 frame payload");

        let frame = WireFrame {
            kind: src[pos + 3],
            stream_id: u32::from_be_bytes([src[pos + 5], src[pos + 6], src[pos + 7], src[pos + 8]])
                & 0x7fff_ffff,
            payload: &src[payload_start..end],
        };
        pos = end;
        Some(frame)
    })
}
