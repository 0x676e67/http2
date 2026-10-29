use h2_support::prelude::*;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

#[tokio::test]
async fn write_continuation_frames() {
    // An invalid dependency ID results in a stream level error. The hpack
    // payload should still be decoded.
    h2_support::trace_init!();
    let (io, mut srv) = mock::new();

    let large = build_large_headers();

    // Build the large request frame
    let frame = large.iter().fold(
        frames::headers(1).request("GET", "https://http2.akamai.com/"),
        |frame, &(name, ref value)| frame.field(name, &value[..]),
    );

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        srv.recv_frame(frame.eos()).await;
        srv.send_frame(frames::headers(1).response(204).eos()).await;
    };

    let client = async move {
        let (mut client, mut conn) = client::handshake(io).await.expect("handshake");

        let mut request = Request::builder();
        request = request.uri("https://http2.akamai.com/");

        for &(name, ref value) in &large {
            request = request.header(name, &value[..]);
        }

        let request = request.body(()).unwrap();

        let req = async {
            let res = client
                .send_request(request, true)
                .expect("send_request1")
                .0
                .await;
            let response = res.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        };

        conn.drive(req).await;
        conn.await.unwrap();
    };

    join(srv, client).await;
}

#[tokio::test]
async fn client_settings_header_table_size() {
    // A server sets the SETTINGS_HEADER_TABLE_SIZE to 0, test that the
    // client doesn't send indexed headers.
    h2_support::trace_init!();

    let io = mock_io::Builder::new()
        // Read SETTINGS_HEADER_TABLE_SIZE = 0
        .handshake_read_settings(&[
            0, 0, 6, // len
            4, // type
            0, // flags
            0, 0, 0, 0, // stream id
            0, 0x1, // id = SETTINGS_HEADER_TABLE_SIZE
            0, 0, 0, 0, // value = 0
        ])
        .write(frames::SETTINGS_ACK)
        // Write GET / (1st, applies the new table size immediately)
        .write(&[
            0, 0, 0x11, 1, 5, 0, 0, 0, 1, 0x20, 0x82, 0x87, 0x1, 0x8B, 0x9D, 0x29, 0xAC, 0x4B,
            0x8F, 0xA8, 0xE9, 0x19, 0x97, 0x21, 0xE9, 0x84,
        ])
        // Read response
        .read(&[0, 0, 1, 1, 5, 0, 0, 0, 1, 137])
        // Write GET / (2nd, doesn't use indexed headers)
        // - Sends :authority as literal instead of indexed
        .write(&[
            0, 0, 0x10, 1, 5, 0, 0, 0, 3, 0x82, 0x87, 0x1, 0x8B, 0x9D, 0x29, 0xAC, 0x4B, 0x8F,
            0xA8, 0xE9, 0x19, 0x97, 0x21, 0xE9, 0x84,
        ])
        .read(&[0, 0, 1, 1, 5, 0, 0, 0, 3, 137])
        .build();

    let (mut client, mut conn) = client::handshake(io).await.expect("handshake");

    let req1 = client.get("https://http2.akamai.com");
    conn.drive(req1).await.expect("req1");

    let req2 = client.get("https://http2.akamai.com");
    conn.drive(req2).await.expect("req1");
}

#[tokio::test]
async fn server_settings_header_table_size() {
    // A client sets the SETTINGS_HEADER_TABLE_SIZE to 0, test that the
    // server doesn't send indexed headers.
    h2_support::trace_init!();

    let io = mock_io::Builder::new()
        .read(MAGIC_PREFACE)
        // Read SETTINGS_HEADER_TABLE_SIZE = 0
        .read(&[
            0, 0, 6, // len
            4, // type
            0, // flags
            0, 0, 0, 0, // stream id
            0, 0x1, // id = SETTINGS_HEADER_TABLE_SIZE
            0, 0, 0, 0, // value = 0
        ])
        .write(frames::SETTINGS)
        .write(frames::SETTINGS_ACK)
        .read(frames::SETTINGS_ACK)
        // Write GET /
        .read(&[
            0, 0, 0x10, 1, 5, 0, 0, 0, 1, 0x82, 0x87, 0x41, 0x8B, 0x9D, 0x29, 0xAC, 0x4B, 0x8F,
            0xA8, 0xE9, 0x19, 0x97, 0x21, 0xE9, 0x84,
        ])
        // Read response
        //.write(&[0, 0, 6, 1, 5, 0, 0, 0, 1, 136, 64, 129, 31, 129, 143])
        .write(&[0, 0, 7, 1, 5, 0, 0, 0, 1, 32, 136, 0, 129, 31, 129, 143])
        .build();

    let mut srv = server::handshake(io).await.expect("handshake");

    let (_req, mut stream) = srv.accept().await.unwrap().unwrap();

    let rsp = http::Response::builder()
        .status(200)
        .header("a", "b")
        .body(())
        .unwrap();
    stream.send_response(rsp, true).unwrap();

    assert!(srv.accept().await.is_none());
}

/// An IO wrapper whose `poll_write` returns `Ready(Ok(0))` once the flag is set.
struct ZeroWriteIo<T> {
    inner: T,
    zero_writes: Arc<AtomicBool>,
}

impl<T: AsyncRead + Unpin> AsyncRead for ZeroWriteIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ZeroWriteIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.zero_writes.load(Ordering::SeqCst) {
            return Poll::Ready(Ok(0));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn write_zero_returns_write_zero_err() {
    use tokio::sync::oneshot;

    h2_support::trace_init!();
    let (io, mut srv) = mock::new();

    let zero_writes = Arc::new(AtomicBool::new(false));
    let io = ZeroWriteIo {
        inner: io,
        zero_writes: zero_writes.clone(),
    };

    let (done_tx, done_rx) = oneshot::channel();

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);

        // 2. Receive the request and respond.
        srv.recv_frame(
            frames::headers(1)
                .request("GET", "https://example.com/")
                .eos(),
        )
        .await;
        srv.send_frame(frames::headers(1).response(200).eos()).await;

        // 6. The client's write side is dead; it can send nothing further.
        // Wait for it to observe the connection error before dropping the
        // mock, which would close the read side too.
        let _ = done_rx.await;
    };

    let client = async move {
        let (mut client, mut conn) = client::handshake(io).await.expect("handshake");

        // 1. Send a request while the transport still accepts writes.
        let request = Request::builder()
            .uri("https://example.com/")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();

        // 3. Complete the round trip
        let response = conn.drive(response).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        // 4. The transport's write side dies: every write from now on
        // returns Ok(0).
        zero_writes.store(true, Ordering::SeqCst);

        // 5. Queue a second request; driving the connection must fail with
        // WriteZero rather than re-polling the zero-length write forever.
        let request = Request::builder()
            .uri("https://example.com/")
            .body(())
            .unwrap();
        let (_response, _) = client.send_request(request, true).unwrap();
        let err = conn
            .await
            .expect_err("connection must error on zero-length write");
        assert_eq!(err.get_io().unwrap().kind(), io::ErrorKind::WriteZero);

        done_tx.send(()).unwrap();
    };

    join(srv, client).await;
}

#[tokio::test]
async fn max_send_data_frame_size_coalesces_queued_data() {
    // A capped DATA frame takes the chunks queued behind it without waiting
    // for more, even when the peer allows larger frames. Each chunk has its
    // own byte value.
    h2_support::trace_init!();
    const BODY1: [usize; 5] = [16_384, 16_384, 16_384, 16_358, 4_096];
    const BODY3: [usize; 5] = [4_096, 4_096, 4_096, 4_096, 32_768];
    let (io, mut srv) = mock::new_vectored();

    let srv = async move {
        let settings = srv
            .assert_client_handshake_with_settings(frames::settings().max_frame_size(65_536))
            .await;
        assert_default_settings!(settings);

        // 16_384-byte chunks fill 16_375-byte frames. The windows end the
        // fifth frame inside the last chunk, whose rest keeps END_STREAM.
        srv.recv_frame(frames::headers(1).request("POST", "https://example.com/"))
            .await;
        let body = chunks(&BODY1).concat();
        recv_data(&mut srv, 1, &body, &[16_375, 16_375, 16_375, 16_375, 35]).await;
        srv.send_frame(frames::window_update(0, 65_535)).await;
        srv.send_frame(frames::window_update(1, 4_071)).await;
        srv.recv_frame(frames::data(1, &body[65_535..]).eos()).await;
        srv.send_frame(frames::headers(1).response(204).eos()).await;

        // 4 KiB chunks fill frames. An empty END_STREAM chunk waits behind
        // a partly sent chunk, then merges even when no room is left.
        srv.recv_frame(frames::headers(3).request("POST", "https://example.com/"))
            .await;
        let body = chunks(&BODY3).concat();
        recv_data(&mut srv, 3, &body, &[16_375, 16_375, 16_375]).await;
        srv.recv_frame(frames::data(3, &body[49_125..]).eos()).await;
        srv.send_frame(frames::headers(3).response(204).eos()).await;

        // Trailers stop the merge and keep their place.
        srv.recv_frame(frames::headers(5).request("POST", "https://example.com/"))
            .await;
        srv.recv_frame(frames::data(5, chunks(&[4_096; 2]).concat()))
            .await;
        srv.recv_frame(frames::headers(5).field("zomg", "hello").eos())
            .await;
        srv.send_frame(frames::headers(5).response(204).eos()).await;

        // 1-byte chunks stop at the part limit.
        srv.recv_frame(frames::headers(7).request("POST", "https://example.com/"))
            .await;
        let body = chunks(&[1; 100]).concat();
        recv_data(&mut srv, 7, &body, &[63]).await;
        srv.recv_frame(frames::data(7, &body[63..]).eos()).await;
        srv.send_frame(frames::headers(7).response(204).eos()).await;
    };

    let client = async move {
        let (mut client, mut conn) = client::Builder::new()
            .max_send_data_frame_size(16_375)
            .handshake::<_, Bytes>(io)
            .await
            .expect("handshake");

        let (resp, _stream) = post_chunks(&mut client, &BODY1, true);
        let resp = conn.drive(resp).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let (resp, mut stream) = post_chunks(&mut client, &BODY3, false);
        stream.send_data(Bytes::new(), true).unwrap();
        let resp = conn.drive(resp).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let (resp, mut stream) = post_chunks(&mut client, &[4_096; 2], false);
        let mut trailers = HeaderMap::new();
        trailers.insert("zomg", "hello".parse().unwrap());
        stream.send_trailers(trailers).unwrap();
        let resp = conn.drive(resp).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let (resp, _stream) = post_chunks(&mut client, &[1; 100], true);
        let resp = conn.drive(resp).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        conn.await.unwrap();
    };

    join(srv, client).await;
}

#[tokio::test]
async fn max_send_data_frame_size_coalesces_only_vectored_writes() {
    // Without vectored writes each part of a merged frame would take its own
    // write, so chunks are framed on their own, within the cap. Without a
    // cap, vectored writes keep the default framing.
    h2_support::trace_init!();
    const BODY: [usize; 3] = [16_384, 4_096, 4_096];
    let cases = [
        (mock::new(), Some(16_375), &[16_375, 9, 4_096, 4_096][..]),
        (mock::new_vectored(), None, &[16_384, 4_096, 4_096][..]),
    ];

    for ((io, mut srv), cap, lens) in cases {
        let srv = async move {
            let settings = srv
                .assert_client_handshake_with_settings(frames::settings().max_frame_size(65_536))
                .await;
            assert_default_settings!(settings);
            srv.recv_frame(frames::headers(1).request("POST", "https://example.com/"))
                .await;
            let body = chunks(&BODY).concat();
            let (last, lens) = lens.split_last().unwrap();
            recv_data(&mut srv, 1, &body, lens).await;
            srv.recv_frame(frames::data(1, &body[body.len() - last..]).eos())
                .await;
            srv.send_frame(frames::headers(1).response(204).eos()).await;
        };

        let client = async move {
            let mut builder = client::Builder::new();
            if let Some(cap) = cap {
                builder.max_send_data_frame_size(cap);
            }
            let (mut client, mut conn) =
                builder.handshake::<_, Bytes>(io).await.expect("handshake");

            let (resp, _stream) = post_chunks(&mut client, &BODY, true);
            let resp = conn.drive(resp).await.unwrap();
            assert_eq!(resp.status(), StatusCode::NO_CONTENT);
            conn.await.unwrap();
        };

        join(srv, client).await;
    }
}

#[tokio::test]
async fn max_send_data_frame_size_reset_drops_rest_of_merged_frame() {
    // A merged frame in flight completes before RST_STREAM, the rest of its
    // last chunk is dropped, and the connection window loses only the sent
    // bytes.
    use futures::future::lazy;
    use futures::FutureExt;
    use tokio::sync::oneshot;

    h2_support::trace_init!();
    // The first writes stop inside the merged DATA frame; 8 KiB leaves room
    // for the handshake and HEADERS to change size.
    let (io, mut srv) = mock::new_vectored_with_write_capacity(8 * 1_024);
    let (reset_tx, reset_rx) = oneshot::channel();
    let (recv_tx, recv_rx) = oneshot::channel();

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        srv.recv_frame(frames::headers(1).request("POST", "https://example.com/"))
            .await;
        reset_rx.await.unwrap();
        srv.unbounded_bytes().await;
        let body = chunks(&[4_096; 4]).concat();
        srv.recv_frame(frames::data(1, &body[..16_375])).await;
        srv.recv_frame(frames::reset(1).cancel()).await;
        recv_tx.send(()).unwrap();

        srv.recv_frame(frames::headers(3).request("POST", "https://example.com/"))
            .await;
        let body = chunks(&[49_161]).concat();
        recv_data(&mut srv, 3, &body, &[16_375, 16_375, 16_375, 35]).await;
        srv.send_frame(frames::window_update(0, 1)).await;
        srv.recv_frame(frames::data(3, &body[49_160..]).eos()).await;
        srv.send_frame(frames::headers(3).response(204).eos()).await;
    };

    let client = async move {
        let mut builder = client::Builder::new();
        builder
            .initial_max_send_streams(0)
            .max_send_data_frame_size(16_375);
        let (mut client, mut conn) = builder.handshake::<_, Bytes>(io).await.expect("handshake");
        let (_resp, mut stream) = post_chunks(&mut client, &[4_096; 5], false);

        // Buffer the merged frame, then reset the stream while it is in flight
        lazy(|cx| {
            if let Poll::Ready(v) = conn.poll_unpin(cx) {
                v.unwrap();
            }
        })
        .await;
        stream.send_reset(Reason::CANCEL);
        reset_tx.send(()).unwrap();
        conn.drive(recv_rx).await.unwrap();

        let (resp, _stream) = post_chunks(&mut client, &[49_161], true);
        let resp = conn.drive(resp).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        conn.await.unwrap();
    };

    join(srv, client).await;
}

/// Chunks of the given lengths, filled with 1, 2, 3, ...
fn chunks(lens: &[usize]) -> Vec<Bytes> {
    lens.iter()
        .zip(1u8..)
        .map(|(&len, byte)| vec![byte; len].into())
        .collect()
}

/// Sends a POST whose body chunks are all queued before the connection runs.
fn post_chunks(
    client: &mut client::SendRequest<Bytes>,
    lens: &[usize],
    eos: bool,
) -> (client::ResponseFuture, SendStream<Bytes>) {
    let request = Request::post("https://example.com/").body(()).unwrap();
    let (resp, mut stream) = client.send_request(request, false).unwrap();
    for (i, chunk) in chunks(lens).into_iter().enumerate() {
        stream.send_data(chunk, eos && i + 1 == lens.len()).unwrap();
    }
    (resp, stream)
}

/// Receives the start of `body` as DATA frames of the given lengths.
async fn recv_data(srv: &mut mock::Handle, id: u32, body: &[u8], lens: &[usize]) {
    let mut start = 0;
    for &len in lens {
        srv.recv_frame(frames::data(id, &body[start..start + len]))
            .await;
        start += len;
    }
}
