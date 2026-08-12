use futures::StreamExt;
use h2_support::prelude::*;

fn raw_frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 0x00ff_ffff);

    let len = (payload.len() as u32).to_be_bytes();
    let stream_id = stream_id.to_be_bytes();
    let mut frame = Vec::with_capacity(frame::HEADER_LEN + payload.len());
    frame.extend_from_slice(&[
        len[1],
        len[2],
        len[3],
        kind,
        flags,
        stream_id[0],
        stream_id[1],
        stream_id[2],
        stream_id[3],
    ]);
    frame.extend_from_slice(payload);
    frame
}

#[tokio::test]
async fn configured_priorities_are_sent_once_before_ordered_requests() {
    h2_support::trace_init!();
    let (io, mut peer) = mock::new();

    let priority_one = frame::Priority::new(
        StreamId::from(1),
        frame::StreamDependency::new(StreamId::zero(), 200, false),
    );
    let priority_three = frame::Priority::new(
        StreamId::from(3),
        frame::StreamDependency::new(StreamId::from(1), 100, true),
    );

    let peer_task = {
        let priority_one = priority_one.clone();
        let priority_three = priority_three.clone();
        async move {
            assert_default_settings!(peer.assert_client_handshake().await);
            peer.recv_frame(priority_one).await;
            peer.recv_frame(priority_three).await;
            peer.recv_frame(
                frames::headers(3)
                    .request("GET", "https://example.com/first")
                    .eos(),
            )
            .await;
            peer.recv_frame(
                frames::headers(5)
                    .request("GET", "https://example.com/second")
                    .eos(),
            )
            .await;
            peer.send_frame(frames::headers(3).response(204).eos())
                .await;
            peer.send_frame(frames::headers(5).response(204).eos())
                .await;
        }
    };

    let client_task = async move {
        let mut builder = client::Builder::new();
        builder.priorities(
            frame::Priorities::builder()
                .extend([priority_one, priority_three])
                .build(),
        );

        let (mut client, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();

        let invalid = Request::builder()
            .uri("https://example.com/invalid")
            .header(http::header::CONNECTION, "close")
            .body(())
            .unwrap();
        assert!(client.send_request(invalid, true).is_err());

        let first = client
            .send_request(
                Request::get("https://example.com/first").body(()).unwrap(),
                true,
            )
            .unwrap()
            .0;
        let second = client
            .send_request(
                Request::get("https://example.com/second").body(()).unwrap(),
                true,
            )
            .unwrap()
            .0;

        connection
            .drive(async move {
                let (first, second) = join(first, second).await;
                assert_eq!(first.unwrap().status(), StatusCode::NO_CONTENT);
                assert_eq!(second.unwrap().status(), StatusCode::NO_CONTENT);
            })
            .await;
        drop(client);
        connection.await.unwrap();
    };

    join(peer_task, client_task).await;
}

#[tokio::test]
async fn invalid_priority_lengths_reset_open_streams_or_close_connection() {
    h2_support::trace_init!();
    let (io, mut client) = mock::new();

    let client_task = async move {
        assert_default_settings!(client.assert_server_handshake().await);

        for (stream_id, payload_len) in [(1, 4), (3, 6)] {
            client
                .send_frame(
                    frames::headers(stream_id)
                        .request("GET", "https://example.com/")
                        .eos(),
                )
                .await;
            client
                .recv_frame(frames::headers(stream_id).response(200))
                .await;
            client
                .send_bytes(&raw_frame(2, 0, stream_id, &vec![0; payload_len]))
                .await;
            client
                .recv_frame(frames::reset(stream_id).reason(Reason::FRAME_SIZE_ERROR))
                .await;
        }

        client
            .send_frame(
                frames::headers(5)
                    .request("GET", "https://example.com/final")
                    .eos(),
            )
            .await;
        client.recv_frame(frames::headers(5).response(200)).await;
        client.send_bytes(&raw_frame(2, 0, 7, &[0, 0, 0, 0])).await;
        client.recv_frame(frames::go_away(5).frame_size()).await;
    };

    let server_task = async move {
        let mut server = server::handshake(io).await.unwrap();
        let mut streams = Vec::new();

        for stream_id in [1, 3, 5] {
            let (request, mut respond) = server.next().await.unwrap().unwrap();
            assert_eq!(request.body().stream_id().as_u32(), stream_id);
            let response = Response::builder().status(200).body(()).unwrap();
            let send = respond.send_response(response, false).unwrap();
            streams.push((request, send));
        }

        let err = server.next().await.unwrap().unwrap_err();
        assert_eq!(err.reason(), Some(Reason::FRAME_SIZE_ERROR));
        drop(streams);
    };

    join(client_task, server_task).await;

    // Retain both stream handles after a complete request and response so the
    // store entry remains occupied while its wire state is closed.
    let (io, mut peer) = mock::new();
    let peer_task = async move {
        assert_default_settings!(peer.assert_server_handshake().await);
        peer.send_frame(
            frames::headers(1)
                .request("GET", "https://example.com/closed")
                .eos(),
        )
        .await;
        peer.recv_frame(frames::headers(1).response(204).eos())
            .await;
        peer.send_bytes(&raw_frame(2, 0xff, 1, &[0, 0, 0, 0, 15]))
            .await;
        peer.send_bytes(&raw_frame(2, 0, 1, &[0, 0, 0, 0])).await;
        peer.recv_frame(frames::go_away(1).frame_size()).await;
    };
    let server_task = async move {
        let mut server = server::handshake(io).await.unwrap();
        let (request, mut respond) = server.next().await.unwrap().unwrap();
        let send = respond
            .send_response(Response::builder().status(204).body(()).unwrap(), true)
            .unwrap();
        let held = (request, send);

        let err = server.next().await.unwrap().unwrap_err();
        assert_eq!(err.reason(), Some(Reason::FRAME_SIZE_ERROR));
        drop(held);
    };

    join(peer_task, server_task).await;

    // A request held behind the local concurrency limit is open only in
    // memory. Until its HEADERS reaches the wire, RFC 9113 section 6.4 still
    // forbids using RST_STREAM to report the malformed PRIORITY frame.
    let (io, mut peer) = mock::new();
    let peer_task = async move {
        peer.assert_client_handshake_with_settings(frames::settings().max_concurrent_streams(0))
            .await;
        peer.send_bytes(&raw_frame(2, 0, 1, &[0, 0, 0, 0])).await;
        peer.recv_frame(frames::go_away(0).frame_size()).await;
    };
    let client_task = async move {
        let mut builder = client::Builder::new();
        builder.initial_max_send_streams(0);
        let (mut client, connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
        let (response, _send_stream) = client
            .send_request(
                Request::get("https://example.com/pending")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();

        let err = connection.await.unwrap_err();
        assert_eq!(err.reason(), Some(Reason::FRAME_SIZE_ERROR));
        assert_eq!(
            response.await.unwrap_err().reason(),
            Some(Reason::FRAME_SIZE_ERROR)
        );
    };

    join(peer_task, client_task).await;
}

#[tokio::test]
async fn deprecated_self_dependency_does_not_break_continuation_hpack_state() {
    h2_support::trace_init!();
    let (io, mut client) = mock::new();

    let client_task = async move {
        assert_default_settings!(client.assert_server_handshake().await);

        let mut first_block = vec![0x82, 0x87, 0x84, 0x01, 11];
        first_block.extend_from_slice(b"example.com");
        first_block.extend_from_slice(&[0x40, 9]);
        first_block.extend_from_slice(b"x-dynamic");
        first_block.extend_from_slice(&[5]);
        first_block.extend_from_slice(b"value");

        let split = 4;
        let mut first_payload = vec![0, 0, 0, 1, 15];
        first_payload.extend_from_slice(&first_block[..split]);
        client
            .send_bytes(&raw_frame(1, 0x21, 1, &first_payload))
            .await;
        client
            .send_bytes(&raw_frame(9, 0x04, 1, &first_block[split..]))
            .await;
        client
            .recv_frame(frames::headers(1).response(204).eos())
            .await;

        let mut second_block = vec![0x82, 0x87, 0x84, 0x01, 11];
        second_block.extend_from_slice(b"example.com");
        second_block.push(0xbe);
        client
            .send_bytes(&raw_frame(1, 0x05, 3, &second_block))
            .await;
        client
            .recv_frame(frames::headers(3).response(204).eos())
            .await;
    };

    let server_task = async move {
        let mut server = server::handshake(io).await.unwrap();

        for stream_id in [1, 3] {
            let (request, mut respond) = server.next().await.unwrap().unwrap();
            assert_eq!(request.body().stream_id().as_u32(), stream_id);
            assert_eq!(request.headers()["x-dynamic"], "value");
            respond
                .send_response(Response::builder().status(204).body(()).unwrap(), true)
                .unwrap();
        }

        assert!(server.next().await.is_none());
    };

    join(client_task, server_task).await;
}

#[tokio::test]
async fn invalid_priority_fields_use_connection_errors() {
    for payload_len in 0..5 {
        let frame = raw_frame(1, 0x24, 1, &vec![0; payload_len]);
        let mut codec = raw_codec! {
            read => [frame,];
        };

        match poll_err!(codec) {
            h2::proto::Error::GoAway(_, Reason::FRAME_SIZE_ERROR, _) => {}
            err => panic!("expected connection FRAME_SIZE_ERROR, got {:?}", err),
        }
    }

    let mut codec = raw_codec! {
        read => [raw_frame(1, 0x2c, 1, &[]),];
    };
    match poll_err!(codec) {
        h2::proto::Error::GoAway(_, Reason::FRAME_SIZE_ERROR, _) => {}
        err => panic!("expected connection FRAME_SIZE_ERROR, got {:?}", err),
    }

    let mut codec = raw_codec! {
        read => [raw_frame(2, 0xff, 0, &[0, 0, 0, 0, 15]),];
    };
    match poll_err!(codec) {
        h2::proto::Error::GoAway(_, Reason::PROTOCOL_ERROR, _) => {}
        err => panic!("expected connection PROTOCOL_ERROR, got {:?}", err),
    }
}
