use h2::ext::{HeadersDependency, HeadersPriority};
use h2_support::prelude::*;

fn request_headers(
    stream_id: u32,
    path: &str,
    (dependency, weight, is_exclusive): (u32, u8, bool),
) -> frame::Headers {
    let mut headers: frame::Headers = frames::headers(stream_id)
        .request("GET", format!("https://example.com/{path}"))
        .eos()
        .into();
    headers.set_stream_dependency(frame::StreamDependency::new(
        StreamId::from(dependency),
        weight,
        is_exclusive,
    ));
    headers
}

fn request(path: &str, priority: Option<HeadersPriority>) -> Request<()> {
    let mut request = Request::get(format!("https://example.com/{path}"))
        .body(())
        .unwrap();
    if let Some(priority) = priority {
        request.extensions_mut().insert(priority);
    }
    request
}

#[tokio::test]
async fn headers_priority_defaults_overrides_and_chain_parents() {
    h2_support::trace_init!();

    let declared = |ids: &[u32]| {
        ids.iter()
            .fold(frame::Priorities::builder(), |builder, &id| {
                builder.push(frame::Priority::new(
                    StreamId::from(id),
                    frame::StreamDependency::new(StreamId::zero(), 200, false),
                ))
            })
            .build()
    };

    // Stream 3 is undeclared, and declared stream 5 would later be a request's
    // own stream, so both defaults fail the handshake.
    for (initial_stream_id, dependency_id, declared_id) in [(1, 3, None), (3, 5, Some(5))] {
        let (io, _peer) = mock::new();
        let mut builder = client::Builder::new();
        builder
            .initial_stream_id(initial_stream_id)
            .headers_priority(HeadersPriority::new(
                HeadersDependency::Declared(h2::StreamId::from(dependency_id)),
                146,
                false,
            ));
        if let Some(id) = declared_id {
            builder.priorities(declared(&[id]));
        }
        let err = builder.handshake::<_, Bytes>(io).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "user error: invalid HEADERS priority dependency"
        );
    }

    let (io, mut peer) = mock::new();
    let peer_task = async move {
        assert_default_settings!(peer.assert_client_handshake().await);
        for stream_id in [3, 19] {
            peer.recv_frame(frame::Priority::new(
                StreamId::from(stream_id),
                frame::StreamDependency::new(StreamId::zero(), 200, false),
            ))
            .await;
        }
        peer.recv_frame(request_headers(5, "chain", (0, 182, true)))
            .await;
        peer.recv_frame(request_headers(7, "urgent", (0, 255, true)))
            .await;
        peer.recv_frame(request_headers(9, "chain-parent", (5, 182, true)))
            .await;
        // Urgency 255 is clamped to 7, so the parent search still reaches level 2.
        peer.recv_frame(request_headers(11, "least-urgent", (9, 109, true)))
            .await;
        // An override may name a declared idle stream above its own stream.
        peer.recv_frame(request_headers(13, "declared-idle", (19, 73, false)))
            .await;
        peer.recv_frame(request_headers(15, "root", (0, 219, true)))
            .await;
        peer.recv_frame(request_headers(17, "declared", (3, 146, false)))
            .await;
        peer.send_frame(frames::headers(15).response(204).eos())
            .await;
        // A locally reset stream stops being a parent before its RST_STREAM is
        // written, so the next urgency 2 request skips it.
        peer.recv_frame(request_headers(19, "after-close", (5, 182, true)))
            .await;
        peer.recv_frame(frames::reset(9).cancel()).await;
        for stream_id in [5, 7, 11, 13, 17, 19] {
            peer.send_frame(frames::headers(stream_id).response(204).eos())
                .await;
        }
    };

    let client_task = async move {
        let mut builder = client::Builder::new();
        builder
            .initial_stream_id(5)
            .priorities(declared(&[3, 19]))
            .headers_priority(HeadersPriority::new(
                HeadersDependency::Chain { urgency: 2 },
                182,
                true,
            ));
        let (mut client, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();

        let mut responses = Vec::new();
        let mut streams = Vec::new();
        for (path, priority) in [
            ("chain", None),
            (
                "urgent",
                Some(HeadersPriority::new(
                    HeadersDependency::Chain { urgency: 0 },
                    255,
                    true,
                )),
            ),
            ("chain-parent", None),
            (
                "least-urgent",
                Some(HeadersPriority::new(
                    HeadersDependency::Chain { urgency: 255 },
                    109,
                    true,
                )),
            ),
            (
                "declared-idle",
                Some(HeadersPriority::new(
                    HeadersDependency::Declared(h2::StreamId::from(19)),
                    73,
                    false,
                )),
            ),
            (
                "root",
                Some(HeadersPriority::new(HeadersDependency::Root, 219, true)),
            ),
            (
                "declared",
                Some(HeadersPriority::new(
                    HeadersDependency::Declared(h2::StreamId::from(3)),
                    146,
                    false,
                )),
            ),
        ] {
            let (response, stream) = client.send_request(request(path, priority), true).unwrap();
            responses.push(response);
            streams.push(stream);
        }

        // An undeclared parent and a self-dependency are both rejected before a
        // stream ID is consumed: the next request still uses 19.
        for (path, dependency_id) in [("undeclared", 7), ("self", 19)] {
            let override_ = HeadersPriority::new(
                HeadersDependency::Declared(h2::StreamId::from(dependency_id)),
                0,
                true,
            );
            let err = client
                .send_request(request(path, Some(override_)), true)
                .unwrap_err();
            assert_eq!(
                err.to_string(),
                "user error: invalid HEADERS priority dependency"
            );
        }

        // Once stream 15 completes, every HEADERS up to stream 17 is written.
        let root = responses.remove(5);
        let response = connection.drive(root).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        drop(responses.remove(2));
        streams[2].send_reset(Reason::CANCEL);

        responses.push(
            client
                .send_request(request("after-close", None), true)
                .unwrap()
                .0,
        );
        connection
            .drive(async move {
                for response in responses {
                    assert_eq!(response.await.unwrap().status(), StatusCode::NO_CONTENT);
                }
            })
            .await;
        drop((client, streams));
        connection.await.unwrap();
    };

    join(peer_task, client_task).await;
}

#[tokio::test]
async fn queued_chain_request_picks_parent_when_headers_are_written() {
    h2_support::trace_init!();
    let (io, mut peer) = mock::new();

    let peer_task = async move {
        let settings = frames::settings().max_concurrent_streams(1);
        assert_default_settings!(peer.assert_client_handshake_with_settings(settings).await);
        peer.recv_frame(request_headers(1, "first", (0, 182, true)))
            .await;
        peer.send_frame(frames::headers(1).response(204).eos())
            .await;
        // Stream 1 closed while stream 3 waited for concurrency, so stream 3
        // depends on the root rather than on the stream open at send time.
        peer.recv_frame(request_headers(3, "queued", (0, 182, true)))
            .await;
        peer.send_frame(frames::headers(3).response(204).eos())
            .await;
    };

    let client_task = async move {
        let mut builder = client::Builder::new();
        builder.headers_priority(HeadersPriority::new(
            HeadersDependency::Chain { urgency: 2 },
            182,
            true,
        ));
        let (client, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();

        let mut client = connection.drive(client.ready()).await.unwrap();
        let first = client.send_request(request("first", None), true).unwrap().0;
        let mut client = connection.drive(client.ready()).await.unwrap();
        let queued = client
            .send_request(request("queued", None), true)
            .unwrap()
            .0;

        connection
            .drive(async move {
                for response in [first, queued] {
                    assert_eq!(response.await.unwrap().status(), StatusCode::NO_CONTENT);
                }
            })
            .await;
        drop(client);
        connection.await.unwrap();
    };

    join(peer_task, client_task).await;
}

#[tokio::test]
async fn flow_control_reset_removes_chain_parent_before_queued_headers() {
    use tokio::sync::oneshot;

    h2_support::trace_init!();
    let (io, mut peer) = mock::new();
    let (opened_tx, opened_rx) = oneshot::channel();
    let (paused_tx, paused_rx) = oneshot::channel();
    let (overflow_tx, overflow_rx) = oneshot::channel();

    let peer_task = async move {
        assert_default_settings!(peer.assert_client_handshake().await);
        let mut open: frame::Headers = frames::headers(1)
            .request("GET", "https://example.com/open")
            .into();
        open.set_stream_dependency(frame::StreamDependency::new(StreamId::zero(), 182, true));
        peer.recv_frame(open).await;
        opened_tx.send(()).unwrap();

        // Sent while the client is not polling, so it is read together with
        // the queued stream 3. It overflows stream 1's send window, and the
        // client resets stream 1 (RFC 9113 section 6.9.1).
        paused_rx.await.unwrap();
        peer.send_frame(frames::window_update(1, u32::MAX >> 1))
            .await;
        overflow_tx.send(()).unwrap();

        // Stream 3's HEADERS leaves before stream 1's RST_STREAM, but must not
        // name the reset stream.
        peer.recv_frame(request_headers(3, "queued", (0, 182, true)))
            .await;
        peer.recv_frame(frames::reset(1).flow_control()).await;
        peer.send_frame(frames::headers(3).response(204).eos())
            .await;
    };

    let client_task = async move {
        let mut builder = client::Builder::new();
        builder.headers_priority(HeadersPriority::new(
            HeadersDependency::Chain { urgency: 2 },
            182,
            true,
        ));
        let (mut client, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();

        let (open, _stream) = client.send_request(request("open", None), false).unwrap();
        connection.drive(opened_rx).await.unwrap();
        paused_tx.send(()).unwrap();
        overflow_rx.await.unwrap();
        let queued = client
            .send_request(request("queued", None), true)
            .unwrap()
            .0;

        connection
            .drive(async move {
                assert!(open.await.is_err());
                assert_eq!(queued.await.unwrap().status(), StatusCode::NO_CONTENT);
            })
            .await;
        drop(client);
        connection.await.unwrap();
    };

    join(peer_task, client_task).await;
}

#[tokio::test]
async fn gracefully_closed_chain_parent_stays_until_final_frame_is_written() {
    h2_support::trace_init!();
    let (io, mut peer) = mock::new();

    let peer_task = async move {
        let settings = frames::settings().initial_window_size(0);
        assert_default_settings!(peer.assert_client_handshake_with_settings(settings).await);
        let mut open: frame::Headers = frames::headers(1)
            .request("GET", "https://example.com/upload")
            .into();
        open.set_stream_dependency(frame::StreamDependency::new(StreamId::zero(), 182, true));
        peer.recv_frame(open).await;
        peer.send_frame(frames::headers(1).response(204).eos())
            .await;
        // Stream 1's final DATA is still blocked by flow control, so the peer
        // sees stream 1 open and stream 3 still chains onto it.
        peer.recv_frame(request_headers(3, "next", (1, 182, true)))
            .await;
        peer.send_frame(frames::window_update(1, 1)).await;
        peer.recv_frame(frames::data(1, "x").eos()).await;
        peer.send_frame(frames::headers(3).response(204).eos())
            .await;
    };

    let client_task = async move {
        let mut builder = client::Builder::new();
        builder.headers_priority(HeadersPriority::new(
            HeadersDependency::Chain { urgency: 2 },
            182,
            true,
        ));
        let (mut client, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();

        let (upload, mut body) = client.send_request(request("upload", None), false).unwrap();
        let response = connection.drive(upload).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        body.send_data(Bytes::from_static(b"x"), true).unwrap();

        let next = client.send_request(request("next", None), true).unwrap().0;
        let response = connection.drive(next).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        drop((client, body));
        connection.await.unwrap();
    };

    join(peer_task, client_task).await;
}
