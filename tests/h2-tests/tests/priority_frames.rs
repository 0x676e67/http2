use h2_support::prelude::*;

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
