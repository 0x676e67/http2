use h2_support::prelude::*;

fn request_headers(
    stream_id: u32,
    path: &str,
    dependency: Option<frame::StreamDependency>,
) -> frame::Headers {
    let mut headers: frame::Headers = frames::headers(stream_id)
        .request("GET", format!("https://example.com/{path}"))
        .eos()
        .into();

    if let Some(dependency) = dependency {
        headers.set_stream_dependency(dependency);
    }

    headers
}

#[tokio::test]
async fn request_dependency_overrides_are_isolated_on_reused_connection() {
    h2_support::trace_init!();
    let (io, mut peer) = mock::new();

    let peer_task = async move {
        assert_default_settings!(peer.assert_client_handshake().await);

        peer.recv_frame(request_headers(
            1,
            "inherited",
            Some(frame::StreamDependency::new(StreamId::zero(), 10, false)),
        ))
        .await;
        peer.recv_frame(request_headers(
            3,
            "root-override",
            Some(frame::StreamDependency::new(StreamId::zero(), 219, true)),
        ))
        .await;
        peer.recv_frame(request_headers(
            5,
            "stream-override",
            Some(frame::StreamDependency::new(StreamId::from(1), 146, true)),
        ))
        .await;
        peer.recv_frame(request_headers(
            7,
            "inherited-again",
            Some(frame::StreamDependency::new(StreamId::zero(), 10, false)),
        ))
        .await;

        for stream_id in [1, 3, 5, 7] {
            peer.send_frame(frames::headers(stream_id).response(204).eos())
                .await;
        }
    };

    let client_task = async move {
        let mut builder = client::Builder::new();
        builder.headers_stream_dependency(frame::StreamDependency::new(
            StreamId::zero(),
            10,
            false,
        ));

        let (mut client, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
        let inherited = Request::get("https://example.com/inherited")
            .body(())
            .unwrap();
        let (inherited_response, _inherited_stream) = client.send_request(inherited, true).unwrap();

        let mut root_override = Request::get("https://example.com/root-override")
            .body(())
            .unwrap();
        root_override
            .extensions_mut()
            .insert(h2::ext::HeadersPriority::new(StreamId::zero(), 219, true));
        let (root_response, _root_stream) = client.send_request(root_override, true).unwrap();

        let mut stream_override = Request::get("https://example.com/stream-override")
            .body(())
            .unwrap();
        stream_override
            .extensions_mut()
            .insert(h2::ext::HeadersPriority::new(StreamId::from(1), 146, true));
        let (stream_response, _stream) = client.send_request(stream_override, true).unwrap();

        let inherited_again = Request::get("https://example.com/inherited-again")
            .body(())
            .unwrap();
        let (inherited_again_response, _inherited_again_stream) =
            client.send_request(inherited_again, true).unwrap();

        connection
            .drive(async move {
                for response in [
                    inherited_response,
                    root_response,
                    stream_response,
                    inherited_again_response,
                ] {
                    assert_eq!(response.await.unwrap().status(), StatusCode::NO_CONTENT);
                }
            })
            .await;
        drop(client);
        connection.await.unwrap();
    };

    join(peer_task, client_task).await;
}
