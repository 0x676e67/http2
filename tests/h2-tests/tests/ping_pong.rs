use futures::channel::oneshot;
use futures::StreamExt;
use h2_support::assert_ping;
use h2_support::prelude::*;
use std::task::Poll;

#[tokio::test]
async fn recv_single_ping() {
    h2_support::trace_init!();
    let (m, mut mock) = mock::new();

    // Create the handshake
    let h2 = async move {
        let (_client, conn) = client::handshake(m).await.unwrap();
        let _: () = conn.await.unwrap();
    };

    let mock = async move {
        let _ = mock.assert_client_handshake().await;
        let frame = frame::Ping::new(Default::default());
        mock.send(frame.into()).await.unwrap();
        let frame = mock.next().await.unwrap();

        let pong = assert_ping!(frame.unwrap());

        // Payload is correct
        assert_eq!(*pong.payload(), <[u8; 8]>::default());

        // Is ACK
        assert!(pong.is_ack());
    };

    join(mock, h2).await;
}

#[tokio::test]
async fn recv_multiple_pings() {
    h2_support::trace_init!();
    let (io, mut client) = mock::new();

    let client = async move {
        let settings = client.assert_server_handshake().await;
        assert_default_settings!(settings);
        client.send_frame(frames::ping([1; 8])).await;
        client.send_frame(frames::ping([2; 8])).await;
        client.recv_frame(frames::ping([1; 8]).pong()).await;
        client.recv_frame(frames::ping([2; 8]).pong()).await;
    };

    let srv = async move {
        let mut s = server::handshake(io).await.expect("handshake");
        assert!(s.next().await.is_none());
    };

    join(client, srv).await;
}

#[tokio::test]
async fn pong_has_highest_priority() {
    h2_support::trace_init!();
    let (io, mut client) = mock::new();

    let data = Bytes::from(vec![0; 16_384]);
    let data_clone = data.clone();

    let client = async move {
        let settings = client.assert_server_handshake().await;
        assert_default_settings!(settings);
        client
            .send_frame(frames::headers(1).request("POST", "https://http2.akamai.com/"))
            .await;
        client.send_frame(frames::data(1, data_clone).eos()).await;
        client.send_frame(frames::ping([1; 8])).await;
        client.recv_frame(frames::ping([1; 8]).pong()).await;
        client
            .recv_frame(frames::headers(1).response(200).eos())
            .await;
    };

    let srv = async move {
        let mut s = server::handshake(io).await.expect("handshake");
        let (req, mut stream) = s.next().await.unwrap().unwrap();
        assert_eq!(req.method(), "POST");
        let body = req.into_parts().1;

        let body = util::concat(body).await.expect("body");
        assert_eq!(body.len(), data.len());
        let res = Response::builder().status(200).body(()).unwrap();
        stream.send_response(res, true).expect("response");
        assert!(s.next().await.is_none());
    };

    join(client, srv).await;
}

#[tokio::test]
async fn user_ping_pong() {
    h2_support::trace_init!();
    let (io, mut srv) = mock::new();

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        srv.recv_frame(frames::ping(frame::Ping::USER)).await;
        srv.send_frame(frames::ping(frame::Ping::USER).pong()).await;
        srv.recv_frame(frames::go_away(0)).await;
        srv.recv_eof().await;
    };

    let client = async move {
        let (client, mut conn) = client::handshake(io).await.expect("client handshake");
        // yield once so we can ack server settings
        conn.drive(util::yield_once()).await;
        // `ping_pong()` method conflict with mock future ext trait.
        let mut ping_pong = client::Connection::ping_pong(&mut conn).expect("taking ping_pong");
        ping_pong.send_ping(Ping::opaque()).expect("send ping");

        // multiple pings results in a user error...
        assert_eq!(
            ping_pong
                .send_ping(Ping::opaque())
                .expect_err("ping 2")
                .to_string(),
            "user error: send_ping before received previous pong",
            "send_ping while ping pending is a user error",
        );

        conn.drive(futures::future::poll_fn(move |cx| ping_pong.poll_pong(cx)))
            .await
            .unwrap();
        drop(client);
        conn.await.expect("client");
    };

    join(srv, client).await;
}

#[tokio::test]
async fn user_ping_custom_payload() {
    h2_support::trace_init!();
    let (io, mut srv) = mock::new();
    let (tx, rx) = oneshot::channel();

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        srv.recv_frame(frames::ping([0; 8])).await;
        // An ACK with another payload is ignored. The pong for the server
        // PING shows that the client has read it.
        srv.send_frame(frames::ping(frame::Ping::USER).pong()).await;
        srv.send_frame(frames::ping([1; 8])).await;
        srv.recv_frame(frames::ping([1; 8]).pong()).await;
        tx.send(()).unwrap();
        srv.send_frame(frames::ping([0; 8]).pong()).await;
        srv.recv_frame(frames::go_away(0)).await;
        srv.recv_eof().await;
    };

    let client = async move {
        let (client, mut conn) = client::handshake(io).await.expect("client handshake");
        // yield once so we can ack server settings
        conn.drive(util::yield_once()).await;
        // `ping_pong()` method conflict with mock future ext trait.
        let mut ping_pong = client::Connection::ping_pong(&mut conn).expect("taking ping_pong");
        ping_pong.send_ping(Ping::new([0; 8])).expect("send ping");
        // A rejected PING does not replace the pending payload.
        ping_pong
            .send_ping(Ping::new([2; 8]))
            .expect_err("send ping while pending");

        conn.drive(rx).await.unwrap();
        assert!(poll_fn(|cx| Poll::Ready(ping_pong.poll_pong(cx)))
            .await
            .is_pending());

        conn.drive(poll_fn(move |cx| ping_pong.poll_pong(cx)))
            .await
            .unwrap();
        drop(client);
        conn.await.expect("client");
    };

    join(srv, client).await;
}

#[tokio::test]
async fn user_notifies_when_connection_closes() {
    h2_support::trace_init!();
    let (io, mut srv) = mock::new();
    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        srv
    };

    #[allow(clippy::async_yields_async)]
    let client = async move {
        let (_client, mut conn) = client::handshake(io).await.expect("client handshake");
        // yield once so we can ack server settings
        conn.drive(util::yield_once()).await;
        conn
    };

    let (srv, mut client) = join(srv, client).await;

    // `ping_pong()` method conflict with mock future ext trait.
    let mut ping_pong = client::Connection::ping_pong(&mut client).expect("taking ping_pong");

    // Spawn a thread so we can park a task waiting on `poll_pong`, and then
    // drop the client and be sure the parked task is notified...
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        poll_fn(|cx| ping_pong.poll_pong(cx))
            .await
            .expect_err("poll_pong should error");
        tx.send(ping_pong).unwrap();
    });

    // Sleep to let the ping thread park its task...
    idle_ms(50).await;
    drop(client);
    drop(srv);

    let mut ping_pong = rx.await.expect("ping pong spawn join");

    // Now that the connection is closed, also test `send_ping` errors...
    assert_eq!(
        ping_pong
            .send_ping(Ping::opaque())
            .expect_err("send_ping")
            .to_string(),
        "broken pipe",
    );
}

#[tokio::test]
async fn preface_ping_after_read_idle() {
    h2_support::trace_init!();
    let (io, mut srv) = mock::new();
    let (tx, rx) = oneshot::channel();

    let large = build_large_headers();
    let get = large.iter().fold(
        frames::headers(3).request("GET", "https://http2.akamai.com/"),
        |frame, &(name, ref value)| frame.field(name, &value[..]),
    );

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        // No PING right after the handshake, nor for empty DATA.
        srv.recv_frame(frames::headers(1).request("POST", "https://http2.akamai.com/"))
            .await;
        srv.recv_frame(frames::data(1, "")).await;
        // The PING follows HEADERS and all of its CONTINUATION frames, and no
        // other PING is sent while it awaits its ACK.
        srv.recv_frame(get.eos()).await;
        srv.recv_frame(frames::ping(1u64.to_be_bytes())).await;
        srv.recv_frame(frames::data(1, "")).await;
        srv.recv_frame(frames::data(1, "a")).await;
        srv.send_frame(frames::ping(1u64.to_be_bytes()).pong())
            .await;
        srv.send_frame(frames::headers(3).response(204).eos()).await;
        // Bytes of an ignored unknown frame also reset the idle time.
        idle_ms(400).await;
        srv.send_bytes(&[0, 0, 0, 0xfa, 0, 0, 0, 0, 0]).await;
        tx.send(()).unwrap();
        srv.recv_frame(frames::data(1, "b")).await;
        // The PING precedes DATA.
        srv.recv_frame(frames::ping(2u64.to_be_bytes())).await;
        srv.recv_frame(frames::data(1, "c").eos()).await;
        srv.send_frame(frames::ping(2u64.to_be_bytes()).pong())
            .await;
        srv.send_frame(frames::headers(1).response(204).eos()).await;
    };

    let client = async move {
        let (mut client, mut conn) = client::Builder::new()
            .preface_ping(Duration::from_millis(200))
            .handshake::<_, Bytes>(io)
            .await
            .expect("handshake");

        let req = async {
            let request = Request::post("https://http2.akamai.com/").body(()).unwrap();
            let (post, mut stream) = client.send_request(request, false).unwrap();

            idle_ms(400).await;
            stream.send_data(Bytes::new(), false).unwrap();
            util::yield_once().await;

            let request = large
                .iter()
                .fold(
                    Request::get("https://http2.akamai.com/"),
                    |request, &(name, ref value)| request.header(name, &value[..]),
                )
                .body(())
                .unwrap();
            let (get, _) = client.send_request(request, true).unwrap();
            stream.send_data(Bytes::new(), false).unwrap();
            stream.send_data("a".into(), false).unwrap();
            assert_eq!(get.await.unwrap().status(), StatusCode::NO_CONTENT);

            rx.await.unwrap();
            stream.send_data("b".into(), false).unwrap();
            idle_ms(400).await;
            stream.send_data("c".into(), true).unwrap();
            assert_eq!(post.await.unwrap().status(), StatusCode::NO_CONTENT);
        };

        conn.drive(req).await;
        conn.await.unwrap();
    };

    join(srv, client).await;
}

#[tokio::test]
async fn preface_ping_skips_user_ping_payload() {
    h2_support::trace_init!();
    let (io, mut srv) = mock::new();

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        srv.recv_frame(frames::ping(1u64.to_be_bytes())).await;
        srv.recv_frame(
            frames::headers(1)
                .request("GET", "https://http2.akamai.com/")
                .eos(),
        )
        .await;
        // The preface PING skips the payload of the user PING in flight, so
        // each ACK completes its own PING.
        srv.recv_frame(frames::ping(2u64.to_be_bytes())).await;
        srv.send_frame(frames::ping(1u64.to_be_bytes()).pong())
            .await;
        srv.send_frame(frames::ping(2u64.to_be_bytes()).pong())
            .await;
        srv.send_frame(frames::headers(1).response(204).eos()).await;
    };

    let client = async move {
        let (mut client, mut conn) = client::Builder::new()
            .preface_ping(Duration::from_millis(200))
            .handshake::<_, Bytes>(io)
            .await
            .expect("handshake");
        // `ping_pong()` method conflict with mock future ext trait.
        let mut ping_pong = client::Connection::ping_pong(&mut conn).expect("taking ping_pong");
        ping_pong
            .send_ping(Ping::new(1u64.to_be_bytes()))
            .expect("send ping");
        conn.drive(idle_ms(400)).await;

        let request = Request::get("https://http2.akamai.com/").body(()).unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        conn.drive(poll_fn(|cx| ping_pong.poll_pong(cx)))
            .await
            .unwrap();
        let response = conn.drive(response).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        conn.await.unwrap();
    };

    join(srv, client).await;
}
