use h2::ext::{WindowUpdatePolicy, WindowUpdateRule};
use h2_support::prelude::*;
use std::time::Duration;
use tokio::sync::mpsc;

// Each step consumes DATA before choosing how much capacity to release.
// PING barriers make unexpected WINDOW_UPDATE frames visible to the peer.
async fn check_updates(
    stream_policy: Option<WindowUpdateRule>,
    connection_policy: Option<WindowUpdateRule>,
    steps: &[(usize, usize, u32, u32)],
) {
    let (io, mut peer) = mock::new();
    let (released_tx, mut released_rx) = mpsc::unbounded_channel();
    let (checked_tx, mut checked_rx) = mpsc::unbounded_channel();
    let remote = async {
        peer.assert_client_handshake().await;
        if connection_policy.is_some() {
            peer.recv_frame(frames::window_update(0, 1)).await;
        }
        peer.recv_frame(
            frames::headers(1)
                .request("GET", "https://example.com/")
                .eos(),
        )
        .await;
        peer.send_frame(frames::headers(1).response(200)).await;
        for &(size, _, connection_update, stream_update) in steps {
            for chunk in vec![0; size].chunks(16_384) {
                peer.send_frame(frames::data(1, chunk)).await;
            }
            released_rx.recv().await.unwrap();
            if connection_update > 0 {
                peer.recv_frame(frames::window_update(0, connection_update))
                    .await;
            }
            if stream_update > 0 {
                peer.recv_frame(frames::window_update(1, stream_update))
                    .await;
            }
            peer.ping_pong([0; 8]).await;
            checked_tx.send(()).unwrap();
        }
        peer.send_frame(frames::data(1, "").eos()).await;
        peer.recv_eof().await;
    };
    let local = async {
        let mut policy = WindowUpdatePolicy::default();
        if let Some(rule) = stream_policy {
            policy = policy.stream(rule);
        }
        if let Some(rule) = connection_policy {
            policy = policy.connection(rule);
        }
        let (mut client, mut conn) = client::Builder::new()
            .initial_window_size(65_536)
            .initial_connection_window_size(65_536)
            .one_frame_per_write(true)
            .window_update_policy(policy)
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let (response, _) = client
            .send_request(
                Request::builder()
                    .uri("https://example.com/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        conn.drive(async {
            let mut body = response.await.unwrap().into_body();
            for &(size, release, _, _) in steps {
                let mut consumed = 0;
                while consumed < size {
                    consumed += body.data().await.unwrap().unwrap().len();
                }
                body.flow_control().release_capacity(release).unwrap();
                released_tx.send(()).unwrap();
                checked_rx.recv().await.unwrap();
            }
            assert!(body.data().await.unwrap().unwrap().is_empty());
            assert!(body.data().await.is_none());
        })
        .await;
    };
    join(local, remote).await;
}

#[tokio::test]
async fn target_half_is_strict_and_counts_outstanding_data() {
    let policy = Some(WindowUpdateRule::TargetWindowHalf { max_delay: None });
    check_updates(
        policy,
        policy,
        &[
            (32_768, 32_768, 0, 0),
            (1, 1, 32_769, 32_769),
            (40_000, 20_000, 0, 0),
            (0, 12_768, 0, 0),
            (0, 1, 32_769, 32_769),
        ],
    )
    .await;
}

#[tokio::test]
async fn threshold_low_window_reclaims_only_released_capacity() {
    let policy = Some(WindowUpdateRule::Threshold {
        increment: 40_000,
        low_window: 16_384,
    });
    check_updates(
        policy,
        policy,
        &[
            (40_000, 1_000, 0, 0),
            (9_151, 0, 0, 0), // one byte above the low-window boundary
            (1, 0, 1_000, 1_000),
            (0, 40_000, 40_000, 40_000),
        ],
    )
    .await;
}

#[tokio::test]
async fn policies_are_independent_and_none_keeps_default() {
    let half = Some(WindowUpdateRule::TargetWindowHalf { max_delay: None });
    check_updates(
        None,
        half,
        &[(21_846, 21_846, 0, 21_846), (10_923, 10_923, 32_769, 0)],
    )
    .await;
    check_updates(
        half,
        None,
        &[(21_846, 21_846, 21_847, 0), (10_923, 10_923, 0, 32_769)],
    )
    .await;
    check_updates(None, None, &[(21_846, 21_846, 21_847, 21_846)]).await;
}

#[tokio::test]
async fn elapsed_delay_needs_nonzero_release() {
    let (io, mut peer) = mock::new();
    let (released_tx, released_rx) = tokio::sync::oneshot::channel();
    let (elapsed_tx, elapsed_rx) = tokio::sync::oneshot::channel();
    let (zero_tx, zero_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
    let rule = WindowUpdateRule::TargetWindowHalf {
        max_delay: Some(Duration::from_secs(1)),
    };
    let remote = async {
        peer.assert_client_handshake().await;
        peer.recv_frame(
            frames::headers(1)
                .request("GET", "https://example.com/")
                .eos(),
        )
        .await;
        peer.send_frame(frames::headers(1).response(200)).await;
        peer.send_frame(frames::data(1, "ab")).await;
        released_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        peer.ping_pong([1; 8]).await;
        elapsed_tx.send(()).unwrap();
        zero_rx.await.unwrap();
        peer.ping_pong([2; 8]).await;
        resume_tx.send(()).unwrap();
        peer.recv_frame(frames::window_update(0, 2)).await;
        peer.recv_frame(frames::window_update(1, 2)).await;
        peer.send_frame(frames::data(1, "").eos()).await;
        peer.recv_eof().await;
    };
    let local = async {
        let (mut client, mut conn) = client::Builder::new()
            .window_update_policy(WindowUpdatePolicy::both(rule))
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let (response, _) = client
            .send_request(
                Request::builder()
                    .uri("https://example.com/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        conn.drive(async {
            let mut body = response.await.unwrap().into_body();
            assert_eq!(body.data().await.unwrap().unwrap().len(), 2);
            body.flow_control().release_capacity(1).unwrap();
            released_tx.send(()).unwrap();
            elapsed_rx.await.unwrap();
            body.flow_control().release_capacity(0).unwrap();
            zero_tx.send(()).unwrap();
            resume_rx.await.unwrap();
            body.flow_control().release_capacity(1).unwrap();
            assert!(body.data().await.unwrap().unwrap().is_empty());
            assert!(body.data().await.is_none());
        })
        .await;
    };
    join(local, remote).await;
}

#[tokio::test]
async fn only_connection_target_growth_bypasses_the_update_threshold() {
    let (io, mut peer) = mock::new();
    let policy = WindowUpdatePolicy::default()
        .connection(WindowUpdateRule::TargetWindowHalf { max_delay: None });
    let (mut client, mut conn) = client::Builder::new()
        .window_update_policy(policy)
        .handshake::<_, Bytes>(io)
        .await
        .unwrap();

    conn.drive(peer.assert_client_handshake()).await;
    let response = client.get("https://example.com/");
    conn.drive(
        peer.recv_frame(
            frames::headers(1)
                .request("GET", "https://example.com/")
                .eos(),
        ),
    )
    .await;
    peer.send_frame(frames::headers(1).response(200)).await;
    peer.send_frame(frames::data(1, vec![0; 4_096])).await;
    let mut body = conn.drive(response).await.unwrap().into_body();
    let data = conn.drive(body.data()).await.unwrap().unwrap();
    body.flow_control().release_capacity(data.len()).unwrap();

    conn.set_target_window_size(64_535);
    conn.drive(util::yield_once()).await;
    conn.drive(peer.ping_pong([1; 8])).await;

    conn.set_target_window_size(64_535);
    conn.drive(util::yield_once()).await;
    conn.drive(peer.ping_pong([2; 8])).await;

    conn.set_target_window_size(65_535);
    conn.drive(peer.recv_frame(frames::window_update(0, 4_096)))
        .await;
}

#[tokio::test]
async fn connection_update_delay_starts_after_the_initial_write() {
    let (io, mut peer) = mock::new_with_write_capacity(0);
    let delay = Duration::from_secs(1);
    let policy = WindowUpdatePolicy::default().connection(WindowUpdateRule::TargetWindowHalf {
        max_delay: Some(delay),
    });
    let (mut client, mut conn) = client::Builder::new()
        .window_update_policy(policy)
        .handshake::<_, Bytes>(io)
        .await
        .unwrap();

    // Poll the connection while the initial write stays blocked past the delay.
    conn.drive(tokio::time::sleep(delay)).await;
    peer.unbounded_bytes().await;
    conn.drive(peer.assert_client_handshake()).await;

    let response = client.get("https://example.com/");
    conn.drive(
        peer.recv_frame(
            frames::headers(1)
                .request("GET", "https://example.com/")
                .eos(),
        ),
    )
    .await;
    peer.send_frame(frames::headers(1).response(200)).await;
    peer.send_frame(frames::data(1, "ab")).await;
    let mut body = conn.drive(response).await.unwrap().into_body();
    let data = conn.drive(body.data()).await.unwrap().unwrap();
    assert_eq!(&data[..], b"ab");
    body.flow_control().release_capacity(1).unwrap();
    conn.drive(util::yield_once()).await;
    conn.drive(peer.ping_pong([1; 8])).await;

    tokio::time::sleep(delay).await;
    body.flow_control().release_capacity(1).unwrap();
    conn.drive(peer.recv_frame(frames::window_update(0, 2)))
        .await;
}

#[tokio::test]
async fn padding_is_released_and_closed_stream_only_updates_connection() {
    let (io, mut peer) = mock::new();
    let (read_tx, read_rx) = tokio::sync::oneshot::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let rule = WindowUpdateRule::Threshold {
        increment: 4,
        low_window: 0,
    };
    let remote = async {
        peer.assert_client_handshake().await;
        peer.recv_frame(
            frames::headers(1)
                .request("GET", "https://example.com/")
                .eos(),
        )
        .await;
        peer.send_frame(frames::headers(1).response(200)).await;
        peer.send_frame(frames::data(1, &b"\x03x\0\0\0"[..]).padded())
            .await;
        peer.recv_frame(frames::window_update(0, 4)).await;
        peer.recv_frame(frames::window_update(1, 4)).await;
        read_rx.await.unwrap();
        peer.ping_pong([3; 8]).await;
        peer.send_frame(frames::data(1, "abc").eos()).await;
        peer.recv_frame(frames::window_update(0, 4)).await;
        peer.ping_pong([4; 8]).await;
        done_tx.send(()).unwrap();
        peer.recv_eof().await;
    };
    let local = async {
        let (mut client, mut conn) = client::Builder::new()
            .window_update_policy(WindowUpdatePolicy::both(rule))
            .one_frame_per_write(true)
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let (response, _) = client
            .send_request(
                Request::builder()
                    .uri("https://example.com/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        conn.drive(async {
            let mut body = response.await.unwrap().into_body();
            assert_eq!(&body.data().await.unwrap().unwrap()[..], b"x");
            body.flow_control().release_capacity(1).unwrap();
            read_tx.send(()).unwrap();
            assert_eq!(&body.data().await.unwrap().unwrap()[..], b"abc");
            body.flow_control().release_capacity(3).unwrap();
            assert!(body.data().await.is_none());
            done_rx.await.unwrap();
        })
        .await;
    };
    join(local, remote).await;
}
