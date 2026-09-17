use futures::StreamExt;
use h2_support::prelude::*;
use std::convert::TryFrom;

fn frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    frame_on_stream(kind, flags, 1, payload)
}

fn frame_on_stream(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("test frame payload fits in u32");
    let mut frame = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn headers(flags: u8, payload: &[u8]) -> Vec<u8> {
    frame(1, flags, payload)
}

fn continuation(flags: u8, payload: &[u8]) -> Vec<u8> {
    frame(9, flags, payload)
}

fn headers_on_stream(stream_id: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    frame_on_stream(1, flags, stream_id, payload)
}

fn assert_stream_protocol_error(error: proto::Error, stream_id: u32) {
    match error {
        proto::Error::Reset(id, reason, _) => {
            assert_eq!(id, stream_id);
            assert_eq!(reason, Reason::PROTOCOL_ERROR);
        }
        other => panic!("expected stream PROTOCOL_ERROR, got {:?}", other),
    }
}

async fn assert_compression_error(input: &[u8], settings: &[usize]) {
    let mut builder = mock_io::Builder::new();
    builder.read(input);
    let mut codec = Codec::new(builder.build());
    for &size in settings {
        codec.set_recv_header_table_size(size);
    }

    let error = codec
        .next()
        .await
        .expect("codec closed without an error")
        .unwrap_err();
    match error {
        proto::Error::GoAway(_, reason, _) => assert_eq!(reason, Reason::COMPRESSION_ERROR),
        other => panic!("expected COMPRESSION_ERROR GOAWAY, got {:?}", other),
    }
}

#[tokio::test]
async fn decoder_preserves_lowest_and_final_acknowledged_table_sizes() {
    // A first update of 129 does not satisfy the acknowledged low-water mark
    // of 128, even though the final acknowledged limit is 256.
    assert_compression_error(&headers(0x4, &[0x3f, 0x62, 0x88]), &[128, 256]).await;

    // The encoder may keep using the acknowledged low-water size. Restoring
    // the final limit with a second update is allowed, but not required.
    let input = headers(0x4, &[0x3f, 0x61, 0x88]);
    let mut builder = mock_io::Builder::new();
    builder.read(&input);
    let mut codec = Codec::new(builder.build());
    codec.set_recv_header_table_size(128);
    codec.set_recv_header_table_size(256);
    assert!(codec.next().await.unwrap().is_ok());

    // Updating to 128 and then 256 is valid and leaves :status 200 as the
    // first decoded header field.
    let input = headers(0x4, &[0x3f, 0x61, 0x3f, 0xe1, 0x01, 0x88]);
    let mut builder = mock_io::Builder::new();
    builder.read(&input);
    let mut codec = Codec::new(builder.build());
    codec.set_recv_header_table_size(128);
    codec.set_recv_header_table_size(256);

    let frame = codec
        .next()
        .await
        .expect("codec closed")
        .expect("valid headers");
    let headers = assert_headers!(frame);
    assert_eq!(headers.into_parts().0.status, Some(StatusCode::OK));
}

#[tokio::test]
async fn decoder_requires_a_size_update_after_the_limit_is_lowered() {
    assert_compression_error(&headers(0x4, &[0x88]), &[128]).await;
    assert_compression_error(&headers(0x4, &[]), &[128]).await;

    // RFC 7541 section 4.2 requires the lowest capacity to be signaled even
    // if the final SETTINGS restores the old limit and the table is empty.
    // https://www.rfc-editor.org/rfc/rfc7541.html#section-4.2
    assert_compression_error(&headers(0x4, &[0x88]), &[128, 4096]).await;
    assert_compression_error(&headers(0x4, &[]), &[128, 4096]).await;
    assert_compression_error(&headers(0x4, &[0x3f, 0xe1, 0x1f, 0x88]), &[128, 4096]).await;

    // A table occupying only 34 bytes must still signal the temporary 128
    // limit: the negotiated capacity, not occupancy, controls the update.
    let mut input = headers(0x4, &[0x40, 0x01, b'x', 0x01, b'a']);
    input.extend_from_slice(&headers_on_stream(3, 0x4, &[0xbe]));
    let mut builder = mock_io::Builder::new();
    builder.read(&input);
    let mut codec = Codec::new(builder.build());
    assert!(codec.next().await.unwrap().is_ok());
    codec.set_recv_header_table_size(128);
    codec.set_recv_header_table_size(4096);
    assert!(matches!(
        codec.next().await.unwrap(),
        Err(proto::Error::GoAway(_, Reason::COMPRESSION_ERROR, _))
    ));

    let mut push_payload = vec![0, 0, 0, 2];
    push_payload.push(0x82);
    assert_compression_error(&frame(5, 0x4, &push_payload), &[128]).await;
}

#[tokio::test]
async fn decoder_keeps_size_update_position_across_continuations() {
    let mut late_update = headers(0, &[0x88]);
    late_update.extend_from_slice(&continuation(0x4, &[0x20]));
    assert_compression_error(&late_update, &[]).await;

    let mut late_after_split_header = headers(0, &[0x00, 0x01, b'x', 0x01]);
    late_after_split_header.extend_from_slice(&continuation(0x4, &[b'a', 0x20]));
    assert_compression_error(&late_after_split_header, &[]).await;

    // The integer for a legal size update may itself span HEADERS and
    // CONTINUATION. It is still the first representation in the block.
    let mut split_update = headers(0, &[0x3f]);
    split_update.extend_from_slice(&continuation(0x4, &[0x61, 0x88]));
    let mut builder = mock_io::Builder::new();
    builder.read(&split_update);
    let mut codec = Codec::new(builder.build());
    codec.set_recv_header_table_size(128);

    let frame = codec
        .next()
        .await
        .expect("codec closed")
        .expect("valid headers");
    let headers = assert_headers!(frame);
    assert_eq!(headers.into_parts().0.status, Some(StatusCode::OK));
}

#[tokio::test]
async fn decoder_maps_invalid_hpack_state_to_compression_error() {
    // A third update is not allowed at the start of one field block.
    assert_compression_error(&headers(0x4, &[0x20, 0x20, 0x20, 0x88]), &[]).await;

    // 257 exceeds the final acknowledged limit of 256.
    assert_compression_error(&headers(0x4, &[0x3f, 0xe2, 0x01]), &[256]).await;

    // Dynamic index 62 is invalid while the table is empty.
    assert_compression_error(&headers(0x4, &[0xbe]), &[]).await;
}

#[tokio::test]
async fn semantic_error_keeps_the_dynamic_table_synchronized() {
    let mut input = headers(
        0x4,
        &[
            0x40, 0x01, b'x', 0x01, b'a', // valid indexed literal
            0x40, 0x01, b'X', 0x01, b'b', // uppercase name is malformed
        ],
    );
    // The malformed entry is index 62 and the preceding valid entry is 63.
    input.extend_from_slice(&headers_on_stream(3, 0x4, &[0xbf]));

    let mut builder = mock_io::Builder::new();
    builder.read(&input);
    let mut codec = Codec::new(builder.build());

    let error = codec.next().await.unwrap().unwrap_err();
    assert_stream_protocol_error(error, 1);

    let frame = codec.next().await.unwrap().unwrap();
    let headers = assert_headers!(frame);
    assert_eq!(headers.stream_id(), 3);
    assert_eq!(headers.fields()["x"], "a");
}

#[tokio::test]
async fn malformed_dynamic_entries_count_toward_header_list_limits() {
    let mut payload = vec![
        0x40, 0x01, b'X', 0x01, b'a', // malformed indexed literal at index 62
    ];
    payload.extend_from_slice(&[0xbe; 7]);

    let input = headers(0x4, &payload);
    let mut builder = mock_io::Builder::new();
    builder.read(&input);
    let mut codec = Codec::new(builder.build());
    codec.set_max_recv_header_list_size(64);

    let error = codec.next().await.unwrap().unwrap_err();
    match error {
        proto::Error::GoAway(_, reason, _) => assert_eq!(reason, Reason::ENHANCE_YOUR_CALM),
        other => panic!("expected ENHANCE_YOUR_CALM GOAWAY, got {:?}", other),
    }
}

#[tokio::test]
async fn malformed_continuation_is_drained_before_the_next_block() {
    let mut input = headers(
        0,
        &[
            0x00, 0x01, b'x', 0x01, b'a', // regular field
            0x82, // :method after a regular field is malformed
            0x00, 0x01, b'y', 0x01, // incomplete literal value
        ],
    );
    input.extend_from_slice(&continuation(0x4, &[b'b']));
    input.extend_from_slice(&headers_on_stream(3, 0x4, &[0x88]));

    let mut builder = mock_io::Builder::new();
    builder.read(&input);
    let mut codec = Codec::new(builder.build());

    let error = codec.next().await.unwrap().unwrap_err();
    assert_stream_protocol_error(error, 1);

    let frame = codec.next().await.unwrap().unwrap();
    let headers = assert_headers!(frame);
    assert_eq!(headers.stream_id(), 3);
    assert_eq!(headers.into_parts().0.status, Some(StatusCode::OK));
}

#[tokio::test]
async fn restored_table_limit_does_not_require_redundant_updates() {
    for (initial, next) in [
        // An encoder already using 64 bytes need not resize for 128 -> 4096.
        (&[0x3f, 0x21, 0x88][..], &[0x88][..]),
        // Otherwise it signals 128 then 4096 once, not in every later block.
        (&[0x88][..], &[0x3f, 0x61, 0x3f, 0xe1, 0x1f, 0x88][..]),
    ] {
        let mut input = headers(0x4, initial);
        input.extend_from_slice(&headers_on_stream(3, 0x4, next));
        input.extend_from_slice(&headers_on_stream(5, 0x4, &[0x88]));
        let mut builder = mock_io::Builder::new();
        builder.read(&input);
        let mut codec = Codec::new(builder.build());
        assert!(codec.next().await.unwrap().is_ok());
        codec.set_recv_header_table_size(128);
        codec.set_recv_header_table_size(4096);
        assert!(codec.next().await.unwrap().is_ok());
        assert!(codec.next().await.unwrap().is_ok());
    }
}

#[tokio::test]
async fn self_dependent_headers_preserve_the_compression_context() {
    for fragmented in [false, true] {
        // The rejected stream inserts x:a and y:b. Both entries must remain
        // available to subsequent streams, including across CONTINUATION.
        let mut payload = vec![0, 0, 0, 1, 15];
        payload.extend_from_slice(&[0x40, 0x01, b'x', 0x01, b'a']);
        let tail = [0x40, 0x01, b'y', 0x01, b'b'];
        let mut input = if fragmented {
            let mut input = headers(0x20, &payload);
            input.extend_from_slice(&continuation(0x4, &tail));
            input
        } else {
            payload.extend_from_slice(&tail);
            headers(0x24, &payload)
        };
        input.extend_from_slice(&headers_on_stream(3, 0x4, &[0xbf, 0xbe]));
        let mut builder = mock_io::Builder::new();
        builder.read(&input);
        let mut codec = Codec::new(builder.build());

        assert_stream_protocol_error(codec.next().await.unwrap().unwrap_err(), 1);
        let headers = assert_headers!(codec.next().await.unwrap().unwrap());
        assert_eq!(headers.stream_id(), 3);
        assert_eq!(headers.fields()["x"], "a");
        assert_eq!(headers.fields()["y"], "b");
    }

    // A stream error must not hide a compression error in the same block.
    let payload = [0, 0, 0, 1, 15, 0xbe];
    assert_compression_error(&headers(0x24, &payload), &[]).await;
    let mut input = headers(0x20, &payload[..5]);
    input.extend_from_slice(&continuation(0x4, &payload[5..]));
    assert_compression_error(&input, &[]).await;
}

#[tokio::test]
async fn never_indexed_fields_retain_sensitivity_without_changing_the_table() {
    let input = headers(
        0x4,
        &[
            0x40, 0x01, b'x', 0x01, b'a', // indexed literal, dynamic entry 62
            0x10, 0x01, b'x', 0x01, b'b', // never indexed, literal name
            0x1f, 0x2f, 0x01, b'c', // never indexed, dynamic name 62
            0x1f, 0x08, 0x01, b'd', // never indexed, static authorization name
            0xbe, // entry 62 is still x:a, and is not sensitive
        ],
    );
    let mut builder = mock_io::Builder::new();
    builder.read(&input);
    let mut codec = Codec::new(builder.build());
    let headers = assert_headers!(codec.next().await.unwrap().unwrap());
    let values: Vec<_> = headers.fields().get_all("x").iter().collect();
    assert_eq!(
        values.iter().map(|v| v.as_bytes()).collect::<Vec<_>>(),
        vec![&b"a"[..], &b"b"[..], &b"c"[..], &b"a"[..]]
    );
    assert_eq!(
        values.iter().map(|v| v.is_sensitive()).collect::<Vec<_>>(),
        vec![false, true, true, false]
    );
    assert!(headers.fields()["authorization"].is_sensitive());

    // Forward the received HeaderValue unchanged. The wire representation
    // must remain never-indexed (0001), not merely avoid this insertion.
    let mut fields = HeaderMap::new();
    fields.insert("x", values[1].clone());
    let outgoing = frame::Headers::new(3.into(), frame::Pseudo::default(), fields);
    let expected = headers_on_stream(3, 0x4, &[0x10, 0x81, 0xf3, 0x81, 0x8f]);
    let mut builder = mock_io::Builder::new();
    builder.write(&expected);
    let mut codec = Codec::new(builder.build());
    futures::future::poll_fn(|cx| codec.poll_ready(cx))
        .await
        .unwrap();
    codec.buffer(outgoing.into()).unwrap();
    futures::future::poll_fn(|cx| codec.flush(cx))
        .await
        .unwrap();
}
