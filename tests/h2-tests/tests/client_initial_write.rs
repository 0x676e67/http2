use futures::{FutureExt, StreamExt};
use h2_support::prelude::*;
use http::HeaderValue;
use std::convert::TryInto;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;
use tokio::io::ReadBuf;

const PARTIAL_WRITE_LEN: usize = 7;
const PEER_SETTINGS_AND_PING: &[u8] = &[
    // Empty initial SETTINGS followed by a non-ACK PING.
    0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
];
const PEER_SETTINGS_AND_ACK: &[u8] = &[
    // Empty initial SETTINGS followed by the ACK for the client SETTINGS.
    0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0,
];
const PEER_SETTINGS_MAX_CONCURRENT_ONE: &[u8] = &[
    // Initial SETTINGS with MAX_CONCURRENT_STREAMS set to one.
    0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1,
];
#[derive(Debug)]
enum IoCall {
    Read,
    Write(Bytes),
    Flush,
    Shutdown,
}

struct RecordingIo {
    calls: Arc<Mutex<Vec<IoCall>>>,
    read: Bytes,
    write_calls: usize,
    write_mode: WriteMode,
    write_blocked: Arc<AtomicBool>,
    blocked_waker: Arc<Mutex<Option<Waker>>>,
}

type RecordingIoParts = (
    RecordingIo,
    Arc<Mutex<Vec<IoCall>>>,
    Arc<AtomicBool>,
    Arc<Mutex<Option<Waker>>>,
);

#[derive(Clone, Copy)]
enum WriteMode {
    PartialThenPending,
    RequestPartialThenPending,
    Complete,
    Fail(io::ErrorKind),
    PendingThenFail(io::ErrorKind),
}

struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn recording_io(write_mode: WriteMode, read: Bytes) -> RecordingIoParts {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let write_blocked = Arc::new(AtomicBool::new(true));
    let blocked_waker = Arc::new(Mutex::new(None));

    (
        RecordingIo {
            calls: calls.clone(),
            read,
            write_calls: 0,
            write_mode,
            write_blocked: write_blocked.clone(),
            blocked_waker: blocked_waker.clone(),
        },
        calls,
        write_blocked,
        blocked_waker,
    )
}

impl AsyncRead for RecordingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.calls.lock().unwrap().push(IoCall::Read);

        if self.read.is_empty() {
            return Poll::Pending;
        }

        let len = self.read.len().min(buf.remaining());
        buf.put_slice(&self.read.split_to(len));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RecordingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.calls
            .lock()
            .unwrap()
            .push(IoCall::Write(Bytes::copy_from_slice(buf)));

        let call = self.write_calls;
        self.write_calls += 1;

        match self.write_mode {
            WriteMode::PartialThenPending if call == 0 => {
                Poll::Ready(Ok(PARTIAL_WRITE_LEN.min(buf.len())))
            }
            WriteMode::RequestPartialThenPending if call == 0 => Poll::Ready(Ok(buf.len())),
            WriteMode::RequestPartialThenPending if call == 1 => {
                Poll::Ready(Ok(buf.len().saturating_sub(5)))
            }
            WriteMode::PartialThenPending if self.write_blocked.load(Ordering::SeqCst) => {
                *self.blocked_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
            WriteMode::RequestPartialThenPending if self.write_blocked.load(Ordering::SeqCst) => {
                *self.blocked_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
            WriteMode::PendingThenFail(_) if self.write_blocked.load(Ordering::SeqCst) => {
                *self.blocked_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
            WriteMode::PartialThenPending
            | WriteMode::RequestPartialThenPending
            | WriteMode::Complete => Poll::Ready(Ok(buf.len())),
            WriteMode::Fail(kind) | WriteMode::PendingThenFail(kind) => {
                Poll::Ready(Err(kind.into()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.lock().unwrap().push(IoCall::Flush);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.lock().unwrap().push(IoCall::Shutdown);
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WireFrame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload_start: usize,
    payload_len: usize,
}

fn wire_frames(buf: &[u8]) -> Vec<WireFrame> {
    assert!(buf.starts_with(MAGIC_PREFACE));
    assert!(
        buf.len() >= MAGIC_PREFACE.len() + 9,
        "initial SETTINGS frame is missing"
    );
    assert_eq!(buf[MAGIC_PREFACE.len() + 3], 4);
    assert_eq!(
        buf[MAGIC_PREFACE.len() + 4] & 1,
        0,
        "initial SETTINGS must not be an ACK"
    );

    encoded_frames_from(buf, MAGIC_PREFACE.len())
}

fn encoded_frames(buf: &[u8]) -> Vec<WireFrame> {
    encoded_frames_from(buf, 0)
}

fn encoded_frames_from(buf: &[u8], mut pos: usize) -> Vec<WireFrame> {
    let mut frames = Vec::new();

    while pos < buf.len() {
        assert!(buf.len() - pos >= 9, "truncated HTTP/2 frame header");

        let payload_len =
            ((buf[pos] as usize) << 16) | ((buf[pos + 1] as usize) << 8) | buf[pos + 2] as usize;
        let end = pos
            .checked_add(9 + payload_len)
            .expect("initial write length overflowed");
        assert!(end <= buf.len(), "truncated HTTP/2 frame payload");

        let stream_id =
            u32::from_be_bytes([buf[pos + 5], buf[pos + 6], buf[pos + 7], buf[pos + 8]])
                & 0x7fff_ffff;
        frames.push(WireFrame {
            kind: buf[pos + 3],
            flags: buf[pos + 4],
            stream_id,
            payload_start: pos + 9,
            payload_len,
        });
        pos = end;
    }

    frames
}

fn frame_layout(buf: &[u8]) -> Vec<(u8, u32)> {
    wire_frames(buf)
        .into_iter()
        .map(|frame| (frame.kind, frame.stream_id))
        .collect()
}

fn frame_payload<'a>(buf: &'a [u8], frame: &WireFrame) -> &'a [u8] {
    &buf[frame.payload_start..frame.payload_start + frame.payload_len]
}

fn decode_hpack_integer(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> usize {
    assert!((1..=7).contains(&prefix_bits));
    let mask = (1_u8 << prefix_bits) - 1;
    let first = *buf.get(*pos).expect("truncated HPACK integer");
    *pos += 1;

    let mut value = (first & mask) as usize;
    if value < mask as usize {
        return value;
    }

    let mut shift = 0;
    loop {
        let byte = *buf.get(*pos).expect("truncated HPACK integer suffix");
        *pos += 1;
        let part = ((byte & 0x7f) as usize)
            .checked_shl(shift)
            .expect("HPACK integer shift overflowed");
        value = value.checked_add(part).expect("HPACK integer overflowed");
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn skip_hpack_string(buf: &[u8], pos: &mut usize) {
    let len = decode_hpack_integer(buf, pos, 7);
    *pos = pos
        .checked_add(len)
        .filter(|end| *end <= buf.len())
        .expect("truncated HPACK string");
}

fn hpack_static_name_order(buf: &[u8]) -> Vec<usize> {
    let mut names = Vec::new();
    let mut pos = 0;

    while pos < buf.len() {
        let first = buf[pos];
        if first & 0x80 != 0 {
            names.push(decode_hpack_integer(buf, &mut pos, 7));
            continue;
        }
        if first & 0x20 != 0 && first & 0x40 == 0 {
            decode_hpack_integer(buf, &mut pos, 5);
            continue;
        }

        let prefix_bits = if first & 0x40 != 0 { 6 } else { 4 };
        let name = decode_hpack_integer(buf, &mut pos, prefix_bits);
        assert_ne!(name, 0, "profile pseudo-header used a literal name");
        names.push(name);
        skip_hpack_string(buf, &mut pos);
    }

    names
}

#[derive(Clone, Copy, Debug)]
enum BrowserProfile {
    Safari,
    Chrome,
}

// These profile values were captured on 2026-08-04. They validate the frame
// bytes independently from the application-layer write queue boundary.
#[tokio::test]
async fn initial_connection_write_is_separate_from_profile_headers() {
    h2_support::trace_init!();

    for profile in [BrowserProfile::Safari, BrowserProfile::Chrome] {
        let (io, calls, _write_blocked, _blocked_waker) =
            recording_io(WriteMode::Complete, Bytes::new());
        let mut builder = client::Builder::new();

        let (
            expected_settings,
            expected_window_update,
            expected_headers_flags,
            expected_pseudo_order,
        ) = match profile {
            BrowserProfile::Safari => {
                builder
                    .enable_push(false)
                    .max_concurrent_streams(100)
                    .initial_window_size(2_097_152)
                    .no_rfc7540_priorities(true)
                    .initial_connection_window_size(10_485_760)
                    .settings_order(
                        h2::frame::SettingsOrder::builder()
                            .extend([
                                h2::frame::SettingId::EnablePush,
                                h2::frame::SettingId::MaxConcurrentStreams,
                                h2::frame::SettingId::InitialWindowSize,
                                h2::frame::SettingId::NoRfc7540Priorities,
                            ])
                            .build(),
                    )
                    .headers_pseudo_order(
                        h2::frame::PseudoOrder::builder()
                            .extend([
                                h2::frame::PseudoId::Method,
                                h2::frame::PseudoId::Scheme,
                                h2::frame::PseudoId::Authority,
                                h2::frame::PseudoId::Path,
                            ])
                            .build(),
                    );

                (
                    [(2, 0), (3, 100), (4, 2_097_152), (9, 1)],
                    10_420_225,
                    0x5,
                    [2, 6, 1, 4],
                )
            }
            BrowserProfile::Chrome => {
                builder
                    .header_table_size(65_536)
                    .enable_push(false)
                    .initial_window_size(6_291_456)
                    .max_header_list_size(262_144)
                    .initial_connection_window_size(15_728_640)
                    .settings_order(
                        h2::frame::SettingsOrder::builder()
                            .extend([
                                h2::frame::SettingId::HeaderTableSize,
                                h2::frame::SettingId::EnablePush,
                                h2::frame::SettingId::InitialWindowSize,
                                h2::frame::SettingId::MaxHeaderListSize,
                            ])
                            .build(),
                    )
                    .headers_pseudo_order(
                        h2::frame::PseudoOrder::builder()
                            .extend([
                                h2::frame::PseudoId::Method,
                                h2::frame::PseudoId::Authority,
                                h2::frame::PseudoId::Scheme,
                                h2::frame::PseudoId::Path,
                            ])
                            .build(),
                    )
                    .headers_stream_dependency(h2::frame::StreamDependency::new(
                        StreamId::zero(),
                        u8::MAX,
                        true,
                    ));

                (
                    [(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)],
                    15_663_105,
                    0x25,
                    [2, 1, 6, 4],
                )
            }
        };

        let (mut send_request, mut connection) = builder
            .handshake::<_, Bytes>(io)
            .now_or_never()
            .expect("handshake attempted transport I/O")
            .unwrap();
        assert!(calls.lock().unwrap().is_empty());

        let request = Request::get(match profile {
            BrowserProfile::Safari => "http://127.0.0.1:39443/capture/safari",
            BrowserProfile::Chrome => "http://127.0.0.1:39443/capture/chrome",
        })
        .body(())
        .unwrap();
        let (_response, _send_stream) = send_request.send_request(request, true).unwrap();
        assert!(calls.lock().unwrap().is_empty());

        let waker = Waker::from(Arc::new(WakeCounter(AtomicUsize::new(0))));
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

        let calls = calls.lock().unwrap();
        let write_positions: Vec<_> = calls
            .iter()
            .enumerate()
            .filter_map(|(index, call)| match call {
                IoCall::Write(buf) => Some((index, buf)),
                IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
            })
            .collect();
        assert_eq!(
            write_positions.len(),
            2,
            "{profile:?} did not use one connection write followed by one request write"
        );
        assert!(
            calls[write_positions[0].0 + 1..write_positions[1].0]
                .iter()
                .all(|call| !matches!(call, IoCall::Flush)),
            "the writer was flushed between the connection and request items"
        );

        let initial_write = write_positions[0].1.as_ref();
        let request_write = write_positions[1].1.as_ref();
        assert_eq!(
            initial_write.len(),
            70,
            "unexpected {profile:?} initial item"
        );
        let frames = wire_frames(initial_write);
        assert_eq!(
            frames
                .iter()
                .map(|frame| (frame.kind, frame.stream_id))
                .collect::<Vec<_>>(),
            [(4, 0), (8, 0)]
        );
        let request_frames = encoded_frames(request_write);
        assert_eq!(
            request_frames
                .iter()
                .map(|frame| (frame.kind, frame.stream_id))
                .collect::<Vec<_>>(),
            [(1, 1)]
        );

        let settings_payload = frame_payload(initial_write, &frames[0]);
        assert_eq!(settings_payload.len(), 24);
        let settings = settings_payload
            .chunks_exact(6)
            .map(|setting| {
                (
                    u16::from_be_bytes([setting[0], setting[1]]),
                    u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(settings.as_slice(), expected_settings.as_slice());

        let window_payload = frame_payload(initial_write, &frames[1]);
        assert_eq!(window_payload.len(), 4);
        assert_eq!(
            u32::from_be_bytes(window_payload.try_into().unwrap()),
            expected_window_update
        );

        assert_eq!(request_frames[0].flags, expected_headers_flags);
        let headers_payload = frame_payload(request_write, &request_frames[0]);
        let hpack = if matches!(profile, BrowserProfile::Chrome) {
            assert_eq!(&headers_payload[..5], &[0x80, 0, 0, 0, 0xff]);
            &headers_payload[5..]
        } else {
            headers_payload
        };
        assert_eq!(
            hpack_static_name_order(hpack).as_slice(),
            expected_pseudo_order.as_slice()
        );
    }
}

#[tokio::test]
async fn drains_connection_and_request_queues_in_one_poll() {
    h2_support::trace_init!();

    for (connection_window, with_priority, request_count, with_body_and_trailers) in [
        (None, false, 2, false),
        (Some(1_000_000), false, 2, false),
        (Some(1_000_000), true, 1, false),
        (None, false, 1, true),
    ] {
        let (io, calls, _write_blocked, _blocked_waker) =
            recording_io(WriteMode::Complete, Bytes::new());
        let mut builder = client::Builder::new();

        if let Some(size) = connection_window {
            builder.initial_connection_window_size(size);
        }
        if with_priority {
            builder.initial_stream_id(3).priorities(
                h2::frame::Priorities::builder()
                    .push(h2::frame::Priority::new(
                        StreamId::from(1),
                        h2::frame::StreamDependency::new(StreamId::zero(), 15, false),
                    ))
                    .build(),
            );
        }

        let (mut send_request, mut connection) = builder
            .handshake::<_, Bytes>(io)
            .now_or_never()
            .expect("handshake attempted transport I/O")
            .unwrap();
        assert!(calls.lock().unwrap().is_empty());

        let mut pending_requests = Vec::with_capacity(request_count);
        for request_index in 0..request_count {
            let request = Request::get(format!("https://example.com/{request_index}"))
                .body(())
                .unwrap();
            let (response, mut send_stream) = send_request
                .send_request(request, !with_body_and_trailers)
                .unwrap();
            if with_body_and_trailers {
                send_stream
                    .send_data(Bytes::from_static(b"request body"), false)
                    .unwrap();
                let mut trailers = HeaderMap::new();
                trailers.insert("x-trailer", HeaderValue::from_static("done"));
                send_stream.send_trailers(trailers).unwrap();
            }
            pending_requests.push((response, send_stream));
        }
        assert!(calls.lock().unwrap().is_empty());

        let waker = Waker::from(Arc::new(WakeCounter(AtomicUsize::new(0))));
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

        let calls = calls.lock().unwrap();
        let writes = calls
            .iter()
            .enumerate()
            .filter_map(|(index, call)| match call {
                IoCall::Write(buf) => Some((index, buf)),
                IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 2, "expected two write queue items");
        assert!(calls[writes[0].0 + 1..writes[1].0]
            .iter()
            .all(|call| !matches!(call, IoCall::Flush)));
        let first_read = calls
            .iter()
            .position(|call| matches!(call, IoCall::Read))
            .expect("connection did not poll the receive side");
        assert!(
            writes[0].0 < first_read && first_read < writes[1].0,
            "the normal upstream read poll did not run between write items"
        );

        let mut expected_initial = vec![(4, 0)];
        if connection_window.is_some() {
            expected_initial.push((8, 0));
        }
        if with_priority {
            expected_initial.push((2, 1));
        }
        assert_eq!(frame_layout(writes[0].1), expected_initial);

        let mut expected_requests = Vec::new();
        let first_request_id = if with_priority { 3 } else { 1 };
        expected_requests
            .extend((0..request_count).map(|index| (1, first_request_id + 2 * index as u32)));
        if with_body_and_trailers {
            expected_requests.extend([(0, first_request_id), (1, first_request_id)]);
        }
        assert_eq!(
            encoded_frames(writes[1].1)
                .iter()
                .map(|frame| (frame.kind, frame.stream_id))
                .collect::<Vec<_>>(),
            expected_requests
        );
        assert!(calls[writes[1].0 + 1..]
            .iter()
            .any(|call| matches!(call, IoCall::Flush)));
    }
}

#[tokio::test]
async fn large_initial_priority_block_resumes_before_read_without_flush() {
    h2_support::trace_init!();

    const PRIORITY_COUNT: u32 = 1_200;
    let priorities = h2::frame::Priorities::builder()
        .extend((0..PRIORITY_COUNT).map(|index| {
            h2::frame::Priority::new(
                StreamId::from(1 + index * 2),
                h2::frame::StreamDependency::new(StreamId::zero(), 15, false),
            )
        }))
        .build();

    let (io, calls, write_blocked, blocked_waker) =
        recording_io(WriteMode::PartialThenPending, Bytes::new());
    let mut builder = client::Builder::new();
    builder
        .initial_stream_id(PRIORITY_COUNT * 2 + 1)
        .priorities(priorities);

    let (send_request, mut connection) = builder
        .handshake::<_, Bytes>(io)
        .now_or_never()
        .expect("handshake attempted transport I/O")
        .unwrap();

    poll_fn(|cx| {
        assert!(Pin::new(&mut connection).poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;

    let (first_write, blocked_call_count) = {
        let calls = calls.lock().unwrap();
        assert!(calls
            .iter()
            .all(|call| !matches!(call, IoCall::Read | IoCall::Flush)));
        let writes = calls
            .iter()
            .filter_map(|call| match call {
                IoCall::Write(buf) => Some(buf),
                IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
            })
            .collect::<Vec<_>>();
        let first = writes
            .first()
            .expect("initial connection item was not written");
        assert!(writes.len() >= 2, "initial write did not block");
        for retry in &writes[1..] {
            assert_eq!(retry.as_ref(), &first[PARTIAL_WRITE_LEN..]);
        }
        ((*first).clone(), calls.len())
    };

    write_blocked.store(false, Ordering::SeqCst);
    blocked_waker
        .lock()
        .unwrap()
        .take()
        .expect("write task was not registered")
        .wake();

    poll_fn(|cx| {
        assert!(Pin::new(&mut connection).poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;

    let calls = calls.lock().unwrap();
    let first_read = calls
        .iter()
        .position(|call| matches!(call, IoCall::Read))
        .expect("connection did not poll the receive side");
    assert!(calls[..first_read]
        .iter()
        .all(|call| !matches!(call, IoCall::Flush)));
    let resumed_writes = calls[blocked_call_count..first_read]
        .iter()
        .filter_map(|call| match call {
            IoCall::Write(buf) => Some(buf),
            IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
        })
        .collect::<Vec<_>>();
    assert!(
        resumed_writes.len() > 1,
        "the resumed write did not exceed codec capacity"
    );

    let wire = resumed_writes.iter().fold(
        first_write[..PARTIAL_WRITE_LEN].to_vec(),
        |mut wire, write| {
            wire.extend_from_slice(write);
            wire
        },
    );
    let frames = wire_frames(&wire);
    assert_eq!(frames.len(), PRIORITY_COUNT as usize + 1);
    assert_eq!((frames[0].kind, frames[0].stream_id), (4, 0));
    assert!(frames[1..]
        .iter()
        .enumerate()
        .all(|(index, frame)| frame.kind == 2
            && frame.flags == 0
            && frame.stream_id == 1 + index as u32 * 2));

    drop(send_request);
}

#[tokio::test]
async fn initial_write_does_not_wait_for_a_request() {
    h2_support::trace_init!();

    for (request_state, with_priority) in [
        (RequestState::None, false),
        (RequestState::None, true),
        (RequestState::Cancelled, false),
        (RequestState::Pending, false),
    ] {
        let (io, calls, _write_blocked, _blocked_waker) =
            recording_io(WriteMode::Complete, Bytes::new());
        let mut builder = client::Builder::new();
        if matches!(request_state, RequestState::Pending) {
            builder.initial_max_send_streams(0);
        }
        if with_priority {
            builder.initial_stream_id(3).priorities(
                h2::frame::Priorities::builder()
                    .push(h2::frame::Priority::new(
                        StreamId::from(1),
                        h2::frame::StreamDependency::new(StreamId::zero(), 15, false),
                    ))
                    .build(),
            );
        }

        let (mut send_request, mut connection) =
            builder.handshake::<_, Bytes>(io).await.expect("handshake");
        let mut pending_request = None;

        if !matches!(request_state, RequestState::None) {
            let request = Request::get("https://example.com/").body(()).unwrap();
            let (response, send_stream) = send_request.send_request(request, false).unwrap();
            if matches!(request_state, RequestState::Cancelled) {
                drop(response);
                drop(send_stream);
            } else {
                pending_request = Some((response, send_stream));
            }
        }

        poll_fn(|cx| {
            assert!(Pin::new(&mut connection).poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        let calls = calls.lock().unwrap();
        let wire = calls.iter().fold(Vec::new(), |mut wire, call| {
            if let IoCall::Write(buf) = call {
                wire.extend_from_slice(buf);
            }
            wire
        });
        assert!(!wire.is_empty(), "initial control frames were not written");
        let layout = frame_layout(&wire);
        assert_eq!(layout.first(), Some(&(4, 0)));
        if with_priority {
            let first_write = calls
                .iter()
                .find_map(|call| match call {
                    IoCall::Write(buf) => Some(buf),
                    IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
                })
                .expect("client initial item was not written");
            assert_eq!(frame_layout(first_write), [(4, 0), (2, 1)]);
            assert_eq!(layout.iter().filter(|&&(kind, _)| kind == 2).count(), 1);
        } else if matches!(request_state, RequestState::None | RequestState::Pending) {
            assert!(layout.iter().all(|&(_, stream_id)| stream_id == 0));
        } else if let Some(&(kind, _)) = layout.iter().find(|&&(_, stream_id)| stream_id != 0) {
            assert_eq!(kind, 1, "a cancelled stream was used before HEADERS");
        }
        assert!(calls.iter().any(|call| matches!(call, IoCall::Flush)));

        drop(pending_request);
    }
}

#[tokio::test]
async fn idle_client_finishes_initial_write_before_go_away() {
    h2_support::trace_init!();

    let (io, calls, write_blocked, blocked_waker) =
        recording_io(WriteMode::PartialThenPending, Bytes::new());
    let mut builder = client::Builder::new();
    builder.initial_stream_id(5).priorities(
        h2::frame::Priorities::builder()
            .extend([
                h2::frame::Priority::new(
                    StreamId::from(1),
                    h2::frame::StreamDependency::new(StreamId::zero(), 200, false),
                ),
                h2::frame::Priority::new(
                    StreamId::from(3),
                    h2::frame::StreamDependency::new(StreamId::from(1), 100, false),
                ),
            ])
            .build(),
    );
    let (send_request, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
    drop(send_request);

    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

    let (first_write, blocked_call_count) = {
        let calls = calls.lock().unwrap();
        let writes = calls
            .iter()
            .filter_map(|call| match call {
                IoCall::Write(buf) => Some(buf),
                IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
            })
            .collect::<Vec<_>>();
        let first = writes
            .first()
            .expect("initial connection item was not written");
        assert!(writes.len() >= 2);
        for retry in &writes[1..] {
            assert!(retry.starts_with(&first[PARTIAL_WRITE_LEN..]));
        }
        ((*first).clone(), calls.len())
    };

    write_blocked.store(false, Ordering::SeqCst);
    let blocked_waker = blocked_waker
        .lock()
        .unwrap()
        .take()
        .expect("write task was not registered");
    let wake_count = wake_counter.0.load(Ordering::SeqCst);
    blocked_waker.wake();
    assert!(wake_counter.0.load(Ordering::SeqCst) > wake_count);
    assert!(matches!(
        Pin::new(&mut connection).poll(&mut cx),
        Poll::Ready(Ok(()))
    ));

    let calls = calls.lock().unwrap();
    let mut wire = first_write[..PARTIAL_WRITE_LEN].to_vec();
    for call in &calls[blocked_call_count..] {
        if let IoCall::Write(buf) = call {
            wire.extend_from_slice(buf);
        }
    }
    assert_eq!(frame_layout(&wire), [(4, 0), (2, 1), (2, 3), (7, 0)]);
    assert_eq!(
        wire.windows(MAGIC_PREFACE.len())
            .filter(|window| *window == MAGIC_PREFACE)
            .count(),
        1
    );
    assert!(matches!(calls.last(), Some(IoCall::Shutdown)));
}

#[derive(Clone, Copy)]
enum RequestState {
    None,
    Cancelled,
    Pending,
}

#[tokio::test]
async fn blocked_initial_write_preserves_upstream_poll_order() {
    h2_support::trace_init!();

    let (io, calls, write_blocked, blocked_waker) = recording_io(
        WriteMode::PartialThenPending,
        Bytes::from_static(PEER_SETTINGS_AND_PING),
    );
    let (mut send_request, mut connection) = client::handshake::<_>(io).await.unwrap();
    let request = Request::get("https://example.com/").body(()).unwrap();
    let (_response, _send_stream) = send_request.send_request(request, true).unwrap();

    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

    {
        let calls = calls.lock().unwrap();
        assert!(calls.iter().any(|call| matches!(call, IoCall::Write(_))));
        assert!(
            calls.iter().all(|call| !matches!(call, IoCall::Read)),
            "the initial connection item must complete before normal reads begin"
        );
    }

    // A spurious poll before the writer wakes must keep the same upstream
    // handshake-style write-before-read behavior.
    assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());
    let (first_write, blocked_call_count) = {
        let calls = calls.lock().unwrap();
        assert!(calls.iter().all(|call| !matches!(call, IoCall::Read)));
        let writes = calls
            .iter()
            .filter_map(|call| match call {
                IoCall::Write(buf) => Some(buf),
                IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
            })
            .collect::<Vec<_>>();
        let first = writes
            .first()
            .expect("initial connection item was not written");
        assert!(writes.len() >= 3);
        for retry in &writes[1..] {
            assert_eq!(retry.as_ref(), &first[PARTIAL_WRITE_LEN..]);
        }
        ((*first).clone(), calls.len())
    };

    write_blocked.store(false, Ordering::SeqCst);
    let blocked_waker = blocked_waker
        .lock()
        .unwrap()
        .take()
        .expect("write task was not registered");
    let wake_count = wake_counter.0.load(Ordering::SeqCst);
    blocked_waker.wake();
    assert!(wake_counter.0.load(Ordering::SeqCst) > wake_count);
    assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

    let calls = calls.lock().unwrap();
    let resumed_calls = &calls[blocked_call_count..];
    let resumed_write = resumed_calls
        .iter()
        .position(|call| matches!(call, IoCall::Write(_)))
        .expect("the initial connection item was not resumed");
    let first_read = resumed_calls
        .iter()
        .position(|call| matches!(call, IoCall::Read))
        .expect("normal connection polling did not resume");
    assert!(
        resumed_write < first_read,
        "the receive side ran before the initial item completed"
    );

    let write_positions = resumed_calls
        .iter()
        .enumerate()
        .filter_map(|(index, call)| match call {
            IoCall::Write(buf) => Some((index, buf)),
            IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(write_positions.len(), 2);
    assert!(
        resumed_calls[write_positions[0].0 + 1..write_positions[1].0]
            .iter()
            .all(|call| !matches!(call, IoCall::Flush))
    );

    let mut wire = first_write[..PARTIAL_WRITE_LEN].to_vec();
    for (_, write) in write_positions {
        wire.extend_from_slice(write);
    }
    let frames = wire_frames(&wire);
    assert_eq!(
        frames
            .iter()
            .map(|frame| (frame.kind, frame.flags, frame.stream_id))
            .collect::<Vec<_>>(),
        [(4, 0, 0), (4, 1, 0), (6, 1, 0), (1, 5, 1)]
    );
    let pong = frames
        .iter()
        .find(|frame| frame.kind == 6)
        .expect("PING acknowledgement was not written");
    assert_eq!(frame_payload(&wire, pong), &[1; 8]);
    assert_eq!(
        wire.windows(MAGIC_PREFACE.len())
            .filter(|window| *window == MAGIC_PREFACE)
            .count(),
        1
    );
}

#[tokio::test]
async fn handshake_defers_write_error_to_connection() {
    h2_support::trace_init!();

    for write_mode in [
        WriteMode::Fail(io::ErrorKind::BrokenPipe),
        WriteMode::PendingThenFail(io::ErrorKind::BrokenPipe),
    ] {
        let (io, calls, write_blocked, blocked_waker) = recording_io(write_mode, Bytes::new());
        let (mut send_request, mut connection) = client::handshake::<_>(io).await.unwrap();
        assert!(calls.lock().unwrap().is_empty());

        let request = Request::get("https://example.com/").body(()).unwrap();
        let (mut response, _send_stream) = send_request.send_request(request, true).unwrap();
        let response_wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let response_waker = Waker::from(response_wake_counter.clone());
        let mut response_cx = Context::from_waker(&response_waker);
        assert!(Pin::new(&mut response).poll(&mut response_cx).is_pending());

        let connection_wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let connection_waker = Waker::from(connection_wake_counter.clone());
        let mut connection_cx = Context::from_waker(&connection_waker);

        let pending_write_calls = if matches!(write_mode, WriteMode::PendingThenFail(_)) {
            assert!(Pin::new(&mut connection)
                .poll(&mut connection_cx)
                .is_pending());
            let pending_write_calls = calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| matches!(call, IoCall::Write(_)))
                .count();
            assert!(pending_write_calls > 0);

            write_blocked.store(false, Ordering::SeqCst);
            let blocked_waker = blocked_waker
                .lock()
                .unwrap()
                .take()
                .expect("write task was not registered");
            let wake_count = connection_wake_counter.0.load(Ordering::SeqCst);
            blocked_waker.wake();
            assert!(connection_wake_counter.0.load(Ordering::SeqCst) > wake_count);
            pending_write_calls
        } else {
            0
        };

        let Poll::Ready(Err(err)) = Pin::new(&mut connection).poll(&mut connection_cx) else {
            panic!("connection did not return the write error");
        };
        assert_eq!(
            err.get_io().map(io::Error::kind),
            Some(io::ErrorKind::BrokenPipe)
        );
        assert!(response_wake_counter.0.load(Ordering::SeqCst) > 0);

        let Poll::Ready(Err(err)) = Pin::new(&mut response).poll(&mut response_cx) else {
            panic!("write error was not propagated to the request");
        };
        assert_eq!(
            err.get_io().map(io::Error::kind),
            Some(io::ErrorKind::BrokenPipe)
        );

        let write_calls = calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| matches!(call, IoCall::Write(_)))
            .count();
        if matches!(write_mode, WriteMode::PendingThenFail(_)) {
            assert_eq!(write_calls, pending_write_calls + 1);
        } else {
            assert_eq!(write_calls, 1);
        }
    }
}

#[tokio::test]
async fn initial_stream_window_update_follows_each_request() {
    h2_support::trace_init!();

    const SETTINGS_WINDOW: u32 = 131_072;
    const TARGET_WINDOW: u32 = 12 * 1024 * 1024;
    const STREAM_INCREMENT: u32 = TARGET_WINDOW - SETTINGS_WINDOW;

    for (target, expected_stream_updates) in [
        (0, Vec::new()),
        (SETTINGS_WINDOW / 2, Vec::new()),
        (SETTINGS_WINDOW, Vec::new()),
        (
            TARGET_WINDOW,
            vec![(3, STREAM_INCREMENT), (5, STREAM_INCREMENT)],
        ),
    ] {
        let (io, calls, _write_blocked, _blocked_waker) =
            recording_io(WriteMode::Complete, Bytes::new());
        let mut builder = client::Builder::new();
        builder
            .initial_window_size(SETTINGS_WINDOW)
            .initial_connection_window_size(TARGET_WINDOW)
            .initial_stream_window_size(target)
            .initial_stream_id(3);

        let (mut send_request, mut connection) = builder
            .handshake::<_, Bytes>(io)
            .now_or_never()
            .expect("handshake attempted transport I/O")
            .unwrap();
        assert!(calls.lock().unwrap().is_empty());

        let first = send_request
            .send_request(
                Request::get("https://example.com/first").body(()).unwrap(),
                true,
            )
            .unwrap();
        let second = send_request
            .send_request(
                Request::get("https://example.com/second").body(()).unwrap(),
                true,
            )
            .unwrap();

        let waker = Waker::from(Arc::new(WakeCounter(AtomicUsize::new(0))));
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

        let calls = calls.lock().unwrap();
        let writes = calls
            .iter()
            .filter_map(|call| match call {
                IoCall::Write(buf) => Some(buf),
                IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 2, "unexpected write item count");

        let initial_frames = wire_frames(writes[0]);
        assert_eq!(
            initial_frames
                .iter()
                .map(|frame| (frame.kind, frame.stream_id))
                .collect::<Vec<_>>(),
            [(4, 0), (8, 0)]
        );
        assert!(frame_payload(writes[0], &initial_frames[0])
            .chunks_exact(6)
            .any(|setting| {
                u16::from_be_bytes([setting[0], setting[1]]) == 4
                    && u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]])
                        == SETTINGS_WINDOW
            }));
        assert_eq!(
            u32::from_be_bytes(
                frame_payload(writes[0], &initial_frames[1])
                    .try_into()
                    .unwrap()
            ),
            TARGET_WINDOW - h2::frame::DEFAULT_INITIAL_WINDOW_SIZE
        );

        let request_frames = encoded_frames(writes[1]);
        let layout = request_frames
            .iter()
            .map(|frame| (frame.kind, frame.stream_id))
            .collect::<Vec<_>>();
        let expected_layout = if expected_stream_updates.is_empty() {
            vec![(1, 3), (1, 5)]
        } else {
            vec![(1, 3), (8, 3), (1, 5), (8, 5)]
        };
        assert_eq!(layout, expected_layout);

        let stream_updates = request_frames
            .iter()
            .filter(|frame| frame.kind == 8)
            .map(|frame| {
                (
                    frame.stream_id,
                    u32::from_be_bytes(frame_payload(writes[1], frame).try_into().unwrap()),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(stream_updates, expected_stream_updates);

        drop((first, second));
    }

    for cancel_pending in [false, true] {
        let (io, calls, _write_blocked, _blocked_waker) =
            recording_io(WriteMode::Complete, Bytes::new());
        let mut builder = client::Builder::new();
        builder
            .initial_window_size(SETTINGS_WINDOW)
            .initial_stream_window_size(TARGET_WINDOW)
            .initial_max_send_streams(0);
        let (mut send_request, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
        let pending = send_request
            .send_request(
                Request::get("https://example.com/pending")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(wake_counter.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());
        let wake_count = wake_counter.0.load(Ordering::SeqCst);
        let _keep_connection = send_request.clone();
        drop(send_request);
        let pending = (!cancel_pending).then_some(pending);
        if cancel_pending {
            assert!(wake_counter.0.load(Ordering::SeqCst) > wake_count);
            assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());
        }

        let wire = calls
            .lock()
            .unwrap()
            .iter()
            .fold(Vec::new(), |mut wire, call| {
                if let IoCall::Write(buf) = call {
                    wire.extend_from_slice(buf);
                }
                wire
            });
        assert!(wire_frames(&wire).iter().all(|frame| frame.stream_id == 0));

        drop(pending);
    }

    // Cancelling before initial HEADERS reaches the codec leaves the stream
    // idle at the peer, even if a stream slot becomes available afterwards.
    let (io, calls, _write_blocked, _blocked_waker) = recording_io(
        WriteMode::Complete,
        Bytes::from_static(PEER_SETTINGS_MAX_CONCURRENT_ONE),
    );
    let mut builder = client::Builder::new();
    builder
        .initial_window_size(SETTINGS_WINDOW)
        .initial_stream_window_size(TARGET_WINDOW)
        .initial_max_send_streams(0);
    let (mut send_request, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
    let (response, mut send_stream) = send_request
        .send_request(
            Request::get("https://example.com/canceled")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    send_stream.send_reset(h2::Reason::CANCEL);
    drop((response, send_stream));

    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(send_request.poll_ready(&mut cx).is_pending());
    let before_cleanup = wake_counter.0.load(Ordering::SeqCst);
    for _ in 0..3 {
        assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());
    }
    assert!(wake_counter.0.load(Ordering::SeqCst) > before_cleanup);
    assert!(matches!(
        send_request.poll_ready(&mut cx),
        Poll::Ready(Ok(()))
    ));

    let wire = calls
        .lock()
        .unwrap()
        .iter()
        .fold(Vec::new(), |mut wire, call| {
            if let IoCall::Write(buf) = call {
                wire.extend_from_slice(buf);
            }
            wire
        });
    let request_layout = wire_frames(&wire)
        .into_iter()
        .filter(|frame| frame.stream_id != 0)
        .map(|frame| (frame.kind, frame.stream_id))
        .collect::<Vec<_>>();
    assert!(request_layout.is_empty());
}

#[tokio::test]
async fn initial_stream_window_update_precedes_request_data() {
    h2_support::trace_init!();

    const TARGET_WINDOW: u32 = 1024 * 1024;
    const BODY: &[u8] = b"request body";
    for (method, uri) in [
        ("GET", "https://example.com/get"),
        ("POST", "https://example.com/post"),
        ("CONNECT", "example.com:443"),
    ] {
        let (io, calls, _write_blocked, _blocked_waker) =
            recording_io(WriteMode::Complete, Bytes::new());
        let mut builder = client::Builder::new();
        builder.initial_stream_window_size(TARGET_WINDOW);
        let (mut send_request, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
        let mut request = Request::builder().method(method).uri(uri);
        if method == "POST" {
            for (name, value) in build_large_headers() {
                request = request.header(name, value);
            }
        }
        let has_body = method != "GET";
        let (response, mut send_stream) = send_request
            .send_request(request.body(()).unwrap(), !has_body)
            .unwrap();
        if has_body {
            send_stream
                .send_data(Bytes::from_static(BODY), true)
                .unwrap();
        }

        let waker = Waker::from(Arc::new(WakeCounter(AtomicUsize::new(0))));
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());
        let calls = calls.lock().unwrap();
        let wire = calls.iter().fold(Vec::new(), |mut wire, call| {
            if let IoCall::Write(buf) = call {
                wire.extend_from_slice(buf);
            }
            wire
        });
        let frames = wire_frames(&wire)
            .into_iter()
            .filter(|frame| frame.stream_id == 1)
            .collect::<Vec<_>>();
        assert_eq!(frames[0].kind, 1);
        assert_eq!(frames[0].flags & 0x1 != 0, !has_body);
        let update_index = frames.iter().position(|frame| frame.kind == 8).unwrap();
        assert!(frames[1..update_index].iter().all(|frame| frame.kind == 9));
        assert!(frames[..update_index - 1]
            .iter()
            .all(|frame| frame.flags & 0x4 == 0));
        assert_ne!(frames[update_index - 1].flags & 0x4, 0);
        if method == "POST" {
            assert!(
                update_index > 1,
                "POST headers did not require CONTINUATION"
            );
        }
        assert_eq!(
            u32::from_be_bytes(
                frame_payload(&wire, &frames[update_index])
                    .try_into()
                    .unwrap()
            ),
            TARGET_WINDOW - h2::frame::DEFAULT_INITIAL_WINDOW_SIZE
        );
        if has_body {
            assert_eq!(frames.len(), update_index + 2);
            let data = &frames[update_index + 1];
            assert_eq!((data.kind, data.flags), (0, 0x1));
            assert_eq!(frame_payload(&wire, data), BODY);
        } else {
            assert_eq!(frames.len(), update_index + 1);
        }
        drop((response, send_stream));
    }
}

#[tokio::test]
async fn initial_stream_window_cancel_before_headers_releases_stream_slot() {
    h2_support::trace_init!();

    for initial_slots in [0, 1] {
        for explicit_reset in [false, true] {
            let (io, calls, _write_blocked, _blocked_waker) = recording_io(
                WriteMode::Complete,
                Bytes::from_static(PEER_SETTINGS_MAX_CONCURRENT_ONE),
            );
            let mut builder = client::Builder::new();
            builder
                .initial_max_send_streams(initial_slots)
                .initial_stream_window_size(1024 * 1024);
            let (mut send_request, mut connection) =
                builder.handshake::<_, Bytes>(io).await.unwrap();
            let (response, mut body) = send_request
                .send_request(
                    Request::post("https://example.com/cancelled")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            body.send_data(Bytes::from_static(b"discard this body"), false)
                .unwrap();
            if explicit_reset {
                body.send_reset(h2::Reason::CANCEL);
            }
            drop((response, body));
            // SendRequest retains a reference to a pending-open request.
            // Drop that handle too so implicit cancellation releases every
            // reference; its clone can submit the next request independently.
            let next_sender = send_request.clone();
            drop(send_request);
            let send_request = next_sender;

            let waker = Waker::from(Arc::new(WakeCounter(AtomicUsize::new(0))));
            let mut cx = Context::from_waker(&waker);
            assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());
            let mut send_request = send_request.ready().now_or_never().unwrap().unwrap();
            let request = send_request
                .send_request(
                    Request::post("https://example.com/live").body(()).unwrap(),
                    false,
                )
                .unwrap();
            let (response, mut body) = request;
            // All reserved connection send capacity must have been returned.
            body.send_data(Bytes::from(vec![b'x'; 65_535]), true)
                .unwrap();
            assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

            let calls = calls.lock().unwrap();
            let wire = calls.iter().fold(Vec::new(), |mut wire, call| {
                if let IoCall::Write(buf) = call {
                    wire.extend_from_slice(buf);
                }
                wire
            });
            let frames = wire_frames(&wire)
                .into_iter()
                .filter(|frame| frame.stream_id != 0)
                .collect::<Vec<_>>();
            assert!(frames.iter().all(|frame| frame.stream_id == 3));
            assert_eq!((frames[0].kind, frames[1].kind), (1, 8));
            assert!(frames[2..].iter().all(|frame| frame.kind == 0));
            assert_eq!(
                frames[2..]
                    .iter()
                    .map(|frame| frame.payload_len)
                    .sum::<usize>(),
                65_535
            );
            assert_eq!(frames.last().unwrap().flags & 1, 1);
            drop(calls);
            drop((response, body));
        }
    }
}

#[tokio::test]
async fn initial_stream_window_update_follows_complete_header_block() {
    h2_support::trace_init!();

    let (io, calls, _write_blocked, _blocked_waker) =
        recording_io(WriteMode::Complete, Bytes::new());
    let mut builder = client::Builder::new();
    builder.initial_stream_window_size(1024 * 1024);
    let (mut send_request, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();

    let mut request = Request::builder()
        .uri("https://example.com/large")
        .extension(h2::ext::HeadersPriority::new(StreamId::zero(), 219, true));
    for (name, value) in build_large_headers() {
        request = request.header(name, value);
    }
    let large = send_request
        .send_request(request.body(()).unwrap(), true)
        .unwrap();
    let small = send_request
        .send_request(
            Request::get("https://example.com/small").body(()).unwrap(),
            true,
        )
        .unwrap();

    let waker = Waker::from(Arc::new(WakeCounter(AtomicUsize::new(0))));
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

    let calls = calls.lock().unwrap();
    let writes = calls
        .iter()
        .enumerate()
        .filter_map(|(index, call)| match call {
            IoCall::Write(buf) => Some((index, buf)),
            IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
        })
        .collect::<Vec<_>>();
    assert!(writes.len() > 3, "large header block was not split");

    let mut request_wire = Vec::new();
    for (_, write) in writes.iter().skip(1) {
        request_wire.extend_from_slice(write);
    }
    let frames = encoded_frames(&request_wire);
    assert!(frames
        .iter()
        .all(|frame| frame.payload_len <= h2::frame::DEFAULT_MAX_FRAME_SIZE as usize));
    assert_eq!(frames[0].kind, 1);
    assert_eq!(frames[0].stream_id, 1);
    assert_eq!(frames[0].flags & 0x4, 0);
    assert_eq!(frames[0].flags & 0x21, 0x21);
    assert_eq!(&request_wire[9..14], &[0x80, 0, 0, 0, 219]);

    let first_update = frames
        .iter()
        .position(|frame| frame.kind == 8 && frame.stream_id == 1)
        .expect("stream 1 WINDOW_UPDATE missing");
    assert!(first_update > 1);
    assert!(frames[1..first_update]
        .iter()
        .all(|frame| frame.kind == 9 && frame.stream_id == 1 && frame.flags & 0x21 == 0));
    assert_ne!(frames[first_update - 1].flags & 0x4, 0);
    assert_eq!(frames[first_update + 1].flags & 0x20, 0);
    assert_eq!(
        frames[first_update + 1..]
            .iter()
            .map(|frame| (frame.kind, frame.stream_id))
            .collect::<Vec<_>>(),
        [(1, 3), (8, 3)]
    );

    let first_header_write = writes[1].0;
    let first_update_write = writes
        .iter()
        .skip(1)
        .find_map(|(index, write)| {
            encoded_frames(write)
                .iter()
                .any(|frame| frame.kind == 8 && frame.stream_id == 1)
                .then_some(*index)
        })
        .expect("stream 1 WINDOW_UPDATE write missing");
    assert!(calls[first_header_write..first_update_write]
        .iter()
        .all(|call| !matches!(call, IoCall::Flush)));

    drop((large, small));
    drop(calls);

    // HPACK encodes GET https://a/ in six bytes. Each literal `x` field adds
    // six bytes around its value, and `Z` has an eight-bit Huffman code.
    // These fixtures fill either HEADERS or its final CONTINUATION exactly.
    // RFC 9113 §6.10 requires the companion frame to follow END_HEADERS.
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.10
    const MAX_FRAME_SIZE: usize = h2::frame::DEFAULT_MAX_FRAME_SIZE as usize;
    for (fragment_count, value_len) in [(1, MAX_FRAME_SIZE - 12), (2, MAX_FRAME_SIZE - 9)] {
        let (io, calls, _write_blocked, _blocked_waker) =
            recording_io(WriteMode::Complete, Bytes::new());
        let mut builder = client::Builder::new();
        builder.initial_stream_window_size(1024 * 1024);
        let (mut send_request, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
        let mut request = Request::get("https://a/");
        for _ in 0..fragment_count {
            request = request.header("x", "Z".repeat(value_len));
        }
        let request = send_request
            .send_request(request.body(()).unwrap(), true)
            .unwrap();
        assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

        let calls = calls.lock().unwrap();
        let writes = calls
            .iter()
            .filter_map(|call| match call {
                IoCall::Write(buf) => Some(buf),
                _ => None,
            })
            .collect::<Vec<_>>();
        let wire = writes
            .iter()
            .skip(1)
            .flat_map(|write| write.iter().copied())
            .collect::<Vec<_>>();
        let frames = encoded_frames(&wire);
        assert_eq!(frames.len(), fragment_count + 1);
        for (index, frame) in frames[..fragment_count].iter().enumerate() {
            assert_eq!(frame.kind, if index == 0 { 1 } else { 9 });
            assert_eq!(frame.stream_id, 1);
            assert_eq!(frame.payload_len, MAX_FRAME_SIZE);
            assert_eq!(frame.flags & 0x4 != 0, index + 1 == fragment_count);
        }
        let update = &frames[fragment_count];
        assert_eq!((update.kind, update.flags, update.stream_id), (8, 0, 1));
        assert_eq!(update.payload_len, 4);
        assert_eq!(
            u32::from_be_bytes(frame_payload(&wire, update).try_into().unwrap()),
            1024 * 1024 - h2::frame::DEFAULT_INITIAL_WINDOW_SIZE
        );
        // The final full fragment and update share a write with no flush between.
        let final_write_frames = encoded_frames(writes.last().unwrap());
        assert_eq!(final_write_frames.len(), 2);
        assert_eq!(final_write_frames[0].payload_len, MAX_FRAME_SIZE);
        assert_eq!(final_write_frames[1].kind, 8);
        drop(request);
    }

    let (io, calls, write_blocked, blocked_waker) =
        recording_io(WriteMode::RequestPartialThenPending, Bytes::new());
    let mut builder = client::Builder::new();
    builder.initial_stream_window_size(1024 * 1024);
    let (mut send_request, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
    let request = send_request
        .send_request(
            Request::get("https://example.com/partial")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();

    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

    let (request_item, blocked_call_count) = {
        let calls = calls.lock().unwrap();
        let writes = calls
            .iter()
            .filter_map(|call| match call {
                IoCall::Write(buf) => Some(buf),
                IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 3);
        assert_eq!(writes[2].as_ref(), &writes[1][writes[1].len() - 5..]);
        ((*writes[1]).clone(), calls.len())
    };

    write_blocked.store(false, Ordering::SeqCst);
    let blocked_waker = blocked_waker
        .lock()
        .unwrap()
        .take()
        .expect("request write task was not registered");
    let wake_count = wake_counter.0.load(Ordering::SeqCst);
    blocked_waker.wake();
    assert!(wake_counter.0.load(Ordering::SeqCst) > wake_count);
    assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

    let calls = calls.lock().unwrap();
    let resumed = calls[blocked_call_count..]
        .iter()
        .find_map(|call| match call {
            IoCall::Write(buf) => Some(buf),
            IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
        })
        .expect("partial request item was not resumed");
    assert_eq!(resumed.as_ref(), &request_item[request_item.len() - 5..]);
    let mut request_wire = request_item[..request_item.len() - 5].to_vec();
    request_wire.extend_from_slice(resumed);
    assert_eq!(
        encoded_frames(&request_wire)
            .iter()
            .map(|frame| (frame.kind, frame.stream_id))
            .collect::<Vec<_>>(),
        [(1, 1), (8, 1)]
    );

    drop(request);
}

#[tokio::test]
async fn invalid_initial_stream_window_fails_before_io() {
    h2_support::trace_init!();

    for (advertised, target) in [(65_535, 1_u32 << 31), (65_535, u32::MAX)] {
        let (io, calls, _write_blocked, _blocked_waker) =
            recording_io(WriteMode::Complete, Bytes::new());
        let mut builder = client::Builder::new();
        builder
            .initial_window_size(advertised)
            .initial_stream_window_size(target);

        let result = builder
            .handshake::<_, Bytes>(io)
            .now_or_never()
            .expect("handshake attempted transport I/O");
        let err = match result {
            Ok(_) => panic!("invalid stream window was accepted"),
            Err(err) => err,
        };
        assert_eq!(
            err.to_string(),
            "user error: invalid initial stream window size"
        );
        assert!(calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn dynamic_initial_window_cannot_outgrow_pending_stream_update() {
    h2_support::trace_init!();

    let (io, _calls, _write_blocked, _blocked_waker) = recording_io(
        WriteMode::Complete,
        Bytes::from_static(PEER_SETTINGS_AND_ACK),
    );
    let mut builder = client::Builder::new();
    builder.initial_stream_window_size(i32::MAX as u32);
    let (mut send_request, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();

    let waker = Waker::from(Arc::new(WakeCounter(AtomicUsize::new(0))));
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

    let request = send_request
        .send_request(
            Request::get("https://example.com/pending-update")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    let err = connection.set_initial_window_size(65_536).unwrap_err();
    assert_eq!(
        err.to_string(),
        "user error: invalid initial stream window size"
    );
    connection.set_initial_window_size(65_535).unwrap();

    drop(request);
}

#[tokio::test]
async fn initial_stream_window_uses_sent_settings_baseline() {
    use h2_support::util::yield_once;
    use tokio::sync::oneshot;

    h2_support::trace_init!();

    const URI: &str = "https://example.com/window";
    const RESPONSE_BYTES: usize = 32;
    for (advertised, lowered, target) in [(65_535, 0, i32::MAX as u32), (16, 4, 32)] {
        let (io, mut server) = mock::new();
        let (handshake_tx, handshake_rx) = oneshot::channel();
        let (ack_tx, ack_rx) = oneshot::channel();
        let (consumed_tx, consumed_rx) = oneshot::channel();
        let (reset_tx, reset_rx) = oneshot::channel();
        let check_overflow = target == RESPONSE_BYTES as u32;

        let server = async move {
            let settings = server
                .assert_client_handshake_with_settings(frames::settings().max_concurrent_streams(0))
                .await;
            assert_eq!(settings.initial_window_size(), Some(advertised));
            handshake_tx.send(()).unwrap();
            server
                .recv_frame(frames::settings().initial_window_size(lowered))
                .await;

            // Hold the ACK until both requests have opened under the new
            // SETTINGS. No response DATA is sent before that ACK.
            server
                .send_frame(frames::settings().max_concurrent_streams(3))
                .await;
            server.recv_frame(frames::settings_ack()).await;
            for stream_id in [1, 3] {
                server
                    .recv_frame(frames::headers(stream_id).request("GET", URI).eos())
                    .await;
                server
                    .recv_frame(frames::window_update(stream_id, target - lowered))
                    .await;
            }
            server.send_frame(frames::settings_ack()).await;
            ack_tx.send(()).unwrap();
            server
                .recv_frame(frames::headers(5).request("GET", URI).eos())
                .await;
            server
                .recv_frame(frames::window_update(5, target - lowered))
                .await;

            for stream_id in [1, 3, 5] {
                server
                    .send_frame(frames::headers(stream_id).response(200))
                    .await;
                let frame = frames::data(stream_id, vec![b'x'; RESPONSE_BYTES]);
                if stream_id == 5 && check_overflow {
                    server.send_frame(frame).await;
                } else {
                    server.send_frame(frame.eos()).await;
                }
            }
            if check_overflow {
                consumed_rx.await.unwrap();
                server.send_frame(frames::data(5, b"!")).await;
                server.recv_frame(frames::reset(5).flow_control()).await;
                reset_tx.send(()).unwrap();
            }
        };

        let client = async move {
            let mut builder = client::Builder::new();
            builder
                .initial_window_size(advertised)
                .initial_stream_window_size(target)
                .initial_max_send_streams(0);
            let (mut send_request, mut connection) =
                builder.handshake::<_, Bytes>(io).await.unwrap();
            let (first, _first_send) = send_request
                .send_request(Request::get(URI).body(()).unwrap(), true)
                .unwrap();
            connection
                .drive(async {
                    handshake_rx.await.unwrap();
                    yield_once().await;
                })
                .await;
            connection.set_initial_window_size(lowered).unwrap();
            let mut send_request = connection.drive(send_request.ready()).await.unwrap();
            let (before_ack, _before_ack_send) = send_request
                .send_request(Request::get(URI).body(()).unwrap(), true)
                .unwrap();
            connection
                .drive(async {
                    ack_rx.await.unwrap();
                    yield_once().await;
                })
                .await;
            let (after_ack, _after_ack_send) = send_request
                .send_request(Request::get(URI).body(()).unwrap(), true)
                .unwrap();

            connection
                .drive(async move {
                    for response in [first, before_ack] {
                        let mut body = response.await.unwrap().into_body();
                        assert_eq!(body.data().await.unwrap().unwrap().len(), RESPONSE_BYTES);
                        assert_eq!(
                            body.flow_control().available_capacity(),
                            (target - RESPONSE_BYTES as u32) as isize
                        );
                        assert!(body.data().await.is_none());
                    }
                    let mut body = after_ack.await.unwrap().into_body();
                    assert_eq!(body.data().await.unwrap().unwrap().len(), RESPONSE_BYTES);
                    assert_eq!(
                        body.flow_control().available_capacity(),
                        (target - RESPONSE_BYTES as u32) as isize
                    );
                    if check_overflow {
                        // Reading the body does not return capacity. One byte
                        // beyond this stream's target must still be rejected.
                        consumed_tx.send(()).unwrap();
                        let err = body.data().await.unwrap().unwrap_err();
                        assert_eq!(err.reason(), Some(h2::Reason::FLOW_CONTROL_ERROR));
                        reset_rx.await.unwrap();
                    } else {
                        assert!(body.data().await.is_none());
                    }
                })
                .await;
        };

        tokio::time::timeout(Duration::from_secs(5), join(server, client))
            .await
            .expect("dynamic initial stream window exchange stalled");
    }
}

#[tokio::test]
async fn initial_stream_window_is_active_before_settings_ack() {
    h2_support::trace_init!();

    const SETTINGS_WINDOW: u32 = 131_072;
    const TARGET_WINDOW: u32 = 163_840;
    const CONNECTION_WINDOW: u32 = 1024 * 1024;
    const CHUNK_SIZE: usize = 16_384;
    const CHUNK_COUNT: usize = 9;

    let (io, mut server) = mock::new();

    let server = async move {
        // Advertise the server SETTINGS, but deliberately withhold the ACK for
        // the client's SETTINGS throughout the response body. This
        // intentionally violates RFC 9113 section 6.5.3 to stress the client's
        // pre-ACK receive accounting; it is not a normal peer frame sequence.
        server.send_frame(frames::settings()).await;
        server.read_preface().await.unwrap();

        let client_settings = server.next().await.unwrap().unwrap();
        let client_settings = match client_settings {
            h2::frame::Frame::Settings(settings) if !settings.is_ack() => settings,
            frame => panic!("expected client SETTINGS, got {:?}", frame),
        };
        assert_eq!(client_settings.initial_window_size(), Some(SETTINGS_WINDOW));

        let mut saw_headers = false;
        let mut saw_stream_update = false;
        while !(saw_headers && saw_stream_update) {
            match server.next().await.unwrap().unwrap() {
                h2::frame::Frame::Settings(settings) if settings.is_ack() => {}
                h2::frame::Frame::WindowUpdate(update) if update.stream_id().is_zero() => {
                    assert_eq!(
                        update.size_increment(),
                        CONNECTION_WINDOW - h2::frame::DEFAULT_INITIAL_WINDOW_SIZE
                    );
                }
                h2::frame::Frame::Headers(headers) => {
                    assert_eq!(headers.stream_id(), StreamId::from(1));
                    saw_headers = true;
                }
                h2::frame::Frame::WindowUpdate(update) => {
                    assert!(saw_headers, "stream WINDOW_UPDATE preceded HEADERS");
                    assert_eq!(update.stream_id(), StreamId::from(1));
                    assert_eq!(update.size_increment(), TARGET_WINDOW - SETTINGS_WINDOW);
                    saw_stream_update = true;
                }
                frame => panic!("unexpected client frame: {:?}", frame),
            }
        }

        server.send_frame(frames::headers(1).response(200)).await;
        for index in 0..CHUNK_COUNT {
            let frame = frames::data(1, vec![b'x'; CHUNK_SIZE]);
            if index + 1 == CHUNK_COUNT {
                server.send_frame(frame.eos()).await;
            } else {
                server.send_frame(frame).await;
            }
        }
    };

    let client = async move {
        let mut builder = client::Builder::new();
        builder
            .initial_window_size(SETTINGS_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .initial_stream_window_size(TARGET_WINDOW);
        let (mut send_request, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
        let (response, _send_stream) = send_request
            .send_request(
                Request::get("https://example.com/large-response")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();

        let received = connection
            .drive(async move {
                let response = response.await.unwrap();
                let mut body = response.into_body();
                let mut received = 0;
                while let Some(chunk) = body.data().await {
                    received += chunk.unwrap().len();
                }
                received
            })
            .await;
        assert_eq!(received, CHUNK_SIZE * CHUNK_COUNT);
    };

    tokio::time::timeout(Duration::from_secs(5), join(server, client))
        .await
        .expect("initial stream window exchange stalled");
}
