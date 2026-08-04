use futures::FutureExt;
use h2_support::prelude::*;
use http::HeaderValue;
use std::convert::TryInto;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use tokio::io::ReadBuf;

const PARTIAL_WRITE_LEN: usize = 7;
const PEER_SETTINGS_AND_GOAWAY: &[u8] = &[
    // SETTINGS_MAX_CONCURRENT_STREAMS = 0
    0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, // GOAWAY, last stream ID 1, NO_ERROR
    0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
];
const PEER_TWO_SETTINGS_AND_GOAWAY: &[u8] = &[
    // SETTINGS_MAX_CONCURRENT_STREAMS = 0
    0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, // A second non-ACK SETTINGS frame.
    0, 0, 0, 4, 0, 0, 0, 0, 0, // GOAWAY, last stream ID 1, NO_ERROR
    0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
];
const SETTINGS_ACK: &[u8] = &[0, 0, 0, 4, 1, 0, 0, 0, 0];

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
    PendingThenComplete,
    FlushThenPending,
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
            WriteMode::PartialThenPending if self.write_blocked.load(Ordering::SeqCst) => {
                *self.blocked_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
            WriteMode::PendingThenComplete if self.write_blocked.load(Ordering::SeqCst) => {
                *self.blocked_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
            WriteMode::PendingThenFail(_) if self.write_blocked.load(Ordering::SeqCst) => {
                *self.blocked_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
            WriteMode::PartialThenPending
            | WriteMode::PendingThenComplete
            | WriteMode::FlushThenPending
            | WriteMode::Complete => Poll::Ready(Ok(buf.len())),
            WriteMode::Fail(kind) | WriteMode::PendingThenFail(kind) => {
                Poll::Ready(Err(kind.into()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.lock().unwrap().push(IoCall::Flush);
        if matches!(self.write_mode, WriteMode::FlushThenPending)
            && self.write_blocked.load(Ordering::SeqCst)
        {
            *self.blocked_waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
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

    let mut frames = Vec::new();
    let mut pos = MAGIC_PREFACE.len();

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

// These profile values were captured on 2026-08-04. They validate that the
// client can reproduce the observed HTTP/2 frames without making their exact
// bytes a permanent browser or transport boundary.
#[tokio::test]
async fn safari_and_chrome_profiles_fit_in_one_initial_transport_write() {
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
        let writes: Vec<_> = calls
            .iter()
            .filter_map(|call| match call {
                IoCall::Write(buf) => Some(buf),
                IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
            })
            .collect();
        assert_eq!(
            writes.len(),
            1,
            "{profile:?} initial frames were split across transport writes"
        );

        let first_write = writes[0].as_ref();
        let frames = wire_frames(first_write);
        assert_eq!(
            frames
                .iter()
                .map(|frame| (frame.kind, frame.stream_id))
                .collect::<Vec<_>>(),
            [(4, 0), (8, 0), (1, 1)]
        );

        let settings_payload = frame_payload(first_write, &frames[0]);
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

        let window_payload = frame_payload(first_write, &frames[1]);
        assert_eq!(window_payload.len(), 4);
        assert_eq!(
            u32::from_be_bytes(window_payload.try_into().unwrap()),
            expected_window_update
        );

        assert_eq!(frames[2].flags, expected_headers_flags);
        let headers_payload = frame_payload(first_write, &frames[2]);
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
async fn coalesces_initial_frames_and_queued_requests_before_first_write() {
    h2_support::trace_init!();

    for (connection_window, with_priority, request_count, with_body_and_trailers) in [
        (None, false, 2, false),
        (Some(1_000_000), false, 2, false),
        (Some(1_000_000), true, 1, false),
        (None, false, 1, true),
    ] {
        let (io, calls, write_blocked, blocked_waker) =
            recording_io(WriteMode::PartialThenPending, Bytes::new());
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

        let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(wake_counter.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

        let first_write = {
            let calls = calls.lock().unwrap();
            let writes: Vec<_> = calls
                .iter()
                .filter_map(|call| match call {
                    IoCall::Write(buf) => Some(buf),
                    IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
                })
                .collect();
            let first = *writes
                .first()
                .expect("initial client batch was not written");
            assert!(writes.len() >= 2);
            for remaining in &writes[1..] {
                assert_eq!(remaining.as_ref(), &first[PARTIAL_WRITE_LEN..]);
            }
            assert!(calls.iter().any(|call| matches!(call, IoCall::Read)));
            first.clone()
        };
        let blocked_call_count = calls.lock().unwrap().len();

        let mut expected = vec![(4, 0)];
        if connection_window.is_some() {
            expected.push((8, 0));
        }
        if with_priority {
            expected.push((2, 1));
        }
        let first_request_id = if with_priority { 3 } else { 1 };
        expected.extend((0..request_count).map(|index| (1, first_request_id + 2 * index as u32)));
        if with_body_and_trailers {
            expected.extend([(0, first_request_id), (1, first_request_id)]);
        }
        assert_eq!(frame_layout(&first_write), expected);

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
        let retried = calls[blocked_call_count..]
            .iter()
            .find_map(|call| match call {
                IoCall::Write(buf) => Some(buf),
                IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
            })
            .expect("partial write was not retried");
        assert_eq!(retried.as_ref(), &first_write[PARTIAL_WRITE_LEN..]);
        assert!(calls[blocked_call_count..]
            .iter()
            .any(|call| matches!(call, IoCall::Flush)));
    }
}

#[tokio::test]
async fn initial_write_does_not_wait_for_a_request() {
    h2_support::trace_init!();

    for request_state in [
        RequestState::None,
        RequestState::Cancelled,
        RequestState::Pending,
    ] {
        let (io, calls, _write_blocked, _blocked_waker) =
            recording_io(WriteMode::Complete, Bytes::new());
        let mut builder = client::Builder::new();
        if matches!(request_state, RequestState::Pending) {
            builder.initial_max_send_streams(0);
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
        if matches!(request_state, RequestState::None | RequestState::Pending) {
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
    let (send_request, mut connection) = client::handshake::<_>(io).await.unwrap();
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
            .expect("initial client batch was not written");
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
    assert_eq!(frame_layout(&wire), [(4, 0), (7, 0)]);
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
async fn blocked_initial_write_still_processes_peer_frames() {
    h2_support::trace_init!();

    for write_mode in [
        WriteMode::PartialThenPending,
        WriteMode::PendingThenComplete,
        WriteMode::FlushThenPending,
    ] {
        let (io, calls, write_blocked, blocked_waker) =
            recording_io(write_mode, Bytes::from_static(PEER_SETTINGS_AND_GOAWAY));
        let mut builder = client::Builder::new();
        builder.initial_connection_window_size(1_000_000);

        let (mut send_request, mut connection) = builder
            .handshake::<_, Bytes>(io)
            .now_or_never()
            .expect("handshake attempted transport I/O")
            .unwrap();
        let request = Request::get("https://example.com/").body(()).unwrap();
        let (_response, _send_stream) = send_request.send_request(request, true).unwrap();

        let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(wake_counter.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

        let first_write = {
            let calls = calls.lock().unwrap();
            let first_read = calls
                .iter()
                .position(|call| matches!(call, IoCall::Read))
                .expect("write backpressure starved the receive side");
            let first_write = calls
                .iter()
                .position(|call| matches!(call, IoCall::Write(_)))
                .expect("initial client batch was not written");
            assert!(first_write < first_read);

            let IoCall::Write(first) = &calls[first_write] else {
                unreachable!();
            };
            assert_eq!(frame_layout(first), vec![(4, 0), (8, 0), (1, 1)]);

            if matches!(write_mode, WriteMode::PartialThenPending) {
                let retries: Vec<_> = calls
                    .iter()
                    .filter_map(|call| match call {
                        IoCall::Write(buf) => Some(buf),
                        IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
                    })
                    .skip(1)
                    .collect();
                assert!(!retries.is_empty());
                assert_eq!(retries[0].as_ref(), &first[PARTIAL_WRITE_LEN..]);
                for retry in retries.into_iter().skip(1) {
                    assert!(retry.starts_with(&first[PARTIAL_WRITE_LEN..]));
                    assert_eq!(&retry[first.len() - PARTIAL_WRITE_LEN..], SETTINGS_ACK);
                }
            }

            first.clone()
        };

        assert_eq!(connection.max_concurrent_send_streams(), 0);
        let request = Request::get("https://example.com/rejected")
            .body(())
            .unwrap();
        assert!(send_request.send_request(request, true).is_err());

        let blocked_call_count = calls.lock().unwrap().len();
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
        let mut wire = Vec::new();
        match write_mode {
            WriteMode::PartialThenPending => {
                wire.extend_from_slice(&first_write[..PARTIAL_WRITE_LEN]);
                for call in &calls[blocked_call_count..] {
                    if let IoCall::Write(buf) = call {
                        wire.extend_from_slice(buf);
                    }
                }
            }
            WriteMode::PendingThenComplete => {
                for call in &calls[blocked_call_count..] {
                    if let IoCall::Write(buf) = call {
                        wire.extend_from_slice(buf);
                    }
                }
            }
            WriteMode::FlushThenPending => {
                for call in calls.iter() {
                    if let IoCall::Write(buf) = call {
                        wire.extend_from_slice(buf);
                    }
                }
            }
            WriteMode::Complete | WriteMode::Fail(_) | WriteMode::PendingThenFail(_) => {
                unreachable!()
            }
        }

        assert_eq!(&wire[..first_write.len()], first_write.as_ref());
        assert_eq!(&wire[first_write.len()..], SETTINGS_ACK);
        assert_eq!(
            wire.windows(MAGIC_PREFACE.len())
                .filter(|window| *window == MAGIC_PREFACE)
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn oversized_initial_headers_keep_reads_live_and_continuations_ordered() {
    h2_support::trace_init!();

    let (io, calls, write_blocked, blocked_waker) = recording_io(
        WriteMode::PartialThenPending,
        Bytes::from_static(PEER_TWO_SETTINGS_AND_GOAWAY),
    );
    let (mut send_request, mut connection) = client::handshake::<_>(io).await.unwrap();
    let request = Request::get("https://example.com/")
        .header("x-large", "a".repeat(40_000))
        .body(())
        .unwrap();
    let (_response, _send_stream) = send_request.send_request(request, true).unwrap();

    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut connection).poll(&mut cx).is_pending());

    let (first_write, blocked_call_count) = {
        let calls = calls.lock().unwrap();
        assert!(
            calls.iter().any(|call| matches!(call, IoCall::Read)),
            "a full continuation buffer starved the receive side"
        );
        let first_write = calls
            .iter()
            .find_map(|call| match call {
                IoCall::Write(buf) => Some(buf.clone()),
                IoCall::Read | IoCall::Flush | IoCall::Shutdown => None,
            })
            .expect("initial client batch was not written");
        (first_write, calls.len())
    };

    assert_eq!(connection.max_concurrent_send_streams(), 0);
    let request = Request::get("https://example.com/rejected")
        .body(())
        .unwrap();
    assert!(send_request.send_request(request, true).is_err());

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
    let mut wire = first_write[..PARTIAL_WRITE_LEN].to_vec();
    for call in &calls[blocked_call_count..] {
        if let IoCall::Write(buf) = call {
            wire.extend_from_slice(buf);
        }
    }
    assert_eq!(
        wire.windows(MAGIC_PREFACE.len())
            .filter(|window| *window == MAGIC_PREFACE)
            .count(),
        1
    );
    let frames = wire_frames(&wire);
    assert_eq!(
        frames.first().map(|frame| (frame.kind, frame.stream_id)),
        Some((4, 0))
    );
    assert_eq!(
        frames.get(1).map(|frame| (frame.kind, frame.stream_id)),
        Some((1, 1))
    );
    let acks: Vec<_> = frames
        .iter()
        .enumerate()
        .skip(1)
        .filter_map(|(index, frame)| {
            (frame.kind == 4 && frame.stream_id == 0 && frame.flags & 1 == 1).then_some(index)
        })
        .collect();
    assert_eq!(acks.len(), 2, "each peer SETTINGS needs exactly one ACK");
    assert!(
        acks[0] > 2,
        "oversized HEADERS did not produce CONTINUATION"
    );
    assert!(frames[2..acks[0]]
        .iter()
        .all(|frame| frame.kind == 9 && frame.stream_id == 1));
    assert_eq!(acks[1], acks[0] + 1);
    assert_eq!(frames.len(), acks[1] + 1);
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
