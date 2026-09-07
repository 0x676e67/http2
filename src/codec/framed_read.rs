use crate::frame::{self, Frame, Kind, Reason};
use crate::frame::{
    DEFAULT_MAX_FRAME_SIZE, DEFAULT_SETTINGS_HEADER_TABLE_SIZE, MAX_MAX_FRAME_SIZE,
};
use crate::proto::Error;

use crate::hpack;
use crate::tracing;

use futures_core::Stream;

use bytes::{Buf, BytesMut};

use std::io;

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncRead;
use tokio_util::codec::FramedRead as InnerFramedRead;
use tokio_util::codec::{Decoder, LengthDelimitedCodec, LengthDelimitedCodecError};

// 16 MB "sane default" taken from golang http2
const DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: usize = 16 << 20;

#[derive(Debug)]
pub struct FramedRead<T> {
    inner: InnerFramedRead<T, DataHeadCodec>,

    decoder: FrameDecoder,
}

#[derive(Debug)]
struct FrameDecoder {
    // hpack decoder state
    hpack: hpack::Decoder,

    max_header_list_size: usize,

    max_continuation_frames: usize,

    partial: Option<Partial>,
}

/// Partially loaded headers frame
#[derive(Debug)]
struct Partial {
    /// Empty frame
    frame: Continuable,

    /// Partial header payload
    buf: BytesMut,

    continuation_frames_count: usize,
}

#[derive(Debug)]
enum Continuable {
    Headers(frame::Headers),
    PushPromise(frame::PushPromise),
}

impl<T> FramedRead<T> {
    pub fn new(inner: InnerFramedRead<T, LengthDelimitedCodec>) -> FramedRead<T> {
        let decoder = FrameDecoder::new(inner.decoder().max_frame_length());
        let inner = inner.map_decoder(DataHeadCodec::new);
        FramedRead { inner, decoder }
    }

    pub fn get_ref(&self) -> &T {
        self.inner.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// Returns the current max frame size setting
    #[inline]
    pub fn max_frame_size(&self) -> usize {
        self.inner.decoder().inner.max_frame_length()
    }

    /// Updates the max frame size setting.
    ///
    /// Must be within 16,384 and 16,777,215.
    #[inline]
    pub fn set_max_frame_size(&mut self, val: usize) {
        assert!(DEFAULT_MAX_FRAME_SIZE as usize <= val && val <= MAX_MAX_FRAME_SIZE as usize);
        self.inner.decoder_mut().inner.set_max_frame_length(val);
        // Update max CONTINUATION frames too, since its based on this
        self.decoder.set_max_frame_size(val);
    }

    /// Update the max header list size setting.
    #[inline]
    pub fn set_max_header_list_size(&mut self, val: usize) {
        self.decoder
            .set_max_header_list_size(val, self.max_frame_size());
    }

    /// Update the header table size setting.
    #[inline]
    pub fn set_header_table_size(&mut self, val: usize) {
        self.decoder.set_header_table_size(val);
    }

    pub(super) fn enable_data_head_events(&mut self) {
        let state = &mut self.inner.decoder_mut().state;
        if matches!(state, DataHeadState::Disabled) {
            *state = DataHeadState::Reading;
        }
    }

    pub(super) fn poll_next_event(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<ReadEvent, Error>>>
    where
        T: AsyncRead + Unpin,
    {
        let _span = tracing::trace_span!("FramedRead::poll_next");
        loop {
            tracing::trace!("poll");
            let bytes = match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(DelimitedEvent::Frame(bytes))) => bytes,
                Some(Ok(DelimitedEvent::DataHead(head))) => {
                    // DATA cannot interrupt a header block (RFC 9113 §6.10).
                    // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.10
                    if self.decoder.partial.is_some() {
                        proto_err!(conn: "expected CONTINUATION, got DATA");
                        return Poll::Ready(Some(Err(Error::library_go_away(
                            Reason::PROTOCOL_ERROR,
                        ))));
                    }
                    return Poll::Ready(Some(Ok(ReadEvent::DataHead(head))));
                }
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => return Poll::Ready(None),
            };

            tracing::trace!(read.bytes = bytes.len());
            if let Some(frame) = self.decoder.decode(bytes)? {
                tracing::debug!(?frame, "received");
                return Poll::Ready(Some(Ok(ReadEvent::Frame(frame))));
            }
        }
    }
}

fn calc_max_continuation_frames(header_max: usize, frame_max: usize) -> usize {
    // At least this many frames needed to use max header list size
    let min_frames_for_list = (header_max / frame_max).max(1);
    // Some padding for imperfectly packed frames
    // 25% without floats
    let padding = min_frames_for_list >> 2;
    min_frames_for_list.saturating_add(padding).max(5)
}

impl FrameDecoder {
    fn new(max_frame_size: usize) -> Self {
        let max_header_list_size = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
        FrameDecoder {
            hpack: hpack::Decoder::new(DEFAULT_SETTINGS_HEADER_TABLE_SIZE),
            max_header_list_size,
            max_continuation_frames: calc_max_continuation_frames(
                max_header_list_size,
                max_frame_size,
            ),
            partial: None,
        }
    }

    fn set_max_frame_size(&mut self, val: usize) {
        self.max_continuation_frames = calc_max_continuation_frames(self.max_header_list_size, val);
    }

    fn set_max_header_list_size(&mut self, val: usize, max_frame_size: usize) {
        self.max_header_list_size = val;
        // Update max CONTINUATION frames too, since its based on this
        self.max_continuation_frames = calc_max_continuation_frames(val, max_frame_size);
    }

    fn set_header_table_size(&mut self, val: usize) {
        self.hpack.queue_size_update(val);
    }

    fn decode(&mut self, bytes: BytesMut) -> Result<Option<Frame>, Error> {
        decode_frame(self, bytes)
    }
}

/// Decodes a frame.
///
/// This function is intentionally de-generified and outlined because it is very large.
fn decode_frame(decoder: &mut FrameDecoder, mut bytes: BytesMut) -> Result<Option<Frame>, Error> {
    let _span = tracing::trace_span!("FramedRead::decode_frame", offset = bytes.len());

    tracing::trace!("decoding frame from {}B", bytes.len());

    // Parse the head
    let head = frame::Head::parse(&bytes);

    if decoder.partial.is_some() && head.kind() != Kind::Continuation {
        proto_err!(conn: "expected CONTINUATION, got {:?}", head.kind());
        return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
    }

    let kind = head.kind();

    tracing::trace!(frame.kind = ?kind);

    macro_rules! header_block {
        ($frame:ident, $head:ident, $bytes:ident) => ({
            // Drop the frame header
            $bytes.advance(frame::HEADER_LEN);

            // Parse the header frame w/o parsing the payload
            let (mut frame, mut payload) = match frame::$frame::load($head, $bytes) {
                Ok(res) => res,
                Err(frame::Error::InvalidDependencyId) => {
                    proto_err!(stream: "invalid HEADERS dependency ID");
                    // A stream cannot depend on itself. An endpoint MUST
                    // treat this as a stream error (Section 5.4.2) of type
                    // `PROTOCOL_ERROR`.
                    return Err(Error::library_reset($head.stream_id(), Reason::PROTOCOL_ERROR));
                },
                Err(_e) => {
                    proto_err!(conn: "failed to load frame; err={:?}", _e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            };

            let is_end_headers = frame.is_end_headers();

            // Load the HPACK encoded headers
            match frame.load_hpack(&mut payload, decoder.max_header_list_size, &mut decoder.hpack) {
                Ok(_) => {},
                Err(frame::Error::Hpack(hpack::DecoderError::NeedMore(_))) if !is_end_headers => {},
                Err(frame::Error::MalformedMessage) => {
                    let id = $head.stream_id();
                    proto_err!(stream: "malformed header block; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                },
                Err(frame::Error::HeaderListWayTooLarge) => {
                    proto_err!(conn: "decoded header list size over abuse limit");
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "header_list_way_too_large",
                    ));
                },
                Err(_e) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", _e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }

            if is_end_headers {
                frame.into()
            } else {
                tracing::trace!("loaded partial header block");
                // Defer returning the frame
                decoder.partial = Some(Partial {
                    frame: Continuable::$frame(frame),
                    buf: payload,
                    continuation_frames_count: 0,
                });

                return Ok(None);
            }
        });
    }

    let frame = match kind {
        Kind::Settings => {
            let res = frame::Settings::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|_e| {
                proto_err!(conn: "failed to load SETTINGS frame; err={:?}", _e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Ping => {
            let res = frame::Ping::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|_e| {
                proto_err!(conn: "failed to load PING frame; err={:?}", _e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::WindowUpdate => {
            let res = frame::WindowUpdate::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|_e| {
                proto_err!(conn: "failed to load WINDOW_UPDATE frame; err={:?}", _e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Data => {
            bytes.advance(frame::HEADER_LEN);
            let res = frame::Data::load(head, bytes.freeze());

            // TODO: Should this always be connection level? Probably not...
            res.map_err(|_e| {
                proto_err!(conn: "failed to load DATA frame; err={:?}", _e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Headers => header_block!(Headers, head, bytes),
        Kind::Reset => {
            let res = frame::Reset::load(head, &bytes[frame::HEADER_LEN..]);
            res.map_err(|_e| {
                proto_err!(conn: "failed to load RESET frame; err={:?}", _e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::GoAway => {
            let res = frame::GoAway::load(head, &bytes[frame::HEADER_LEN..]);
            res.map_err(|_e| {
                proto_err!(conn: "failed to load GO_AWAY frame; err={:?}", _e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::PushPromise => header_block!(PushPromise, head, bytes),
        Kind::Priority => {
            if head.stream_id() == 0 {
                // Invalid stream identifier
                proto_err!(conn: "invalid stream ID 0");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }

            match frame::Priority::load(head, &bytes[frame::HEADER_LEN..]) {
                Ok(frame) => frame.into(),
                Err(frame::Error::InvalidDependencyId) => {
                    // A stream cannot depend on itself. An endpoint MUST
                    // treat this as a stream error (Section 5.4.2) of type
                    // `PROTOCOL_ERROR`.
                    let id = head.stream_id();
                    proto_err!(stream: "PRIORITY invalid dependency ID; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                }
                Err(_e) => {
                    proto_err!(conn: "failed to load PRIORITY frame; err={:?};", _e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }
        }
        Kind::Continuation => {
            let is_end_headers = (head.flag() & 0x4) == 0x4;

            let mut partial = match decoder.partial.take() {
                Some(partial) => partial,
                None => {
                    proto_err!(conn: "received unexpected CONTINUATION frame");
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            };

            // The stream identifiers must match
            if partial.frame.stream_id() != head.stream_id() {
                proto_err!(conn: "CONTINUATION frame stream ID does not match previous frame stream ID");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }

            // Check for CONTINUATION flood
            if is_end_headers {
                partial.continuation_frames_count = 0;
            } else {
                let cnt = partial.continuation_frames_count + 1;
                if cnt > decoder.max_continuation_frames {
                    tracing::debug!(
                        "too_many_continuations, max = {}",
                        decoder.max_continuation_frames
                    );
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "too_many_continuations",
                    ));
                } else {
                    partial.continuation_frames_count = cnt;
                }
            }

            // Extend the buf
            if partial.buf.is_empty() {
                partial.buf = bytes.split_off(frame::HEADER_LEN);
            } else {
                if partial.frame.is_over_size() {
                    // If there was left over bytes previously, they may be
                    // needed to continue decoding, even though we will
                    // be ignoring this frame. This is done to keep the HPACK
                    // decoder state up-to-date.
                    //
                    // Still, we need to be careful, because if a malicious
                    // attacker were to try to send a gigantic string, such
                    // that it fits over multiple header blocks, we could
                    // grow memory uncontrollably again, and that'd be a shame.
                    //
                    // Instead, we use a simple heuristic to determine if
                    // we should continue to ignore decoding, or to tell
                    // the attacker to go away.
                    if partial.buf.len() + bytes.len() > decoder.max_header_list_size {
                        proto_err!(conn: "CONTINUATION frame header block size over ignorable limit");
                        return Err(Error::library_go_away(Reason::COMPRESSION_ERROR));
                    }
                }
                partial.buf.extend_from_slice(&bytes[frame::HEADER_LEN..]);
            }

            match partial.frame.load_hpack(
                &mut partial.buf,
                decoder.max_header_list_size,
                &mut decoder.hpack,
            ) {
                Ok(_) => {}
                Err(frame::Error::Hpack(hpack::DecoderError::NeedMore(_))) if !is_end_headers => {}
                Err(frame::Error::MalformedMessage) => {
                    let id = head.stream_id();
                    proto_err!(stream: "malformed CONTINUATION frame; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                }
                Err(frame::Error::HeaderListWayTooLarge) => {
                    proto_err!(conn: "decoded CONTINUATION header list size over abuse limit");
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "header_list_way_too_large",
                    ));
                }
                Err(_e) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", _e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }

            if is_end_headers {
                partial.frame.into()
            } else {
                decoder.partial = Some(partial);
                return Ok(None);
            }
        }
        Kind::Unknown => {
            // Unknown frames are ignored
            return Ok(None);
        }
    };

    Ok(Some(frame))
}

impl<T> Stream for FramedRead<T>
where
    T: AsyncRead + Unpin,
{
    type Item = Result<Frame, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(self.poll_next_event(cx)) {
                Some(Ok(ReadEvent::DataHead(_))) => continue,
                Some(Ok(ReadEvent::Frame(frame))) => return Poll::Ready(Some(Ok(frame))),
                Some(Err(err)) => return Poll::Ready(Some(Err(err))),
                None => return Poll::Ready(None),
            }
        }
    }
}

fn map_err(err: io::Error) -> Error {
    if let io::ErrorKind::InvalidData = err.kind() {
        if let Some(custom) = err.get_ref() {
            if custom.is::<LengthDelimitedCodecError>() {
                return Error::library_go_away(Reason::FRAME_SIZE_ERROR);
            }
        }
    }
    err.into()
}

// ===== impl Continuable =====

impl Continuable {
    fn stream_id(&self) -> frame::StreamId {
        match *self {
            Continuable::Headers(ref h) => h.stream_id(),
            Continuable::PushPromise(ref p) => p.stream_id(),
        }
    }

    fn is_over_size(&self) -> bool {
        match *self {
            Continuable::Headers(ref h) => h.is_over_size(),
            Continuable::PushPromise(ref p) => p.is_over_size(),
        }
    }

    fn load_hpack(
        &mut self,
        src: &mut BytesMut,
        max_header_list_size: usize,
        decoder: &mut hpack::Decoder,
    ) -> Result<(), frame::Error> {
        match *self {
            Continuable::Headers(ref mut h) => h.load_hpack(src, max_header_list_size, decoder),
            Continuable::PushPromise(ref mut p) => p.load_hpack(src, max_header_list_size, decoder),
        }
    }
}

impl<T> From<Continuable> for Frame<T> {
    fn from(cont: Continuable) -> Self {
        match cont {
            Continuable::Headers(mut headers) => {
                headers.set_end_headers();
                headers.into()
            }
            Continuable::PushPromise(mut push) => {
                push.set_end_headers();
                push.into()
            }
        }
    }
}

/// DATA metadata available before the payload has been read completely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataHead {
    pub(crate) stream_id: frame::StreamId,
    pub(crate) flow_len: u32,
    pub(crate) payload_len: u32,
    pub(crate) end_stream: bool,
}

#[derive(Debug)]
// Keep the existing inline Frame transfer without a heap allocation per frame.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ReadEvent {
    DataHead(DataHead),
    Frame(Frame),
}

#[derive(Debug)]
enum DelimitedEvent {
    DataHead(DataHead),
    Frame(BytesMut),
}

#[derive(Debug)]
struct DataHeadCodec {
    inner: LengthDelimitedCodec,
    state: DataHeadState,
}

#[derive(Debug)]
enum DataHeadState {
    Disabled,
    Reading,
    // A complete frame may already be buffered when its head is reported.
    // Keep ownership of that allocation until the next decode, without copying.
    Reported(Option<BytesMut>),
}

impl DataHeadCodec {
    fn new(inner: LengthDelimitedCodec) -> Self {
        Self {
            inner,
            state: DataHeadState::Disabled,
        }
    }
}

impl Decoder for DataHeadCodec {
    type Item = DelimitedEvent;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let DataHeadState::Reported(frame) = &mut self.state {
            let frame = match frame.take() {
                Some(frame) => Some(frame),
                None => self.inner.decode(src).map_err(map_err)?,
            };
            if frame.is_some() {
                self.state = DataHeadState::Reading;
            }
            return Ok(frame.map(DelimitedEvent::Frame));
        }

        // Let the original decoder validate and retain the frame length first.
        // This preserves the max-frame-size setting across partial reads.
        let frame = self.inner.decode(src).map_err(map_err)?;
        if matches!(self.state, DataHeadState::Reading) {
            if let Some(head) = DataHead::parse(frame.as_deref().unwrap_or(src))? {
                self.state = DataHeadState::Reported(frame);
                return Ok(Some(DelimitedEvent::DataHead(head)));
            }
        }
        Ok(frame.map(DelimitedEvent::Frame))
    }
}

impl DataHead {
    fn parse(bytes: &[u8]) -> Result<Option<Self>, Error> {
        if bytes.len() < frame::HEADER_LEN {
            return Ok(None);
        }
        let head = frame::Head::parse(bytes);
        if head.kind() != Kind::Data {
            return Ok(None);
        }
        if head.stream_id().is_zero() {
            return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
        }

        // Padding, including its length byte, consumes flow-control credit but
        // is not application data (RFC 9113 §6.1 and §6.9.1).
        // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.1
        // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.1
        let flow_len = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        let payload_len = if head.flag() & 0x8 != 0 {
            if flow_len == 0 {
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }
            let Some(&padding) = bytes.get(frame::HEADER_LEN) else {
                return Ok(None);
            };
            flow_len
                .checked_sub(u32::from(padding) + 1)
                .ok_or_else(|| Error::library_go_away(Reason::PROTOCOL_ERROR))?
        } else {
            flow_len
        };

        Ok(Some(Self {
            stream_id: head.stream_id(),
            flow_len,
            payload_len,
            end_stream: head.flag() & 0x1 != 0,
        }))
    }
}

#[cfg(test)]
mod data_head_tests {
    use super::*;

    fn codec(enabled: bool) -> DataHeadCodec {
        let mut codec = DataHeadCodec::new(
            LengthDelimitedCodec::builder()
                .length_field_length(3)
                .length_adjustment(9)
                .num_skip(0)
                .max_frame_length(DEFAULT_MAX_FRAME_SIZE as usize)
                .new_codec(),
        );
        if enabled {
            codec.state = DataHeadState::Reading;
        }
        codec
    }

    fn wire_data(payload: &[u8], flags: u8) -> BytesMut {
        let mut bytes = BytesMut::new();
        frame::Head::new(Kind::Data, flags, 1.into()).encode(payload.len(), &mut bytes);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn data_heads_preserve_fragmented_and_buffered_frames() {
        for (payload, flags, header_len, payload_len) in [
            (&b""[..], 0, 9, 0),
            (&b"body"[..], 0, 9, 4),
            (&b"\x02\0\0"[..], 0x9, 10, 0),
            (&b"\x02body\0\0"[..], 0x9, 10, 4),
        ] {
            let wire = wire_data(payload, flags);
            for enabled in [false, true] {
                for split in 0..=wire.len() {
                    let mut codec = codec(enabled);
                    let mut src = BytesMut::from(&wire[..split]);
                    let mut heads = Vec::new();
                    let mut frames = Vec::new();
                    for (step, suffix) in [&wire[split..], &[][..]].into_iter().enumerate() {
                        while let Some(event) = codec.decode(&mut src).unwrap() {
                            match event {
                                DelimitedEvent::DataHead(head) => heads.push(head),
                                DelimitedEvent::Frame(frame) => {
                                    assert_eq!(heads.len(), usize::from(enabled));
                                    frames.push(frame);
                                }
                            }
                        }
                        if step == 0 {
                            assert_eq!(heads.len(), usize::from(enabled && split >= header_len));
                            assert_eq!(frames.len(), usize::from(split == wire.len()));
                        }
                        src.extend_from_slice(suffix);
                    }
                    assert!(src.is_empty());
                    assert_eq!(frames, [wire.clone()]);
                    assert_eq!(heads.len(), usize::from(enabled));
                    if enabled {
                        assert_eq!(
                            heads[0],
                            DataHead {
                                stream_id: 1.into(),
                                flow_len: payload.len() as u32,
                                payload_len,
                                end_stream: flags & 1 != 0,
                            }
                        );
                    }
                }
            }

            // An already buffered frame is moved, not copied, across the event.
            let mut codec = codec(true);
            let mut src = wire.clone();
            let ptr = src.as_ptr();
            assert!(matches!(
                codec.decode(&mut src).unwrap(),
                Some(DelimitedEvent::DataHead(_))
            ));
            let Some(DelimitedEvent::Frame(frame)) = codec.decode(&mut src).unwrap() else {
                panic!("missing DATA after its head");
            };
            assert_eq!(frame.as_ptr(), ptr);
            assert_eq!(frame, wire);
        }
    }

    #[test]
    fn data_heads_reject_invalid_headers_and_truncated_eof() {
        let mut zero_stream = wire_data(b"body", 0);
        zero_stream[8] = 0;
        for wire in [zero_stream, wire_data(b"", 0x8), wire_data(b"\x02\0", 0x8)] {
            assert!(matches!(
                codec(true).decode(&mut wire.clone()),
                Err(Error::GoAway(_, Reason::PROTOCOL_ERROR, _))
            ));
        }

        for flags in [0, 0x8] {
            let wire = wire_data(b"\x01body\0", flags);
            for enabled in [false, true] {
                for cut in 0..=wire.len() {
                    let mut codec = codec(enabled);
                    let mut src = wire.clone();
                    src.extend_from_slice(&wire[..cut]);
                    let mut frames = 0;
                    let err = loop {
                        match codec.decode_eof(&mut src) {
                            Ok(Some(DelimitedEvent::DataHead(_))) => (),
                            Ok(Some(DelimitedEvent::Frame(_))) => frames += 1,
                            Ok(None) => break None,
                            Err(err) => break Some(err),
                        }
                    };
                    assert_eq!(frames, 1 + usize::from(cut == wire.len()));
                    if cut == 0 || cut == wire.len() {
                        assert!(err.is_none());
                    } else {
                        assert!(matches!(err, Some(Error::Io(..))), "cut={cut}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn data_heads_preserve_size_admission_and_continuation_checks() {
        let wire = wire_data(&vec![0; 2 * DEFAULT_MAX_FRAME_SIZE as usize], 0);
        for enabled in [false, true] {
            for split in [3, frame::HEADER_LEN] {
                let mut codec = codec(enabled);
                codec
                    .inner
                    .set_max_frame_length(2 * DEFAULT_MAX_FRAME_SIZE as usize);
                let mut src = BytesMut::from(&wire[..split]);
                let event = codec.decode(&mut src).unwrap();
                assert_eq!(event.is_some(), enabled && split == frame::HEADER_LEN);
                codec
                    .inner
                    .set_max_frame_length(DEFAULT_MAX_FRAME_SIZE as usize);
                src.extend_from_slice(&wire[split..]);
                if enabled && split == 3 {
                    assert!(matches!(
                        codec.decode(&mut src).unwrap(),
                        Some(DelimitedEvent::DataHead(_))
                    ));
                }
                assert!(matches!(
                    codec.decode(&mut src).unwrap(),
                    Some(DelimitedEvent::Frame(frame)) if frame == wire
                ));
                src.extend_from_slice(&wire[..3]);
                assert!(matches!(
                    codec.decode(&mut src),
                    Err(Error::GoAway(_, Reason::FRAME_SIZE_ERROR, _))
                ));
            }
        }

        let mut wire = BytesMut::new();
        frame::Head::new(Kind::Headers, 0, 1.into()).encode(0, &mut wire);
        wire.extend_from_slice(&wire_data(b"body", 0)[..frame::HEADER_LEN]);
        let delimited = LengthDelimitedCodec::builder()
            .length_field_length(3)
            .length_adjustment(9)
            .num_skip(0)
            .new_read(&wire[..]);
        let mut read = FramedRead::new(delimited);
        read.enable_data_head_events();
        assert!(matches!(
            std::future::poll_fn(|cx| read.poll_next_event(cx)).await,
            Some(Err(Error::GoAway(_, Reason::PROTOCOL_ERROR, _)))
        ));
    }
}
