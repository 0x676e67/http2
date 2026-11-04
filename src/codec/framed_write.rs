use crate::codec::UserError;
use crate::codec::UserError::*;
use crate::frame::{self, Frame, FrameSize};
use crate::{hpack, tracing};

use bytes::{Buf, BufMut, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_write_buf;

use std::io::{self, Cursor, IoSlice};

// A macro to get around a method needing to borrow &mut self
macro_rules! limited_write_buf {
    ($self:expr) => {{
        let limit = $self.max_frame_size() + frame::HEADER_LEN;
        $self.buf.get_mut().limit(limit)
    }};
}

#[derive(Debug)]
pub struct FramedWrite<T, B> {
    /// Upstream `AsyncWrite`
    inner: T,
    final_flush_done: bool,

    encoder: Encoder<B>,
}

#[derive(Debug)]
struct Encoder<B> {
    /// HPACK encoder
    hpack: hpack::Encoder,

    /// Write buffer
    ///
    /// TODO: Should this be a ring buffer?
    buf: Cursor<BytesMut>,

    /// Next frame to encode
    next: Option<Next<B>>,

    /// Last data frame
    last_data_frame: Option<frame::Data<B>>,

    /// Max frame size, this is specified by the peer
    max_frame_size: FrameSize,

    /// Local cap on DATA payloads; `max_frame_size` still applies. Capped
    /// frames copy their small leading chunks and can start a write of their
    /// own.
    max_data_frame_size: Option<FrameSize>,

    /// Whether the upstream writer takes vectored writes
    vectored: bool,

    /// Chain payloads bigger than this.
    chain_threshold: usize,

    /// Min buffer required to attempt to write a frame
    min_buffer_capacity: usize,
}

#[derive(Debug)]
enum Next<B> {
    /// A chained DATA frame, and its start in `buf` if the bytes before it
    /// may go alone; see `split_before_data`
    Data(frame::Data<B>, Option<DataStart>),
    Continuation(frame::Continuation),
}

/// Where a chained capped DATA frame starts in `buf`, after unwritten bytes,
/// and the length of its first write.
///
/// Both stay fixed while those bytes are written: nothing is buffered behind
/// the frame, and a chained write takes `buf` first.
#[derive(Debug)]
struct DataStart {
    /// Offset of the frame head in `buf`
    at: usize,
    /// Length of the frame's first write
    first_write: usize,
}

/// Initialize the connection with this amount of write buffer.
///
/// The minimum MAX_FRAME_SIZE is 16kb, so always be able to send a HEADERS
/// frame that big.
const DEFAULT_BUFFER_CAPACITY: usize = 16 * 1_024;

/// Chain payloads bigger than this when vectored I/O is enabled. The remote
/// will never advertise a max frame size less than this (well, the spec says
/// the max frame size can't be less than 16kb, so not even close).
const CHAIN_THRESHOLD: usize = 256;

/// Chain payloads bigger than this when vectored I/O is **not** enabled.
/// A larger value in this scenario will reduce the number of small and
/// fragmented data being sent, and hereby improve the throughput.
const CHAIN_THRESHOLD_WITHOUT_VECTORED_IO: usize = 1024;

/// Max plaintext of a TLS record ([RFC 8446 §5.1]); TLS layers seal each
/// write into records of up to this size.
///
/// [RFC 8446 §5.1]: https://www.rfc-editor.org/rfc/rfc8446.html#section-5.1
const TLS_RECORD_SIZE: usize = 1 << 14;

/// Max slices `poll_write_buf` passes to one vectored write (tokio-util's
/// private `MAX_BUFS`).
const WRITE_SLICES: usize = 64;

/// Max payload slices one vectored write lists beside the write buffer.
const DATA_WRITE_SLICES: usize = WRITE_SLICES - 1;

// TODO: Make generic
impl<T, B> FramedWrite<T, B>
where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    pub fn new(inner: T) -> FramedWrite<T, B> {
        let vectored = inner.is_write_vectored();
        let chain_threshold = if vectored {
            CHAIN_THRESHOLD
        } else {
            CHAIN_THRESHOLD_WITHOUT_VECTORED_IO
        };
        FramedWrite {
            inner,
            final_flush_done: false,
            encoder: Encoder {
                hpack: hpack::Encoder::default(),
                buf: Cursor::new(BytesMut::with_capacity(DEFAULT_BUFFER_CAPACITY)),
                next: None,
                last_data_frame: None,
                max_frame_size: frame::DEFAULT_MAX_FRAME_SIZE,
                max_data_frame_size: None,
                vectored,
                chain_threshold,
                min_buffer_capacity: chain_threshold + frame::HEADER_LEN,
            },
        }
    }

    pub(super) fn buffer_client_magic(&mut self, client_magic: &[u8]) {
        debug_assert!(
            self.encoder.buf.position() == 0
                && self.encoder.buf.get_ref().is_empty()
                && self.encoder.next.is_none(),
            "client magic must be buffered before any frame bytes"
        );
        self.encoder.buf.get_mut().extend_from_slice(client_magic);
    }

    /// Returns `Ready` when `send` is able to accept a frame
    ///
    /// Calling this function may result in the current contents of the buffer
    /// to be flushed to `T`.
    pub fn poll_ready(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.encoder.has_capacity() {
            // Try flushing
            ready!(self.flush(cx))?;

            if !self.encoder.has_capacity() {
                return Poll::Pending;
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Returns whether a frame can be buffered without first flushing the
    /// underlying I/O object.
    pub(crate) fn has_capacity(&self) -> bool {
        self.encoder.has_capacity()
    }

    /// Buffer a frame.
    ///
    /// `poll_ready` or `poll_capacity` must be called first to ensure that a
    /// frame may be accepted.
    pub fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        self.encoder.buffer(item)
    }

    /// Writes all encoded bytes without flushing the upstream writer.
    ///
    /// This lets the client connection driver finish its connection-level
    /// initial write before it starts draining the stream frame queue. The
    /// regular flush still happens after all currently ready write items have
    /// been processed.
    pub(crate) fn poll_write_buffered(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        #[cfg(feature = "tracing")]
        let _span = tracing::trace_span!("FramedWrite::poll_write_buffered");

        loop {
            while !self.encoder.is_empty() {
                let n = match (self.encoder.split_before_data(), &mut self.encoder.next) {
                    // The bytes before a capped DATA frame go alone when that
                    // adds no TLS record
                    (Some(before), _) => {
                        tracing::trace!(frames_before_capped_data = true);
                        let mut buf = (&mut self.encoder.buf).take(before);
                        ready!(poll_write_buf(Pin::new(&mut self.inner), cx, &mut buf))?
                    }
                    (None, Some(Next::Data(frame, _))) => {
                        tracing::trace!(queued_data_frame = true);
                        let mut buf = (&mut self.encoder.buf).chain(frame.payload_mut());
                        ready!(poll_write_buf(Pin::new(&mut self.inner), cx, &mut buf))?
                    }
                    (None, _) => {
                        tracing::trace!(queued_data_frame = false);
                        ready!(poll_write_buf(
                            Pin::new(&mut self.inner),
                            cx,
                            &mut self.encoder.buf
                        ))?
                    }
                };
                if n == 0 {
                    // No progress is possible; retrying would busy-loop.
                    tracing::trace!("write returned zero, but non-zero bytes remaining");
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
            }

            match self.encoder.unset_frame() {
                ControlFlow::Continue => (),
                ControlFlow::Break => break,
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Flush buffered data to the wire
    pub fn flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        let _span = tracing::trace_span!("FramedWrite::flush");

        ready!(self.poll_write_buffered(cx))?;

        tracing::trace!("flushing buffer");
        // Flush the upstream
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }

    /// Close the codec
    pub fn shutdown(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.final_flush_done {
            ready!(self.flush(cx))?;
            self.final_flush_done = true;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    /// Returns `Ready` when `buffer` can accept a frame, writing queued bytes
    /// without flushing the upstream writer.
    ///
    /// Connection control frames use this so a pending upstream flush cannot
    /// hold them behind the DATA frames that `poll_ready` callers queue next.
    pub(crate) fn poll_capacity(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.encoder.has_capacity() {
            ready!(self.poll_write_buffered(cx))?;

            if !self.encoder.has_capacity() {
                return Poll::Pending;
            }
        }

        Poll::Ready(Ok(()))
    }
}

#[must_use]
enum ControlFlow {
    Continue,
    Break,
}

impl<B> Encoder<B>
where
    B: Buf,
{
    fn unset_frame(&mut self) -> ControlFlow {
        // Clear internal buffer
        self.buf.set_position(0);
        self.buf.get_mut().clear();

        // The data frame has been written, so unset it
        match self.next.take() {
            Some(Next::Data(frame, _)) => {
                self.last_data_frame = Some(frame);
                debug_assert!(self.is_empty());
                ControlFlow::Break
            }
            Some(Next::Continuation(frame)) => {
                // Buffer the continuation frame, then try to write again
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = frame.encode(&mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
                ControlFlow::Continue
            }
            None => ControlFlow::Break,
        }
    }

    fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        // Ensure that we have enough capacity to accept the write.
        assert!(self.has_capacity());
        let _span = tracing::trace_span!("FramedWrite::buffer", frame = ?item);

        tracing::debug!(frame = ?item, "send");

        match item {
            Frame::Data(mut v) => {
                // Ensure that the payload is not greater than the max frame.
                let len = v.payload().remaining();

                if len > self.max_frame_size() {
                    return Err(PayloadTooBig);
                }

                if len >= self.chain_threshold {
                    let head = v.head();
                    let at = self.buf.get_ref().len();

                    // Encode the frame head to the buffer
                    head.encode(len, self.buf.get_mut());

                    // Capped DATA can carry many chunks: copy the small
                    // leading ones, as smaller frames are copied
                    if self.max_data_frame_size.is_some() {
                        self.copy_small_chunks(&mut v);
                    }

                    // Copied whole, like a smaller frame
                    if !v.payload().has_remaining() {
                        self.last_data_frame = Some(v);
                        return Ok(());
                    }

                    if self.buf.get_ref().remaining() < self.chain_threshold {
                        let extra_bytes = self.chain_threshold - self.buf.remaining();
                        self.buf.get_mut().put(v.payload_mut().take(extra_bytes));
                    }

                    // Save the data frame
                    let start = self.data_start(at, &v);
                    self.next = Some(Next::Data(v, start));
                } else {
                    v.encode_chunk(self.buf.get_mut());

                    // The chunk has been fully encoded, so there is no need to
                    // keep it around
                    assert_eq!(v.payload().remaining(), 0, "chunk not fully encoded");

                    // Save off the last frame...
                    self.last_data_frame = Some(v);
                }
            }
            Frame::Headers(v) => {
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = v.encode(&mut self.hpack, &mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
            }
            Frame::PushPromise(v) => {
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = v.encode(&mut self.hpack, &mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
            }
            Frame::Settings(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded settings");
            }
            Frame::GoAway(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded go_away");
            }
            Frame::Ping(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded ping");
            }
            Frame::WindowUpdate(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded window_update");
            }

            Frame::Priority(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!("encoded priority; rem={:?}", self.buf.remaining());
            }
            Frame::Reset(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded reset");
            }
        }

        Ok(())
    }

    /// Copies the payload's leading chunks under the chain threshold while
    /// they fit the buffer, so a frame made only of such chunks does not end
    /// the write.
    fn copy_small_chunks(&mut self, frame: &mut frame::Data<B>) {
        let buf = self.buf.get_mut();

        loop {
            let chunk = frame.payload().chunk();
            let n = chunk.len();

            if n == 0 || n >= self.chain_threshold || n > buf.capacity() - buf.len() {
                return;
            }

            buf.extend_from_slice(chunk);
            frame.payload_mut().advance(n);
        }
    }

    /// Returns the start of a capped DATA frame chained at `at` after
    /// unwritten bytes, unless a vectored first write would list only part of
    /// its payload.
    fn data_start(&self, at: usize, frame: &frame::Data<B>) -> Option<DataStart> {
        if self.max_data_frame_size.is_none() || at <= self.buf.position() as usize {
            return None;
        }

        // The frame's first write takes its buffered bytes and, with vectored
        // I/O, the payload slices listed beside them
        let mut first_write = self.buf.get_ref().len().saturating_sub(at);
        if self.vectored {
            let mut slices = [IoSlice::new(&[]); DATA_WRITE_SLICES];
            let n = frame.payload().chunks_vectored(&mut slices);
            let listed = slices[..n].iter().map(|slice| slice.len()).sum::<usize>();

            // Payload left for a later write can cost a record once the
            // transport cuts the write, even on a record boundary
            if listed < frame.payload().remaining() {
                return None;
            }
            first_write += listed;
        }

        Some(DataStart { at, first_write })
    }

    /// Returns how many bytes are buffered before the chained capped DATA
    /// frame when writing them alone adds no TLS record, so the frame starts
    /// a record instead of straddling one needlessly.
    ///
    /// Records are counted as if each write is taken whole; a transport that
    /// takes part of the frame's first write can still seal one more record.
    fn split_before_data(&self) -> Option<usize> {
        let Some(Next::Data(_, Some(DataStart { at, first_write }))) = self.next else {
            return None;
        };
        let before = at
            .checked_sub(self.buf.position() as usize)
            .filter(|&before| before > 0)?;

        let records = |n: usize| n.div_ceil(TLS_RECORD_SIZE);
        (records(before) + records(first_write) == records(before + first_write)).then_some(before)
    }

    fn has_capacity(&self) -> bool {
        self.next.is_none()
            && (self.buf.get_ref().capacity() - self.buf.get_ref().len()
                >= self.min_buffer_capacity)
    }

    fn is_empty(&self) -> bool {
        match self.next {
            Some(Next::Data(ref frame, _)) => !frame.payload().has_remaining(),
            _ => !self.buf.has_remaining(),
        }
    }
}

impl<B> Encoder<B> {
    fn max_frame_size(&self) -> usize {
        self.max_frame_size as usize
    }
}

impl<T, B> FramedWrite<T, B> {
    /// Returns the max frame size that can be sent
    pub fn max_frame_size(&self) -> usize {
        self.encoder.max_frame_size()
    }

    /// Set the peer's max frame size.
    pub fn set_max_frame_size(&mut self, val: usize) {
        assert!(val <= frame::MAX_MAX_FRAME_SIZE as usize);
        self.encoder.max_frame_size = val as FrameSize;
    }

    /// Returns the max DATA payload size if a local cap was set.
    pub(crate) fn max_data_frame_size(&self) -> Option<usize> {
        self.encoder
            .max_data_frame_size
            .map(|max| max.min(self.encoder.max_frame_size) as usize)
    }

    /// Caps DATA payloads; the peer's max frame size still applies.
    pub(crate) fn set_max_data_frame_size(&mut self, val: usize) {
        self.encoder.max_data_frame_size =
            Some(val.clamp(1, frame::MAX_MAX_FRAME_SIZE as usize) as FrameSize);
    }

    /// Returns the max parts of a capped DATA frame coalesced from queued
    /// chunks, so one vectored write lists them all, or `None` if queued DATA
    /// is not coalesced, as plain writes would send each part alone.
    pub(crate) fn max_data_frame_parts(&self) -> Option<usize> {
        (self.encoder.max_data_frame_size.is_some() && self.encoder.vectored)
            .then_some(DATA_WRITE_SLICES)
    }

    /// Set the peer's header table size.
    pub fn set_header_table_size(&mut self, val: usize) {
        self.encoder.hpack.update_max_size(val);
    }

    /// Retrieve the last data frame that has been sent
    pub fn take_last_data_frame(&mut self) -> Option<frame::Data<B>> {
        self.encoder.last_data_frame.take()
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: AsyncRead + Unpin, B> AsyncRead for FramedWrite<T, B> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// We never project the Pin to `B`.
impl<T: Unpin, B> Unpin for FramedWrite<T, B> {}

#[cfg(feature = "unstable")]
mod unstable {
    use super::*;

    impl<T, B> FramedWrite<T, B> {
        pub fn get_ref(&self) -> &T {
            &self.inner
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Reason, StreamId};
    use bytes::Bytes;
    use std::collections::VecDeque;
    use std::task::Waker;

    /// Keeps the length of each write, taking at most `max` bytes per write.
    #[derive(Default)]
    struct Writes {
        lens: Vec<usize>,
        max: Option<usize>,
        /// Without vectored writes
        plain: bool,
    }

    impl Writes {
        fn take(&mut self, n: usize) -> Poll<io::Result<usize>> {
            let n = self.max.map_or(n, |max| n.min(max));
            self.lens.push(n);
            Poll::Ready(Ok(n))
        }
    }

    impl AsyncWrite for Writes {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.take(buf.len())
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            self.take(bufs.iter().map(|buf| buf.len()).sum())
        }

        fn is_write_vectored(&self) -> bool {
            !self.plain
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A payload listing all its chunks for vectored writes.
    struct Rope(VecDeque<Bytes>);

    impl Buf for Rope {
        fn remaining(&self) -> usize {
            self.0.iter().map(Bytes::len).sum()
        }

        fn chunk(&self) -> &[u8] {
            match self.0.front() {
                Some(chunk) => chunk,
                None => &[],
            }
        }

        fn advance(&mut self, mut cnt: usize) {
            while let Some(chunk) = self.0.front_mut() {
                if cnt < chunk.len() {
                    chunk.advance(cnt);
                    return;
                }
                cnt -= chunk.len();
                self.0.pop_front();
            }
        }

        fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
            for (slice, chunk) in dst.iter_mut().zip(&self.0) {
                *slice = IoSlice::new(chunk);
            }
            dst.len().min(self.0.len())
        }
    }

    /// A DATA frame of chunks of the given lengths.
    fn data(lens: &[usize]) -> Frame<Rope> {
        let chunks = lens.iter().map(|&len| Bytes::from(vec![0; len])).collect();
        frame::Data::new(StreamId::from(1), Rope(chunks)).into()
    }

    fn ping() -> Frame<Rope> {
        frame::Ping::new([0; 8]).into()
    }

    /// Buffers the frames, then writes everything out.
    fn send<const N: usize>(codec: &mut FramedWrite<Writes, Rope>, frames: [Frame<Rope>; N]) {
        for frame in frames {
            codec.buffer(frame).unwrap();
        }
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(codec.flush(&mut cx), Poll::Ready(Ok(()))));
    }

    #[test]
    fn capped_data_frames_copy_small_leading_chunks() {
        let mut codec = FramedWrite::new(Writes::default());

        // Without a cap, frames of 256 bytes or more end the write
        codec.buffer(data(&[100, 200])).unwrap();
        assert!(!codec.has_capacity());
        send(&mut codec, []);

        // With one, chunks under 256 bytes are copied while they fit, so
        // frames share a write until the buffer fills. The frame it cannot
        // hold whole is chained, and goes alone as it would straddle a record
        codec.set_max_data_frame_size(16_375);
        while codec.has_capacity() {
            codec.buffer(data(&[255, 255])).unwrap();
        }
        send(&mut codec, []);

        // A chunk of 256 bytes is chained
        codec.buffer(data(&[255, 256])).unwrap();
        assert!(!codec.has_capacity());
        send(&mut codec, []);

        assert_eq!(codec.get_mut().lens, [309, 31 * 519, 519, 520]);
    }

    #[test]
    fn capped_data_frames_start_a_write_adding_no_record() {
        // Without a cap, a chained frame shares the write of the frames before it
        let mut codec = FramedWrite::new(Writes::default());
        send(&mut codec, [ping(), data(&[16_375])]);

        // With one, those frames are written first when the frame would
        // otherwise straddle two TLS records, which adds no record
        codec.set_max_data_frame_size(16_375);
        for len in [16_375, 16_359, 16_358] {
            send(&mut codec, [ping(), data(&[len])]);
        }
        assert_eq!(
            codec.get_mut().lens,
            [16_401, 17, 16_384, 17, 16_368, 16_384]
        );

        // With a cap past one record, records are counted the same way: the
        // split adds no record at 32_759 bytes but would at 20_480
        codec.get_mut().lens.clear();
        codec.set_max_frame_size(32_768);
        codec.set_max_data_frame_size(32_768);
        send(&mut codec, [ping(), data(&[32_759])]);
        send(&mut codec, [ping(), data(&[20_480])]);
        assert_eq!(codec.get_mut().lens, [17, 32_768, 20_506]);

        // After a short write, the rest goes alone only while that still adds
        // no record
        codec.get_mut().max = Some(10);
        for (len, leading) in [(16_375, [10, 7, 10]), (16_359, [10, 10, 10])] {
            codec.get_mut().lens.clear();
            send(&mut codec, [ping(), data(&[len])]);

            let lens = &codec.get_mut().lens;
            assert_eq!(lens[..3], leading);
            assert_eq!(lens.iter().sum::<usize>(), 17 + 9 + len);
        }

        // Plain writes carry only the frame's buffered bytes first: they share
        // the write of the frames before it when they fit its last record, and
        // go alone when they would straddle one. GOAWAY frames grow the buffer
        // past a record here
        let go_away = |len| {
            let debug_data = Bytes::from(vec![0; len]);
            frame::GoAway::with_debug_data(StreamId::zero(), Reason::NO_ERROR, debug_data).into()
        };
        let mut codec = FramedWrite::new(Writes {
            plain: true,
            ..Writes::default()
        });
        codec.set_max_data_frame_size(16_375);
        send(&mut codec, [ping(), data(&[16_375])]);
        send(&mut codec, [go_away(24_541), ping(), data(&[16_375])]);
        send(&mut codec, [go_away(16_342), ping(), data(&[16_375])]);
        assert_eq!(
            codec.get_mut().lens,
            [1_024, 15_377, 24_584, 16_375, 16_376, 9, 16_375]
        );

        // A vectored write lists 63 payload slices beside the buffer, so the
        // frame starts a write with 63 slices but not with 64, which would
        // leave one for a later write
        let mut codec = FramedWrite::new(Writes::default());
        codec.set_max_data_frame_size(16_375);
        for last in [&[70][..], &[60, 10]] {
            let lens = [&[16_000][..], &[5; 61], last].concat();
            send(&mut codec, [ping(), data(&lens)]);
        }
        assert_eq!(codec.get_mut().lens, [17, 16_384, 16_391, 10]);
    }
}
