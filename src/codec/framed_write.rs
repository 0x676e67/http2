use crate::codec::UserError;
use crate::codec::UserError::*;
use crate::frame::{self, Frame, FrameSize};
use crate::{hpack, tracing};

use bytes::{Buf, BufMut, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_write_buf;

use std::io::{self, Cursor};

// A macro to get around a method needing to borrow &mut self
macro_rules! limited_write_buf {
    ($self:expr) => {{
        let limit = $self.max_header_frame_size() + frame::HEADER_LEN;
        $self.buf.get_mut().limit(limit)
    }};
}

#[derive(Debug)]
pub struct FramedWrite<T, B> {
    /// Upstream `AsyncWrite`
    inner: T,
    final_flush_done: bool,

    encoder: Encoder<B>,

    /// Whether `inner` returned bytes since the last `take_read_activity`.
    read_activity: bool,
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
    /// frames are always chained, share no write with other frames and copy
    /// their small leading chunks, or without vectored writes their whole
    /// payload up to `MAX_COPIED_DATA_FRAME_SIZE`.
    max_data_frame_size: Option<FrameSize>,

    /// Whether the upstream writer takes vectored writes
    vectored: bool,

    /// Local cap on HEADERS, PUSH_PROMISE and CONTINUATION payloads
    max_header_frame_size: Option<FrameSize>,

    /// Whether each frame takes a write of its own
    one_frame_per_write: OneFramePerWrite,

    /// Bytes of frames gathered for one write while DATA frames are coalesced
    max_write_buffer_size: usize,

    /// Chain payloads bigger than this.
    chain_threshold: usize,

    /// Min buffer required to attempt to write a frame
    min_buffer_capacity: usize,
}

/// When each frame takes a write of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OneFramePerWrite {
    Off,
    On,
    WaitingForInitialWrite,
}

#[derive(Debug)]
enum Next<B> {
    /// A chained DATA frame, and the offset of its head in `buf` when it goes
    /// alone; see `split_before_data`
    Data(frame::Data<B>, Option<usize>),
    Continuation(frame::Continuation),
}

/// Initialize the connection with this amount of write buffer.
///
/// The minimum MAX_FRAME_SIZE is 16kb, so always be able to send a HEADERS
/// frame that big.
const DEFAULT_BUFFER_CAPACITY: usize = 16 * 1_024;

/// Bytes of frames gathered for one write while DATA frames are coalesced:
/// four full TLS records of 2^14 bytes ([RFC 8446 §5.1]).
///
/// [RFC 8446 §5.1]: https://www.rfc-editor.org/rfc/rfc8446.html#section-5.1
const DEFAULT_MAX_WRITE_BUFFER_SIZE: usize = 64 * 1_024;

/// Returns the bytes the write buffer still takes, counted within its default
/// capacity, so a grown buffer takes no more than a default one.
fn buffer_room(buf: &BytesMut) -> usize {
    DEFAULT_BUFFER_CAPACITY.saturating_sub(buf.len())
}

/// Smallest cap on header frame payloads, so a HEADERS frame's priority
/// fields fit ([RFC 9113 §6.2]).
///
/// [RFC 9113 §6.2]: https://www.rfc-editor.org/rfc/rfc9113.html#section-6.2
const MIN_HEADER_FRAME_SIZE: usize = frame::StreamDependency::LEN;

/// Chain payloads bigger than this when vectored I/O is enabled. The remote
/// will never advertise a max frame size less than this (well, the spec says
/// the max frame size can't be less than 16kb, so not even close).
const CHAIN_THRESHOLD: usize = 256;

/// Chain payloads bigger than this when vectored I/O is **not** enabled.
/// A larger value in this scenario will reduce the number of small and
/// fragmented data being sent, and hereby improve the throughput.
const CHAIN_THRESHOLD_WITHOUT_VECTORED_IO: usize = 1024;

/// Max slices `poll_write_buf` passes to one vectored write (tokio-util's
/// private `MAX_BUFS`).
const WRITE_SLICES: usize = 64;

/// Max payload slices one vectored write lists beside the write buffer.
const DATA_WRITE_SLICES: usize = WRITE_SLICES - 1;

/// Without vectored writes, a DATA frame going alone with at most this much
/// payload, the default max frame size, is copied whole into the buffer so
/// it takes one write; `max_data_frame_parts` coalesces only up to it.
const MAX_COPIED_DATA_FRAME_SIZE: usize = frame::DEFAULT_MAX_FRAME_SIZE as usize;

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
                max_header_frame_size: None,
                one_frame_per_write: OneFramePerWrite::Off,
                max_write_buffer_size: DEFAULT_MAX_WRITE_BUFFER_SIZE,
                chain_threshold,
                min_buffer_capacity: chain_threshold + frame::HEADER_LEN,
            },
            read_activity: false,
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
                    // The bytes before a DATA frame going alone are written first
                    (Some(before), _) => {
                        tracing::trace!(frames_before_data = true);
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

    /// Returns whether the encoder still has capacity after buffering `len`
    /// more bytes.
    pub(crate) fn has_capacity_after(&self, len: usize) -> bool {
        self.encoder.has_capacity_after(len)
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
        if self.buf.get_ref().capacity() > self.max_idle_capacity() {
            *self.buf.get_mut() = BytesMut::with_capacity(DEFAULT_BUFFER_CAPACITY);
        }

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
        // Ensure that we have enough capacity to accept the write. A frame
        // may follow another before the write, as a preface PING precedes
        // DATA; with one frame per write only DATA may, and it goes alone
        assert!(self.has_room_after(0));
        debug_assert!(
            self.one_frame_per_write != OneFramePerWrite::On
                || !self.buf.has_remaining()
                || matches!(item, Frame::Data(_)),
            "only DATA may follow unwritten frames with one frame per write"
        );
        let _span = tracing::trace_span!("FramedWrite::buffer", frame = ?item);

        tracing::debug!(frame = ?item, "send");

        match item {
            Frame::Data(mut v) => {
                // Ensure that the payload is not greater than the max frame.
                let len = v.payload().remaining();

                if len > self.max_frame_size() {
                    return Err(PayloadTooBig);
                }

                // A capped frame, and any frame with one frame per write, is
                // always chained, so it shares no write with other frames
                let capped = self.max_data_frame_size.is_some();
                let alone = capped || self.one_frame_per_write == OneFramePerWrite::On;

                // Otherwise a frame that fits is copied, so frames of many
                // streams share one write
                let copied = self.coalesces() && frame::HEADER_LEN + len <= self.room();

                if !copied && (len >= self.chain_threshold || alone) {
                    let head = v.head();
                    let at = self.buf.get_ref().len();

                    // Encode the frame head to the buffer
                    head.encode(len, self.buf.get_mut());

                    if alone && !self.vectored && len <= MAX_COPIED_DATA_FRAME_SIZE {
                        // Without vectored writes, each chunk would take a
                        // write: copy them all, growing the buffer if needed
                        self.buf.get_mut().put(v.payload_mut());
                    } else {
                        // Capped DATA can carry many chunks: copy the small
                        // leading ones
                        if capped {
                            self.copy_small_chunks(&mut v);
                        }

                        if self.buf.get_ref().remaining() < self.chain_threshold {
                            let extra_bytes = self.chain_threshold - self.buf.remaining();
                            self.buf.get_mut().put(v.payload_mut().take(extra_bytes));
                        }
                    }

                    // Save the data frame, with where one going alone starts
                    self.next = Some(Next::Data(v, alone.then_some(at)));
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
                let mut continuation = v.encode(&mut self.hpack, &mut buf);

                // A header block goes out in one write
                if self.one_frame_per_write == OneFramePerWrite::On {
                    while let Some(frame) = continuation {
                        let mut buf = limited_write_buf!(self);
                        continuation = frame.encode(&mut buf);
                    }
                }

                if let Some(continuation) = continuation {
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
    /// they fit the buffer's room, so they go with the frame head instead of
    /// taking slices or writes of their own.
    fn copy_small_chunks(&mut self, frame: &mut frame::Data<B>) {
        let buf = self.buf.get_mut();

        loop {
            let chunk = frame.payload().chunk();
            let n = chunk.len();

            if n == 0 || n >= self.chain_threshold || n > buffer_room(buf) {
                return;
            }

            buf.extend_from_slice(chunk);
            frame.payload_mut().advance(n);
        }
    }

    /// Returns how many bytes are still buffered before a chained DATA frame
    /// that goes alone, so they are written first and the frame starts a write.
    fn split_before_data(&self) -> Option<usize> {
        let Some(Next::Data(_, Some(at))) = self.next else {
            return None;
        };
        at.checked_sub(self.buf.position() as usize)
            .filter(|&before| before > 0)
    }

    fn has_capacity(&self) -> bool {
        self.has_capacity_after(0)
    }

    fn is_empty(&self) -> bool {
        match self.next {
            // A chained payload is written after `buf`, which may hold the
            // whole of a frame that goes alone
            Some(Next::Data(ref frame, _)) => {
                !frame.payload().has_remaining() && !self.buf.has_remaining()
            }
            _ => !self.buf.has_remaining(),
        }
    }

    /// With one frame per write, a frame also waits for the bytes before it to be
    /// written.
    fn has_capacity_after(&self, len: usize) -> bool {
        !(self.one_frame_per_write == OneFramePerWrite::On && self.buf.has_remaining())
            && self.has_room_after(len)
    }

    /// A grown buffer takes no more bytes ahead of a frame than
    /// `write_buffer_size`, so a frame copied whole after them grows it at
    /// most once.
    fn has_room_after(&self, len: usize) -> bool {
        self.next.is_none() && self.room() >= self.min_buffer_capacity.saturating_add(len)
    }

    /// Whether DATA frames that fit are copied to share a write: neither a cap
    /// nor one frame per write, set or waiting for the initial write, applies.
    fn coalesces(&self) -> bool {
        self.max_data_frame_size.is_none() && self.one_frame_per_write == OneFramePerWrite::Off
    }

    /// Bytes of frames gathered for one write.
    fn write_buffer_size(&self) -> usize {
        if self.coalesces() {
            self.max_write_buffer_size
        } else {
            DEFAULT_BUFFER_CAPACITY
        }
    }

    /// Bytes the buffer still takes for this write.
    fn room(&self) -> usize {
        self.write_buffer_size()
            .saturating_sub(self.buf.get_ref().len())
    }

    /// A buffer grown past this is replaced by a default one once written. A
    /// header block or a frame copied whole adds up to a default buffer past
    /// `write_buffer_size`, and growth at most doubles that.
    fn max_idle_capacity(&self) -> usize {
        self.write_buffer_size()
            .saturating_add(DEFAULT_BUFFER_CAPACITY)
            .saturating_mul(2)
    }
}

impl<B> Encoder<B> {
    fn max_frame_size(&self) -> usize {
        self.max_frame_size as usize
    }

    fn max_header_frame_size(&self) -> usize {
        self.max_header_frame_size
            .map_or(self.max_frame_size, |max| max.min(self.max_frame_size)) as usize
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
    /// chunks, so one write takes them all, or `None` without a cap, or
    /// without vectored writes when a capped frame is too large to copy.
    pub(crate) fn max_data_frame_parts(&self) -> Option<usize> {
        let max = self.max_data_frame_size()?;
        (self.encoder.vectored || max <= MAX_COPIED_DATA_FRAME_SIZE).then_some(DATA_WRITE_SLICES)
    }

    /// Caps header block frame payloads; the peer's max frame size still
    /// applies.
    pub(crate) fn set_max_header_frame_size(&mut self, val: usize) {
        self.encoder.max_header_frame_size =
            Some(val.clamp(MIN_HEADER_FRAME_SIZE, frame::MAX_MAX_FRAME_SIZE as usize) as FrameSize);
    }

    /// Sets the bytes of frames gathered for one write while DATA frames are
    /// coalesced, at least the default buffer capacity.
    pub(crate) fn set_max_write_buffer_size(&mut self, val: usize) {
        self.encoder.max_write_buffer_size = val.max(DEFAULT_BUFFER_CAPACITY);
    }

    /// Gives each frame a write of its own once the client's initial
    /// connection write is out; see `start_one_frame_per_write`.
    pub(crate) fn set_one_frame_per_write(&mut self) {
        self.encoder.one_frame_per_write = OneFramePerWrite::WaitingForInitialWrite;
    }

    /// Starts writing each frame alone, if set.
    pub(crate) fn start_one_frame_per_write(&mut self) {
        if self.encoder.one_frame_per_write == OneFramePerWrite::WaitingForInitialWrite {
            self.encoder.one_frame_per_write = OneFramePerWrite::On;
        }
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

    /// Returns whether any bytes were read since the last call.
    pub(crate) fn take_read_activity(&mut self) -> bool {
        std::mem::take(&mut self.read_activity)
    }
}

impl<T: AsyncRead + Unpin, B> AsyncRead for FramedWrite<T, B> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let filled = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        if buf.filled().len() > filled {
            self.read_activity = true;
        }

        Poll::Ready(Ok(()))
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
    use crate::frame::{Reason, StreamDependency, StreamId};
    use bytes::Bytes;
    use std::collections::VecDeque;
    use std::io::IoSlice;
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

    /// A HEADERS frame with a field value of `len` bytes that HPACK barely
    /// compresses.
    fn headers(len: usize) -> frame::Headers {
        let value = (0..len)
            .map(|i| (b'!' + (i % 90) as u8) as char)
            .collect::<String>();
        let mut fields = http::HeaderMap::new();
        fields.insert("x-big", value.parse().unwrap());
        let uri = "https://example.com/".parse().unwrap();
        let pseudo = frame::Pseudo::request(http::Method::GET, uri, None);
        frame::Headers::new(StreamId::from(1), pseudo, fields)
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
    fn capped_data_frames_take_a_write_of_their_own() {
        // Without a cap, frames that fit are copied and share the write of the
        // frames around them
        let mut codec = FramedWrite::new(Writes::default());
        send(&mut codec, [ping(), data(&[100]), ping(), data(&[16_375])]);
        assert_eq!(codec.get_mut().lens, [16_527]);

        // With one, the frames before a DATA frame are written first and later
        // ones wait, also for small and empty frames
        codec.get_mut().lens.clear();
        codec.set_max_data_frame_size(16_375);
        for len in [100, 0, 16_375] {
            codec.buffer(ping()).unwrap();
            codec.buffer(data(&[len])).unwrap();
            assert!(!codec.has_capacity());
            send(&mut codec, []);
        }
        assert_eq!(codec.get_mut().lens, [17, 109, 17, 9, 17, 16_384]);

        // After a short write, the rest still goes alone
        codec.get_mut().lens.clear();
        codec.get_mut().max = Some(10);
        send(&mut codec, [ping(), data(&[16_375])]);
        let lens = &codec.get_mut().lens;
        assert_eq!(lens[..3], [10, 7, 10]);
        assert_eq!(lens.iter().sum::<usize>(), 17 + 9 + 16_375);

        // Plain writes copy an uncapped frame that fits. With a cap they split
        // as before, and the frame is copied whole, growing the buffer, so it
        // still takes one write
        let mut codec = FramedWrite::new(Writes {
            plain: true,
            ..Writes::default()
        });
        send(&mut codec, [data(&[16_375])]);
        codec.set_max_data_frame_size(16_375);
        send(&mut codec, [ping(), data(&[16_375])]);
        assert_eq!(codec.get_mut().lens, [16_384, 17, 16_384]);

        // The grown buffer takes no more bytes ahead of a frame than a
        // default one
        let debug_data = Bytes::from(vec![0; 15_335]);
        let go_away =
            frame::GoAway::with_debug_data(StreamId::zero(), Reason::NO_ERROR, debug_data);
        codec.buffer(go_away.into()).unwrap();
        assert!(!codec.has_capacity());

        // Chunks are coalesced only while capped frames, within the peer's
        // max frame size, are at most 16,384 bytes
        codec.set_max_data_frame_size(16_385);
        assert_eq!(codec.max_data_frame_parts(), Some(DATA_WRITE_SLICES));
        codec.set_max_frame_size(20_000);
        assert_eq!(codec.max_data_frame_parts(), None);
    }

    #[test]
    fn capped_data_frames_copy_small_leading_chunks() {
        // Chunks under 256 bytes are copied with the frame head while they
        // fit, so many of them take one write. Larger ones are listed beside
        // the buffer, 63 at most, so the rest takes another write
        let mut codec = FramedWrite::new(Writes::default());
        codec.set_max_data_frame_size(16_375);
        send(&mut codec, [data(&[255; 64])]);
        send(&mut codec, [data(&[256; 64])]);
        assert_eq!(codec.get_mut().lens, [16_329, 16_137, 256]);

        // Plain writes copy the chunks under 1 KiB of a frame over 16,384
        // bytes while they fit, which then take no write of their own
        let mut codec = FramedWrite::new(Writes {
            plain: true,
            ..Writes::default()
        });
        codec.set_max_frame_size(20_000);
        codec.set_max_data_frame_size(20_000);
        send(&mut codec, [data(&[1_023, 15_362])]);
        send(&mut codec, [data(&[1_024, 15_361])]);

        // A chunk that no longer fits the buffer stays in the payload instead
        // of growing the buffer
        let debug_data = Bytes::from(vec![0; 15_334]);
        let go_away =
            frame::GoAway::with_debug_data(StreamId::zero(), Reason::NO_ERROR, debug_data);
        send(&mut codec, [go_away.into(), data(&[1_000, 1_000, 16_000])]);

        // A frame of up to 16,384 bytes is copied whole. The buffer it grew
        // then copies no more chunks than a default one
        send(&mut codec, [data(&[1_023, 15_361])]);
        assert!(codec.encoder.buf.get_ref().capacity() > DEFAULT_BUFFER_CAPACITY);
        let debug_data = Bytes::from(vec![0; 15_334]);
        let go_away =
            frame::GoAway::with_debug_data(StreamId::zero(), Reason::NO_ERROR, debug_data);
        send(&mut codec, [go_away.into(), data(&[1_000, 1_000, 16_000])]);
        assert_eq!(
            codec.get_mut().lens,
            [
                1_032, 15_362, 1_024, 9, 15_361, 15_351, 1_009, 1_000, 16_000, 16_393, 15_351,
                1_009, 1_000, 16_000
            ]
        );
    }

    #[test]
    fn data_frames_share_a_write_up_to_max_write_buffer_size() {
        let mut cx = Context::from_waker(Waker::noop());

        // DATA frames that fit 64 KiB are copied and share a write; the next
        // one is chained after them and ends it. Sizes under 16 KiB are 16 KiB
        let mut codec = FramedWrite::new(Writes::default());
        for size in [None, Some(0), Some(usize::MAX)] {
            if let Some(size) = size {
                codec.set_max_write_buffer_size(size);
            }
            for _ in 0..10 {
                assert!(codec.poll_ready(&mut cx).is_ready());
                codec.buffer(data(&[8_000])).unwrap();
            }
            send(&mut codec, []);
        }
        assert_eq!(
            codec.get_mut().lens,
            [72_081, 8_009, 24_027, 24_027, 24_027, 8_009, 80_090]
        );

        // With one frame per write, frames are not coalesced, also before it
        // starts
        let mut codec = FramedWrite::new(Writes::default());
        codec.set_one_frame_per_write();
        codec.buffer(data(&[8_000])).unwrap();
        assert!(!codec.has_capacity());
    }

    #[test]
    fn one_frame_per_write_gives_each_frame_a_write() {
        let mut cx = Context::from_waker(Waker::noop());

        // Frames share a write until one frame per write starts, as the
        // client's initial write does
        let mut codec = FramedWrite::new(Writes::default());
        codec.set_one_frame_per_write();
        codec.buffer(ping()).unwrap();
        assert!(codec.has_capacity());
        send(&mut codec, [ping()]);

        // Then each frame goes alone, and a header block in one write with
        // its CONTINUATION frames, which the cap splits. The buffer the block
        // grew is released once written
        codec.start_one_frame_per_write();
        codec.set_max_header_frame_size(16_374);
        for frame in [ping(), headers(200_000).into(), ping()] {
            assert!(codec.poll_ready(&mut cx).is_ready());
            codec.buffer(frame).unwrap();
            assert!(!codec.has_capacity());
        }
        send(&mut codec, []);
        assert!(codec.encoder.buf.get_ref().capacity() <= codec.encoder.max_idle_capacity());

        // A frame can still follow another before the write, as a preface
        // PING precedes DATA; the DATA frame then starts its own write, also
        // a small one without a cap
        send(&mut codec, [ping(), data(&[100])]);
        codec.set_max_data_frame_size(16_375);
        send(&mut codec, [ping(), data(&[16_375])]);

        let lens = &codec.get_mut().lens;
        assert_eq!(lens[..2], [34, 17]);
        assert!(lens[2] > 16_383 + frame::HEADER_LEN);
        assert_eq!(lens[3..], [17, 17, 109, 17, 16_384]);
    }

    #[test]
    fn max_header_frame_size_bounds_header_frames() {
        // Each header frame takes a write here, so the first write is the
        // HEADERS frame: the cap applies within the peer's max frame size,
        // and one under 5 still fits the priority fields
        for (cap, len, priority) in [
            (16_374, 16_374, true),
            (20_000, 16_384, false),
            (0, 5, false),
            (4, 5, true),
        ] {
            let mut block = headers(20_000);
            if priority {
                block.set_stream_dependency(StreamDependency::new(StreamId::zero(), 255, true));
            }
            let mut codec = FramedWrite::new(Writes::default());
            codec.set_max_header_frame_size(cap);
            send(&mut codec, [block.into()]);
            assert_eq!(codec.get_mut().lens[0], frame::HEADER_LEN + len);
        }
    }
}
