use super::store::Resolve;
use super::*;

use crate::frame::Reason;

use crate::codec::UserError;
use crate::codec::UserError::*;

use crate::tracing;

use bytes::buf::Take;
use smallvec::SmallVec;
use std::{
    cmp::{self, Ordering},
    fmt, io, mem,
    task::Waker,
};

/// # Warning
///
/// Queued streams are ordered by stream ID, as we need to ensure that
/// lower-numbered streams are sent headers before higher-numbered ones.
/// This is because "idle" stream IDs – those which have been initiated but
/// have yet to receive frames – will be implicitly closed on receipt of a
/// frame on a higher stream ID. If these queues was not ordered by stream
/// IDs, some mechanism would be necessary to ensure that the lowest-numbered]
/// idle stream is opened first.
#[derive(Debug)]
pub(super) struct Prioritize {
    /// Queue of streams waiting for socket capacity to send a frame.
    pending_send: store::Queue<stream::NextSend>,

    /// Queue of streams waiting for window capacity to produce data.
    pending_capacity: store::Queue<stream::NextSendCapacity>,

    /// Streams waiting for capacity due to max concurrency
    ///
    /// The `SendRequest` handle is `Clone`. This enables initiating requests
    /// from many tasks. However, offering this capability while supporting
    /// backpressure at some level is tricky. If there are many `SendRequest`
    /// handles and a single stream becomes available, which handle gets
    /// assigned that stream? Maybe that handle is no longer ready to send a
    /// request.
    ///
    /// The strategy used is to allow each `SendRequest` handle one buffered
    /// request. A `SendRequest` handle is ready to send a request if it has no
    /// associated buffered requests. This is the same strategy as `mpsc` in the
    /// futures library.
    pending_open: store::Queue<stream::NextOpen>,

    /// Connection level flow control governing sent data
    flow: FlowControl,

    /// Stream ID of the last stream opened.
    last_opened_id: StreamId,

    /// What `DATA` frame is currently being sent in the codec.
    in_flight_data_frame: InFlightData,

    /// The maximum amount of bytes a stream should buffer.
    max_buffer_size: usize,
}

#[derive(Debug, Eq, PartialEq)]
enum InFlightData {
    /// There is no `DATA` frame in flight.
    Nothing,
    /// There is a `DATA` frame in flight belonging to the given stream.
    DataFrame(store::Key),
    /// There was a `DATA` frame, but the stream's queue was since cleared.
    Drop,
}

/// Max payload parts of a coalesced DATA frame.
///
/// Plus the frame head, contiguous parts fit the 64 slices that
/// `poll_write_buf` passes to one vectored write, and tiny chunks cannot
/// build a long part list.
const MAX_DATA_FRAME_PARTS: usize = 63;

pub(crate) struct Prioritized<B> {
    // The buffer, then any queued chunks coalesced after it. Only the last
    // part can be partly taken.
    parts: SmallVec<[Take<B>; 1]>,

    // Whether the chunk of the last part ends the stream
    end_of_stream: bool,

    // The stream that this is associated with
    stream: store::Key,
}

// ===== impl Prioritize =====

impl Prioritize {
    pub fn new(config: &Config) -> Prioritize {
        let mut flow = FlowControl::new();

        flow.inc_window(config.remote_init_window_sz)
            .expect("invalid initial window size");

        // TODO: proper error handling
        let _res = flow.assign_capacity(config.remote_init_window_sz);
        debug_assert!(_res.is_ok());

        tracing::trace!("Prioritize::new; flow={:?}", flow);

        Prioritize {
            pending_send: store::Queue::new(),
            pending_capacity: store::Queue::new(),
            pending_open: store::Queue::new(),
            flow,
            last_opened_id: StreamId::ZERO,
            in_flight_data_frame: InFlightData::Nothing,
            max_buffer_size: config.local_max_buffer_size,
        }
    }

    pub(crate) fn max_buffer_size(&self) -> usize {
        self.max_buffer_size
    }

    /// Queue a frame to be sent to the remote
    pub fn queue_frame<B>(
        &mut self,
        frame: Frame<B>,
        buffer: &mut Buffer<Frame<B>>,
        stream: &mut store::Ptr,
        task: &mut Option<Waker>,
    ) {
        let _span = tracing::trace_span!("Prioritize::queue_frame", ?stream.id);
        // Queue the frame in the buffer
        stream.pending_send.push_back(buffer, frame);
        self.schedule_send(stream, task);
    }

    pub fn schedule_send(&mut self, stream: &mut store::Ptr, task: &mut Option<Waker>) {
        // If the stream is waiting to be opened, nothing more to do.
        if stream.is_send_ready() {
            tracing::trace!(?stream.id, "schedule_send");
            // Queue the stream
            self.pending_send.push(stream);

            // Notify the connection.
            if let Some(task) = task.take() {
                task.wake();
            }
        }
    }

    pub fn queue_open(&mut self, stream: &mut store::Ptr) {
        self.pending_open.push(stream);
    }

    /// Send a data frame
    pub fn send_data<B>(
        &mut self,
        frame: frame::Data<B>,
        buffer: &mut Buffer<Frame<B>>,
        stream: &mut store::Ptr,
        counts: &mut Counts,
        task: &mut Option<Waker>,
    ) -> Result<(), UserError>
    where
        B: Buf,
    {
        let sz = frame.payload().remaining();

        if sz > MAX_WINDOW_SIZE as usize {
            return Err(UserError::PayloadTooBig);
        }

        let sz = sz as WindowSize;

        if !stream.state.is_send_streaming() {
            if stream.state.is_closed() {
                return Err(InactiveStreamId);
            } else {
                return Err(UnexpectedFrameType);
            }
        }

        // Update the buffered data counter
        stream.buffered_send_data += sz as usize;

        let _span =
            tracing::trace_span!("send_data", sz, requested = stream.requested_send_capacity);
        tracing::trace!(buffered = stream.buffered_send_data);

        // Implicitly request more send capacity if not enough has been
        // requested yet.
        if (stream.requested_send_capacity as usize) < stream.buffered_send_data {
            // Update the target requested capacity
            stream.requested_send_capacity =
                cmp::min(stream.buffered_send_data, WindowSize::MAX as usize) as WindowSize;

            // `try_assign_capacity` will queue the stream to `pending_capacity` if the capcaity
            // cannot be assigned at the time it is called.
            self.try_assign_capacity(stream);
        }

        if frame.is_end_stream() {
            stream.state.send_close();
            self.reserve_capacity(0, stream, counts);
        }

        tracing::trace!(
            available = %stream.send_flow.available(),
            buffered = stream.buffered_send_data,
        );

        // The `stream.buffered_send_data == 0` check is here so that, if a zero
        // length data frame is queued to the front (there is no previously
        // queued data), it gets sent out immediately even if there is no
        // available send window.
        //
        // Sending out zero length data frames can be done to signal
        // end-of-stream.
        //
        if stream.send_flow.available() > 0 || stream.buffered_send_data == 0 {
            // The stream currently has capacity to send the data frame, so
            // queue it up and notify the connection task.
            self.queue_frame(frame.into(), buffer, stream, task);
        } else {
            // The stream has no capacity to send the frame now, save it but
            // don't notify the connection task. Once additional capacity
            // becomes available, the frame will be flushed.
            stream.pending_send.push_back(buffer, frame.into());
        }

        Ok(())
    }

    /// Request capacity to send data
    pub fn reserve_capacity(
        &mut self,
        capacity: WindowSize,
        stream: &mut store::Ptr,
        counts: &mut Counts,
    ) {
        let _span = tracing::trace_span!(
            "reserve_capacity",
            ?stream.id,
            requested = capacity,
            effective = (capacity as usize) + stream.buffered_send_data,
            curr = stream.requested_send_capacity
        );

        // Actual capacity is `capacity` + the current amount of buffered data.
        // If it were less, then we could never send out the buffered data.
        let capacity = (capacity as usize) + stream.buffered_send_data;

        match capacity.cmp(&(stream.requested_send_capacity as usize)) {
            Ordering::Equal => {
                // Nothing to do
            }
            Ordering::Less => {
                // Update the target requested capacity
                stream.requested_send_capacity = capacity as WindowSize;

                // Currently available capacity assigned to the stream
                let available = stream.send_flow.available().as_size();

                // If the stream has more assigned capacity than requested, reclaim
                // some for the connection
                if available as usize > capacity {
                    let diff = available - capacity as WindowSize;

                    // TODO: proper error handling
                    let _res = stream.send_flow.claim_capacity(diff);
                    debug_assert!(_res.is_ok());

                    self.assign_connection_capacity(diff, stream, counts);
                }
            }
            Ordering::Greater => {
                // If trying to *add* capacity, but the stream send side is closed,
                // there's nothing to be done.
                if stream.state.is_send_closed() {
                    return;
                }

                // Update the target requested capacity
                stream.requested_send_capacity =
                    cmp::min(capacity, WindowSize::MAX as usize) as WindowSize;

                // Try to assign additional capacity to the stream. If none is
                // currently available, the stream will be queued to receive some
                // when more becomes available.
                self.try_assign_capacity(stream);
            }
        }
    }

    pub fn recv_stream_window_update(
        &mut self,
        inc: WindowSize,
        stream: &mut store::Ptr,
    ) -> Result<(), Reason> {
        let _span = tracing::trace_span!(
            "recv_stream_window_update",
            ?stream.id,
            ?stream.state,
            inc,
            flow = ?stream.send_flow
        );

        if stream.state.is_send_closed() && stream.buffered_send_data == 0 {
            // We can't send any data, so don't bother doing anything else.
            return Ok(());
        }

        // Update the stream level flow control.
        stream.send_flow.inc_window(inc)?;

        // If the stream is waiting on additional capacity, then this will
        // assign it (if available on the connection) and notify the producer
        self.try_assign_capacity(stream);

        Ok(())
    }

    pub fn recv_connection_window_update(
        &mut self,
        inc: WindowSize,
        store: &mut Store,
        counts: &mut Counts,
    ) -> Result<(), Reason> {
        // Update the connection's window
        self.flow.inc_window(inc)?;

        self.assign_connection_capacity(inc, store, counts);
        Ok(())
    }

    /// Reclaim all capacity assigned to the stream and re-assign it to the
    /// connection
    pub fn reclaim_all_capacity(&mut self, stream: &mut store::Ptr, counts: &mut Counts) {
        let available = stream.send_flow.available().as_size();
        if available > 0 {
            // TODO: proper error handling
            let _res = stream.send_flow.claim_capacity(available);
            debug_assert!(_res.is_ok());
            // Re-assign all capacity to the connection
            self.assign_connection_capacity(available, stream, counts);
        }
    }

    /// Reclaim just reserved capacity, not buffered capacity, and re-assign
    /// it to the connection
    pub fn reclaim_reserved_capacity(&mut self, stream: &mut store::Ptr, counts: &mut Counts) {
        // only reclaim reserved capacity that isn't already buffered
        if stream.send_flow.available().as_size() as usize > stream.buffered_send_data {
            let reserved =
                stream.send_flow.available().as_size() - stream.buffered_send_data as WindowSize;

            // Panic safety: due to how `reserved` is computed it can't be greater
            // than what's available.
            stream
                .send_flow
                .claim_capacity(reserved)
                .expect("window size should be greater than reserved");

            self.assign_connection_capacity(reserved, stream, counts);
        }
    }

    pub fn clear_pending_capacity(&mut self, store: &mut Store, counts: &mut Counts) {
        let _span = tracing::trace_span!("clear_pending_capacity");
        while let Some(stream) = self.pending_capacity.pop(store) {
            counts.transition(stream, |_, _stream| {
                tracing::trace!(?_stream.id, "clear_pending_capacity");
            })
        }
    }

    pub fn assign_connection_capacity<R>(
        &mut self,
        inc: WindowSize,
        store: &mut R,
        counts: &mut Counts,
    ) where
        R: Resolve,
    {
        let _span = tracing::trace_span!("assign_connection_capacity", inc);

        // TODO: proper error handling
        let _res = self.flow.assign_capacity(inc);
        debug_assert!(_res.is_ok());

        let held_key = store.held_key();

        // Assign newly acquired capacity to streams pending capacity.
        while self.flow.available() > 0 {
            let stream = match self.pending_capacity.pop(store) {
                Some(stream) => stream,
                None => return,
            };

            // Streams pending capacity may have been reset before capacity
            // became available. In that case, the stream won't want any
            // capacity, so evict it. If this queue was all that kept it, free
            // it; it was unlinked when it closed, so this is safe inside
            // `Store::for_each`. The caller transitions its own stream.
            if !(stream.state.is_send_streaming() || stream.buffered_send_data > 0) {
                if held_key != Some(stream.key()) && stream.is_released() {
                    counts.transition_after(stream, false);
                }
                continue;
            }

            counts.transition(stream, |_, stream| {
                // Try to assign capacity to the stream. This will also re-queue the
                // stream if there isn't enough connection level capacity to fulfill
                // the capacity request.
                self.try_assign_capacity(stream);
            })
        }
    }

    /// Request capacity to send data
    fn try_assign_capacity(&mut self, stream: &mut store::Ptr) {
        // Streams over the max concurrent count should not have capacity assign to avoid starving the connection
        // capacity for open streams
        if stream.is_pending_open {
            return;
        }

        let total_requested = stream.requested_send_capacity;

        // Total requested should never go below actual assigned
        // (Note: the window size can go lower than assigned)
        debug_assert!(stream.send_flow.available() <= total_requested as usize);

        // The amount of additional capacity that the stream requests.
        // Don't assign more than the window has available!
        let additional = cmp::min(
            total_requested - stream.send_flow.available().as_size(),
            // Can't assign more than what is available
            stream.send_flow.window_size() - stream.send_flow.available().as_size(),
        );
        let _span = tracing::trace_span!("try_assign_capacity", ?stream.id);
        tracing::trace!(
            requested = total_requested,
            additional,
            buffered = stream.buffered_send_data,
            window = stream.send_flow.window_size(),
            conn = %self.flow.available()
        );

        if additional == 0 {
            // Nothing more to do
            return;
        }

        // The stream may have been reset or closed since capacity was requested.
        if !stream.state.is_send_streaming() && stream.buffered_send_data == 0 {
            return;
        }

        // The amount of currently available capacity on the connection
        let conn_available = self.flow.available().as_size();

        // First check if capacity is immediately available
        if conn_available > 0 {
            // The amount of capacity to assign to the stream
            // TODO: Should prioritization factor into this?
            let assign = cmp::min(conn_available, additional);

            tracing::trace!(capacity = assign, "assigning");

            // Assign the capacity to the stream
            stream.assign_capacity(assign, self.max_buffer_size);

            // Claim the capacity from the connection
            // TODO: proper error handling
            let _res = self.flow.claim_capacity(assign);
            debug_assert!(_res.is_ok());
        }

        tracing::trace!(
            available = %stream.send_flow.available(),
            requested = stream.requested_send_capacity,
            buffered = stream.buffered_send_data,
            has_unavailable = %stream.send_flow.has_unavailable()
        );

        if stream.send_flow.available() < stream.requested_send_capacity as usize
            && stream.send_flow.has_unavailable()
        {
            // The stream requires additional capacity and the stream's
            // window has available capacity, but the connection window
            // does not.
            //
            // In this case, the stream needs to be queued up for when the
            // connection has more capacity.
            self.pending_capacity.push(stream);
        }

        // If data is buffered and the stream is send ready, then
        // schedule the stream for execution
        if stream.buffered_send_data > 0 && stream.is_send_ready() {
            // TODO: This assertion isn't *exactly* correct. There can still be
            // buffered send data while the stream's pending send queue is
            // empty. This can happen when a large data frame is in the process
            // of being **partially** sent. Once the window has been sent, the
            // data frame will be returned to the prioritization layer to be
            // re-scheduled.
            //
            // That said, it would be nice to figure out how to make this
            // assertion correctly.
            //
            // debug_assert!(!stream.pending_send.is_empty());

            self.pending_send.push(stream);
        }
    }

    pub fn buffer_pending<T, B>(
        &mut self,
        buffer: &mut Buffer<Frame<B>>,
        store: &mut Store,
        counts: &mut Counts,
        recv: &mut Recv,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> io::Result<BufferStatus>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
    {
        // Reclaim any frame that has previously been written
        self.reclaim_frame(buffer, store, dst);

        // The max DATA frame length. A local cap also coalesces queued DATA,
        // but only on vectored transports: other writes send each part alone.
        let data_cap = dst.max_send_data_frame_size();
        let max_frame_len = data_cap.unwrap_or_else(|| dst.max_send_frame_size());
        let coalesce = data_cap.is_some() && dst.is_write_vectored();

        tracing::trace!("buffer_pending");

        loop {
            if !dst.has_send_capacity() {
                return Ok(BufferStatus::CodecFull);
            }

            while let Some(mut stream) = self.pending_open.pop_if(store, |stream| {
                stream.initial_window == Some(stream::InitialWindow::Pending)
                    && (stream.state.is_reset() || stream.state.is_scheduled_reset())
            }) {
                let is_pending_reset = stream.is_pending_reset_expiration();
                self.discard_unopened_request(buffer, &mut stream, counts);
                counts.transition_after(stream, is_pending_reset);
            }

            if let Some(mut stream) = self.pop_pending_open(store, counts) {
                self.pending_send.push_front(&mut stream);
                self.try_assign_capacity(&mut stream);
            }

            match self.pop_frame(buffer, store, max_frame_len, coalesce, counts, recv)? {
                Some(frame) => {
                    tracing::trace!(?frame, "writing");

                    debug_assert_eq!(self.in_flight_data_frame, InFlightData::Nothing);
                    if let Frame::Data(ref frame) = frame {
                        self.in_flight_data_frame = InFlightData::DataFrame(frame.payload().stream);
                    }
                    dst.buffer(frame).expect("invalid frame");

                    // Small DATA frames can be fully encoded by `buffer`,
                    // which records completion in a single codec slot. Reclaim
                    // before accepting another frame so that slot is not
                    // overwritten.
                    self.reclaim_frame(buffer, store, dst);
                }
                None => {
                    return Ok(BufferStatus::Complete);
                }
            }
        }
    }

    pub fn reclaim_written_frame<T, B>(
        &mut self,
        buffer: &mut Buffer<Frame<B>>,
        store: &mut Store,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> bool
    where
        B: Buf,
    {
        self.reclaim_frame(buffer, store, dst)
    }

    /// Tries to reclaim a pending data frame from the codec.
    ///
    /// Returns true if a frame was reclaimed.
    ///
    /// When a data frame is written to the codec, it may not be written in its
    /// entirety (large chunks are split up into potentially many data frames).
    /// In this case, the stream needs to be reprioritized.
    fn reclaim_frame<T, B>(
        &mut self,
        buffer: &mut Buffer<Frame<B>>,
        store: &mut Store,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> bool
    where
        B: Buf,
    {
        let _span = tracing::trace_span!("try_reclaim_frame");

        // First check if there are any data chunks to take back
        if let Some(frame) = dst.take_last_data_frame() {
            self.reclaim_frame_inner(buffer, store, frame)
        } else {
            false
        }
    }

    fn reclaim_frame_inner<B>(
        &mut self,
        buffer: &mut Buffer<Frame<B>>,
        store: &mut Store,
        mut frame: frame::Data<Prioritized<B>>,
    ) -> bool
    where
        B: Buf,
    {
        tracing::trace!(
            ?frame,
            sz = frame
                .payload()
                .parts
                .last()
                .map_or(0, |part| part.get_ref().remaining()),
            "reclaimed"
        );

        let key = frame.payload().stream;

        match mem::replace(&mut self.in_flight_data_frame, InFlightData::Nothing) {
            InFlightData::Nothing => panic!("wasn't expecting a frame to reclaim"),
            InFlightData::Drop => {
                tracing::trace!("not reclaiming frame for cancelled stream");
                return false;
            }
            InFlightData::DataFrame(k) => {
                debug_assert_eq!(k, key);
            }
        }

        // TODO: Ensure fully written
        // Earlier parts were taken whole, so only the last can have bytes left
        let Some(last) = frame.payload_mut().parts.pop() else {
            return false;
        };
        let eos = frame.payload().end_of_stream;
        let mut frame = frame.map(|_| last.into_inner());

        if frame.payload().has_remaining() {
            let mut stream = store.resolve(key);

            if eos {
                frame.set_end_stream(true);
            }

            self.push_back_frame(frame.into(), buffer, &mut stream);

            return true;
        }

        false
    }

    /// Push the frame to the front of the stream's deque, scheduling the
    /// stream if needed.
    fn push_back_frame<B>(
        &mut self,
        frame: Frame<B>,
        buffer: &mut Buffer<Frame<B>>,
        stream: &mut store::Ptr,
    ) {
        // Push the frame to the front of the stream's deque
        stream.pending_send.push_front(buffer, frame);

        // If needed, schedule the sender
        if stream.send_flow.available() > 0 {
            debug_assert!(!stream.pending_send.is_empty());
            self.pending_send.push(stream);
        }
    }

    pub fn clear_queue<B>(&mut self, buffer: &mut Buffer<Frame<B>>, stream: &mut store::Ptr) {
        let _span = tracing::trace_span!("clear_queue", ?stream.id);

        // TODO: make this more efficient?
        while let Some(_frame) = stream.pending_send.pop_front(buffer) {
            tracing::trace!(?_frame, "dropping");
        }

        stream.buffered_send_data = 0;
        stream.requested_send_capacity = 0;
        if let InFlightData::DataFrame(key) = self.in_flight_data_frame {
            if stream.key() == key {
                // This stream could get cleaned up now - don't allow the buffered frame to get reclaimed.
                self.in_flight_data_frame = InFlightData::Drop;
            }
        }
    }

    pub fn clear_pending_send(&mut self, store: &mut Store, counts: &mut Counts) {
        while let Some(mut stream) = self.pending_send.pop(store) {
            let is_pending_reset = stream.is_pending_reset_expiration();
            if let Some(reason) = stream.state.get_scheduled_reset() {
                stream.set_reset(reason, Initiator::Library);
            }
            counts.transition_after(stream, is_pending_reset);
        }
    }

    pub fn clear_pending_open(&mut self, store: &mut Store, counts: &mut Counts) {
        while let Some(stream) = self.pending_open.pop(store) {
            let is_pending_reset = stream.is_pending_reset_expiration();
            counts.transition_after(stream, is_pending_reset);
        }
    }

    fn pop_frame<B>(
        &mut self,
        buffer: &mut Buffer<Frame<B>>,
        store: &mut Store,
        max_len: usize,
        coalesce: bool,
        counts: &mut Counts,
        recv: &mut Recv,
    ) -> io::Result<Option<Frame<Prioritized<B>>>>
    where
        B: Buf,
    {
        let _span = tracing::trace_span!("pop_frame");

        loop {
            let Some(mut stream) = self.pending_send.pop(store) else {
                return Ok(None);
            };
            let _span = tracing::trace_span!("popped", ?stream.id, ?stream.state);

            // It's possible that this stream, besides having data to send,
            // is also queued to send a reset, and thus is already in the queue
            // to wait for "some time" after a reset.
            //
            // To be safe, we just always ask the stream.
            let is_pending_reset = stream.is_pending_reset_expiration();

            tracing::trace!(is_pending_reset);

            if stream.initial_window == Some(stream::InitialWindow::Pending)
                && (stream.state.is_reset() || stream.state.is_scheduled_reset())
            {
                self.discard_unopened_request(buffer, &mut stream, counts);
                counts.transition_after(stream, is_pending_reset);
                continue;
            }

            let frame = match stream.pending_send.pop_front(buffer) {
                Some(Frame::Headers(mut headers)) => {
                    recv.prepare_initial_stream_window_update(&mut stream, &mut headers)?;
                    Frame::Headers(headers)
                }
                Some(Frame::Data(mut frame)) => {
                    if let Some(reason) = stream.state.get_scheduled_reset() {
                        // If a reset is scheduled due to cancellation or
                        // an error, discard buffered DATA and let the `None`
                        // arm emit the RST_STREAM on the next iteration.
                        //
                        // NO_ERROR is excluded. Per RFC 9113 §8.1, a NO_ERROR
                        // stream reset may only be sent after a complete
                        // response, which requires sending all queued DATA.
                        if reason != Reason::NO_ERROR {
                            stream.pending_send.push_front(buffer, frame.into());
                            self.clear_queue(buffer, &mut stream);
                            self.reclaim_all_capacity(&mut stream, counts);
                            self.pending_send.push(&mut stream);
                            continue;
                        }
                    }

                    // Get the amount of capacity remaining for stream's
                    // window.
                    let stream_capacity = stream.send_flow.available();
                    let sz = frame.payload().remaining();

                    tracing::trace!(
                        sz,
                        eos = frame.is_end_stream(),
                        window = %stream_capacity,
                        available = %stream.send_flow.available(),
                        requested = stream.requested_send_capacity,
                        buffered = stream.buffered_send_data,
                        "data frame"
                    );

                    // Zero length data frames always have capacity to
                    // be sent.
                    if sz > 0 && stream_capacity == 0 {
                        tracing::trace!("stream capacity is 0");

                        // Ensure that the stream is waiting for
                        // connection level capacity
                        //
                        // TODO: uncomment
                        // debug_assert!(stream.is_pending_send_capacity);

                        // The stream has no more capacity, this can
                        // happen if the remote reduced the stream
                        // window. In this case, we need to buffer the
                        // frame and wait for a window update...
                        stream.pending_send.push_front(buffer, frame.into());

                        continue;
                    }

                    // Only send up to the max frame length
                    let len = cmp::min(sz, max_len);

                    // Only send up to the stream's window capacity
                    let mut len = cmp::min(len, stream_capacity.as_size() as usize) as WindowSize;

                    // There *must* be be enough connection level
                    // capacity at this point.
                    debug_assert!(len <= self.flow.window_size());

                    // Check if the stream level window the peer knows is available. In some
                    // scenarios, maybe the window we know is available but the window which
                    // peer knows is not.
                    if len > 0 && len > stream.send_flow.window_size() {
                        stream.pending_send.push_front(buffer, frame.into());
                        continue;
                    }

                    let eos = frame.is_end_stream();

                    if sz > len as usize {
                        frame.set_end_stream(false);
                    }

                    // Wrap the frame's data payload to ensure that the
                    // correct amount of data gets written.
                    let mut frame = frame.map(|buf| Prioritized {
                        parts: SmallVec::from_buf([buf.take(len as usize)]),
                        end_of_stream: eos,
                        stream: stream.key(),
                    });

                    // DATA frames carry arbitrary sequences of octets, so the
                    // DATA queued behind a fully taken chunk joins this frame,
                    // without waiting for more, up to the cap and the window.
                    // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.1
                    if coalesce && sz == len as usize && !eos {
                        let window =
                            cmp::min(stream_capacity.as_size(), stream.send_flow.window_size());
                        let room = cmp::min(max_len, window as usize).saturating_sub(sz);
                        let (added, end_stream) =
                            frame.payload_mut().coalesce(room, &mut stream, buffer);
                        len += added as WindowSize;
                        frame.set_end_stream(end_stream);
                    }

                    tracing::trace!(len, "sending data frame");

                    // Update the flow control
                    {
                        let _span = tracing::trace_span!("updating stream flow");

                        stream.send_data(len, self.max_buffer_size);

                        // Assign the capacity back to the connection that
                        // was just consumed from the stream in the previous
                        // line.
                        // TODO: proper error handling
                        let _res = self.flow.assign_capacity(len);
                        debug_assert!(_res.is_ok());
                    }

                    {
                        let _span = tracing::trace_span!("updating connection flow");

                        // TODO: proper error handling
                        let _res = self.flow.send_data(len);
                        debug_assert!(_res.is_ok());
                    }

                    Frame::Data(frame)
                }
                Some(Frame::PushPromise(pp)) => {
                    let mut pushed = stream.store_mut().find_mut(&pp.promised_id()).unwrap();
                    pushed.is_pending_push = false;
                    // Transition stream from pending_push to pending_open
                    // if possible
                    if !pushed.pending_send.is_empty() {
                        if counts.can_inc_num_send_streams() {
                            counts.inc_num_send_streams(&mut pushed);
                            self.pending_send.push(&mut pushed);
                        } else {
                            self.queue_open(&mut pushed);
                        }
                    }
                    Frame::PushPromise(pp)
                }
                Some(frame) => frame.map(|_| {
                    unreachable!(
                        "Frame::map closure will only be called \
                             on DATA frames."
                    )
                }),
                None => {
                    if let Some(reason) = stream.state.get_scheduled_reset() {
                        stream.set_reset(reason, Initiator::Library);

                        let frame = frame::Reset::new(stream.id, reason);
                        Frame::Reset(frame)
                    } else {
                        // If the stream receives a RESET from the peer, it may have
                        // had data buffered to be sent, but all the frames are cleared
                        // in clear_queue(). Instead of doing O(N) traversal through queue
                        // to remove, lets just ignore the stream here.
                        tracing::trace!("removing dangling stream from pending_send");
                        // Since this should only happen as a consequence of `clear_queue`,
                        // we must be in a closed state of some kind.
                        debug_assert!(stream.state.is_closed());
                        counts.transition_after(stream, is_pending_reset);
                        continue;
                    }
                }
            };

            tracing::trace!("pop_frame; frame={:?}", frame);

            if cfg!(debug_assertions) && stream.state.is_idle() {
                debug_assert!(stream.id > self.last_opened_id);
                self.last_opened_id = stream.id;
            }

            if !stream.pending_send.is_empty() || stream.state.is_scheduled_reset() {
                // TODO: Only requeue the sender IF it is ready to send
                // the next frame. i.e. don't requeue it if the next
                // frame is a data frame and the stream does not have
                // any more capacity.
                self.pending_send.push(&mut stream);
            }

            counts.transition_after(stream, is_pending_reset);

            return Ok(Some(frame));
        }
    }

    fn pop_pending_open<'s>(
        &mut self,
        store: &'s mut Store,
        counts: &mut Counts,
    ) -> Option<store::Ptr<'s>> {
        tracing::trace!("schedule_pending_open");
        // check for any pending open streams
        if counts.can_inc_num_send_streams() {
            if let Some(mut stream) = self.pending_open.pop(store) {
                tracing::trace!("schedule_pending_open; stream={:?}", stream.id);

                counts.inc_num_send_streams(&mut stream);
                stream.notify_send();
                return Some(stream);
            }
        }

        None
    }

    fn discard_unopened_request<B>(
        &mut self,
        buffer: &mut Buffer<Frame<B>>,
        stream: &mut store::Ptr,
        counts: &mut Counts,
    ) {
        tracing::trace!(?stream.id, "discarding cancelled request before initial HEADERS");
        self.clear_queue(buffer, stream);
        if let Some(reason) = stream.state.get_scheduled_reset() {
            stream.set_reset(reason, Initiator::Library);
        }
        // poll_ready may have registered after an explicit reset but before
        // removal from pending_open. Removing it makes that sender ready.
        stream.notify_send();
        self.reclaim_all_capacity(stream, counts);
    }
}

// ===== impl Prioritized =====

impl<B: Buf> Prioritized<B> {
    /// Appends the stream's queued DATA chunks, up to `room` bytes.
    ///
    /// Stops at a non-DATA frame, a partly taken chunk or END_STREAM. Returns
    /// the bytes added and whether the frame now ends the stream.
    fn coalesce(
        &mut self,
        mut room: usize,
        stream: &mut store::Ptr,
        buffer: &mut Buffer<Frame<B>>,
    ) -> (usize, bool) {
        let mut added = 0;

        loop {
            let frame = match stream.pending_send.pop_front(buffer) {
                // Empty chunks add no part, so they merge even into a full frame
                Some(Frame::Data(frame))
                    if !frame.payload().has_remaining()
                        || (room > 0 && self.parts.len() < MAX_DATA_FRAME_PARTS) =>
                {
                    frame
                }
                // Trailers and DATA past the room keep their place
                Some(frame) => {
                    stream.pending_send.push_front(buffer, frame);
                    return (added, false);
                }
                None => return (added, false),
            };

            let sz = frame.payload().remaining();
            let len = cmp::min(sz, room);
            self.end_of_stream = frame.is_end_stream();

            if len > 0 {
                self.parts.push(frame.into_payload().take(len));
                added += len;
                room -= len;
            }

            // The rest of a partly taken chunk is pushed back on reclaim
            if len < sz {
                return (added, false);
            }

            if self.end_of_stream {
                return (added, true);
            }
        }
    }
}

impl<B> Buf for Prioritized<B>
where
    B: Buf,
{
    fn remaining(&self) -> usize {
        self.parts.iter().map(Buf::remaining).sum()
    }

    fn chunk(&self) -> &[u8] {
        self.parts
            .iter()
            .map(Buf::chunk)
            .find(|chunk| !chunk.is_empty())
            .unwrap_or_default()
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [std::io::IoSlice<'a>]) -> usize {
        let mut n = 0;

        for part in &self.parts {
            let cnt = part.chunks_vectored(&mut dst[n..]);
            let len: usize = dst[n..n + cnt].iter().map(|slice| slice.len()).sum();
            n += cnt;

            // Stop at a part not fully listed, so no bytes are skipped
            if len < part.remaining() {
                break;
            }
        }

        n
    }

    fn advance(&mut self, mut cnt: usize) {
        for part in &mut self.parts {
            if cnt == 0 {
                break;
            }

            let n = cmp::min(cnt, part.remaining());
            part.advance(n);
            cnt -= n;
        }
    }
}

impl<B: Buf> fmt::Debug for Prioritized<B> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Prioritized")
            .field(
                "remaining",
                &self
                    .parts
                    .last()
                    .map_or(0, |part| part.get_ref().remaining()),
            )
            .field("parts", &self.parts.len())
            .field("end_of_stream", &self.end_of_stream)
            .field("stream", &self.stream)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::buf::Chain;
    use std::io::IoSlice;

    /// Two chunks, of which the default `chunks_vectored` lists only the first.
    struct Split(Chain<&'static [u8], &'static [u8]>);

    impl Buf for Split {
        fn remaining(&self) -> usize {
            self.0.remaining()
        }

        fn chunk(&self) -> &[u8] {
            self.0.chunk()
        }

        fn advance(&mut self, cnt: usize) {
            self.0.advance(cnt)
        }
    }

    fn part(a: &'static [u8], b: &'static [u8], len: usize) -> Take<Split> {
        Split(a.chain(b)).take(len)
    }

    fn listed<'a>(buf: &'a Prioritized<Split>, slices: &'a mut [IoSlice<'a>]) -> Vec<&'a [u8]> {
        let n = buf.chunks_vectored(slices);
        slices[..n].iter().map(|slice| &**slice).collect()
    }

    #[test]
    fn prioritized_buf_spans_parts_without_gaps() {
        let mut store = Store::new();
        let mut stream = store.insert(StreamId::from(1), Stream::new(StreamId::from(1), 0, 0));
        let mut buf = Prioritized {
            parts: SmallVec::from_vec(vec![
                part(b"ab", b"", 2),
                part(b"cd", b"ef", 3),
                part(b"gh", b"", 2),
            ]),
            end_of_stream: false,
            stream: stream.key(),
        };

        assert_eq!(buf.remaining(), 7);
        // The second part is listed only up to "cd", so "gh" must wait.
        assert_eq!(listed(&buf, &mut [IoSlice::new(&[]); 64]), [b"ab", b"cd"]);

        buf.advance(4);
        assert_eq!(buf.chunk(), b"e");
        assert_eq!(
            listed(&buf, &mut [IoSlice::new(&[]); 64]),
            [&b"e"[..], b"gh"]
        );

        buf.advance(3);
        assert!(!buf.has_remaining());
        assert!(buf.chunk().is_empty());
        assert_eq!(buf.chunks_vectored(&mut [IoSlice::new(&[]); 64]), 0);

        stream.unlink();
        stream.remove();
    }
}
