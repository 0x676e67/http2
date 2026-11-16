use crate::codec::UserError;
use crate::{Reason, tracing};

use super::recv::Event;
use super::state::RecvStatus;
use super::sync::{Mutex, MutexGuard};
use super::*;

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

/// Tracks Stream related state
///
/// # Reference counting
///
/// There can be a number of outstanding handles to a single Stream. These are
/// tracked using reference counting. The `ref_count` field represents the
/// number of outstanding userspace handles that can reach this stream.
///
/// It's important to note that when the stream is placed in an internal queue
/// (such as an accept queue), this is **not** tracked by a reference count.
/// Thus, `ref_count` can be zero and the stream still has to be kept around.
pub(super) struct Stream {
    /// The http2 stream identifier
    pub id: StreamId,

    /// Current state of the stream
    pub state: State,

    /// Set to `true` when the stream is counted against the connection's max
    /// concurrent streams.
    pub is_counted: bool,

    /// Number of outstanding handles pointing to this stream
    pub ref_count: usize,

    // ===== Fields related to sending =====
    /// Next node in the accept linked list
    pub next_pending_send: Option<store::Key>,

    /// Set to true when the stream is pending accept
    pub is_pending_send: bool,

    /// Send data flow control
    pub send_flow: FlowControl,

    /// Amount of send capacity that has been requested, but not yet allocated.
    pub requested_send_capacity: WindowSize,

    /// Amount of data buffered at the prioritization layer.
    /// TODO: Technically this could be greater than the window size...
    pub buffered_send_data: usize,

    /// Task tracking additional send capacity (i.e. window updates).
    send_task: Option<Waker>,

    /// `SendRequest::poll_ready` waiting for this stream to leave
    /// `pending_open`. Kept apart from `send_task`, which the stream's own
    /// `SendStream` may hold at the same time.
    open_task: Option<Waker>,

    /// Frames pending for this stream being sent to the socket
    pub pending_send: buffer::Deque,

    /// Next node in the linked list of streams waiting for additional
    /// connection level capacity.
    pub next_pending_send_capacity: Option<store::Key>,

    /// True if the stream is waiting for outbound connection capacity
    pub is_pending_send_capacity: bool,

    /// Set to true when the send capacity has been incremented
    pub send_capacity_inc: bool,

    /// Next node in the open linked list
    pub next_open: Option<store::Key>,

    /// Set to true when the stream is pending to be opened
    pub is_pending_open: bool,

    /// Set to true when a push is pending for this stream
    pub is_pending_push: bool,

    // ===== Fields related to receiving =====
    /// Next node in the accept linked list
    pub next_pending_accept: Option<store::Key>,

    /// Set to true when the stream is pending accept
    pub is_pending_accept: bool,

    /// Receive data flow control
    pub recv_flow: FlowControl,

    /// Next node in the linked list of streams waiting to send window updates.
    pub next_window_update: Option<store::Key>,

    /// True if the stream is waiting to send a window update
    pub is_pending_window_update: bool,

    /// The time when this stream may have been locally reset.
    pub reset_at: Option<Instant>,

    /// Next node in list of reset streams that should expire eventually
    pub next_reset_expire: Option<store::Key>,

    /// Receive queue shared with the stream's handles
    pub shared: Arc<Shared>,

    /// Receive status last published to `shared`
    recv_status: RecvStatus,

    /// When the RecvStream drop occurs, no data should be received.
    pub is_recv: bool,

    /// Task tracking pushed promises.
    pub push_task: Option<Waker>,

    /// The stream's pending push promises
    pub pending_push_promises: store::Queue<NextAccept>,

    /// Validate content-length headers
    pub content_length: ContentLength,

    /// Initial request window state, only for clients using a stream target.
    pub initial_window: Option<InitialWindow>,

    /// `HeadersDependency::Chain` link of a client request.
    pub chain_link: Option<ChainLink>,
}

/// Receive state a stream shares with its handles.
///
/// A handle reaches it through its own `Arc`, so reading a queued frame takes
/// this lock alone. The connection takes it while holding the lock on all
/// streams, never the other way round.
#[derive(Debug)]
pub(super) struct Shared {
    recv: Mutex<RecvQueue>,
}

/// Frames a stream has received, and the task waiting for more.
///
/// Laid out as declared, like [`Events`]: what every frame reads and writes
/// comes first, next to the lock, and the frames it rarely reaches last.
#[derive(Debug)]
#[repr(C)]
pub(super) struct RecvQueue {
    /// Task tracking receiving frames
    task: Option<Waker>,

    /// Received DATA whose capacity is yet to be released
    pub in_flight: WindowSize,

    /// What the stream's state allows once `pending` is empty
    status: RecvStatus,

    /// Frames pending for this stream to read
    pub pending: Events,
}

/// A queue of received frames, oldest first.
///
/// The first few are held in place. A message is mostly read before more
/// than its head, a DATA frame and its trailers are queued, and then takes
/// no allocation.
#[derive(Debug, Default)]
#[repr(C)]
pub(super) struct Events {
    head: usize,
    len: usize,

    /// Frames received while the ring was full or these were queued
    rest: VecDeque<Event>,

    /// Ring of the oldest frames, starting at `head`
    ring: [Option<Event>; Events::INLINE],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InitialWindow {
    Pending,
    /// SETTINGS baseline already included in this stream's receive window.
    Sent(WindowSize),
}

/// State related to validating a stream's content-length
#[derive(Debug)]
pub enum ContentLength {
    Omitted,
    Head,
    /// The request was CONNECT; see [`ContentLength::ignores`].
    Connect,
    Remaining(u64),
}

#[derive(Debug)]
pub(super) struct NextAccept;

#[derive(Debug)]
pub(super) struct NextSend;

#[derive(Debug)]
pub(super) struct NextSendCapacity;

#[derive(Debug)]
pub(super) struct NextWindowUpdate;

#[derive(Debug)]
pub(super) struct NextOpen;

#[derive(Debug)]
pub(super) struct NextResetExpire;

impl Stream {
    /// Creates a stream with a receive queue of its own.
    #[cfg(test)]
    pub fn new(id: StreamId, init_send_window: WindowSize, init_recv_window: WindowSize) -> Stream {
        Self::with_shared(
            id,
            init_send_window,
            init_recv_window,
            Arc::new(Shared::new()),
        )
    }

    /// Creates a stream on `shared`, which no other stream or handle uses.
    pub fn with_shared(
        id: StreamId,
        init_send_window: WindowSize,
        init_recv_window: WindowSize,
        shared: Arc<Shared>,
    ) -> Stream {
        let mut send_flow = FlowControl::new();
        let mut recv_flow = FlowControl::new();

        recv_flow
            .inc_window(init_recv_window)
            .expect("invalid initial receive window");
        // TODO: proper error handling?
        let _res = recv_flow.assign_capacity(init_recv_window);
        debug_assert!(_res.is_ok());

        send_flow
            .inc_window(init_send_window)
            .expect("invalid initial send window size");

        Stream {
            id,
            state: State::default(),
            ref_count: 0,
            is_counted: false,

            // ===== Fields related to sending =====
            next_pending_send: None,
            is_pending_send: false,
            send_flow,
            requested_send_capacity: 0,
            buffered_send_data: 0,
            send_task: None,
            open_task: None,
            pending_send: buffer::Deque::new(),
            is_pending_send_capacity: false,
            next_pending_send_capacity: None,
            send_capacity_inc: false,
            is_pending_open: false,
            next_open: None,
            is_pending_push: false,

            // ===== Fields related to receiving =====
            next_pending_accept: None,
            is_pending_accept: false,
            recv_flow,
            next_window_update: None,
            is_pending_window_update: false,
            reset_at: None,
            next_reset_expire: None,
            shared,
            recv_status: RecvStatus::Open,
            is_recv: true,
            push_task: None,
            pending_push_promises: store::Queue::new(),
            content_length: ContentLength::Omitted,
            initial_window: None,
            chain_link: None,
        }
    }

    /// Increment the stream's ref count
    pub fn ref_inc(&mut self) {
        assert!(self.ref_count < usize::MAX);
        self.ref_count += 1;
    }

    /// Decrements the stream's ref count
    pub fn ref_dec(&mut self) {
        assert!(self.ref_count > 0);
        self.ref_count -= 1;
    }

    /// Returns true if stream is currently being held for some time because of
    /// a local reset.
    pub fn is_pending_reset_expiration(&self) -> bool {
        self.reset_at.is_some()
    }

    /// Returns true if frames for this stream are ready to be sent over the wire
    pub fn is_send_ready(&self) -> bool {
        // Why do we check pending_open?
        //
        // We allow users to call send_request() which schedules a stream to be pending_open
        // if there is no room according to the concurrency limit (max_send_streams), and we
        // also allow data to be buffered for send with send_data() if there is no capacity for
        // the stream to send the data, which attempts to place the stream in pending_send.
        // If the stream is not open, we don't want the stream to be scheduled for
        // execution (pending_send). Note that if the stream is in pending_open, it will be
        // pushed to pending_send when there is room for an open stream.
        //
        // In pending_push we track whether a PushPromise still needs to be sent
        // from a different stream before we can start sending frames on this one.
        // This is different from the "open" check because reserved streams don't count
        // toward the concurrency limit.
        // See https://httpwg.org/specs/rfc7540.html#rfc.section.5.1.2
        !self.is_pending_open && !self.is_pending_push
    }

    /// Returns true if the stream is closed
    pub fn is_closed(&self) -> bool {
        // The state has fully transitioned to closed.
        self.state.is_closed() &&
            // Because outbound frames transition the stream state before being
            // buffered, we have to ensure that all frames have been flushed.
            self.pending_send.is_empty() &&
            // Sometimes large data frames are sent out in chunks. After a chunk
            // of the frame is sent, the remainder is pushed back onto the send
            // queue to be rescheduled.
            //
            // Checking for additional buffered data lets us catch this case.
            self.buffered_send_data == 0
    }

    /// Returns true if the stream is no longer in use
    pub fn is_released(&self) -> bool {
        // The stream is closed and fully flushed
        self.is_closed() &&
            // There are no more outstanding references to the stream
            self.ref_count == 0 &&
            // The stream is not in any queue
            !self.is_pending_send && !self.is_pending_send_capacity &&
            !self.is_pending_accept && !self.is_pending_window_update &&
            !self.is_pending_open && self.reset_at.is_none()
    }

    /// Returns true when the consumer of the stream has dropped all handles
    /// (indicating no further interest in the stream) and the stream state is
    /// not actually closed.
    ///
    /// In this case, a reset should be sent.
    pub fn is_canceled_interest(&self) -> bool {
        self.ref_count == 0 && !self.state.is_closed()
    }

    /// Current available stream send capacity
    pub fn capacity(&self, max_buffer_size: usize) -> WindowSize {
        let available = self.send_flow.available().as_size() as usize;
        let buffered = self.buffered_send_data;

        available.min(max_buffer_size).saturating_sub(buffered) as WindowSize
    }

    pub fn assign_capacity(&mut self, capacity: WindowSize, max_buffer_size: usize) {
        let prev_capacity = self.capacity(max_buffer_size);
        debug_assert!(capacity > 0);
        // TODO: proper error handling
        let _res = self.send_flow.assign_capacity(capacity);
        debug_assert!(_res.is_ok());

        tracing::trace!(
            "  assigned capacity to stream; available={}; buffered={}; id={:?}; max_buffer_size={} prev={}",
            self.send_flow.available(),
            self.buffered_send_data,
            self.id,
            max_buffer_size,
            prev_capacity,
        );

        if prev_capacity < self.capacity(max_buffer_size) {
            self.notify_capacity();
        }
    }

    pub fn send_data(&mut self, len: WindowSize, max_buffer_size: usize) {
        let prev_capacity = self.capacity(max_buffer_size);

        // TODO: proper error handling
        let _res = self.send_flow.send_data(len);
        debug_assert!(_res.is_ok());

        // Decrement the stream's buffered data counter
        debug_assert!(self.buffered_send_data >= len as usize);
        self.buffered_send_data -= len as usize;
        self.requested_send_capacity -= len;

        tracing::trace!(
            "  sent stream data; available={}; buffered={}; id={:?}; max_buffer_size={} prev={}",
            self.send_flow.available(),
            self.buffered_send_data,
            self.id,
            max_buffer_size,
            prev_capacity,
        );

        if prev_capacity < self.capacity(max_buffer_size) {
            self.notify_capacity();
        }
    }

    /// If the capacity was limited because of the max_send_buffer_size,
    /// then consider waking the send task again...
    pub fn notify_capacity(&mut self) {
        self.send_capacity_inc = true;
        tracing::trace!("  notifying task");
        self.notify_send();
    }

    /// Returns `Err` when the decrement cannot be completed due to overflow.
    pub fn dec_content_length(&mut self, len: usize) -> Result<(), ()> {
        match self.content_length {
            ContentLength::Remaining(ref mut rem) => match rem.checked_sub(len as u64) {
                Some(val) => *rem = val,
                None => return Err(()),
            },
            ContentLength::Head if len != 0 => {
                return Err(());
            }
            _ => {}
        }

        Ok(())
    }

    pub fn ensure_content_length_zero(&self) -> Result<(), ()> {
        match self.content_length {
            ContentLength::Remaining(0) => Ok(()),
            ContentLength::Remaining(_) => Err(()),
            _ => Ok(()),
        }
    }

    pub fn notify_send(&mut self) {
        if let Some(task) = self.send_task.take() {
            sync::defer_wake(task);
        }
        if let Some(task) = self.open_task.take() {
            sync::defer_wake(task);
        }
    }

    pub fn wait_open(&mut self, cx: &Context) {
        self.open_task = Some(cx.waker().clone());
    }

    pub fn wait_send(&mut self, cx: &Context) {
        self.send_task = Some(cx.waker().clone());
    }

    /// Locks the receive queue shared with the stream's handles.
    #[inline]
    pub fn recv(&self) -> MutexGuard<'_, RecvQueue> {
        self.shared.recv()
    }

    /// Queues a received frame and notifies the receiver.
    ///
    /// The frame is queued together with the status the state has reached by
    /// receiving it, so a handle never reads the last frame as one of more.
    pub fn push_recv(&mut self, event: Event) {
        self.push_recv_in_flight(event, 0);
    }

    /// Queues a received DATA frame like `push_recv`. Its payload is in
    /// flight until its capacity is released.
    pub fn push_recv_data(&mut self, data: recv::DataEvent) {
        let in_flight = data.payload.len() as WindowSize;
        self.push_recv_in_flight(Event::Data(data), in_flight);
    }

    // Inlined, so that a frame whose kind is known is written in place.
    #[inline]
    fn push_recv_in_flight(&mut self, event: Event, in_flight: WindowSize) {
        self.recv_status = self.state.recv_status();

        let mut recv = self.shared.recv();
        recv.status = self.recv_status;
        recv.in_flight += in_flight;
        recv.pending.push_back(event);
        recv.notify();
    }

    pub fn notify_recv(&mut self) {
        // A state change is what the receiver is most often notified of.
        if !self.publish_recv_status() {
            self.recv().notify();
        }
    }

    /// Publishes what the state allows the receiver, and returns whether that
    /// changed, in which case the receiver was notified.
    ///
    /// Handles read the published status without the lock on all streams, so
    /// every change of `state` must be followed by this, which
    /// `Counts::transition_after` and `notify_recv` see to.
    #[inline]
    pub fn publish_recv_status(&mut self) -> bool {
        let status = self.state.recv_status();
        if status == self.recv_status {
            return false;
        }
        self.set_recv_status(status);
        true
    }

    /// A stream changes its status a few times at most, so this is kept out
    /// of the check that runs after every action on it.
    #[cold]
    fn set_recv_status(&mut self, status: RecvStatus) {
        self.recv_status = status;

        let mut recv = self.shared.recv();
        recv.status = status;
        recv.notify();
    }

    pub(super) fn notify_push(&mut self) {
        if let Some(task) = self.push_task.take() {
            sync::defer_wake(task);
        }
    }

    /// Set the stream's state to `Closed` with the given reason and initiator.
    /// Notify the send, receive, and push tasks, if they exist.
    pub(super) fn set_reset(&mut self, reason: Reason, initiator: Initiator) {
        self.state.set_reset(self.id, reason, initiator);
        self.notify_send();
        self.notify_push();
        self.notify_recv();
    }
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("is_counted", &self.is_counted)
            .field("ref_count", &self.ref_count)
            .h2_field_some("next_pending_send", &self.next_pending_send)
            .h2_field_if("is_pending_send", &self.is_pending_send)
            .field("send_flow", &self.send_flow)
            .field("requested_send_capacity", &self.requested_send_capacity)
            .field("buffered_send_data", &self.buffered_send_data)
            .h2_field_some("send_task", &self.send_task.as_ref().map(|_| ()))
            .h2_field_some("open_task", &self.open_task.as_ref().map(|_| ()))
            .h2_field_if_then(
                "pending_send",
                !self.pending_send.is_empty(),
                &self.pending_send,
            )
            .h2_field_some(
                "next_pending_send_capacity",
                &self.next_pending_send_capacity,
            )
            .h2_field_if("is_pending_send_capacity", &self.is_pending_send_capacity)
            .h2_field_if("send_capacity_inc", &self.send_capacity_inc)
            .h2_field_some("next_open", &self.next_open)
            .h2_field_if("is_pending_open", &self.is_pending_open)
            .h2_field_if("is_pending_push", &self.is_pending_push)
            .h2_field_some("next_pending_accept", &self.next_pending_accept)
            .h2_field_if("is_pending_accept", &self.is_pending_accept)
            .field("recv_flow", &self.recv_flow)
            .h2_field_some("next_window_update", &self.next_window_update)
            .h2_field_if("is_pending_window_update", &self.is_pending_window_update)
            .h2_field_some("reset_at", &self.reset_at)
            .h2_field_some("next_reset_expire", &self.next_reset_expire)
            .field("recv_status", &self.recv_status)
            .h2_field_if("is_recv", &self.is_recv)
            .h2_field_some("push_task", &self.push_task.as_ref().map(|_| ()))
            .h2_field_if_then(
                "pending_push_promises",
                !self.pending_push_promises.is_empty(),
                &self.pending_push_promises,
            )
            .field("content_length", &self.content_length)
            .finish()
    }
}

impl store::Next for NextAccept {
    fn next(stream: &Stream) -> Option<store::Key> {
        stream.next_pending_accept
    }

    fn set_next(stream: &mut Stream, key: Option<store::Key>) {
        stream.next_pending_accept = key;
    }

    fn take_next(stream: &mut Stream) -> Option<store::Key> {
        stream.next_pending_accept.take()
    }

    fn is_queued(stream: &Stream) -> bool {
        stream.is_pending_accept
    }

    fn set_queued(stream: &mut Stream, val: bool) {
        stream.is_pending_accept = val;
    }
}

impl store::Next for NextSend {
    fn next(stream: &Stream) -> Option<store::Key> {
        stream.next_pending_send
    }

    fn set_next(stream: &mut Stream, key: Option<store::Key>) {
        stream.next_pending_send = key;
    }

    fn take_next(stream: &mut Stream) -> Option<store::Key> {
        stream.next_pending_send.take()
    }

    fn is_queued(stream: &Stream) -> bool {
        stream.is_pending_send
    }

    fn set_queued(stream: &mut Stream, val: bool) {
        if val {
            // ensure that stream is not queued for being opened
            // if it's being put into queue for sending data
            debug_assert!(!stream.is_pending_open);
        }
        stream.is_pending_send = val;
    }
}

impl store::Next for NextSendCapacity {
    fn next(stream: &Stream) -> Option<store::Key> {
        stream.next_pending_send_capacity
    }

    fn set_next(stream: &mut Stream, key: Option<store::Key>) {
        stream.next_pending_send_capacity = key;
    }

    fn take_next(stream: &mut Stream) -> Option<store::Key> {
        stream.next_pending_send_capacity.take()
    }

    fn is_queued(stream: &Stream) -> bool {
        stream.is_pending_send_capacity
    }

    fn set_queued(stream: &mut Stream, val: bool) {
        stream.is_pending_send_capacity = val;
    }
}

impl store::Next for NextWindowUpdate {
    fn next(stream: &Stream) -> Option<store::Key> {
        stream.next_window_update
    }

    fn set_next(stream: &mut Stream, key: Option<store::Key>) {
        stream.next_window_update = key;
    }

    fn take_next(stream: &mut Stream) -> Option<store::Key> {
        stream.next_window_update.take()
    }

    fn is_queued(stream: &Stream) -> bool {
        stream.is_pending_window_update
    }

    fn set_queued(stream: &mut Stream, val: bool) {
        stream.is_pending_window_update = val;
    }
}

impl store::Next for NextOpen {
    fn next(stream: &Stream) -> Option<store::Key> {
        stream.next_open
    }

    fn set_next(stream: &mut Stream, key: Option<store::Key>) {
        stream.next_open = key;
    }

    fn take_next(stream: &mut Stream) -> Option<store::Key> {
        stream.next_open.take()
    }

    fn is_queued(stream: &Stream) -> bool {
        stream.is_pending_open
    }

    fn set_queued(stream: &mut Stream, val: bool) {
        if val {
            // ensure that stream is not queued for being sent
            // if it's being put into queue for opening the stream
            debug_assert!(!stream.is_pending_send);
        }
        stream.is_pending_open = val;
    }
}

impl store::Next for NextResetExpire {
    fn next(stream: &Stream) -> Option<store::Key> {
        stream.next_reset_expire
    }

    fn set_next(stream: &mut Stream, key: Option<store::Key>) {
        stream.next_reset_expire = key;
    }

    fn take_next(stream: &mut Stream) -> Option<store::Key> {
        stream.next_reset_expire.take()
    }

    fn is_queued(stream: &Stream) -> bool {
        stream.reset_at.is_some()
    }

    fn set_queued(stream: &mut Stream, val: bool) {
        if val {
            stream.reset_at = Some(Instant::now());
        } else {
            stream.reset_at = None;
        }
    }
}

// ===== impl Shared =====

impl Shared {
    pub fn new() -> Self {
        Shared {
            recv: Mutex::new(RecvQueue {
                task: None,
                in_flight: 0,
                status: RecvStatus::Open,
                pending: Events::default(),
            }),
        }
    }

    /// Returns the queue to its initial state, for the next stream to use.
    pub fn reset(&mut self) {
        let recv = self.recv.get_mut();
        while recv.pending.pop_front().is_some() {}
        recv.in_flight = 0;
        recv.task = None;
        recv.status = RecvStatus::Open;
    }

    /// Locks the receive queue.
    #[inline]
    pub fn recv(&self) -> MutexGuard<'_, RecvQueue> {
        self.recv.lock()
    }
}

// ===== impl RecvQueue =====

impl RecvQueue {
    /// Registers the task to notify when a frame arrives or the status changes.
    pub fn wait(&mut self, cx: &Context) {
        self.task = Some(cx.waker().clone());
    }

    /// Wakes the waiting task, which a connection that wakes the readers of
    /// its frames in batches holds back for the batch.
    pub fn notify(&mut self) {
        if let Some(task) = self.task.take() {
            sync::defer_wake(task);
        }
    }

    /// Takes the request head a server stream's queue starts with.
    ///
    /// # Panics
    ///
    /// Panics if the queue has no `Event::Headers` at its front.
    pub fn take_request(&mut self) -> http::Request<()> {
        match self.pending.pop_front() {
            Some(Event::Headers(peer::PollMessage::Server(request))) => request,
            _ => unreachable!("server stream queue must start with Headers"),
        }
    }

    /// Polls for the response head, as `Recv::poll_response` does. `None`
    /// leaves the outcome to the stream's state.
    pub fn poll_response(&mut self, cx: &Context) -> Option<Poll<http::Response<()>>> {
        use peer::PollMessage::Client;

        loop {
            match self.pending.front() {
                Some(Event::Headers(Client(_))) => break,
                // Interim responses are read through `poll_informational`.
                Some(Event::InformationalHeaders(_)) => {
                    self.pending.pop_front();
                }
                Some(_) => return None,
                None if self.status == RecvStatus::Open => {
                    self.wait(cx);
                    return Some(Poll::Pending);
                }
                None => return None,
            }
        }

        match self.pending.pop_front() {
            Some(Event::Headers(Client(response))) => Some(Poll::Ready(response)),
            _ => None,
        }
    }

    /// Polls for a DATA frame, as `Recv::poll_data` does. `None` leaves the
    /// outcome to the stream's state.
    pub fn poll_data(&mut self, cx: &Context) -> Option<Poll<Option<recv::DataEvent>>> {
        if let Some(data) = self.pending.pop_front_data() {
            return Some(Poll::Ready(Some(data)));
        }

        match self.pending.front() {
            // The frame is trailers, which may already be waited for.
            Some(_) => {
                self.notify();
                Some(Poll::Ready(None))
            }
            None => self.poll_empty(cx),
        }
    }

    /// Polls for trailers, as `Recv::poll_trailers` does. `None` leaves the
    /// outcome to the stream's state.
    pub fn poll_trailers(&mut self, cx: &Context) -> Option<Poll<Option<http::HeaderMap>>> {
        match self.pending.front() {
            Some(Event::Trailers(_)) => match self.pending.pop_front() {
                Some(Event::Trailers(trailers)) => Some(Poll::Ready(Some(trailers))),
                _ => None,
            },
            // Not trailers yet, so the frames ahead must be read first.
            Some(_) => {
                self.wait(cx);
                Some(Poll::Pending)
            }
            None => self.poll_empty(cx),
        }
    }

    /// The outcome of polling an empty queue for a body frame.
    fn poll_empty<T>(&mut self, cx: &Context) -> Option<Poll<Option<T>>> {
        match self.status {
            RecvStatus::Open => {
                self.wait(cx);
                Some(Poll::Pending)
            }
            RecvStatus::EndStream => Some(Poll::Ready(None)),
            RecvStatus::Closed => None,
        }
    }

    /// Returns whether END_STREAM was received and every frame before it read.
    pub fn is_end_stream(&self) -> bool {
        self.status == RecvStatus::EndStream && self.pending.is_empty()
    }

    /// Takes `capacity` off the received data that is yet to be released.
    pub fn release_in_flight(&mut self, capacity: WindowSize) -> Result<(), UserError> {
        if capacity > self.in_flight {
            return Err(UserError::ReleaseCapacityTooBig);
        }
        self.in_flight -= capacity;
        Ok(())
    }
}

// ===== impl Events =====

impl Events {
    const INLINE: usize = 3;

    pub fn is_empty(&self) -> bool {
        self.len == 0 && self.rest.is_empty()
    }

    pub fn front(&self) -> Option<&Event> {
        if self.len == 0 {
            return self.rest.front();
        }
        self.ring[self.head].as_ref()
    }

    #[inline]
    pub fn push_back(&mut self, event: Event) {
        // The ring only holds frames older than all of `rest`.
        if self.len == Self::INLINE || !self.rest.is_empty() {
            self.rest.push_back(event);
            return;
        }

        self.ring[Self::wrap(self.head + self.len)] = Some(event);
        self.len += 1;
    }

    pub fn push_front(&mut self, event: Event) {
        // Make room by moving the ring's newest frame ahead of `rest`.
        if self.len == Self::INLINE {
            let newest = Self::wrap(self.head + self.len - 1);
            if let Some(newest) = self.ring[newest].take() {
                self.rest.push_front(newest);
            }
            self.len -= 1;
        }

        self.head = Self::wrap(self.head + Self::INLINE - 1);
        self.ring[self.head] = Some(event);
        self.len += 1;
    }

    pub fn pop_front(&mut self) -> Option<Event> {
        if self.len == 0 {
            return self.rest.pop_front();
        }

        let event = self.ring[self.head].take();
        self.advance();
        event
    }

    /// Like `pop_front` if a DATA frame is at the front, of which only the
    /// frame itself is moved, not a slot sized for a message head.
    pub fn pop_front_data(&mut self) -> Option<recv::DataEvent> {
        if self.len == 0 {
            return match self.rest.front() {
                Some(Event::Data(_)) => match self.rest.pop_front() {
                    Some(Event::Data(data)) => Some(data),
                    _ => None,
                },
                _ => None,
            };
        }

        let slot = &mut self.ring[self.head];
        let Some(Event::Data(data)) = slot else {
            return None;
        };
        let data = recv::DataEvent {
            payload: std::mem::take(&mut data.payload),
            is_budgeted: data.is_budgeted,
        };
        *slot = None;
        self.advance();
        Some(data)
    }

    /// Moves past the ring's oldest slot, which was just emptied.
    fn advance(&mut self) {
        self.len -= 1;
        // An emptied ring starts over, so that a stream read as fast as it
        // receives keeps to one slot of it.
        self.head = match self.len {
            0 => 0,
            _ => Self::wrap(self.head + 1),
        };
    }

    fn wrap(index: usize) -> usize {
        index % Self::INLINE
    }
}

// ===== impl ContentLength =====

impl ContentLength {
    pub fn is_head(&self) -> bool {
        matches!(*self, Self::Head)
    }

    /// Whether a response with `status` ignores its content-length, even an invalid one.
    ///
    /// A server must not send the header on a 1xx, which has no content, and a client ignores
    /// it on a 2xx to CONNECT, which starts a tunnel instead.
    /// <https://www.rfc-editor.org/rfc/rfc9110#section-8.6>
    /// <https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6>
    pub fn ignores(&self, status: Option<http::StatusCode>) -> bool {
        status.is_some_and(|status| {
            status.is_informational() || (matches!(*self, Self::Connect) && status.is_success())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::recv::DataEvent;
    use super::*;

    fn event(n: u8) -> Event {
        Event::Data(DataEvent {
            payload: Bytes::from(vec![n]),
            is_budgeted: false,
        })
    }

    fn pop(events: &mut Events) -> Option<u8> {
        events.pop_front_data().map(|data| data.payload[0])
    }

    #[test]
    fn events_keep_their_order_in_and_past_the_ring() {
        let mut events = Events::default();
        assert!(events.is_empty() && events.front().is_none());

        // Fill the ring and spill, then drain it while more frames arrive:
        // these must stay behind the spilled ones.
        for n in 0..5 {
            events.push_back(event(n));
        }
        assert_eq!(pop(&mut events), Some(0));
        assert_eq!(pop(&mut events), Some(1));
        events.push_back(event(5));
        assert_eq!(pop(&mut events), Some(2));

        // A frame put back goes first, whether or not the ring has room.
        events.push_front(event(2));
        events.push_front(event(1));
        events.push_front(event(0));
        events.push_front(event(9));
        assert!(matches!(events.front(), Some(Event::Data(data)) if data.payload[0] == 9));

        let drained: Vec<_> = std::iter::from_fn(|| pop(&mut events)).collect();
        assert_eq!(drained, [9, 0, 1, 2, 3, 4, 5]);

        // The emptied ring takes frames again. Only DATA is taken as such,
        // in the ring and past it.
        events.push_back(event(6));
        events.push_back(Event::Trailers(http::HeaderMap::new()));
        (7..10).for_each(|n| events.push_back(event(n)));
        assert_eq!((pop(&mut events), pop(&mut events)), (Some(6), None));
        assert!(matches!(events.pop_front(), Some(Event::Trailers(_))));
        events.push_back(Event::Trailers(http::HeaderMap::new()));
        assert_eq!(std::iter::from_fn(|| pop(&mut events)).count(), 3);
        assert!(matches!(events.pop_front(), Some(Event::Trailers(_))));
        assert!(events.is_empty());
    }
}
