//! Scheduling for receive-side `WINDOW_UPDATE` frames.
//!
//! `Recv` accounts for received DATA and queues streams. `UpdateRule` decides
//! when each window is due for an update. `WindowUpdateScheduler` tracks why a
//! connection update is pending and advances the advertised window only after
//! the codec accepts the frame.

use super::{BufferStatus, FlowControl, Stream};
use crate::codec::Codec;
use crate::frame::{StreamId, WindowUpdate};
use crate::proto::WindowSize;
use bytes::Buf;
use std::time::{Duration, Instant};
use tokio::io::AsyncWrite;

/// Applies the configured rules, tracks pending connection updates, and keeps
/// the connection's delay timestamp. Each stream keeps its own timestamp.
#[derive(Debug)]
pub(super) struct WindowUpdateScheduler {
    stream_rule: UpdateRule,
    connection_rule: UpdateRule,
    connection_last_update_at: Option<Instant>,
    connection_pending: PendingConnectionUpdate,
}

// ===== impl WindowUpdateScheduler =====

impl WindowUpdateScheduler {
    pub(super) fn new(policy: WindowUpdatePolicy) -> Self {
        Self {
            stream_rule: UpdateRule(policy.stream),
            connection_rule: UpdateRule(policy.connection),
            connection_last_update_at: None,
            connection_pending: PendingConnectionUpdate::default(),
        }
    }

    /// Starts the configured delay when preparing request `HEADERS` or handling
    /// the first incoming non-trailer `HEADERS`, which may be a `1xx` response.
    /// Keeps any timestamp already set.
    pub(super) fn start_stream_delay(&self, stream: &mut Stream) {
        if stream.last_window_update_at.is_none() {
            stream.last_window_update_at = self.stream_rule.initial_update_at();
        }
    }

    /// Checks whether to queue the stream after crediting released capacity.
    /// A configured rule is checked only for a nonzero release.
    pub(super) fn stream_update_due_on_release(
        &self,
        stream: &Stream,
        capacity: WindowSize,
    ) -> bool {
        self.stream_rule.checks_release(capacity)
            && self.stream_rule.update_due(
                &stream.recv_flow,
                stream.in_flight_recv_data,
                stream.last_window_update_at,
            )
    }

    /// Checks the rule after crediting released capacity and marks the update
    /// pending if due. A `true` result tells `Recv` to wake a parked connection.
    /// A configured rule sees only nonzero releases and excludes unbuffered growth.
    pub(super) fn on_connection_capacity_released(
        &mut self,
        flow: &FlowControl,
        in_flight: WindowSize,
        capacity: WindowSize,
    ) -> bool {
        let due = self.connection_rule.checks_release(capacity)
            && self.connection_rule.update_due(
                &self.connection_pending.flow_for_rule(flow, in_flight),
                in_flight,
                self.connection_last_update_at,
            );
        self.connection_pending.mark_rule_due(due);
        due
    }

    /// Checks whether DATA lowered the stream window enough to return credit
    /// that has already been released. Applies only to the threshold rule.
    pub(super) fn stream_update_due_on_data(&self, stream: &Stream) -> bool {
        self.stream_rule.update_due_on_data(&stream.recv_flow)
    }

    /// Checks the threshold after DATA reduces the connection window and marks
    /// a due update pending, excluding credit from unbuffered growth.
    pub(super) fn on_connection_data_received(
        &mut self,
        flow: &FlowControl,
        in_flight: WindowSize,
    ) {
        let due = self
            .connection_rule
            .update_due_on_data(&self.connection_pending.flow_for_rule(flow, in_flight));
        self.connection_pending.mark_rule_due(due);
    }

    /// Rechecks the stream rule after applying an acknowledged window reduction.
    /// The delay is checked only when capacity is released.
    pub(super) fn stream_update_due_after_shrink(&self, stream: &Stream) -> bool {
        self.stream_rule
            .update_due(&stream.recv_flow, stream.in_flight_recv_data, None)
    }

    /// Lets a target increase bypass the configured rule until the update is
    /// buffered, the target returns to the growth baseline or below, or no
    /// released credit remains. Already scheduled rule updates stay pending.
    /// `Recv` wakes a parked connection when this returns `true`.
    pub(super) fn on_connection_target_changed(
        &mut self,
        flow: &FlowControl,
        previous_target: WindowSize,
        target: WindowSize,
    ) -> bool {
        if self.connection_rule.is_default() {
            // A target change can leave enough credit to cross the default
            // threshold and schedule a connection WINDOW_UPDATE.
            return flow.unclaimed_capacity().is_some();
        }

        self.connection_pending
            .on_target_changed(previous_target, target, flow.released_capacity())
    }

    /// Recomputes the increment from the live window. The adjusted window
    /// used to check the rule excludes growth that this frame can advertise.
    /// Clears both pending reasons if no update can be sent.
    fn prepare_connection_update(&mut self, flow: &FlowControl) -> Option<WindowSize> {
        if (self.connection_rule.is_default() || self.connection_pending.is_due())
            && let Some(increment) = self.connection_rule.increment(flow)
        {
            return Some(increment);
        }

        self.connection_pending.clear();
        None
    }

    /// Starts the configured delay once the client finishes its initial write
    /// and enters `Open`.
    pub(super) fn start_connection_delay(&mut self) {
        self.connection_last_update_at = self.connection_rule.initial_update_at();
    }

    /// Buffers a due connection update and clears its pending reasons on success.
    /// With no increment, stale reasons are cleared even when the codec is full.
    /// If the increment is ready but the codec is full, the update can be retried.
    pub(super) fn buffer_connection_update<T, B>(
        &mut self,
        flow: &mut FlowControl,
        dst: &mut Codec<T, B>,
    ) -> BufferStatus
    where
        T: AsyncWrite + Unpin,
        B: Buf,
    {
        let Some(increment) = self.prepare_connection_update(flow) else {
            return BufferStatus::Complete;
        };
        // Ensure the codec has capacity before committing the update.
        if !dst.has_send_capacity() {
            return BufferStatus::CodecFull;
        }

        buffer_update(
            dst,
            StreamId::zero(),
            increment,
            flow,
            &mut self.connection_last_update_at,
        );
        self.connection_pending.clear();
        BufferStatus::Complete
    }

    /// Buffers any available credit for a queued stream still receiving DATA.
    /// `Recv` checks codec capacity before removing the stream from the queue.
    pub(super) fn buffer_stream_update<T, B>(&self, stream: &mut Stream, dst: &mut Codec<T, B>)
    where
        T: AsyncWrite + Unpin,
        B: Buf,
    {
        if let Some(increment) = self.stream_rule.increment(&stream.recv_flow) {
            buffer_update(
                dst,
                stream.id,
                increment,
                &mut stream.recv_flow,
                &mut stream.last_window_update_at,
            );
        }
    }
}

/// Evaluates the receive rule for one window. `None` uses the default
/// flow-control threshold.
#[derive(Debug)]
struct UpdateRule(Option<WindowUpdateRule>);

// ===== impl UpdateRule =====

impl UpdateRule {
    fn is_default(&self) -> bool {
        self.0.is_none()
    }

    /// Only the default rule rechecks the window on a zero-byte release.
    fn checks_release(&self, capacity: WindowSize) -> bool {
        capacity > 0 || self.is_default()
    }

    /// Reads the clock only when a delay is configured.
    fn initial_update_at(&self) -> Option<Instant> {
        matches!(
            self.0,
            Some(WindowUpdateRule::TargetWindowHalf { max_delay: Some(_) })
        )
        .then(Instant::now)
    }

    /// Computes the increment from live flow-control credit. The default rule
    /// checks its threshold here. With a configured rule, the caller has
    /// already scheduled the update, possibly because the connection grew.
    fn increment(&self, flow: &FlowControl) -> Option<WindowSize> {
        if self.is_default() {
            flow.unclaimed_capacity()
        } else {
            flow.released_capacity()
        }
    }

    /// Rechecks the threshold rule when DATA lowers the remaining window.
    fn update_due_on_data(&self, flow: &FlowControl) -> bool {
        let Some(WindowUpdateRule::Threshold {
            increment,
            low_window,
        }) = self.0
        else {
            return false;
        };
        threshold_due(flow, increment, low_window)
    }

    /// Checks the rule after a release or stream window reduction. A window
    /// reduction supplies no timestamp, so it cannot trigger the delay.
    fn update_due(
        &self,
        flow: &FlowControl,
        in_flight: WindowSize,
        last_update: Option<Instant>,
    ) -> bool {
        match self.0 {
            None => flow.unclaimed_capacity().is_some(),
            Some(WindowUpdateRule::TargetWindowHalf { max_delay }) => {
                flow.released_capacity().is_some_and(|released| {
                    i64::from(released) > flow.receive_target(in_flight) / 2
                        || max_delay
                            .zip(last_update)
                            .is_some_and(|(delay, last)| last.elapsed() >= delay)
                })
            }
            Some(WindowUpdateRule::Threshold {
                increment,
                low_window,
            }) => threshold_due(flow, increment, low_window),
        }
    }
}

fn threshold_due(flow: &FlowControl, increment: WindowSize, low_window: WindowSize) -> bool {
    flow.released_capacity()
        .is_some_and(|released| released >= increment || flow.window_size() <= low_window)
}

/// Buffers the WINDOW_UPDATE frame before updating flow control and the timer.
fn buffer_update<T, B>(
    dst: &mut Codec<T, B>,
    id: StreamId,
    increment: WindowSize,
    flow: &mut FlowControl,
    last_update_at: &mut Option<Instant>,
) where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    dst.buffer(WindowUpdate::new(id, increment).into())
        .expect("invalid WINDOW_UPDATE frame");
    flow.inc_window(increment)
        .expect("unexpected flow control state");
    if let Some(last_update_at) = last_update_at {
        *last_update_at = Instant::now();
    }
}

/// The two reasons a connection update can be pending at the same time.
#[derive(Debug, Default)]
struct PendingConnectionUpdate {
    /// A rule already triggered on released credit.
    rule_due: bool,
    /// Baseline for unbuffered growth, excluding any shrink deficit.
    growth_from: Option<WindowSize>,
}

// ===== impl PendingConnectionUpdate =====

impl PendingConnectionUpdate {
    fn is_due(&self) -> bool {
        self.rule_due || self.growth_from.is_some()
    }

    fn mark_rule_due(&mut self, due: bool) {
        self.rule_due |= due;
    }

    /// Excludes unbuffered growth while checking whether the rule is due.
    fn flow_for_rule(&self, flow: &FlowControl, in_flight: WindowSize) -> FlowControl {
        flow.for_receive_rule(self.growth_from, in_flight)
    }

    /// Revokes only the growth reason when the target falls back or credit
    /// runs out. A rule that already triggered stays pending.
    fn on_target_changed(
        &mut self,
        previous_target: WindowSize,
        target: WindowSize,
        released: Option<WindowSize>,
    ) -> bool {
        let Some(released) = released else {
            self.growth_from = None;
            return false;
        };
        // Filling a shrink deficit adds no credit the peer can use.
        let growth_from = self
            .growth_from
            .unwrap_or_else(|| previous_target.max(target - released));
        if target <= growth_from {
            self.growth_from = None;
            return false;
        }

        let due = target > previous_target;
        if due {
            self.growth_from = Some(growth_from);
        }
        due
    }

    /// Clears both reasons after buffering an update or finding no increment.
    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Controls when the receiver advertises released capacity with `WINDOW_UPDATE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WindowUpdateRule {
    /// Updates after releasing strictly more than half the receive target.
    /// An optional delay also permits an update on the next nonzero release;
    /// elapsed time alone does not send a frame.
    TargetWindowHalf {
        /// Time since opening the stream/connection or its last update.
        max_delay: Option<Duration>,
    },
    /// Updates when released capacity reaches `increment`, or the peer's
    /// remaining window falls to `low_window` or below.
    Threshold {
        /// Minimum accumulated release, in bytes. Zero updates on every release.
        increment: u32,
        /// Remaining receive window at which any released capacity is returned.
        low_window: u32,
    },
}

/// Receive window update rules for streams and the connection.
/// The default uses the library's remaining-window thresholds for both.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WindowUpdatePolicy {
    stream: Option<WindowUpdateRule>,
    connection: Option<WindowUpdateRule>,
}

// ===== impl WindowUpdatePolicy =====

impl WindowUpdatePolicy {
    /// Uses the same rule for streams and the connection.
    pub fn both(rule: WindowUpdateRule) -> Self {
        Self {
            stream: Some(rule),
            connection: Some(rule),
        }
    }

    /// Sets the rule for all receive streams on the connection.
    pub fn stream(mut self, rule: WindowUpdateRule) -> Self {
        self.stream = Some(rule);
        self
    }

    /// Sets the rule for the connection receive window.
    pub fn connection(mut self, rule: WindowUpdateRule) -> Self {
        self.connection = Some(rule);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_does_not_count_pending_growth_toward_the_threshold() {
        let mut scheduler = WindowUpdateScheduler::new(WindowUpdatePolicy::default().connection(
            WindowUpdateRule::Threshold {
                increment: 4_096,
                low_window: 65_531,
            },
        ));
        let mut flow = FlowControl::new();
        flow.inc_window(65_535).unwrap();
        flow.assign_capacity(65_535).unwrap();
        flow.send_data(2).unwrap();
        flow.assign_capacity(1).unwrap();
        assert!(!scheduler.on_connection_capacity_released(&flow, 1, 1));

        flow.assign_capacity(4_096).unwrap();
        assert!(scheduler.on_connection_target_changed(&flow, 65_535, 69_631));
        flow.send_data(1).unwrap();
        scheduler.on_connection_data_received(&flow, 2);
        flow.claim_capacity(4_096).unwrap();
        assert!(!scheduler.on_connection_target_changed(&flow, 69_631, 65_535));
        assert_eq!(scheduler.prepare_connection_update(&flow), None);

        flow.assign_capacity(4_096).unwrap();
        assert!(scheduler.on_connection_target_changed(&flow, 65_535, 69_631));
        flow.send_data(1).unwrap();
        scheduler.on_connection_data_received(&flow, 3);
        flow.claim_capacity(4_096).unwrap();
        assert!(!scheduler.on_connection_target_changed(&flow, 69_631, 65_535));
        assert_eq!(scheduler.prepare_connection_update(&flow), Some(1));
    }
}
