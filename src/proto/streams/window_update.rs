//! Scheduling for receive-side `WINDOW_UPDATE` frames.
//!
//! `Recv` keeps the flow-control counters, queues streams, and buffers the
//! frames. The rules use those counters to decide when to return credit.

use super::{FlowControl, Stream};
use crate::ext::{WindowUpdatePolicy, WindowUpdateRule};
use crate::proto::WindowSize;
use std::time::Instant;

/// Applies the configured rules, tracks pending connection updates, and keeps
/// the connection's delay timestamp. Each stream keeps its own timestamp.
#[derive(Debug)]
pub(super) struct RecvWindowUpdates {
    policy: WindowUpdatePolicy,
    connection_last_update_at: Option<Instant>,
    connection_rule_pending: bool,
    connection_growth_from: Option<WindowSize>,
}

// ===== impl RecvWindowUpdates =====

impl RecvWindowUpdates {
    pub(super) fn new(policy: WindowUpdatePolicy) -> Self {
        Self {
            policy,
            connection_last_update_at: None,
            connection_rule_pending: false,
            connection_growth_from: None,
        }
    }

    /// Starts the configured delay when preparing request `HEADERS` or handling
    /// the first incoming non-trailer `HEADERS`, which may be a `1xx` response.
    /// Keeps any timestamp already set.
    pub(super) fn start_stream(&self, stream: &mut Stream) {
        if stream.last_window_update_at.is_none() {
            stream.last_window_update_at = initial_update_at(self.policy.stream);
        }
    }

    /// Checks whether to queue the stream after crediting released capacity.
    /// A configured rule is checked only for a nonzero release.
    pub(super) fn stream_release_due(&self, stream: &Stream, capacity: WindowSize) -> bool {
        (capacity > 0 || self.policy.stream.is_none())
            && update_due(
                self.policy.stream,
                &stream.recv_flow,
                stream.in_flight_recv_data,
                stream.last_window_update_at,
            )
    }

    /// Checks the rule after crediting released capacity and marks the update
    /// pending if due. A `true` result tells `Recv` to wake a parked connection.
    /// A configured rule is checked only for a nonzero release.
    pub(super) fn on_connection_capacity_released(
        &mut self,
        flow: &FlowControl,
        in_flight: WindowSize,
        capacity: WindowSize,
    ) -> bool {
        let due = (capacity > 0 || self.policy.connection.is_none())
            && update_due(
                self.policy.connection,
                flow,
                in_flight,
                self.connection_last_update_at,
            );
        self.connection_rule_pending |= due;
        due
    }

    /// Checks whether DATA lowered the stream window enough to return credit
    /// that has already been released. Applies only to the threshold rule.
    pub(super) fn stream_update_due_on_data(&self, stream: &Stream) -> bool {
        update_due_on_data(self.policy.stream, &stream.recv_flow)
    }

    /// Checks the threshold rule after DATA reduces the connection window and
    /// marks an update pending if due.
    pub(super) fn on_connection_data_received(&mut self, flow: &FlowControl) {
        self.connection_rule_pending |= update_due_on_data(self.policy.connection, flow);
    }

    /// Rechecks the stream rule after applying an acknowledged window reduction.
    /// The delay is checked only when capacity is released.
    pub(super) fn stream_update_due_after_shrink(&self, stream: &Stream) -> bool {
        update_due(
            self.policy.stream,
            &stream.recv_flow,
            stream.in_flight_recv_data,
            None,
        )
    }

    /// Lets a target increase bypass the configured rule until the update is
    /// buffered or the target returns to its pre-growth size or below.
    /// `Recv` wakes a parked connection when this returns `true`.
    pub(super) fn on_connection_target_changed(
        &mut self,
        flow: &FlowControl,
        previous_target: WindowSize,
        target: WindowSize,
    ) -> bool {
        if self.policy.connection.is_none() {
            return flow.unclaimed_capacity().is_some();
        }

        let growth_from = self.connection_growth_from.unwrap_or(previous_target);
        if target <= growth_from {
            self.connection_growth_from = None;
        }

        let due = target > previous_target && flow.released_capacity().is_some();
        if due {
            self.connection_growth_from = Some(growth_from);
        }
        due
    }

    /// Recomputes the increment and clears both pending reasons if no credit
    /// is available. Otherwise both survive a full codec and can be retried.
    pub(super) fn prepare_connection_update(&mut self, flow: &FlowControl) -> Option<WindowSize> {
        let increment = if self.policy.connection.is_none()
            || self.connection_rule_pending
            || self.connection_growth_from.is_some()
        {
            increment(self.policy.connection, flow)
        } else {
            None
        };
        if increment.is_none() {
            self.connection_rule_pending = false;
            self.connection_growth_from = None;
        }
        increment
    }

    /// Recomputes the increment for a stream taken from the update queue.
    pub(super) fn stream_increment(&self, stream: &Stream) -> Option<WindowSize> {
        increment(self.policy.stream, &stream.recv_flow)
    }

    /// Clears both pending reasons and restarts the configured delay after the codec
    /// accepts the frame and `Recv` advances the connection window.
    pub(super) fn connection_buffered(&mut self) {
        record_update(&mut self.connection_last_update_at);
        self.connection_rule_pending = false;
        self.connection_growth_from = None;
    }

    /// Restarts the stream's configured delay after the codec accepts its update
    /// and `Recv` advances the stream window.
    pub(super) fn stream_buffered(&self, stream: &mut Stream) {
        record_update(&mut stream.last_window_update_at);
    }

    /// Starts the configured delay once the client finishes its initial write
    /// and enters `Open`.
    pub(super) fn start_connection(&mut self) {
        self.connection_last_update_at = initial_update_at(self.policy.connection);
    }
}

fn initial_update_at(rule: Option<WindowUpdateRule>) -> Option<Instant> {
    matches!(
        rule,
        Some(WindowUpdateRule::TargetWindowHalf { max_delay: Some(_) })
    )
    .then(Instant::now)
}

fn record_update(last_update: &mut Option<Instant>) {
    if let Some(last) = last_update {
        *last = Instant::now();
    }
}

fn increment(rule: Option<WindowUpdateRule>, flow: &FlowControl) -> Option<WindowSize> {
    if rule.is_some() {
        flow.released_capacity()
    } else {
        flow.unclaimed_capacity()
    }
}

fn update_due_on_data(rule: Option<WindowUpdateRule>, flow: &FlowControl) -> bool {
    let Some(WindowUpdateRule::Threshold {
        increment,
        low_window,
    }) = rule
    else {
        return false;
    };
    threshold_due(flow, increment, low_window)
}

fn update_due(
    rule: Option<WindowUpdateRule>,
    flow: &FlowControl,
    in_flight: WindowSize,
    last_update: Option<Instant>,
) -> bool {
    let Some(rule) = rule else {
        return flow.unclaimed_capacity().is_some();
    };
    match rule {
        WindowUpdateRule::TargetWindowHalf { max_delay } => {
            flow.released_capacity().is_some_and(|released| {
                i64::from(released) > flow.receive_target(in_flight) / 2
                    || max_delay
                        .zip(last_update)
                        .is_some_and(|(delay, last)| last.elapsed() >= delay)
            })
        }
        WindowUpdateRule::Threshold {
            increment,
            low_window,
        } => threshold_due(flow, increment, low_window),
    }
}

fn threshold_due(flow: &FlowControl, increment: WindowSize, low_window: WindowSize) -> bool {
    flow.released_capacity()
        .is_some_and(|released| released >= increment || flow.window_size() <= low_window)
}
