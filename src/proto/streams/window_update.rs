use super::{FlowControl, Stream};
use crate::ext::{WindowUpdatePolicy, WindowUpdateRule};
use crate::proto::WindowSize;
use std::time::Instant;

#[derive(Debug)]
pub(super) struct RecvWindowUpdates {
    policy: WindowUpdatePolicy,
    connection_last_update_at: Option<Instant>,
    connection_pending: bool,
}

impl RecvWindowUpdates {
    pub(super) fn new(policy: WindowUpdatePolicy) -> Self {
        Self {
            policy,
            connection_last_update_at: initial_update_at(policy.connection),
            connection_pending: false,
        }
    }

    pub(super) fn start_stream(&self, stream: &mut Stream) {
        if stream.last_window_update_at.is_none() {
            stream.last_window_update_at = initial_update_at(self.policy.stream);
        }
    }

    pub(super) fn stream_release_due(&self, stream: &Stream, capacity: WindowSize) -> bool {
        (capacity > 0 || self.policy.stream.is_none())
            && update_due(
                self.policy.stream,
                &stream.recv_flow,
                stream.in_flight_recv_data,
                stream.last_window_update_at,
            )
    }

    pub(super) fn connection_release_due(
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
        self.connection_pending |= due;
        due
    }

    pub(super) fn stream_receive_due(&self, stream: &Stream) -> bool {
        receive_due(self.policy.stream, &stream.recv_flow)
    }

    pub(super) fn connection_received(&mut self, flow: &FlowControl) {
        self.connection_pending |= receive_due(self.policy.connection, flow);
    }

    pub(super) fn stream_window_changed(&self, stream: &Stream) -> bool {
        update_due(
            self.policy.stream,
            &stream.recv_flow,
            stream.in_flight_recv_data,
            None,
        )
    }

    pub(super) fn connection_target_changed(&mut self, flow: &FlowControl) -> bool {
        // Explicit target growth bypasses the optional release threshold.
        let due = increment(self.policy.connection, flow).is_some();
        self.connection_pending |= due;
        due
    }

    pub(super) fn connection_increment(&mut self, flow: &FlowControl) -> Option<WindowSize> {
        let increment = if self.policy.connection.is_none() || self.connection_pending {
            increment(self.policy.connection, flow)
        } else {
            None
        };
        if increment.is_none() {
            self.connection_pending = false;
        }
        increment
    }

    pub(super) fn stream_increment(&self, stream: &Stream) -> Option<WindowSize> {
        increment(self.policy.stream, &stream.recv_flow)
    }

    pub(super) fn connection_buffered(&mut self) {
        record_update(&mut self.connection_last_update_at);
        self.connection_pending = false;
    }

    pub(super) fn stream_buffered(&self, stream: &mut Stream) {
        record_update(&mut stream.last_window_update_at);
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

fn receive_due(rule: Option<WindowUpdateRule>, flow: &FlowControl) -> bool {
    matches!(rule, Some(WindowUpdateRule::Threshold { .. })) && update_due(rule, flow, 0, None)
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
    let Some(released) = flow.released_capacity() else {
        return false;
    };
    match rule {
        WindowUpdateRule::TargetWindowHalf { max_delay } => {
            let target = flow.receive_target(in_flight);
            i64::from(released) > target / 2
                || max_delay
                    .zip(last_update)
                    .is_some_and(|(delay, last)| last.elapsed() >= delay)
        }
        WindowUpdateRule::Threshold {
            increment,
            low_window,
        } => released >= increment || flow.window_size() <= low_window,
    }
}
