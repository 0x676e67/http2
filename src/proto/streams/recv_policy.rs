use super::{FlowControl, WindowSize};
use crate::codec::DataHead;
use crate::frame::WindowUpdate;
use crate::proto::MAX_WINDOW_SIZE;
use std::collections::VecDeque;

const MIN_ACK: WindowSize = 4 * 1024 * 1024;
const EMERGENCY: WindowSize = 96 * 1024;

#[derive(Debug)]
pub(super) struct ReceiveDriven {
    pub(super) max_buffered_data: WindowSize,
    pub(super) queued_data: WindowSize,
    pub(super) pending: VecDeque<WindowUpdate>,
    pub(super) incoming: Option<IncomingData>,
}

/// Only the current wire frame can be incomplete. Its reservation is not
/// application-owned capacity and must survive cancellation of its stream.
#[derive(Clone, Copy, Debug)]
pub(super) struct IncomingData {
    pub(super) head: DataHead,
    pub(super) stream_reserved: bool,
}

impl ReceiveDriven {
    pub(super) fn new(max_buffered_data: WindowSize) -> Self {
        Self {
            max_buffered_data,
            queued_data: 0,
            pending: VecDeque::new(),
            incoming: None,
        }
    }

    pub(super) fn increment(
        &self,
        flow: &FlowControl,
        in_flight: WindowSize,
    ) -> Option<WindowSize> {
        let increment = update_increment(flow, in_flight)?;
        // Reserve space for every byte the peer is already allowed to send.
        // Early release does not remove DATA still queued for the application.
        // https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2.2
        let headroom = self
            .max_buffered_data
            .saturating_sub(self.queued_data.max(in_flight))
            .saturating_sub(self.incoming.map_or(0, |incoming| incoming.head.flow_len))
            .saturating_sub(flow.window_size());
        let increment = increment.min(headroom);
        (increment != 0).then_some(increment)
    }
}

/// `additional` accounts for in-flight connection DATA or a complete stream
/// payload. A DATA head has already reduced only the peer window, so zero
/// also includes its reservation until the payload completes.
pub(super) fn update_increment(flow: &FlowControl, additional: WindowSize) -> Option<WindowSize> {
    // Window stores i32, so widening its existing isize conversion is lossless.
    let available = isize::from(flow.available()) as i64;
    let remaining = i64::from(flow.raw_window_size());
    let candidate = available - remaining + i64::from(additional);
    if candidate <= 0 || (candidate < i64::from(MIN_ACK) && remaining > i64::from(EMERGENCY)) {
        return None;
    }

    // Both the increment and resulting window must fit in 31 bits. Keep the
    // signed remaining window: a SETTINGS reduction can make it negative.
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9
    let maximum = i64::from(MAX_WINDOW_SIZE);
    let increment = candidate.min(maximum).min(maximum - remaining);
    WindowSize::try_from(increment)
        .ok()
        .filter(|increment| *increment != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(size: WindowSize) -> FlowControl {
        let mut flow = FlowControl::new();
        flow.inc_window(size).unwrap();
        flow.assign_capacity(size).unwrap();
        flow
    }

    #[test]
    fn receive_driven_credit_thresholds_pregrants_and_buffer_headroom() {
        const TARGET: WindowSize = 12 * 1024 * 1024;

        let mut flow = window(TARGET);
        assert_eq!(update_increment(&flow, 0), None);
        flow.send_data(MIN_ACK - 1).unwrap();
        flow.assign_capacity(MIN_ACK - 1).unwrap();
        assert_eq!(update_increment(&flow, 0), None);
        flow.send_data(1).unwrap();
        flow.assign_capacity(1).unwrap();
        assert_eq!(update_increment(&flow, 0), Some(MIN_ACK));

        // The current frame can receive credit before consumption; an older
        // unconsumed frame cannot. Later release must not grant credit twice.
        let mut flow = window(TARGET);
        flow.send_data(MIN_ACK).unwrap();
        assert_eq!(update_increment(&flow, 0), None);
        assert_eq!(update_increment(&flow, MIN_ACK), Some(MIN_ACK));
        flow.inc_window(MIN_ACK).unwrap();
        flow.assign_capacity(MIN_ACK).unwrap();
        assert_eq!(update_increment(&flow, 0), None);
        flow.send_data(MIN_ACK).unwrap();
        flow.send_data(1).unwrap();
        assert_eq!(update_increment(&flow, 1), None);

        // After padding's automatic release, add only the application payload.
        let mut flow = window(TARGET);
        const PADDING: WindowSize = 17;
        flow.send_data(MIN_ACK).unwrap();
        flow.assign_capacity(PADDING).unwrap();
        assert_eq!(update_increment(&flow, MIN_ACK - PADDING), Some(MIN_ACK));

        for (remaining, expected) in [(EMERGENCY + 1, None), (EMERGENCY, Some(1))] {
            let mut flow = window(remaining + 1);
            flow.send_data(1).unwrap();
            flow.assign_capacity(1).unwrap();
            assert_eq!(update_increment(&flow, 0), expected);
        }

        let mut flow = window(100);
        flow.send_data(100).unwrap();
        flow.dec_recv_window(50).unwrap();
        flow.assign_capacity(60).unwrap();
        assert_eq!(flow.raw_window_size(), -50);
        assert_eq!(update_increment(&flow, 0), Some(60));

        let mut flow = window(TARGET);
        flow.send_data(MIN_ACK).unwrap();
        let mut policy = ReceiveDriven::new(TARGET + MIN_ACK);
        assert_eq!(policy.increment(&flow, MIN_ACK), Some(MIN_ACK));
        policy.max_buffered_data = TARGET;
        assert_eq!(policy.increment(&flow, MIN_ACK), None);
        // Freeing only part of the budget grants only that much new credit.
        flow.assign_capacity(1024).unwrap();
        assert_eq!(policy.increment(&flow, MIN_ACK - 1024), Some(1024));
        // Releasing before polling does not free the queued-payload budget.
        policy.queued_data = MIN_ACK;
        assert_eq!(policy.increment(&flow, MIN_ACK - 1024), None);

        let flow = window(EMERGENCY);
        assert_eq!(
            update_increment(&flow, MAX_WINDOW_SIZE),
            Some(MAX_WINDOW_SIZE - EMERGENCY)
        );
        let mut flow = window(0);
        flow.dec_recv_window(1).unwrap();
        assert_eq!(update_increment(&flow, u32::MAX), Some(MAX_WINDOW_SIZE));
    }
}
