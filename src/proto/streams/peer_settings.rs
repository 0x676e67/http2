use std::{
    mem,
    sync::atomic::{AtomicU8, Ordering},
    task::{Context, Poll, Waker},
};

use super::sync::Mutex;

const PENDING: u8 = 0;
const DISABLED: u8 = 1;
const ENABLED: u8 = 2;
const CLOSED: u8 = 3;

/// Remote SETTINGS published for readers outside the connection task.
///
/// The state leaves `PENDING` once, when the initial SETTINGS frame is applied
/// or the connection ends first. Waiters are only registered before that, and
/// all writers hold the streams lock.
#[derive(Debug)]
pub(crate) struct PeerSettings {
    state: AtomicU8,
    waiters: Mutex<Vec<Waker>>,
}

impl PeerSettings {
    pub(crate) fn new() -> Self {
        Self {
            state: AtomicU8::new(PENDING),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Returns the peer's extended CONNECT setting, or `None` before the initial SETTINGS.
    pub(crate) fn is_extended_connect_protocol_enabled(&self) -> Option<bool> {
        match self.state.load(Ordering::Acquire) {
            ENABLED => Some(true),
            DISABLED => Some(false),
            _ => None,
        }
    }

    /// Polls until the initial SETTINGS is applied or the connection closes.
    pub(crate) fn poll_received(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.state.load(Ordering::Acquire) != PENDING {
            return Poll::Ready(());
        }

        let mut waiters = self.waiters.lock();
        // Publishers change the state before draining under this lock.
        if self.state.load(Ordering::Acquire) != PENDING {
            return Poll::Ready(());
        }
        if !waiters.iter().any(|waker| waker.will_wake(cx.waker())) {
            waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }

    /// Publishes the extended CONNECT value of an applied SETTINGS frame.
    pub(crate) fn apply(&self, extended_connect: bool) {
        let state = if extended_connect { ENABLED } else { DISABLED };
        // Writers hold the streams lock, so only the first SETTINGS races with readers.
        match self
            .state
            .compare_exchange(PENDING, state, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => self.wake(),
            Err(current) if current != CLOSED && current != state => {
                self.state.store(state, Ordering::Release);
            }
            Err(_) => {}
        }
    }

    /// Releases waiters when the connection ends before the initial SETTINGS.
    pub(crate) fn close(&self) {
        if self
            .state
            .compare_exchange(PENDING, CLOSED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.wake();
        }
    }

    fn wake(&self) {
        let waiters = mem::take(&mut *self.waiters.lock());
        for waker in waiters {
            waker.wake();
        }
    }
}
