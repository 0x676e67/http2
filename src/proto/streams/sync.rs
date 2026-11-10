//! Synchronization primitives: a [`Mutex`] backed by `std` or `parking_lot`,
//! and the deferral of task wake-ups past the lock they were found under.
//!
//! - With the `parking_lot` feature enabled, [`parking_lot::Mutex`] is used.
//! - Without the feature, [`std::sync::Mutex`] is used, with poisoning ignored.

use std::{
    cell::Cell,
    fmt,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    task::Waker,
};

#[cfg(feature = "parking_lot")]
use parking_lot as imp;
#[cfg(not(feature = "parking_lot"))]
use std::sync as imp;

/// Deferred wakers that make a full batch, see [`WakeScope::wake_full_batch`].
const MAX_DEFERRED: usize = 32;

thread_local! {
    /// Number of `WakeScope`s this thread is in.
    static SCOPES: Cell<usize> = const { Cell::new(0) };

    /// Number of wakers in `DEFERRED`. Kept apart, as only a thread-local
    /// without a destructor is read at no more than the cost of a static.
    static PENDING: Cell<usize> = const { Cell::new(0) };

    /// Wakers held back until the thread leaves its scopes. Taken out to be
    /// changed, so that nothing is borrowed while a waker runs.
    static DEFERRED: Cell<Vec<Waker>> = const { Cell::new(Vec::new()) };
}

/// A `Mutex` that never poisons.
pub(super) struct Mutex<T: ?Sized>(imp::Mutex<T>);

/// Like [`std::sync::MutexGuard`].
#[must_use]
pub(super) struct MutexGuard<'a, T: ?Sized>(imp::MutexGuard<'a, T>);

/// A span in which [`defer_wake`] holds wakers back, woken on leaving it.
///
/// It covers a run of received frames, so that the tasks reading them are
/// woken once for the run and under no lock, not once for each frame under
/// the lock that a woken task takes at once, often from another thread.
pub(crate) struct WakeScope {
    /// Scopes are counted per thread, so one must end on the thread it began.
    _not_send: PhantomData<*const ()>,
}

/// Wakes `waker` once this thread has left its [`WakeScope`]s, or at once
/// when it is in none.
pub(super) fn defer_wake(waker: Waker) {
    if SCOPES.get() == 0 {
        waker.wake();
        return;
    }

    let mut waker = Some(waker);
    // Fails only for a thread that is running its destructors.
    let _ = DEFERRED.try_with(|deferred| {
        let mut wakers = deferred.take();
        wakers.extend(waker.take());
        deferred.set(wakers);
    });

    match waker {
        // Not held back, so not to be lost either.
        Some(waker) => waker.wake(),
        None => PENDING.set(PENDING.get() + 1),
    }
}

// ===== impl Mutex =====

impl<T> Mutex<T> {
    #[inline]
    pub(super) fn new(t: T) -> Mutex<T> {
        Mutex(imp::Mutex::new(t))
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Returns the value, which the exclusive borrow shows no one else holds.
    pub(super) fn get_mut(&mut self) -> &mut T {
        #[cfg(feature = "parking_lot")]
        let value = self.0.get_mut();
        #[cfg(not(feature = "parking_lot"))]
        let value = self.0.get_mut().unwrap_or_else(|e| e.into_inner());

        value
    }

    #[inline]
    pub(super) fn lock(&self) -> MutexGuard<'_, T> {
        #[cfg(feature = "parking_lot")]
        let guard = self.0.lock();
        #[cfg(not(feature = "parking_lot"))]
        let guard = self.0.lock().unwrap_or_else(|e| e.into_inner());

        MutexGuard(guard)
    }

    /// Returns the guard unless the lock is held.
    #[inline]
    pub(super) fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        #[cfg(feature = "parking_lot")]
        let guard = self.0.try_lock();
        #[cfg(not(feature = "parking_lot"))]
        let guard = match self.0.try_lock() {
            Ok(guard) => Some(guard),
            Err(imp::TryLockError::Poisoned(e)) => Some(e.into_inner()),
            Err(imp::TryLockError::WouldBlock) => None,
        };

        guard.map(MutexGuard)
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

// ===== impl MutexGuard =====

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

// ===== impl WakeScope =====

impl WakeScope {
    #[inline]
    pub(crate) fn enter() -> Self {
        SCOPES.set(SCOPES.get() + 1);
        WakeScope {
            _not_send: PhantomData,
        }
    }

    /// Wakes what was held back if that is a full batch, which bounds how
    /// long the tasks of a long scope wait. To call while holding no lock.
    #[inline]
    pub(crate) fn wake_full_batch(&self) {
        if PENDING.get() >= MAX_DEFERRED {
            wake_deferred();
        }
    }
}

impl Drop for WakeScope {
    #[inline]
    fn drop(&mut self) {
        let scopes = SCOPES.get() - 1;
        SCOPES.set(scopes);

        if scopes == 0 && PENDING.get() != 0 {
            wake_deferred();
        }
    }
}

/// Wakes the deferred wakers, leaving their buffer for the next ones.
#[cold]
fn wake_deferred() {
    PENDING.set(0);

    let Ok(mut wakers) = DEFERRED.try_with(Cell::take) else {
        return;
    };

    for waker in wakers.drain(..) {
        waker.wake();
    }

    // A waker may have deferred others in a scope of its own, which stay.
    let _ = DEFERRED.try_with(|deferred| {
        let newer = deferred.take();
        deferred.set(if newer.capacity() == 0 { wakers } else { newer });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::task::Wake;

    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn wakers_wait_for_the_outermost_scope_unless_a_full_batch_is_woken() {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let woken = || count.0.load(Ordering::SeqCst);
        let defer = || defer_wake(Waker::from(count.clone()));

        // Outside of a scope nothing is held back.
        defer();
        assert_eq!(woken(), 1);

        let outer = WakeScope::enter();
        {
            let _inner = WakeScope::enter();
            defer();
        }
        defer();
        assert_eq!(woken(), 1);
        drop(outer);
        assert_eq!(woken(), 3);

        // Only a full batch is woken ahead of leaving the scope.
        let scope = WakeScope::enter();
        (1..MAX_DEFERRED).for_each(|_| defer());
        scope.wake_full_batch();
        assert_eq!(woken(), 3);
        defer();
        scope.wake_full_batch();
        assert_eq!(woken(), 3 + MAX_DEFERRED);
        drop(scope);
        assert_eq!(woken(), 3 + MAX_DEFERRED);
    }
}
