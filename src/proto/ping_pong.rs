use crate::codec::Codec;
use crate::frame::{self, Ping};
use crate::proto::{self, PingPayload};
use crate::tracing;

use atomic_waker::AtomicWaker;
use bytes::Buf;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::AsyncWrite;

/// Acknowledges ping requests from the remote.
#[derive(Debug)]
pub(crate) struct PingPong {
    pending_ping: Option<PendingPing>,
    pending_pong: Option<PingPayload>,
    user_pings: Option<UserPingsRx>,
    preface_ping: Option<PrefacePing>,
}

/// PING sent after the next HEADERS frame or ahead of the next non-empty DATA
/// frame once nothing has been read for longer than `threshold`.
///
/// Payloads carry a big-endian counter starting at 1. The ACK only allows the
/// next PING; a missing ACK is not acted on.
#[derive(Debug)]
pub(crate) struct PrefacePing {
    threshold: Duration,
    last_read: Instant,
    next_id: u64,
    state: PrefaceState,
}

#[derive(Debug)]
enum PrefaceState {
    Idle,
    /// Armed by a frame but not buffered yet.
    Pending(PingPayload),
    /// Buffered and waiting for the ACK.
    InFlight(PingPayload),
}

#[derive(Debug)]
pub(crate) struct UserPings(Arc<UserPingsInner>);

#[derive(Debug)]
struct UserPingsRx(Arc<UserPingsInner>);

#[derive(Debug)]
struct UserPingsInner {
    state: AtomicUsize,
    /// Task to wake up the main `Connection`.
    ping_task: AtomicWaker,
    /// Task to wake up `share::PingPong::poll_pong`.
    pong_task: AtomicWaker,
}

#[derive(Debug)]
struct PendingPing {
    payload: PingPayload,
    sent: bool,
}

/// Status returned from `PingPong::recv_ping`.
#[derive(Debug)]
pub(crate) enum ReceivedPing {
    MustAck,
    Unknown,
    Shutdown,
}

/// No user ping pending.
const USER_STATE_EMPTY: usize = 0;
/// User has called `send_ping`, but PING hasn't been written yet.
const USER_STATE_PENDING_PING: usize = 1;
/// User PING has been written, waiting for PONG.
const USER_STATE_PENDING_PONG: usize = 2;
/// We've received user PONG, waiting for user to `poll_pong`.
const USER_STATE_RECEIVED_PONG: usize = 3;
/// The connection is closed.
const USER_STATE_CLOSED: usize = 4;

// ===== impl PingPong =====

impl PingPong {
    pub(crate) fn new(preface_ping: Option<Duration>) -> Self {
        PingPong {
            pending_ping: None,
            pending_pong: None,
            user_pings: None,
            preface_ping: preface_ping.map(PrefacePing::new),
        }
    }

    pub(crate) fn preface_ping_mut(&mut self) -> Option<&mut PrefacePing> {
        self.preface_ping.as_mut()
    }

    /// Sends a preface PING armed by an already buffered frame.
    pub(crate) fn send_pending_preface_ping<T, B>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, B>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
    {
        if let Some(ref mut preface_ping) = self.preface_ping {
            if !preface_ping.buffer_pending(dst) {
                ready!(dst.poll_ready(cx))?;
                let buffered = preface_ping.buffer_pending(dst);
                debug_assert!(buffered);
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Records read activity for the preface PING.
    pub(crate) fn record_read(&mut self) {
        if let Some(ref mut preface_ping) = self.preface_ping {
            preface_ping.last_read = Instant::now();
        }
    }

    /// Can only be called once. If called a second time, returns `None`.
    pub(crate) fn take_user_pings(&mut self) -> Option<UserPings> {
        if self.user_pings.is_some() {
            return None;
        }

        let user_pings = Arc::new(UserPingsInner {
            state: AtomicUsize::new(USER_STATE_EMPTY),
            ping_task: AtomicWaker::new(),
            pong_task: AtomicWaker::new(),
        });
        self.user_pings = Some(UserPingsRx(user_pings.clone()));
        Some(UserPings(user_pings))
    }

    pub(crate) fn ping_shutdown(&mut self) {
        assert!(self.pending_ping.is_none());

        self.pending_ping = Some(PendingPing {
            payload: Ping::SHUTDOWN,
            sent: false,
        });
    }

    /// Process a ping
    pub(crate) fn recv_ping(&mut self, ping: Ping) -> ReceivedPing {
        // The caller should always check that `send_pongs` returns ready before
        // calling `recv_ping`.
        assert!(self.pending_pong.is_none());

        if ping.is_ack() {
            if let Some(pending) = self.pending_ping.take() {
                if &pending.payload == ping.payload() {
                    assert_eq!(
                        &pending.payload,
                        &Ping::SHUTDOWN,
                        "pending_ping should be for shutdown",
                    );
                    tracing::trace!("recv PING SHUTDOWN ack");
                    return ReceivedPing::Shutdown;
                }

                // if not the payload we expected, put it back.
                self.pending_ping = Some(pending);
            }

            if let Some(ref mut preface_ping) = self.preface_ping {
                if preface_ping.recv_ack(ping.payload()) {
                    tracing::trace!("recv PING preface ack");
                    return ReceivedPing::Unknown;
                }
            }

            if let Some(ref users) = self.user_pings {
                if ping.payload() == &Ping::USER && users.receive_pong() {
                    tracing::trace!("recv PING USER ack");
                    return ReceivedPing::Unknown;
                }
            }

            // else we were acked a ping we didn't send?
            // The spec doesn't require us to do anything about this,
            // so for resiliency, just ignore it for now.
            tracing::warn!("recv PING ack that we never sent: {:?}", ping);
            ReceivedPing::Unknown
        } else {
            // Save the ping's payload to be sent as an acknowledgement.
            self.pending_pong = Some(ping.into_payload());
            ReceivedPing::MustAck
        }
    }

    /// Send any pending pongs.
    pub(crate) fn send_pending_pong<T, B>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, B>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
    {
        if let Some(pong) = self.pending_pong.take() {
            if !dst.poll_send_capacity(cx)?.is_ready() {
                self.pending_pong = Some(pong);
                return Poll::Pending;
            }

            dst.buffer(Ping::pong(pong).into())
                .expect("invalid pong frame");
        }

        Poll::Ready(Ok(()))
    }

    /// Send any pending pings.
    pub(crate) fn send_pending_ping<T, B>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, B>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
    {
        if let Some(ref mut ping) = self.pending_ping {
            if !ping.sent {
                if !dst.poll_send_capacity(cx)?.is_ready() {
                    return Poll::Pending;
                }

                dst.buffer(Ping::new(ping.payload).into())
                    .expect("invalid ping frame");
                ping.sent = true;
            }
        } else if let Some(ref users) = self.user_pings {
            if users.0.state.load(Ordering::Acquire) == USER_STATE_PENDING_PING {
                if !dst.poll_send_capacity(cx)?.is_ready() {
                    return Poll::Pending;
                }

                dst.buffer(Ping::new(Ping::USER).into())
                    .expect("invalid ping frame");
                users
                    .0
                    .state
                    .store(USER_STATE_PENDING_PONG, Ordering::Release);
            } else {
                users.0.ping_task.register(cx.waker());
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl ReceivedPing {
    pub(crate) fn is_shutdown(&self) -> bool {
        matches!(*self, Self::Shutdown)
    }
}

// ===== impl PrefacePing =====

impl PrefacePing {
    /// Encoded size of a PING frame.
    pub(crate) const FRAME_LEN: usize = frame::HEADER_LEN + 8;

    fn new(threshold: Duration) -> Self {
        PrefacePing {
            threshold,
            last_read: Instant::now(),
            next_id: 1,
            state: PrefaceState::Idle,
        }
    }

    /// Returns whether no PING is outstanding and the connection has been
    /// read-idle for longer than the threshold.
    pub(crate) fn is_due(&self) -> bool {
        matches!(self.state, PrefaceState::Idle) && self.last_read.elapsed() > self.threshold
    }

    /// Arms the next PING; callers check `is_due` first.
    pub(crate) fn arm(&mut self) {
        let payload = self.next_id.to_be_bytes();
        self.next_id = self.next_id.wrapping_add(1);
        self.state = PrefaceState::Pending(payload);
    }

    /// Buffers an armed PING. Returns `false` if the codec is full.
    pub(crate) fn buffer_pending<T, B>(&mut self, dst: &mut Codec<T, B>) -> bool
    where
        T: AsyncWrite + Unpin,
        B: Buf,
    {
        if let PrefaceState::Pending(payload) = self.state {
            if !dst.has_send_capacity() {
                return false;
            }

            dst.buffer(Ping::new(payload).into())
                .expect("invalid ping frame");
            self.state = PrefaceState::InFlight(payload);
        }

        true
    }

    fn recv_ack(&mut self, payload: &PingPayload) -> bool {
        match self.state {
            PrefaceState::InFlight(ref sent) if sent == payload => {
                self.state = PrefaceState::Idle;
                true
            }
            _ => false,
        }
    }
}

// ===== impl UserPings =====

impl UserPings {
    pub(crate) fn send_ping(&self) -> Result<(), Option<proto::Error>> {
        let prev = self
            .0
            .state
            .compare_exchange(
                USER_STATE_EMPTY,        // current
                USER_STATE_PENDING_PING, // new
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .unwrap_or_else(|v| v);

        match prev {
            USER_STATE_EMPTY => {
                self.0.ping_task.wake();
                Ok(())
            }
            USER_STATE_CLOSED => Err(Some(broken_pipe().into())),
            _ => {
                // Was already pending, user error!
                Err(None)
            }
        }
    }

    pub(crate) fn poll_pong(&self, cx: &mut Context) -> Poll<Result<(), proto::Error>> {
        // Must register before checking state, in case state were to change
        // before we could register, and then the ping would just be lost.
        self.0.pong_task.register(cx.waker());
        let prev = self
            .0
            .state
            .compare_exchange(
                USER_STATE_RECEIVED_PONG, // current
                USER_STATE_EMPTY,         // new
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .unwrap_or_else(|v| v);

        match prev {
            USER_STATE_RECEIVED_PONG => Poll::Ready(Ok(())),
            USER_STATE_CLOSED => Poll::Ready(Err(broken_pipe().into())),
            _ => Poll::Pending,
        }
    }
}

// ===== impl UserPingsRx =====

impl UserPingsRx {
    fn receive_pong(&self) -> bool {
        let prev = self
            .0
            .state
            .compare_exchange(
                USER_STATE_PENDING_PONG,  // current
                USER_STATE_RECEIVED_PONG, // new
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .unwrap_or_else(|v| v);

        if prev == USER_STATE_PENDING_PONG {
            self.0.pong_task.wake();
            true
        } else {
            false
        }
    }
}

impl Drop for UserPingsRx {
    fn drop(&mut self) {
        self.0.state.store(USER_STATE_CLOSED, Ordering::Release);
        self.0.pong_task.wake();
    }
}

fn broken_pipe() -> io::Error {
    io::ErrorKind::BrokenPipe.into()
}
