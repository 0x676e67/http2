use crate::codec::UserError;
use crate::error::Reason;
use crate::proto::*;
use crate::tracing;
use smallvec::SmallVec;
use std::io;
use std::task::{Context, Poll};

/// SETTINGS ACKs that may wait for write capacity while reading goes on.
/// Reading stops at this many, so a SETTINGS flood cannot grow the queue.
const MAX_PENDING_ACKS: usize = 16;

#[derive(Debug)]
pub(crate) struct Settings {
    /// Our local SETTINGS sync state with the remote.
    local: Local,
    /// Received SETTINGS frames whose ACK is not written yet. They are applied
    /// on receipt, except for the codec, which picks them up with the ACK.
    remote: SmallVec<[frame::Settings; 1]>,
    /// Whether the connection has received the initial SETTINGS frame from the
    /// remote peer.
    has_received_remote_initial_settings: bool,
    /// Latest applied `SETTINGS_ENABLE_CONNECT_PROTOCOL` from the remote peer.
    remote_extended_connect: bool,
}

#[derive(Debug)]
enum Local {
    /// We want to send these SETTINGS to the remote when the socket is ready.
    ToSend(frame::Settings),
    /// We have sent these SETTINGS and are waiting for the remote to ACK
    /// before we apply them.
    WaitingAck(frame::Settings),
    /// Our local settings are in sync with the remote.
    Synced,
}

impl Settings {
    pub(crate) fn new(local: frame::Settings) -> Self {
        Settings {
            // The initial local SETTINGS are already buffered in the codec and
            // are written by the connection's initial send path.
            local: Local::WaitingAck(local),
            remote: SmallVec::new(),
            has_received_remote_initial_settings: false,
            remote_extended_connect: false,
        }
    }

    pub(crate) fn recv_settings<T, B, C, P>(
        &mut self,
        frame: frame::Settings,
        codec: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Result<(), Error>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        if frame.is_ack() {
            match &self.local {
                Local::WaitingAck(local) => {
                    tracing::debug!("received settings ACK; applying {:?}", local);

                    if let Some(max) = local.max_frame_size() {
                        codec.set_max_recv_frame_size(max as usize);
                    }

                    if let Some(max) = local.max_header_list_size() {
                        codec.set_max_recv_header_list_size(max as usize);
                    }

                    if let Some(val) = local.header_table_size() {
                        codec.set_recv_header_table_size(val as usize);
                    }

                    streams.apply_local_settings(local)?;
                    self.local = Local::Synced;
                    Ok(())
                }
                Local::ToSend(..) | Local::Synced => {
                    // We haven't sent any SETTINGS frames to be ACKed, so
                    // this is very bizarre! Remote is either buggy or malicious.
                    proto_err!(conn: "received unexpected settings ack");
                    Err(Error::library_go_away(Reason::PROTOCOL_ERROR))
                }
            }
        } else {
            // Frames read before the ACK can be written must see these.
            // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.3
            let is_initial = self.mark_remote_initial_settings_as_received();
            streams.apply_remote_settings(&frame, is_initial)?;
            if let Some(enabled) = frame.is_extended_connect_protocol_enabled() {
                self.remote_extended_connect = enabled;
            }

            // `poll_send` returns ready before more frames are read, so there
            // is room for another ACK.
            assert!(self.remote.len() < MAX_PENDING_ACKS);
            self.remote.push(frame);
            Ok(())
        }
    }

    pub(crate) fn send_settings(&mut self, frame: frame::Settings) -> Result<(), UserError> {
        assert!(!frame.is_ack());
        match &self.local {
            Local::ToSend(..) | Local::WaitingAck(..) => Err(UserError::SendSettingsWhilePending),
            Local::Synced => {
                tracing::trace!("queue to send local settings: {:?}", frame);
                self.local = Local::ToSend(frame);
                Ok(())
            }
        }
    }

    /// Sets `true` to `self.has_received_remote_initial_settings`.
    /// Returns `true` if this method is called for the first time.
    /// (i.e. it is the initial SETTINGS frame from the remote peer)
    fn mark_remote_initial_settings_as_received(&mut self) -> bool {
        let has_received = self.has_received_remote_initial_settings;
        self.has_received_remote_initial_settings = true;
        !has_received
    }

    pub(crate) fn poll_send<T, B, C, P>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Poll<Result<(), Error>>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        if self.poll_send_acks(cx, dst)?.is_pending() {
            // Reading goes on while another ACK can be queued.
            return if self.remote.len() < MAX_PENDING_ACKS {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        }

        match &self.local {
            Local::ToSend(settings) => {
                if !dst.poll_send_capacity(cx)?.is_ready() {
                    // Our SETTINGS can wait without stopping reads.
                    return Poll::Ready(Ok(()));
                }

                // Buffer the settings frame
                dst.buffer(settings.clone().into())
                    .expect("invalid settings frame");
                streams.sent_local_settings(settings);
                tracing::trace!("local settings sent; waiting for ack: {:?}", settings);

                self.local = Local::WaitingAck(settings.clone());
            }
            Local::WaitingAck(..) | Local::Synced => {}
        }

        Poll::Ready(Ok(()))
    }

    /// Buffers the ACKs owed for received SETTINGS, and returns `Pending`
    /// until all of them are. Frames that may rely on those settings must
    /// follow their ACK, since the peer applies them only once it reads it.
    pub(crate) fn poll_send_acks<T, B>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, B>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
    {
        while let Some(settings) = self.remote.first() {
            if !dst.poll_send_capacity(cx)?.is_ready() {
                return Poll::Pending;
            }

            // Create an ACK settings frame
            let frame = frame::Settings::ack();

            // Buffer the settings frame
            dst.buffer(frame.into()).expect("invalid settings frame");

            tracing::trace!("ACK sent; applying codec settings");

            // A new table size is signaled only after the ACK.
            // https://www.rfc-editor.org/rfc/rfc7541.html#section-4.2
            if let Some(val) = settings.header_table_size() {
                dst.set_send_header_table_size(val as usize);
            }

            if let Some(val) = settings.max_frame_size() {
                dst.set_max_send_frame_size(val as usize);
            }

            self.remote.remove(0);
        }

        Poll::Ready(Ok(()))
    }

    /// Returns the remote extended CONNECT setting, or `None` before its initial SETTINGS.
    pub(crate) fn remote_extended_connect(&self) -> Option<bool> {
        self.has_received_remote_initial_settings
            .then_some(self.remote_extended_connect)
    }
}
