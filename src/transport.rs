//! Channel-backed [`Transport`] adapter between a BRC-103 [`Peer`] and a
//! Socket.IO connection.
//!
//! The bsv-sdk `Peer` talks to a `Transport` (send `AuthMessage` / subscribe to
//! incoming `AuthMessage`s). Socket.IO is the actual pipe. This adapter is the
//! seam: the Peer's outgoing messages are pushed onto `outgoing` (which the
//! Socket.IO layer drains and `emit`s as `"authMessage"`), and inbound
//! `"authMessage"` frames are pushed onto `incoming` (which the Peer drains).
//!
//! Identical in shape on server (socketioxide) and client (rust_socketio) — only
//! the code that wires `outgoing`/`incoming` to the concrete socket differs, so
//! that wiring lives in the `server`/`client` modules and this stays shared.
//!
//! [`Peer`]: bsv::auth::peer::Peer

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bsv::auth::error::AuthError;
use bsv::auth::transports::Transport;
use bsv::auth::types::{AuthMessage, MessageType};
use tokio::sync::mpsc;

/// Channel size for in-flight auth frames in each direction.
const CHANNEL_CAP: usize = 32;

/// A [`Transport`] whose two directions are plain mpsc channels.
///
/// Construct with [`ChannelTransport::new`], which returns the transport plus
/// the two channel ends the Socket.IO layer owns:
/// - `incoming_tx`: push inbound `"authMessage"` frames here (Socket.IO → Peer).
/// - `outgoing_rx`: drain Peer → Socket.IO frames here and `emit` them.
pub struct ChannelTransport {
    outgoing_tx: mpsc::Sender<AuthMessage>,
    incoming_rx: Mutex<Option<mpsc::Receiver<AuthMessage>>>,
    block_initial_requests: AtomicBool,
}

/// RAII guard used by non-initiating server operations. If the guarded SDK
/// call ever tries to fall back to a handshake, the transport rejects its
/// `initialRequest`; cancellation and early returns restore normal behavior.
pub(crate) struct InitialRequestBlock(Arc<ChannelTransport>);

impl Drop for InitialRequestBlock {
    fn drop(&mut self) {
        self.0.block_initial_requests.store(false, Ordering::SeqCst);
    }
}

impl ChannelTransport {
    /// Returns `(transport, incoming_tx, outgoing_rx)`.
    pub fn new() -> (Self, mpsc::Sender<AuthMessage>, mpsc::Receiver<AuthMessage>) {
        let (in_tx, in_rx) = mpsc::channel(CHANNEL_CAP);
        let (out_tx, out_rx) = mpsc::channel(CHANNEL_CAP);
        let transport = Self {
            outgoing_tx: out_tx,
            incoming_rx: Mutex::new(Some(in_rx)),
            block_initial_requests: AtomicBool::new(false),
        };
        (transport, in_tx, out_rx)
    }

    /// Reject any SDK fallback that attempts to initiate a handshake until the
    /// returned guard is dropped.
    pub(crate) fn block_initial_requests(self: &Arc<Self>) -> InitialRequestBlock {
        self.block_initial_requests.store(true, Ordering::SeqCst);
        InitialRequestBlock(self.clone())
    }
}

#[async_trait::async_trait]
impl Transport for ChannelTransport {
    async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
        if message.message_type == MessageType::InitialRequest
            && self.block_initial_requests.load(Ordering::SeqCst)
        {
            return Err(AuthError::NotAuthenticated(
                "server certificate response requires an existing authenticated session".into(),
            ));
        }
        self.outgoing_tx
            .send(message)
            .await
            .map_err(|e| AuthError::TransportError(format!("authsocket transport send: {e}")))
    }

    fn subscribe(&self) -> mpsc::Receiver<AuthMessage> {
        self.incoming_rx
            .lock()
            .unwrap()
            .take()
            .expect("ChannelTransport::subscribe called more than once")
    }
}
