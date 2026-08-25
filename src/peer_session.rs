//! Per-connection BRC-103 session lifecycle, shared by server and client.
//!
//! [`PeerHandle`] owns one bsv-sdk [`Peer`] plus the channel ends of its
//! [`ChannelTransport`]. Inbound frames are feed-only; the server adapter takes
//! exclusive ownership of the observer receivers and drains them for the life
//! of the connection.
//!  - [`PeerHandle::emit_existing`] — sign an application event for an
//!    **already-authenticated** session and return the `AuthMessage` to emit.
//!    Fails closed (`SessionNotFound`) if no authenticated session exists;
//!    never initiates a handshake. This is the ONLY correct primitive for
//!    server→client emits and room broadcasts.
//!
//! The bsv-sdk `Peer` owns its receive task. Observer results are asynchronous
//! and intentionally are not correlated back to individual inbound frames.
//!
//! [`Peer`]: bsv::auth::peer::Peer
//! [`ChannelTransport`]: crate::transport::ChannelTransport

use std::sync::Arc;

#[cfg(feature = "server")]
use bsv::auth::certificates::VerifiableCertificate;
use bsv::auth::error::AuthError;
use bsv::auth::peer::Peer;
#[cfg(feature = "server")]
use bsv::auth::peer::{OnCertificateRequestReceived, OnCertificatesReceived};
use bsv::auth::types::AuthMessage;
#[cfg(feature = "server")]
use bsv::auth::types::RequestedCertificateSet;
use bsv::wallet::interfaces::WalletInterface;
#[cfg(feature = "server")]
use parking_lot::Mutex as SyncMutex;
use serde_json::Value;
use tokio::sync::mpsc;
#[cfg(feature = "server")]
use tokio::sync::Mutex;

use crate::transport::ChannelTransport;
use crate::wire::encode_event;

/// A verified application event decoded from a BRC-103 general message.
///
/// `sender` is the general message's envelope `identity_key` field — but by the
/// time it reaches here it is **self-proving**, not a bare claim. The bsv-sdk
/// `Peer` pushes onto its general-message channel only after
/// `verify_general_message` succeeds, and that verification derives its check
/// key from this exact field (`counterparty = msg.identity_key`) — so a valid
/// signature proves the sender holds the private key behind `sender`. A frame
/// with a forged `identity_key` verifies under a key the attacker cannot sign
/// for, fails, and produces no event. This is the ONLY sender value that may be
/// trusted; the same field on a *raw*, undriven `AuthMessage` is unverified.
#[derive(Debug, Clone)]
pub struct VerifiedEvent {
    /// Verified sender identity key (compressed pubkey, hex).
    pub sender: String,
    /// Application event name (e.g. `sendMessage`, `joinRoom`).
    pub event_name: String,
    /// Application event data.
    pub data: Value,
}

/// SDK-verified general-message sender and encoded application payload.
pub type VerifiedGeneralMessage = (String, Vec<u8>);
/// Take-once receiver for SDK-verified general messages.
pub type GeneralMessageReceiver = mpsc::Receiver<VerifiedGeneralMessage>;

/// Take-once observer receivers owned by a connection's long-lived pump.
#[cfg(feature = "server")]
pub struct PeerPumpReceivers {
    pub outgoing: mpsc::Receiver<AuthMessage>,
    pub general: GeneralMessageReceiver,
}

/// Owns a `Peer` and the channels bridging it to a Socket.IO connection.
pub struct PeerHandle<W: WalletInterface + 'static> {
    /// The SDK Peer is cloneable and internally synchronized.
    peer: Peer<W>,
    /// Push inbound `"authMessage"` frames here (Socket.IO → Peer).
    incoming_tx: mpsc::Sender<AuthMessage>,
    /// Drain Peer → Socket.IO frames here (then `emit` each as `"authMessage"`).
    ///
    /// Server-only: `take_pump_receivers` is the sole reader, and the client
    /// backend drives its own `Peer` directly rather than through a pump. On a
    /// client build these would be an allocated receiver nothing ever drains —
    /// the transport's outbound channel held open with no consumer.
    #[cfg(feature = "server")]
    outgoing_rx: SyncMutex<Option<mpsc::Receiver<AuthMessage>>>,
    /// Decoded, verified BRC-103 general-message payloads with their verified
    /// sender key (app events). Server-only, for the same reason.
    #[cfg(feature = "server")]
    general_rx: SyncMutex<Option<GeneralMessageReceiver>>,
    /// Serializes server-side certificate response production on this peer.
    #[cfg(feature = "server")]
    certificate_io: Mutex<()>,
}

impl<W: WalletInterface + 'static> PeerHandle<W> {
    /// Build a fresh session for one connection.
    ///
    /// Must be called from inside a Tokio runtime because bsv-sdk starts the
    /// Peer's background receive task during construction.
    pub fn new(wallet: W) -> Self {
        #[cfg(feature = "server")]
        {
            Self::build(wallet, None)
        }
        #[cfg(not(feature = "server"))]
        {
            Self::build(wallet)
        }
    }

    /// Internal server construction path.
    #[cfg(feature = "server")]
    pub(crate) fn new_for_server(wallet: W, requested: Option<RequestedCertificateSet>) -> Self {
        Self::build(wallet, requested)
    }

    fn build(
        wallet: W,
        #[cfg(feature = "server")] requested: Option<RequestedCertificateSet>,
    ) -> Self {
        #[cfg(feature = "server")]
        let (transport, incoming_tx, outgoing_rx) = ChannelTransport::new();
        #[cfg(not(feature = "server"))]
        let (transport, incoming_tx, _outgoing_rx) = ChannelTransport::new();
        let transport = Arc::new(transport);
        let peer = Peer::new(wallet, transport.clone());
        #[cfg(feature = "server")]
        if let Some(requested) = requested {
            peer.set_certificates_to_request(requested);
        }
        // Take-once: must be called on the fresh Peer before it is stored.
        #[cfg(feature = "server")]
        let general_rx = peer
            .on_general_message()
            .expect("on_general_message must succeed on a fresh Peer");
        // Client builds never pump, so take and drop the observer rather than
        // leaving the SDK's bounded channel with a receiver nothing drains.
        #[cfg(not(feature = "server"))]
        drop(
            peer.on_general_message()
                .expect("on_general_message must succeed on a fresh Peer"),
        );
        // The certificate-request observer is unused. Take and drop it so the
        // SDK's bounded observer channel can never retain stale notifications.
        drop(
            peer.on_certificate_request()
                .expect("on_certificate_request must succeed on a fresh Peer"),
        );
        let mut error_rx = peer
            .on_error()
            .expect("on_error must succeed on a fresh Peer");
        tokio::spawn(async move {
            while let Some(background) = error_rx.recv().await {
                tracing::warn!(
                    message_type = ?background.message_type,
                    error = %background.error,
                    "authsocket: background peer dispatch failed"
                );
            }
        });
        Self {
            peer,
            incoming_tx,
            #[cfg(feature = "server")]
            outgoing_rx: SyncMutex::new(Some(outgoing_rx)),
            #[cfg(feature = "server")]
            general_rx: SyncMutex::new(Some(general_rx)),
            #[cfg(feature = "server")]
            certificate_io: Mutex::new(()),
        }
    }

    /// Sign an application event for an **already-authenticated** session and
    /// return the `AuthMessage`s to `emit`. Fails closed: if the session for
    /// `identity_key` does not exist or is not authenticated, this returns
    /// `Err(SessionNotFound | NotAuthenticated)` and NEVER initiates a
    /// handshake — so a server emit/broadcast can only ever reach a peer that
    /// has completed mutual auth.
    pub async fn emit_existing(
        &self,
        identity_key: &str,
        event_name: &str,
        data: &Value,
    ) -> Result<Vec<AuthMessage>, AuthError> {
        let payload = encode_event(event_name, data);
        let msg = self
            .peer
            .create_general_message(identity_key, payload)
            .await?;
        Ok(vec![msg])
    }

    /// Direct access to the owned, internally synchronized `Peer`.
    pub fn peer(&self) -> &Peer<W> {
        &self.peer
    }

    /// Register a handler for certificate requests received by this peer.
    #[cfg(feature = "server")]
    pub(crate) fn listen_for_certificates_requested(
        &self,
        callback: Arc<OnCertificateRequestReceived>,
    ) -> u64 {
        self.peer.listen_for_certificates_requested(callback)
    }

    /// Stop a certificate-request handler registered on this peer.
    #[cfg(feature = "server")]
    pub(crate) fn stop_listening_for_certificates_requested(&self, callback_id: u64) {
        self.peer
            .stop_listening_for_certificates_requested(callback_id);
    }

    /// Register the awaited certificate listener used by server authorization.
    #[cfg(feature = "server")]
    pub(crate) fn listen_for_certificates_received(
        &self,
        callback: Arc<OnCertificatesReceived>,
    ) -> u64 {
        self.peer.listen_for_certificates_received(callback)
    }

    /// Send certificates only when `identity_key` already resolves an
    /// authenticated session. The connection pump owns and emits the produced
    /// frame. This method cannot initiate a handshake: the TTL-honoring
    /// `create_general_message` preflight fails before the SDK's potentially
    /// initiating certificate-response API is called.
    #[cfg(feature = "server")]
    pub(crate) async fn send_certificate_response_existing(
        &self,
        identity_key: &str,
        certificates: Vec<VerifiableCertificate>,
    ) -> Result<(), AuthError> {
        let _guard = self.certificate_io.lock().await;
        // Use the same active-session lookup as SDK verification/signing paths.
        // The discarded message refreshes session activity and proves that the
        // following SDK call cannot take its missing-session handshake fallback.
        self.peer
            .create_general_message(identity_key, Vec::new())
            .await?;
        self.peer
            .send_certificate_response(identity_key, certificates)
            .await?;
        Ok(())
    }

    /// Push one inbound frame to the SDK-owned background receive task.
    pub async fn feed(&self, inbound: AuthMessage) {
        let _ = self.incoming_tx.send(inbound).await;
    }

    /// Transfer observer ownership to the one long-lived connection pump.
    #[cfg(feature = "server")]
    pub(crate) fn take_pump_receivers(&self) -> Option<PeerPumpReceivers> {
        let outgoing = self.outgoing_rx.lock().take()?;
        let general = self.general_rx.lock().take()?;
        Some(PeerPumpReceivers { outgoing, general })
    }

    pub fn normalize_outbound(mut message: AuthMessage) -> AuthMessage {
        if message
            .requested_certificates
            .as_ref()
            .is_some_and(bsv::auth::types::RequestedCertificateSet::is_empty)
        {
            message.requested_certificates = None;
        }
        message
    }

    #[cfg(all(test, feature = "server"))]
    pub(crate) async fn lock_certificate_io_for_test(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.certificate_io.lock().await
    }
}
