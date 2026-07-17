//! Per-connection BRC-103 session lifecycle, shared by server and client.
//!
//! [`PeerHandle`] owns one bsv-sdk [`Peer`] plus the channel ends of its
//! [`ChannelTransport`], and exposes the operations both Socket.IO sides need:
//!  - [`PeerHandle::drive`] — feed one inbound `AuthMessage`, advance the Peer,
//!    and return (a) outbound `AuthMessage`s to `emit` over the socket and
//!    (b) decoded, *verified* application events, each tagged with the
//!    cryptographically verified sender key.
//!  - [`PeerHandle::emit_existing`] — sign an application event for an
//!    **already-authenticated** session and return the `AuthMessage` to emit.
//!    Fails closed (`SessionNotFound`) if no authenticated session exists;
//!    never initiates a handshake. This is the ONLY correct primitive for
//!    server→client emits and room broadcasts.
//!  - [`PeerHandle::emit`] — sign an event via `Peer::send_message`, which
//!    **initiates a handshake** when no session exists. Client-side only (the
//!    initial `authenticated` emit is what starts the handshake); a server
//!    must never call this on a broadcast path.
//!
//! The bsv-sdk `Peer` is not self-driving (no internal read loop), so the caller
//! must `drive` it whenever an inbound frame arrives.
//!
//! [`Peer`]: bsv::auth::peer::Peer
//! [`ChannelTransport`]: crate::transport::ChannelTransport

use std::sync::Arc;

use bsv::auth::error::AuthError;
use bsv::auth::peer::Peer;
use bsv::auth::types::AuthMessage;
use bsv::wallet::interfaces::WalletInterface;
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};

use crate::transport::ChannelTransport;
use crate::wire::{decode_event, encode_event};

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

/// Owns a `Peer` and the channels bridging it to a Socket.IO connection.
pub struct PeerHandle<W: WalletInterface + 'static> {
    /// The 0.3 `Peer` is fully `&self` (interior mutability), so no outer lock
    /// is needed — per-socket operations never serialize on this handle.
    peer: Peer<W>,
    /// Push inbound `"authMessage"` frames here (Socket.IO → Peer).
    incoming_tx: mpsc::Sender<AuthMessage>,
    /// Drain Peer → Socket.IO frames here (then `emit` each as `"authMessage"`).
    outgoing_rx: Mutex<mpsc::Receiver<AuthMessage>>,
    /// Decoded, verified BRC-103 general-message payloads with their verified
    /// sender key (app events).
    general_rx: Mutex<mpsc::Receiver<(String, Vec<u8>)>>,
}

impl<W: WalletInterface + 'static> PeerHandle<W> {
    /// Build a fresh session for one connection.
    pub fn new(wallet: W) -> Self {
        let (transport, incoming_tx, outgoing_rx) = ChannelTransport::new();
        let peer = Peer::new(wallet, Arc::new(transport));
        // Take-once: must be called on the fresh Peer before it is stored.
        let general_rx = peer
            .on_general_message()
            .expect("on_general_message must succeed on a fresh Peer");
        Self {
            peer,
            incoming_tx,
            outgoing_rx: Mutex::new(outgoing_rx),
            general_rx: Mutex::new(general_rx),
        }
    }

    /// Feed one inbound `AuthMessage`, advance the protocol, and collect results.
    ///
    /// Returns `(outbound, events)`:
    ///  - `outbound`: `AuthMessage`s the Peer produced (handshake responses and/or
    ///    signed replies) — `emit` each over the socket as `"authMessage"`.
    ///  - `events`: verified application events decoded from BRC-103 general
    ///    messages. Each carries the **verified** sender key (see
    ///    [`VerifiedEvent`]); a frame that fails verification produces no event.
    pub async fn drive(&self, inbound: AuthMessage) -> (Vec<AuthMessage>, Vec<VerifiedEvent>) {
        // Hand the frame to the Peer's transport input.
        let _ = self.incoming_tx.send(inbound).await;

        // Advance the protocol (verifies signatures, runs handshake steps, emits
        // general messages onto general_rx and outbound frames onto outgoing_rx).
        // A failure means verification did not complete for some frame — the
        // Peer never pushes an unverified event, so we just log and drain.
        if let Err(e) = self.peer.process_pending().await {
            tracing::warn!(error = %e, "authsocket: process_pending (frame not verified)");
        }

        (self.drain_outbound().await, self.drain_events().await)
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

    /// Sign an application event via [`Peer::send_message`], which initiates a
    /// BRC-103 handshake if no session exists yet. **Client-side only** — this
    /// is how the client's first `authenticated` emit starts the handshake.
    /// Server emit/broadcast paths must use [`PeerHandle::emit_existing`]
    /// instead, so they can never be tricked into initiating a handshake
    /// toward an unauthenticated socket.
    pub async fn emit(
        &self,
        identity_key: &str,
        event_name: &str,
        data: &Value,
    ) -> Result<Vec<AuthMessage>, AuthError> {
        let payload = encode_event(event_name, data);
        self.peer.send_message(identity_key, payload).await?;
        Ok(self.drain_outbound().await)
    }

    /// Direct access to the owned `Peer` (client backend needs `send_message`
    /// concurrently with the receive loop).
    pub fn peer(&self) -> &Peer<W> {
        &self.peer
    }

    /// Push one inbound frame without driving (client receive loop feeds the
    /// transport from its socket callback, then drives from its own task).
    pub async fn feed(&self, inbound: AuthMessage) {
        let _ = self.incoming_tx.send(inbound).await;
    }

    /// Drain any outbound frames produced by the Peer.
    pub async fn drain_outbound(&self) -> Vec<AuthMessage> {
        let mut out = Vec::new();
        let mut rx = self.outgoing_rx.lock().await;
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    async fn drain_events(&self) -> Vec<VerifiedEvent> {
        let mut events = Vec::new();
        let mut rx = self.general_rx.lock().await;
        while let Ok((sender, payload)) = rx.try_recv() {
            if let Some((event_name, data)) = decode_event(&payload) {
                events.push(VerifiedEvent {
                    sender,
                    event_name,
                    data,
                });
            }
        }
        events
    }
}
