//! Server-side authenticated room core.
//!
//! This is deliberately **Socket.IO-implementation-agnostic**: it owns the
//! per-connection [`PeerHandle`]s and room membership, and turns "emit/broadcast
//! an app event" into a list of signed `AuthMessage`s tagged with the socket id
//! to send them over. The consumer (e.g. `rust-messagebox-server`, using
//! `socketioxide`) wires the actual socket I/O to these calls:
//!
//! - on a new connection: [`AuthSocketServer::add_connection`].
//! - on an inbound `"authMessage"` event: [`AuthSocketServer::on_auth_message`],
//!   then `emit` each returned `AuthMessage` back over that socket and dispatch
//!   the returned verified events to your handlers.
//! - on disconnect: [`AuthSocketServer::remove_connection`].
//! - to push a live message to a room: [`AuthSocketServer::emit_to_room`], then
//!   `emit` each `(socket_id, AuthMessage)` over the matching socket.
//!
//! ## Security invariants
//!
//! - **Identity comes only from the verified sender.** A socket's identity key
//!   is set exclusively from [`VerifiedEvent::sender`] — the general message's
//!   `identity_key` field *after* the bsv-sdk `Peer` verified the signature
//!   against a key derived from that same field. A valid signature therefore
//!   proves the sender holds that key's private half; a forged envelope
//!   `identity_key` fails verification, yields no event, and never owns a room.
//!   The same field on a raw, undriven `AuthMessage` is an unverified claim.
//! - **Per-socket `Peer` isolation is the backbone.** Each connection gets its
//!   own `Peer` + `SessionManager` ([`Self::add_connection`]), so a genuine
//!   signed frame from one socket's session cannot be replayed onto another
//!   (its `your_nonce` resolves no session there). Do NOT consolidate to a
//!   shared `Peer` — the `genuine_general_frame_does_not_replay_onto_another_socket`
//!   test locks this.
//! - **Broadcasts fail closed.** [`AuthSocketServer::emit_to_room`] /
//!   [`AuthSocketServer::emit_to_socket`] sign via
//!   [`PeerHandle::emit_existing`], which requires an existing authenticated
//!   session and never initiates a handshake — an emit can only reach a socket
//!   that completed mutual auth.
//! - **No global lock across crypto.** Connection and room maps are behind
//!   brief `parking_lot::RwLock`s; per-socket handles are `Arc`s cloned out
//!   under the lock, and all Peer work (drive/sign) runs outside any map lock.
//!   Fan-out signs run concurrently (`join_all`), not in a sequential loop.
//!
//! **The fix this replaces:** the old server `broadcast_to_room` did a RAW,
//! unsigned `io.to(room).emit(...)`, which only hit the client's fallback
//! receive path. Here every broadcast is a per-recipient **signed** general
//! message, so it lands on the client's authenticated primary path — instant
//! and authenticated.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bsv::auth::error::AuthError;
use bsv::auth::peer::OnCertificateRequestReceived;
use bsv::auth::types::{AuthMessage, MessageType, RequestedCertificateSet};
use bsv::wallet::interfaces::{Certificate, WalletInterface};
use futures_util::future::join_all;
use parking_lot::RwLock;
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::peer_session::{PeerHandle, VerifiedEvent};

/// Result of advancing one socket's protocol on an inbound frame.
pub struct Driven {
    /// `AuthMessage`s to `emit` back over the same socket as `"authMessage"`.
    pub outbound: Vec<AuthMessage>,
    /// Verified app events to dispatch to your handlers. Each carries the
    /// cryptographically verified sender key; the socket's identity has
    /// already been recorded from it before dispatch.
    pub events: Vec<VerifiedEvent>,
}

/// The blocking authorization decision returned by a server certificate
/// authorizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateAuthorizationDecision {
    /// Admit the peer and allow its verified application events to proceed.
    Accept,
    /// Reject the peer. The socketioxide adapter closes the socket and the
    /// transport-agnostic core suppresses all application events.
    Reject(String),
}

/// Current certificate-authorization state for one socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateAuthorization {
    /// This server did not request certificates; legacy behavior is unchanged.
    NotRequired,
    /// Certificates were requested and no authorization decision exists yet.
    Pending,
    /// The configured authorizer accepted certificates signed by this socket's
    /// BRC-103 session peer.
    Accepted { identity_key: String },
    /// The configured authorizer rejected this identity.
    Rejected {
        identity_key: String,
        reason: String,
    },
}

/// Default maximum time a certificate-gated connection may remain pending.
///
/// This spans the BRC-103 handshake, certificate retrieval and network round
/// trips, and the configured authorizer (which commonly performs a revocation
/// lookup). Use [`AuthSocketServer::set_certificate_authorization_timeout`] to
/// tune it before adding connections.
pub const CERTIFICATE_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(30);

impl CertificateAuthorization {
    /// The rejection reason, if authorization failed.
    pub fn rejection_reason(&self) -> Option<&str> {
        match self {
            Self::Rejected { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

type CertificateAuthorizerFuture =
    Pin<Box<dyn Future<Output = CertificateAuthorizationDecision> + Send + 'static>>;
type CertificateAuthorizer =
    Arc<dyn Fn(String, Vec<Certificate>) -> CertificateAuthorizerFuture + Send + Sync>;

/// Server-wide listener for inbound certificate requests.
///
/// Arguments are `(socket_id, requester_identity_key, requested_certificates)`.
/// Like the SDK listener, this callback is synchronous and may spawn async work
/// that calls [`AuthSocketServer::send_certificate_response`].
pub type OnCertificatesRequested =
    dyn Fn(String, String, RequestedCertificateSet) + Send + Sync + 'static;

struct Connection<W: WalletInterface + 'static> {
    handle: PeerHandle<W>,
    /// Set exclusively from a verified general-message sender — never from the
    /// unverified envelope claim.
    identity_key: RwLock<Option<String>>,
    /// Identity recorded by the SDK for this socket's successfully processed
    /// responder-side BRC-103 session. Certificate responses must be signed by
    /// this same key before application authorization can accept them.
    session_peer_identity_key: RwLock<Option<String>>,
    certificate_authorization: RwLock<CertificateAuthorization>,
    certificate_deadline: Option<Instant>,
    certificate_timeout: Option<Duration>,
    /// Serializes authorization transitions with pending-event deferral. The
    /// vector owns verified events until a pending decision becomes terminal.
    deferred_events: Mutex<Vec<VerifiedEvent>>,
    /// Aborted when authorization resolves or the socket disconnects, so the
    /// deadline task does not retain the socket/server until the full timeout.
    certificate_deadline_task: RwLock<Option<JoinHandle<()>>>,
    /// Once enabled it stays enabled, even after the last request listener is
    /// removed, so an in-flight response can never race an un-serialized drive.
    certificate_exchange_enabled: AtomicBool,
    /// SDK callback id for the bridge to the server-wide listener registry.
    certificate_request_bridge_id: RwLock<Option<u64>>,
}

/// `true` iff `key` has the shape of a compressed secp256k1 pubkey
/// (66 hex chars, `02`/`03` prefix). Defense-in-depth on top of the SDK's
/// signature verification.
fn is_valid_identity_key(key: &str) -> bool {
    key.len() == 66
        && (key.starts_with("02") || key.starts_with("03"))
        && key.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Owns all authenticated connections + room membership for one server.
pub struct AuthSocketServer<W: WalletInterface + 'static> {
    /// socket id -> connection. Brief lock only — handles are cloned out as
    /// `Arc`s and all Peer work happens outside this lock.
    conns: RwLock<HashMap<String, Arc<Connection<W>>>>,
    /// room id -> set of socket ids.
    rooms: RwLock<HashMap<String, HashSet<String>>>,
    /// Applied to every Peer created after configuration, matching AuthFetch's
    /// per-peer wiring pattern.
    certificates_to_request: RwLock<Option<RequestedCertificateSet>>,
    /// Awaited inline while driving a certificateResponse. No application
    /// event is returned until it accepts.
    certificate_authorizer: RwLock<Option<CertificateAuthorizer>>,
    /// Snapshotted by each newly-created connection.
    certificate_authorization_timeout: RwLock<Duration>,
    certificate_request_listeners: Arc<RwLock<HashMap<u64, Arc<OnCertificatesRequested>>>>,
    certificate_request_listener_id: AtomicU64,
}

impl<W: WalletInterface + 'static> Default for AuthSocketServer<W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: WalletInterface + 'static> AuthSocketServer<W> {
    pub fn new() -> Self {
        Self {
            conns: RwLock::new(HashMap::new()),
            rooms: RwLock::new(HashMap::new()),
            certificates_to_request: RwLock::new(None),
            certificate_authorizer: RwLock::new(None),
            certificate_authorization_timeout: RwLock::new(CERTIFICATE_AUTHORIZATION_TIMEOUT),
            certificate_request_listeners: Arc::new(RwLock::new(HashMap::new())),
            certificate_request_listener_id: AtomicU64::new(0),
        }
    }

    /// Set certificate types that every subsequently-created peer requests in
    /// its BRC-103 handshake. Existing connections keep their original Peer
    /// configuration.
    pub fn set_certificates_to_request(&self, requested: RequestedCertificateSet) {
        *self.certificates_to_request.write() = Some(requested);
    }

    /// Set the pending certificate-authorization deadline for subsequently
    /// created connections. Existing connections retain their snapshotted
    /// deadline. Configure this before [`crate::server_io::attach`].
    pub fn set_certificate_authorization_timeout(&self, timeout: Duration) {
        assert!(
            !timeout.is_zero(),
            "certificate authorization timeout must be non-zero"
        );
        *self.certificate_authorization_timeout.write() = timeout;
    }

    /// Register the async accept/reject decision for received certificates.
    ///
    /// The future is awaited inside [`Self::on_auth_message`]. While a requested
    /// certificate decision is pending, verified application events are
    /// suppressed. Rejection is terminal for the core connection and is also
    /// exposed through [`Self::certificate_authorization`]; [`crate::server_io::attach`]
    /// closes the corresponding socket immediately.
    ///
    /// The authorizer receives only batches emitted by bsv-sdk 0.7.1's verified
    /// certificate channel. Before delivery, the SDK verifies the response's
    /// nonce, active session (including idle TTL), response signature and
    /// replay nonce, then verifies each certificate's subject and certificate
    /// signature. On this response path 0.7.1 does **not** enforce that a
    /// certificate's type was requested, so the authorizer MUST check the type
    /// as well as application policy such as trusted certifiers and current
    /// revocation status before accepting.
    ///
    /// `Certificate` does not include the selective-disclosure keyring, so its
    /// field values generally remain encrypted here and cannot be passed to
    /// `decrypt_fields`. Base authorization on authenticated metadata, or carry
    /// a separately verified disclosure proof in the application protocol.
    ///
    /// Configure both the request and authorizer before connections are added
    /// (normally before [`crate::server_io::attach`]); configuration is
    /// snapshotted at connect time and never retrofits existing sockets. An
    /// accepted socket does not re-run this authorizer for later certificate
    /// responses: renewal, rotation, and step-up require a new connection.
    ///
    /// Configuring an authorizer without [`Self::set_certificates_to_request`]
    /// still gates every new connection as `Pending`; the peer must provide a
    /// session-bound certificate response before the deadline. The inverse
    /// configuration (a requested set without an authorizer) is rejected when
    /// the connection is created and logged as an error.
    pub fn set_certificate_authorizer<F, Fut>(&self, authorizer: F)
    where
        F: Fn(String, Vec<Certificate>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = CertificateAuthorizationDecision> + Send + 'static,
    {
        *self.certificate_authorizer.write() = Some(Arc::new(move |identity, certificates| {
            Box::pin(authorizer(identity, certificates))
        }));
    }

    /// Register a freshly-connected socket with its own BRC-103 session.
    /// `wallet` is the server wallet (e.g. a `ProtoWallet` over the server key).
    pub fn add_connection(&self, socket_id: impl Into<String>, wallet: W) {
        let socket_id = socket_id.into();
        let requested = self.certificates_to_request.read().clone();
        let has_authorizer = self.certificate_authorizer.read().is_some();
        let authorization_timeout = *self.certificate_authorization_timeout.read();
        let (authorization, certificate_deadline) = match (requested.is_some(), has_authorizer) {
            (_, true) => (
                CertificateAuthorization::Pending,
                Some(Instant::now() + authorization_timeout),
            ),
            (true, false) => {
                tracing::error!(socket = %socket_id,
                    "authsocket: certificates requested without a certificate authorizer; connection rejected");
                (
                    CertificateAuthorization::Rejected {
                        identity_key: String::new(),
                        reason: "server requested certificates but no certificate authorizer is configured"
                            .into(),
                    },
                    None,
                )
            }
            (false, false) => (CertificateAuthorization::NotRequired, None),
        };
        let listeners = self.certificate_request_listeners.read();
        let conn = Arc::new(Connection {
            handle: PeerHandle::new_for_server(wallet, requested, has_authorizer),
            identity_key: RwLock::new(None),
            session_peer_identity_key: RwLock::new(None),
            certificate_authorization: RwLock::new(authorization),
            certificate_deadline,
            certificate_timeout: has_authorizer.then_some(authorization_timeout),
            deferred_events: Mutex::new(Vec::new()),
            certificate_deadline_task: RwLock::new(None),
            certificate_exchange_enabled: AtomicBool::new(has_authorizer || !listeners.is_empty()),
            certificate_request_bridge_id: RwLock::new(None),
        });
        // Listener check, bridge installation, and insertion are one atomic
        // critical section with respect to listen/stop operations.
        let mut conns = self.conns.write();
        if !listeners.is_empty() {
            self.install_certificate_request_bridge(&socket_id, &conn);
        }
        conns.insert(socket_id, conn);
    }

    /// Drop a socket and its room memberships.
    pub fn remove_connection(&self, socket_id: &str) {
        if let Some(conn) = self.conns.write().remove(socket_id) {
            Self::abort_certificate_deadline_task(&conn);
        }
        let mut rooms = self.rooms.write();
        for members in rooms.values_mut() {
            members.remove(socket_id);
        }
        rooms.retain(|_, m| !m.is_empty());
    }

    /// Look up a connection handle (brief lock, `Arc` cloned out).
    fn conn(&self, socket_id: &str) -> Option<Arc<Connection<W>>> {
        self.conns.read().get(socket_id).cloned()
    }

    /// Current certificate authorization state for `socket_id`.
    pub fn certificate_authorization(&self, socket_id: &str) -> Option<CertificateAuthorization> {
        let conn = self.conn(socket_id)?;
        Self::expire_connection(&conn);
        let authorization = conn.certificate_authorization.read().clone();
        Some(authorization)
    }

    /// Transition an overdue `Pending` connection to terminal rejection.
    /// Returns `true` only when this call performed the transition.
    pub fn expire_certificate_authorization(&self, socket_id: &str) -> bool {
        let Some(conn) = self.conn(socket_id) else {
            return false;
        };
        Self::expire_connection(&conn)
    }

    fn expire_connection(conn: &Connection<W>) -> bool {
        if !matches!(conn.certificate_deadline, Some(deadline) if Instant::now() >= deadline) {
            return false;
        }
        let mut authorization = conn.certificate_authorization.write();
        if !matches!(*authorization, CertificateAuthorization::Pending) {
            return false;
        }
        *authorization = CertificateAuthorization::Rejected {
            identity_key: conn.identity_key.read().clone().unwrap_or_default(),
            reason: format!(
                "certificate authorization timed out after {}s",
                conn.certificate_timeout.unwrap_or_default().as_secs_f64()
            ),
        };
        drop(authorization);
        Self::abort_certificate_deadline_task(conn);
        true
    }

    fn abort_certificate_deadline_task(conn: &Connection<W>) {
        if let Some(task) = conn.certificate_deadline_task.write().take() {
            task.abort();
        }
    }

    pub(crate) fn set_certificate_authorization_deadline_task(
        &self,
        socket_id: &str,
        task: JoinHandle<()>,
    ) {
        let Some(conn) = self.conn(socket_id) else {
            task.abort();
            return;
        };
        if !matches!(
            *conn.certificate_authorization.read(),
            CertificateAuthorization::Pending
        ) {
            task.abort();
            return;
        }
        *conn.certificate_deadline_task.write() = Some(task);
        // Close the small race where authorization resolved after the first
        // state check but before the handle was stored.
        if !matches!(
            *conn.certificate_authorization.read(),
            CertificateAuthorization::Pending
        ) {
            Self::abort_certificate_deadline_task(&conn);
        }
    }

    pub(crate) fn certificate_authorization_deadline(&self, socket_id: &str) -> Option<Instant> {
        self.conn(socket_id)
            .and_then(|conn| conn.certificate_deadline)
    }

    /// Register a server-wide certificate-request listener and install an SDK
    /// listener bridge on every current and future peer. While at least one
    /// listener is registered, SDK auto-response is overridden, matching
    /// `Peer::listen_for_certificates_requested`.
    pub fn listen_for_certificates_requested(&self, callback: Arc<OnCertificatesRequested>) -> u64 {
        let id = self
            .certificate_request_listener_id
            .fetch_add(1, Ordering::Relaxed);
        let mut listeners = self.certificate_request_listeners.write();
        listeners.insert(id, callback);
        let conns = self.conns.read();
        for (sid, conn) in conns.iter() {
            conn.certificate_exchange_enabled
                .store(true, Ordering::SeqCst);
            self.install_certificate_request_bridge(sid, conn);
        }
        id
    }

    /// Stop a server-wide certificate-request listener. Removing the final
    /// listener restores SDK auto-response behavior on all current peers.
    pub fn stop_listening_for_certificates_requested(&self, callback_id: u64) {
        let mut listeners = self.certificate_request_listeners.write();
        listeners.remove(&callback_id);
        let empty = listeners.is_empty();
        if !empty {
            return;
        }
        let conns = self.conns.read();
        for conn in conns.values() {
            if let Some(id) = conn.certificate_request_bridge_id.write().take() {
                conn.handle.stop_listening_for_certificates_requested(id);
            }
        }
    }

    fn install_certificate_request_bridge(&self, socket_id: &str, conn: &Arc<Connection<W>>) {
        let mut bridge_id = conn.certificate_request_bridge_id.write();
        if bridge_id.is_some() {
            return;
        }
        let listeners = self.certificate_request_listeners.clone();
        let socket_id = socket_id.to_string();
        let callback: Arc<OnCertificateRequestReceived> = Arc::new(
            move |identity_key: String, requested: RequestedCertificateSet| {
                let callbacks: Vec<Arc<OnCertificatesRequested>> =
                    listeners.read().values().cloned().collect();
                for callback in callbacks {
                    callback(socket_id.clone(), identity_key.clone(), requested.clone());
                }
            },
        );
        *bridge_id = Some(conn.handle.listen_for_certificates_requested(callback));
    }

    /// Send a certificate response on one connection and return the signed
    /// BRC-103 frames the transport consumer must emit as `authMessage`.
    pub async fn send_certificate_response(
        &self,
        socket_id: &str,
        identity_key: &str,
        certificates: Vec<Certificate>,
    ) -> Result<Vec<AuthMessage>, AuthError> {
        let conn = self.conn(socket_id).ok_or_else(|| {
            AuthError::SessionNotFound(format!("socket connection not found: {socket_id}"))
        })?;
        conn.handle
            .send_certificate_response_existing(identity_key, certificates)
            .await
    }

    /// Advance a socket's protocol on an inbound `"authMessage"`.
    ///
    /// Records the socket's identity from the **verified sender** of each
    /// decoded general message (never from the frame's unverified
    /// `identity_key` claim), *before* returning the events for dispatch — so
    /// room-ownership / sender checks in the consumer always see the verified
    /// identity.
    pub async fn on_auth_message(&self, socket_id: &str, msg: AuthMessage) -> Driven {
        let Some(conn) = self.conn(socket_id) else {
            return Driven {
                outbound: vec![],
                events: vec![],
            };
        };
        Self::expire_connection(&conn);

        if matches!(
            *conn.certificate_authorization.read(),
            CertificateAuthorization::Rejected { .. }
        ) {
            return Driven {
                outbound: vec![],
                events: vec![],
            };
        }

        // Peer work outside any map lock — other sockets proceed concurrently.
        // The default-off path calls the original drive primitive directly: no
        // certificate channel allocation and no additional await/yield.
        let message_type = msg.message_type.clone();
        let message_identity_key = msg.identity_key.clone();
        let certificate_response = message_type == MessageType::CertificateResponse;
        let (outbound, mut events) = if conn.certificate_exchange_enabled.load(Ordering::SeqCst) {
            let certificate_drive = conn.handle.drive_certificate_aware(msg).await;
            if message_type == MessageType::InitialRequest && certificate_drive.error.is_none() {
                let mut session_identity = conn.session_peer_identity_key.write();
                match session_identity.as_ref() {
                    None => *session_identity = Some(message_identity_key),
                    Some(identity) if identity == &message_identity_key => {}
                    Some(_) => Self::reject_pending_certificate_response(
                        &conn,
                        "BRC-103 session identity changed on one socket".into(),
                    ),
                }
            }
            if certificate_response {
                if let Some(error) = &certificate_drive.error {
                    Self::reject_pending_certificate_response(
                        &conn,
                        format!("bsv-sdk rejected certificateResponse: {error}"),
                    );
                }
            }
            let mut released_events = Vec::new();
            // On a server peer, bsv-sdk 0.7.1 delivers this channel only from a
            // successfully processed certificateResponse.
            for (identity_key, certificates) in certificate_drive.certificates {
                released_events.extend(
                    self.authorize_verified_certificates(&conn, identity_key, certificates)
                        .await,
                );
            }
            let mut events = certificate_drive.events;
            events.extend(released_events);
            (certificate_drive.outbound, events)
        } else {
            conn.handle.drive(msg).await
        };

        self.gate_or_defer_events(socket_id, &conn, &mut events)
            .await;

        for ev in &events {
            if is_valid_identity_key(&ev.sender) {
                *conn.identity_key.write() = Some(ev.sender.clone());
            }
        }
        Driven { outbound, events }
    }

    fn reject_pending_certificate_response(conn: &Connection<W>, reason: String) {
        let mut authorization = conn.certificate_authorization.write();
        if matches!(*authorization, CertificateAuthorization::Pending) {
            *authorization = CertificateAuthorization::Rejected {
                identity_key: conn.identity_key.read().clone().unwrap_or_default(),
                reason,
            };
            drop(authorization);
            Self::abort_certificate_deadline_task(conn);
        }
    }

    async fn gate_or_defer_events(
        &self,
        socket_id: &str,
        conn: &Connection<W>,
        events: &mut Vec<VerifiedEvent>,
    ) {
        if events.is_empty()
            || matches!(
                *conn.certificate_authorization.read(),
                CertificateAuthorization::NotRequired
            )
        {
            return;
        }

        // The same mutex covers the pending queue and the authorizer's state
        // transition. If a decision is in flight, this handler waits here and
        // then either delivers its event after acceptance or drops it after a
        // terminal rejection. If no decision has started yet, it deposits the
        // events for the certificateResponse handler to release.
        let mut deferred = conn.deferred_events.lock().await;
        let authorization = conn.certificate_authorization.read().clone();
        match authorization {
            CertificateAuthorization::NotRequired => {}
            CertificateAuthorization::Accepted { identity_key } => {
                if events.iter().any(|event| event.sender != identity_key) {
                    *conn.certificate_authorization.write() = CertificateAuthorization::Rejected {
                        identity_key,
                        reason: "certificate identity does not match general-message sender".into(),
                    };
                    deferred.clear();
                    events.clear();
                    Self::abort_certificate_deadline_task(conn);
                }
            }
            CertificateAuthorization::Pending => {
                tracing::debug!(socket = %socket_id,
                    count = events.len(),
                    "authsocket: application events deferred pending certificate authorization");
                deferred.append(events);
            }
            CertificateAuthorization::Rejected { .. } => {
                deferred.clear();
                events.clear();
            }
        }
    }

    async fn authorize_verified_certificates(
        &self,
        conn: &Arc<Connection<W>>,
        identity_key: String,
        certificates: Vec<Certificate>,
    ) -> Vec<VerifiedEvent> {
        let mut deferred = conn.deferred_events.lock().await;
        if !matches!(
            *conn.certificate_authorization.read(),
            CertificateAuthorization::Pending
        ) {
            deferred.clear();
            return Vec::new();
        }

        if conn.session_peer_identity_key.read().as_deref() != Some(identity_key.as_str()) {
            *conn.certificate_authorization.write() = CertificateAuthorization::Rejected {
                identity_key,
                reason: "certificate-response signer does not match the BRC-103 session peer"
                    .into(),
            };
            deferred.clear();
            Self::abort_certificate_deadline_task(conn);
            return Vec::new();
        }

        let Some(authorizer) = self.certificate_authorizer.read().clone() else {
            Self::reject_pending_certificate_response(
                conn,
                "SDK-verified certificates received but no certificate authorizer is configured"
                    .into(),
            );
            deferred.clear();
            return Vec::new();
        };

        // `identity_key` and the batch come exclusively from Peer::on_certificates,
        // after bsv-sdk authenticated the response and certificate signatures.
        let decision = authorizer(identity_key.clone(), certificates).await;

        // This is the sole post-await transition guard. A timeout/rejection that
        // won concurrently is terminal and cannot be revived by a late Accept.
        let mut authorization = conn.certificate_authorization.write();
        if !matches!(*authorization, CertificateAuthorization::Pending) {
            deferred.clear();
            return Vec::new();
        }
        let accepted = matches!(decision, CertificateAuthorizationDecision::Accept);
        *authorization = match decision {
            CertificateAuthorizationDecision::Accept => {
                CertificateAuthorization::Accepted { identity_key }
            }
            CertificateAuthorizationDecision::Reject(reason) => {
                CertificateAuthorization::Rejected {
                    identity_key,
                    reason,
                }
            }
        };
        drop(authorization);
        Self::abort_certificate_deadline_task(conn);
        if accepted {
            std::mem::take(&mut *deferred)
        } else {
            deferred.clear();
            Vec::new()
        }
    }

    /// This socket's verified identity key, if a verified general message has
    /// established one.
    pub fn identity_key(&self, socket_id: &str) -> Option<String> {
        self.conn(socket_id)
            .and_then(|c| c.identity_key.read().clone())
    }

    pub fn join_room(&self, socket_id: impl Into<String>, room_id: impl Into<String>) {
        self.rooms
            .write()
            .entry(room_id.into())
            .or_default()
            .insert(socket_id.into());
    }

    pub fn leave_room(&self, socket_id: &str, room_id: &str) {
        let mut rooms = self.rooms.write();
        if let Some(members) = rooms.get_mut(room_id) {
            members.remove(socket_id);
            if members.is_empty() {
                rooms.remove(room_id);
            }
        }
    }

    /// Socket ids currently joined to `room_id`.
    pub fn room_members(&self, room_id: &str) -> Vec<String> {
        self.rooms
            .read()
            .get(room_id)
            .map(|m| m.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Sign `event`/`data` for every **authenticated** member of `room_id` and
    /// return `(socket_id, AuthMessage)` pairs to `emit` as `"authMessage"`.
    /// THE signed broadcast — replaces the raw `io.to(room).emit`.
    ///
    /// Fails closed per member: a socket without a verified identity or
    /// without an authenticated session is skipped (`emit_existing` never
    /// initiates a handshake). Signs run concurrently across members — the
    /// signs are independent (distinct sockets), so fan-out is O(sign), not
    /// O(members x sign).
    pub async fn emit_to_room(
        &self,
        room_id: &str,
        event_name: &str,
        data: &Value,
    ) -> Vec<(String, AuthMessage)> {
        let member_ids = self.room_members(room_id);

        // Snapshot (socket id, connection, identity) under brief locks…
        let members: Vec<(String, Arc<Connection<W>>, String)> = {
            let conns = self.conns.read();
            member_ids
                .into_iter()
                .filter_map(|sid| {
                    let conn = conns.get(&sid)?.clone();
                    let key = conn.identity_key.read().clone()?; // not yet authed -> skip
                    Some((sid, conn, key))
                })
                .collect()
        };

        // …then sign for all members concurrently, outside every map lock.
        let signs = members.iter().map(|(sid, conn, key)| async move {
            (sid, conn.handle.emit_existing(key, event_name, data).await)
        });
        let mut out = Vec::new();
        for (sid, result) in join_all(signs).await {
            match result {
                Ok(msgs) => out.extend(msgs.into_iter().map(|m| (sid.clone(), m))),
                Err(e) => tracing::warn!(
                    socket = %sid, room = %room_id, error = %e,
                    "emit_to_room: sign failed (no authenticated session or signer error) — member skipped"
                ),
            }
        }
        out
    }

    /// Sign an app event for a single **authenticated** socket; returns the
    /// `AuthMessage`s to emit. Fails closed like [`Self::emit_to_room`].
    pub async fn emit_to_socket(
        &self,
        socket_id: &str,
        event_name: &str,
        data: &Value,
    ) -> Vec<AuthMessage> {
        let Some(conn) = self.conn(socket_id) else {
            return vec![];
        };
        let Some(key) = conn.identity_key.read().clone() else {
            return vec![];
        };
        match conn.handle.emit_existing(&key, event_name, data).await {
            Ok(msgs) => msgs,
            Err(e) => {
                tracing::debug!(socket = %socket_id, error = %e,
                    "emit_to_socket: no authenticated session, skipping");
                vec![]
            }
        }
    }
}

/// Convenience alias for sharing the server across socketioxide handlers.
pub type SharedAuthSocketServer<W> = Arc<AuthSocketServer<W>>;

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::auth::certificates::AuthCertificate;
    use bsv::auth::peer::Peer;
    use bsv::auth::types::{AuthMessage, MessageType, RequestedCertificateSet};
    use bsv::primitives::private_key::PrivateKey;
    use bsv::primitives::public_key::PublicKey;
    use bsv::wallet::interfaces::{Certificate, CertificateType, SerialNumber};
    use bsv::wallet::proto_wallet::ProtoWallet;
    use serde_json::json;

    use crate::transport::ChannelTransport;
    use crate::wire::encode_event;

    fn wallet(scalar_hex_byte: u8) -> ProtoWallet {
        let mut hex = String::new();
        for _ in 0..31 {
            hex.push_str("00");
        }
        hex.push_str(&format!("{scalar_hex_byte:02x}"));
        ProtoWallet::new(PrivateKey::from_hex(&hex).expect("test key"))
    }

    /// A client-side Peer wired to raw channels, plus its identity key.
    struct TestClient {
        peer: Arc<Peer<ProtoWallet>>,
        /// Frames the client produced (to hand to the server).
        out_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<AuthMessage>>,
        /// Feed server->client frames here.
        in_tx: tokio::sync::mpsc::Sender<AuthMessage>,
        identity: String,
    }

    async fn test_client(scalar: u8) -> TestClient {
        use bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
        let w = wallet(scalar);
        let identity = w
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .expect("identity key")
            .public_key
            .to_der_hex();
        let (transport, in_tx, out_rx) = ChannelTransport::new();
        let peer = Arc::new(Peer::new(w, Arc::new(transport)));
        TestClient {
            peer,
            out_rx: tokio::sync::Mutex::new(out_rx),
            in_tx,
            identity,
        }
    }

    /// Complete a full BRC-103 handshake + first general message between a
    /// client Peer and `server` socket `sid`, by pumping frames both ways.
    /// Returns once the client's `send_message` future resolves.
    async fn client_send(
        server: &AuthSocketServer<ProtoWallet>,
        sid: &str,
        client: &TestClient,
        event: &str,
        data: &Value,
    ) {
        let _ = client_send_collect(server, sid, client, event, data).await;
    }

    async fn client_send_collect(
        server: &AuthSocketServer<ProtoWallet>,
        sid: &str,
        client: &TestClient,
        event: &str,
        data: &Value,
    ) -> Vec<VerifiedEvent> {
        let payload = encode_event(event, data);
        let peer = client.peer.clone();
        // send_message("") initiates the handshake and blocks polling the
        // transport until the initialResponse arrives — pump concurrently.
        let send = tokio::spawn(async move { peer.send_message("", payload).await });

        // Pump frames until the send completes AND its frames are drained
        // (send_message enqueues the general frame before resolving, so one
        // more empty try_recv after observing completion is a true quiescence).
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut finished = false;
        let mut events = Vec::new();
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "handshake pump timed out"
            );
            // client -> server
            let frame = {
                let mut rx = client.out_rx.lock().await;
                rx.try_recv().ok()
            };
            if let Some(frame) = frame {
                let driven = server.on_auth_message(sid, frame).await;
                events.extend(driven.events);
                // server -> client
                for m in driven.outbound {
                    let _ = client.in_tx.send(m).await;
                }
            } else if finished {
                break;
            } else {
                finished = send.is_finished();
                if !finished {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
        }
        send.await.expect("send task").expect("client send_message");
        events
    }

    async fn identity_for_scalar(scalar: u8) -> String {
        use bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
        wallet(scalar)
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .expect("identity key")
            .public_key
            .to_der_hex()
    }

    fn requested_certificates(certifier: String) -> RequestedCertificateSet {
        let mut requested = RequestedCertificateSet {
            certifiers: vec![certifier],
            ..RequestedCertificateSet::default()
        };
        // base64([7; 32])
        requested.insert(
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".to_string(),
            vec!["membership".to_string()],
        );
        requested
    }

    async fn membership_certificate(subject: &str, certifier_scalar: u8) -> Certificate {
        let certifier_wallet = wallet(certifier_scalar);
        let mut certificate = Certificate {
            cert_type: CertificateType([7; 32]),
            serial_number: SerialNumber([9; 32]),
            subject: PublicKey::from_string(subject).expect("subject key"),
            certifier: PublicKey::from_string(&identity_for_scalar(certifier_scalar).await)
                .expect("certifier key"),
            revocation_outpoint: Some("00".repeat(32)),
            fields: None,
            signature: None,
        };
        AuthCertificate::sign(&mut certificate, &certifier_wallet)
            .await
            .expect("sign membership certificate");
        certificate
    }

    async fn send_certificates(
        server: &AuthSocketServer<ProtoWallet>,
        sid: &str,
        client: &TestClient,
        server_identity: &str,
        certificates: Vec<Certificate>,
    ) {
        let frame = certificate_response_frame(client, server_identity, certificates).await;
        let driven = server.on_auth_message(sid, frame).await;
        for message in driven.outbound {
            let _ = client.in_tx.send(message).await;
        }
    }

    async fn certificate_response_frame(
        client: &TestClient,
        server_identity: &str,
        certificates: Vec<Certificate>,
    ) -> AuthMessage {
        client
            .peer
            .send_certificate_response(server_identity, certificates)
            .await
            .expect("send certificateResponse");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let frame = {
                let mut rx = client.out_rx.lock().await;
                rx.try_recv().ok()
            };
            if let Some(frame) = frame {
                return frame;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "certificateResponse was not emitted"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn requested_certificates_are_received_and_acceptance_gates_session() {
        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        client
            .peer
            .listen_for_certificates_requested(Arc::new(|_, _| {}));
        let mut request_rx = client
            .peer
            .on_certificate_request()
            .expect("fresh certificate request receiver");

        let server = AuthSocketServer::new();
        server.set_certificates_to_request(requested_certificates(server_identity.clone()));
        let seen = Arc::new(std::sync::Mutex::new(Vec::<(String, usize)>::new()));
        let seen_cb = seen.clone();
        let expected_identity = client.identity.clone();
        server.set_certificate_authorizer(move |identity, certificates| {
            let seen = seen_cb.clone();
            let expected_identity = expected_identity.clone();
            async move {
                seen.lock()
                    .expect("seen mutex")
                    .push((identity.clone(), certificates.len()));
                if identity == expected_identity
                    && certificates.len() == 1
                    && certificates[0].cert_type == CertificateType([7; 32])
                {
                    CertificateAuthorizationDecision::Accept
                } else {
                    CertificateAuthorizationDecision::Reject(
                        "membership certificate did not match".into(),
                    )
                }
            }
        });
        server.add_connection("sock1", wallet(0x11));

        // The first general event completes BRC-103 structurally, but cannot
        // establish application identity before certificate authorization.
        let events =
            client_send_collect(&server, "sock1", &client, "authenticated", &json!({})).await;
        assert!(
            events.is_empty(),
            "pending certificate gate must suppress events"
        );
        assert_eq!(server.identity_key("sock1"), None);
        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Pending)
        );

        let (requester, requested) = request_rx
            .try_recv()
            .expect("handshake certificate request");
        assert_eq!(requester, server_identity);
        assert!(requested.contains_key("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="));

        let certificate = membership_certificate(&client.identity, 0x11).await;
        send_certificates(
            &server,
            "sock1",
            &client,
            &server_identity,
            vec![certificate],
        )
        .await;
        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Accepted {
                identity_key: client.identity.clone()
            })
        );
        assert_eq!(
            *seen.lock().expect("seen mutex"),
            vec![(client.identity.clone(), 1)],
            "the blocking authorizer receives the peer identity and certificates"
        );

        let events =
            client_send_collect(&server, "sock1", &client, "authenticated", &json!({})).await;
        assert_eq!(events.len(), 1, "accepted peer may proceed");
        assert_eq!(server.identity_key("sock1"), Some(client.identity.clone()));
    }

    #[tokio::test]
    async fn certificate_rejection_is_surfaced_and_never_silently_passes() {
        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        client
            .peer
            .listen_for_certificates_requested(Arc::new(|_, _| {}));
        let server = AuthSocketServer::new();
        server.set_certificates_to_request(requested_certificates(server_identity.clone()));
        let decisions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let decisions_cb = decisions.clone();
        server.set_certificate_authorizer(move |_, _| {
            let attempt = decisions_cb.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt == 0 {
                    CertificateAuthorizationDecision::Reject("membership revoked".into())
                } else {
                    CertificateAuthorizationDecision::Accept
                }
            }
        });
        server.add_connection("sock1", wallet(0x11));

        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        send_certificates(
            &server,
            "sock1",
            &client,
            &server_identity,
            vec![membership_certificate(&client.identity, 0x11).await],
        )
        .await;

        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected {
                identity_key: client.identity.clone(),
                reason: "membership revoked".into(),
            }),
            "the rejection and reason are observable by transport consumers"
        );
        let rejected_frame = client
            .peer
            .create_general_message(&server_identity, encode_event("appPing", &json!({})))
            .await
            .expect("sign against existing session");
        let events = server.on_auth_message("sock1", rejected_frame).await.events;
        assert!(
            events.is_empty(),
            "a rejected peer must never dispatch events"
        );
        assert_eq!(server.identity_key("sock1"), None);

        // A later valid batch whose callback would accept must not run and must
        // never revive a terminal rejection.
        send_certificates(
            &server,
            "sock1",
            &client,
            &server_identity,
            vec![membership_certificate(&client.identity, 0x11).await],
        )
        .await;
        assert_eq!(decisions.load(Ordering::SeqCst), 1);
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected { reason, .. })
                if reason == "membership revoked"
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn no_certificate_configuration_preserves_legacy_handshake() {
        let server = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        let conn = server.conn("sock1").expect("default connection");
        assert!(
            conn.handle.peer().on_certificates().is_none(),
            "default server construction must take and drop the bounded SDK certificate receiver"
        );
        let client = test_client(0x22).await;

        let payload = encode_event("authenticated", &json!({}));
        let peer = client.peer.clone();
        let send = tokio::spawn(async move { peer.send_message("", payload).await });
        let initial_request = loop {
            if let Ok(frame) = client.out_rx.lock().await.try_recv() {
                break frame;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        };
        let certificate_io = conn.handle.lock_certificate_io_for_test().await;
        let before = tokio::time::Instant::now();
        let driven = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            server.on_auth_message("sock1", initial_request),
        )
        .await
        .expect("legacy drive must not acquire the certificate I/O mutex");
        assert_eq!(
            tokio::time::Instant::now(),
            before,
            "legacy initialRequest drive must introduce no timer await"
        );
        drop(certificate_io);
        assert_eq!(driven.outbound.len(), 1);
        assert_eq!(
            driven.outbound[0].message_type,
            MessageType::InitialResponse
        );
        assert!(
            driven.outbound[0].requested_certificates.is_none(),
            "default-off must not add requestedCertificates to the wire"
        );
        assert!(driven.outbound[0].certificates.is_none());
        assert!(driven.outbound[0].payload.is_none());
        assert!(driven.outbound[0].signature.is_some());
        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::NotRequired)
        );
        for response in driven.outbound {
            let _ = client.in_tx.send(response).await;
        }

        let general = loop {
            if let Ok(frame) = client.out_rx.lock().await.try_recv() {
                break frame;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        };
        let certificate_io = conn.handle.lock_certificate_io_for_test().await;
        let before = tokio::time::Instant::now();
        let driven = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            server.on_auth_message("sock1", general),
        )
        .await
        .expect("legacy drive must not acquire the certificate I/O mutex");
        assert_eq!(
            tokio::time::Instant::now(),
            before,
            "legacy general-message drive must introduce no timer await"
        );
        assert_eq!(driven.events.len(), 1, "legacy event flow remains admitted");
        assert!(
            driven.outbound.is_empty(),
            "legacy event ordering is unchanged"
        );
        drop(certificate_io);
        send.await.expect("send task").expect("send message");
    }

    #[tokio::test]
    async fn default_server_drains_unsolicited_verified_certificate_batches() {
        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        let server = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        let certificate = membership_certificate(&client.identity, 0x11).await;

        for response_number in 1..=33 {
            let frame =
                certificate_response_frame(&client, &server_identity, vec![certificate.clone()])
                    .await;
            tokio::time::timeout(
                Duration::from_millis(250),
                server.on_auth_message("sock1", frame),
            )
            .await
            .unwrap_or_else(|_| panic!("certificateResponse {response_number} wedged"));
        }
    }

    #[tokio::test]
    async fn late_certificate_listener_does_not_wedge_response_processing() {
        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        let server = Arc::new(AuthSocketServer::new());
        server.add_connection("sock1", wallet(0x11));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        server.listen_for_certificates_requested(Arc::new(|_, _, _| {}));
        let certificate = membership_certificate(&client.identity, 0x11).await;

        for response_number in 1..=33 {
            let frame =
                certificate_response_frame(&client, &server_identity, vec![certificate.clone()])
                    .await;
            tokio::time::timeout(
                Duration::from_millis(250),
                server.on_auth_message("sock1", frame),
            )
            .await
            .unwrap_or_else(|_| panic!("certificateResponse {response_number} wedged"));
        }

        tokio::time::timeout(
            Duration::from_millis(250),
            server.send_certificate_response("sock1", &client.identity, Vec::new()),
        )
        .await
        .expect("a later server certificate response must not wedge")
        .expect("the established session accepts a certificate response");
    }

    #[tokio::test]
    async fn tampered_certificate_batch_and_garbage_signature_never_reach_authorizer() {
        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        client
            .peer
            .listen_for_certificates_requested(Arc::new(|_, _| {}));

        let invocations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let invocations_cb = invocations.clone();
        let server = AuthSocketServer::new();
        server.set_certificates_to_request(requested_certificates(server_identity.clone()));
        server.set_certificate_authorizer(move |_, _| {
            invocations_cb.fetch_add(1, Ordering::SeqCst);
            async { CertificateAuthorizationDecision::Accept }
        });
        server.add_connection("sock1", wallet(0x11));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;

        let genuine = membership_certificate(&client.identity, 0x11).await;
        let mut tampered =
            certificate_response_frame(&client, &server_identity, vec![genuine]).await;
        let attacker_chosen_subject = identity_for_scalar(0x33).await;
        tampered.certificates = Some(vec![
            membership_certificate(&attacker_chosen_subject, 0x11).await,
        ]);
        tampered.signature = Some(vec![0xde, 0xad, 0xbe, 0xef]);

        let driven = server.on_auth_message("sock1", tampered).await;
        assert!(driven.outbound.is_empty() && driven.events.is_empty());
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            0,
            "only SDK-verified batches may reach the authorizer"
        );
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected { reason, .. })
                if reason.contains("bsv-sdk rejected certificateResponse")
        ));
    }

    #[tokio::test]
    async fn unsigned_pre_handshake_certificate_response_is_terminally_rejected() {
        let client_identity = identity_for_scalar(0x22).await;
        let invocations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let invocations_cb = invocations.clone();
        let server = AuthSocketServer::new();
        server.set_certificate_authorizer(move |_, _| {
            invocations_cb.fetch_add(1, Ordering::SeqCst);
            async { CertificateAuthorizationDecision::Accept }
        });
        server.add_connection("sock1", wallet(0x11));

        let driven = server
            .on_auth_message(
                "sock1",
                AuthMessage {
                    version: "0.1".into(),
                    message_type: MessageType::CertificateResponse,
                    identity_key: client_identity.clone(),
                    nonce: Some("attacker-nonce".into()),
                    your_nonce: Some("forged-session-nonce".into()),
                    initial_nonce: None,
                    certificates: Some(vec![membership_certificate(&client_identity, 0x11).await]),
                    requested_certificates: None,
                    payload: None,
                    signature: None,
                },
            )
            .await;
        assert!(driven.outbound.is_empty() && driven.events.is_empty());
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected { identity_key, reason })
                if identity_key.is_empty() && reason.contains("bsv-sdk rejected certificateResponse")
        ));

        // Terminal means even a subsequent genuine handshake cannot revive or
        // produce a response/event on this socket.
        let client = test_client(0x22).await;
        let peer = client.peer.clone();
        let send = tokio::spawn(async move {
            peer.send_message("", encode_event("authenticated", &json!({})))
                .await
        });
        let initial_request = loop {
            if let Ok(frame) = client.out_rx.lock().await.try_recv() {
                break frame;
            }
            tokio::task::yield_now().await;
        };
        let driven = server.on_auth_message("sock1", initial_request).await;
        assert!(driven.outbound.is_empty() && driven.events.is_empty());
        send.abort();
    }

    #[tokio::test]
    async fn half_configurations_fail_closed_and_are_observable() {
        let authorizer_only = AuthSocketServer::new();
        authorizer_only.set_certificate_authorizer(|_, _| async {
            CertificateAuthorizationDecision::Reject("denied".into())
        });
        authorizer_only.add_connection("sock-authorizer", wallet(0x11));
        assert_eq!(
            authorizer_only.certificate_authorization("sock-authorizer"),
            Some(CertificateAuthorization::Pending),
            "an authorizer by itself must gate instead of silently admitting"
        );

        let requested_only = AuthSocketServer::new();
        requested_only
            .set_certificates_to_request(requested_certificates(identity_for_scalar(0x11).await));
        requested_only.add_connection("sock-request", wallet(0x11));
        assert!(matches!(
            requested_only.certificate_authorization("sock-request"),
            Some(CertificateAuthorization::Rejected { reason, .. })
                if reason.contains("no certificate authorizer")
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn pending_certificate_authorization_has_a_terminal_deadline() {
        let server = AuthSocketServer::new();
        assert!(CERTIFICATE_AUTHORIZATION_TIMEOUT >= Duration::from_secs(30));
        server.set_certificate_authorization_timeout(Duration::from_secs(45));
        server
            .set_certificate_authorizer(|_, _| async { CertificateAuthorizationDecision::Accept });
        server.add_connection("sock1", wallet(0x11));
        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Pending)
        );
        tokio::time::advance(Duration::from_secs(44)).await;
        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Pending),
            "the per-server timeout must be snapshotted by the connection"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected { reason, .. })
                if reason.contains("timed out")
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn legitimate_slow_authorizer_completes_with_the_sane_default() {
        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        client
            .peer
            .listen_for_certificates_requested(Arc::new(|_, _| {}));
        let server = AuthSocketServer::new();
        server.set_certificates_to_request(requested_certificates(server_identity.clone()));
        server.set_certificate_authorizer(|_, _| async {
            tokio::time::sleep(Duration::from_millis(3_500)).await;
            CertificateAuthorizationDecision::Accept
        });
        server.add_connection("sock1", wallet(0x11));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        send_certificates(
            &server,
            "sock1",
            &client,
            &server_identity,
            vec![membership_certificate(&client.identity, 0x11).await],
        )
        .await;
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Accepted { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_winning_during_authorizer_is_terminal_after_late_accept() {
        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        client
            .peer
            .listen_for_certificates_requested(Arc::new(|_, _| {}));
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let server = Arc::new(AuthSocketServer::new());
        server.set_certificate_authorization_timeout(Duration::from_secs(5));
        server.set_certificates_to_request(requested_certificates(server_identity.clone()));
        let started_cb = started.clone();
        let release_cb = release.clone();
        server.set_certificate_authorizer(move |_, _| {
            let started = started_cb.clone();
            let release = release_cb.clone();
            async move {
                started.notify_one();
                release.notified().await;
                CertificateAuthorizationDecision::Accept
            }
        });
        server.add_connection("sock1", wallet(0x11));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        let frame = certificate_response_frame(
            &client,
            &server_identity,
            vec![membership_certificate(&client.identity, 0x11).await],
        )
        .await;
        let server_drive = server.clone();
        let drive = tokio::spawn(async move { server_drive.on_auth_message("sock1", frame).await });
        started.notified().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(server.expire_certificate_authorization("sock1"));
        release.notify_one();
        drive.await.expect("certificate drive");
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected { reason, .. }) if reason.contains("timed out")
        ));
    }

    #[tokio::test]
    async fn accepted_identity_mismatch_is_terminally_rejected() {
        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        client
            .peer
            .listen_for_certificates_requested(Arc::new(|_, _| {}));
        let server = AuthSocketServer::new();
        server.set_certificates_to_request(requested_certificates(server_identity.clone()));
        server
            .set_certificate_authorizer(|_, _| async { CertificateAuthorizationDecision::Accept });
        server.add_connection("sock1", wallet(0x11));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        send_certificates(
            &server,
            "sock1",
            &client,
            &server_identity,
            vec![membership_certificate(&client.identity, 0x11).await],
        )
        .await;

        let victim_identity = identity_for_scalar(0x33).await;
        let conn = server.conn("sock1").expect("connection");
        *conn.certificate_authorization.write() = CertificateAuthorization::Accepted {
            identity_key: victim_identity,
        };
        let frame = client
            .peer
            .create_general_message(&server_identity, encode_event("appPing", &json!({})))
            .await
            .expect("signed general frame");
        let driven = server.on_auth_message("sock1", frame).await;
        assert!(driven.events.is_empty());
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected { reason, .. })
                if reason.contains("does not match general-message sender")
        ));
    }

    #[tokio::test]
    async fn server_certificate_response_never_initiates_a_handshake() {
        let server = AuthSocketServer::new();
        server.listen_for_certificates_requested(Arc::new(|_, _, _| {}));
        server.add_connection("sock1", wallet(0x11));
        let unknown_identity = identity_for_scalar(0x22).await;
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            server.send_certificate_response("sock1", &unknown_identity, Vec::new()),
        )
        .await
        .expect("must fail immediately without polling for a handshake");
        assert!(matches!(result, Err(AuthError::SessionNotFound(_))));
        let conn = server.conn("sock1").expect("connection");
        assert!(
            conn.handle.drain_outbound().await.is_empty(),
            "non-initiating response must not queue an initialRequest"
        );
    }

    #[tokio::test]
    async fn certificate_request_listener_applies_to_peers_and_can_be_stopped() {
        let server = AuthSocketServer::new();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_cb = seen.clone();
        let listener_id = server.listen_for_certificates_requested(Arc::new(
            move |socket_id, identity_key, requested| {
                seen_cb.lock().expect("seen mutex").push((
                    socket_id,
                    identity_key,
                    requested.types.len(),
                ));
            },
        ));
        server.add_connection("sock1", wallet(0x11));

        let client = test_client(0x22).await;
        client
            .peer
            .set_certificates_to_request(requested_certificates(client.identity.clone()));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;

        assert_eq!(
            *seen.lock().expect("seen mutex"),
            vec![("sock1".to_string(), client.identity.clone(), 1)],
            "the server-wide listener receives socket, requester, and requested set"
        );
        let conn = server.conn("sock1").expect("connection");
        assert!(conn.certificate_request_bridge_id.read().is_some());

        server.stop_listening_for_certificates_requested(listener_id);
        assert!(conn.certificate_request_bridge_id.read().is_none());
    }

    #[tokio::test]
    async fn verified_sender_sets_identity() {
        let server = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        let client = test_client(0x22).await;

        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;

        assert_eq!(
            server.identity_key("sock1").as_deref(),
            Some(client.identity.as_str()),
            "identity must be the cryptographically verified sender"
        );
    }

    /// A1a: a general message whose envelope `identity_key` is forged (differs
    /// from the actual signer) must NOT set the room identity — the signature
    /// does not verify under the forged key, so the frame yields no event and
    /// no identity.
    #[tokio::test]
    async fn forged_envelope_identity_does_not_own_the_socket() {
        let server = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        let client = test_client(0x22).await;
        // The victim key the attacker claims to be.
        let victim = test_client(0x33).await;
        assert_ne!(client.identity, victim.identity);

        let payload = encode_event("authenticated", &json!({}));
        let peer = client.peer.clone();
        let send = tokio::spawn(async move { peer.send_message("", payload).await });

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_general = false;
        let mut finished = false;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "handshake pump timed out"
            );
            let frame = {
                let mut rx = client.out_rx.lock().await;
                rx.try_recv().ok()
            };
            if let Some(mut frame) = frame {
                let is_general = frame.message_type == MessageType::General;
                if is_general {
                    // Forge the unverified envelope claim.
                    frame.identity_key = victim.identity.clone();
                    saw_general = true;
                }
                let driven = server.on_auth_message("sock1", frame).await;
                if is_general {
                    assert!(
                        driven.events.is_empty(),
                        "forged general message must not verify into an event"
                    );
                }
                for m in driven.outbound {
                    let _ = client.in_tx.send(m).await;
                }
            } else if finished {
                break;
            } else {
                finished = send.is_finished();
                if !finished {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
        }
        let _ = send.await.expect("send task"); // client-side send may report success
        assert!(saw_general, "test must exercise the forged general frame");

        // The forged claim must not have become the socket identity.
        assert_ne!(
            server.identity_key("sock1").as_deref(),
            Some(victim.identity.as_str()),
            "A1a: forged envelope identity_key must never own the socket"
        );
        assert_eq!(
            server.identity_key("sock1"),
            None,
            "no verified general message -> no identity at all"
        );
    }

    /// A1b: an emit/broadcast to a socket that has not completed mutual auth
    /// must produce nothing — and must NOT initiate a handshake toward it.
    #[tokio::test]
    async fn emit_to_unauthenticated_socket_fails_closed() {
        let server = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        // Socket joined a room but never authenticated.
        server.join_room("sock1", "roomA");

        let msgs = server
            .emit_to_room("roomA", "sendMessage-roomA", &json!({"x": 1}))
            .await;
        assert!(
            msgs.is_empty(),
            "no signed frames for unauthenticated members"
        );

        let msgs = server.emit_to_socket("sock1", "hello", &json!({})).await;
        assert!(
            msgs.is_empty(),
            "no signed frames for unauthenticated socket"
        );

        // Crucially: nothing was queued toward the socket — no handshake was
        // initiated by the broadcast path (send_message would have produced an
        // initialRequest on the outbound channel).
        let conn = server.conn("sock1").expect("conn");
        assert!(
            conn.handle.drain_outbound().await.is_empty(),
            "A1b: broadcast must never initiate a handshake"
        );
    }

    /// A1a backbone — per-socket `Peer`/`SessionManager` isolation. A genuine,
    /// fully-signed general frame captured from one socket's completed handshake
    /// must NOT verify when replayed onto a *different* socket: its `your_nonce`
    /// names a session that lives only in the origin socket's independent
    /// `Peer`, so the replay resolves no session and yields no event/identity.
    /// This is the invariant the forged-envelope test does not exercise, and the
    /// one a future consolidation to a shared `Peer` (e.g. for per-server memory
    /// at scale) would silently break — this test fails if that ever happens.
    #[tokio::test]
    async fn genuine_general_frame_does_not_replay_onto_another_socket() {
        let server = AuthSocketServer::new();
        // Same server key on both sockets — only the per-socket Peer/session
        // isolation (not a key difference) stops the replay.
        server.add_connection("sockA", wallet(0x11));
        server.add_connection("sockB", wallet(0x11));
        let client = test_client(0x22).await;

        // Drive the client's handshake against sockA, capturing the signed
        // General frame it emits after the handshake completes.
        let payload = encode_event("authenticated", &json!({}));
        let peer = client.peer.clone();
        let send = tokio::spawn(async move { peer.send_message("", payload).await });

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut captured_general: Option<AuthMessage> = None;
        let mut finished = false;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "handshake pump timed out"
            );
            let frame = {
                let mut rx = client.out_rx.lock().await;
                rx.try_recv().ok()
            };
            if let Some(frame) = frame {
                if frame.message_type == MessageType::General {
                    captured_general = Some(frame.clone());
                }
                let driven = server.on_auth_message("sockA", frame).await;
                for m in driven.outbound {
                    let _ = client.in_tx.send(m).await;
                }
            } else if finished {
                break;
            } else {
                finished = send.is_finished();
                if !finished {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
        }
        let _ = send.await.expect("send task");

        let general = captured_general.expect("must capture a signed general frame");
        // Sanity: on its origin socket the frame genuinely established identity.
        assert_eq!(
            server.identity_key("sockA").as_deref(),
            Some(client.identity.as_str()),
            "the captured frame is a genuine, identity-establishing general message"
        );

        // Replay the exact signed frame onto sockB's independent Peer/session.
        let driven = server.on_auth_message("sockB", general).await;
        assert!(
            driven.events.is_empty(),
            "cross-socket replay must not verify into an event"
        );
        assert_eq!(
            server.identity_key("sockB"),
            None,
            "A1a backbone: a frame from another socket's session owns nothing here"
        );
    }

    /// A1b (positive): after real mutual auth, emit_to_room signs exactly one
    /// frame for the member, bound to its verified identity.
    #[tokio::test]
    async fn emit_to_authenticated_room_member_signs() {
        let server = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        let client = test_client(0x22).await;

        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        server.join_room("sock1", "roomA");

        let msgs = server
            .emit_to_room("roomA", "sendMessage-roomA", &json!({"x": 1}))
            .await;
        assert_eq!(msgs.len(), 1, "one signed frame for the authed member");
        assert_eq!(msgs[0].0, "sock1");
        assert_eq!(msgs[0].1.message_type, MessageType::General);
        assert!(msgs[0].1.signature.is_some(), "broadcast frame is signed");
    }

    #[tokio::test]
    async fn room_membership_lifecycle() {
        let server: AuthSocketServer<ProtoWallet> = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        server.add_connection("sock2", wallet(0x11));

        server.join_room("sock1", "room");
        server.join_room("sock2", "room");
        let mut members = server.room_members("room");
        members.sort();
        assert_eq!(members, vec!["sock1".to_string(), "sock2".to_string()]);

        server.leave_room("sock1", "room");
        assert_eq!(server.room_members("room"), vec!["sock2".to_string()]);

        // Disconnect clears membership + connection.
        server.remove_connection("sock2");
        assert!(server.room_members("room").is_empty());
        assert!(server.conn("sock2").is_none());
    }

    #[test]
    fn identity_key_shape_check() {
        let good = format!("02{}", "a".repeat(64));
        assert!(is_valid_identity_key(&good));
        assert!(!is_valid_identity_key(""));
        assert!(!is_valid_identity_key("02abc"));
        assert!(!is_valid_identity_key(&format!("04{}", "a".repeat(64))));
        assert!(!is_valid_identity_key(&format!("02{}", "g".repeat(64))));
    }
}
