//! Server-side authenticated room core.
//!
//! This is deliberately **Socket.IO-implementation-agnostic**: it owns the
//! per-connection [`PeerHandle`]s and room membership, and turns "emit/broadcast
//! an app event" into a list of signed `AuthMessage`s tagged with the socket id
//! to send them over. The consumer (e.g. `rust-messagebox-server`, using
//! `socketioxide`) wires the actual socket I/O to these calls:
//!
//! - on a new connection: [`AuthSocketServer::add_connection`].
//! - on an inbound `"authMessage"` event: [`AuthSocketServer::on_auth_message`]
//!   feeds the connection; the socket adapter's long-lived pump emits outbound
//!   messages and dispatches verified events.
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
//!   under the lock, and all Peer work (feed/sign) runs outside any map lock.
//!   Fan-out signs run concurrently (`join_all`), not in a sequential loop.
//! - **One per-connection lock order, stated on `Connection::deferred_events`.**
//!   Read it before adding a lock to any path. socketioxide spawns a task per
//!   inbound frame, so one socket's handlers run concurrently and these are
//!   blocking locks: an inversion wedges tokio workers permanently rather than
//!   parking them. That is not hypothetical — a rejection path once acquired
//!   the deferral lock while holding the session-identity guard, inverting a
//!   path that already held them the other way round.
//!
//! **The fix this replaces:** the old server `broadcast_to_room` did a RAW,
//! unsigned `io.to(room).emit(...)`, which only hit the client's fallback
//! receive path. Here every broadcast is a per-recipient **signed** general
//! message, so it lands on the client's authenticated primary path — instant
//! and authenticated.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use bsv::auth::certificates::VerifiableCertificate;
use bsv::auth::error::AuthError;
use bsv::auth::peer::OnCertificateRequestReceived;
use bsv::auth::types::{AuthMessage, MessageType, RequestedCertificateSet};
use bsv::wallet::interfaces::WalletInterface;
use futures_util::future::join_all;
use parking_lot::{Mutex, RwLock};
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::peer_session::{PeerHandle, PeerPumpReceivers, VerifiedEvent};

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

/// Default maximum number of verified application events retained while a
/// certificate decision is pending.
pub const MAX_DEFERRED_EVENTS: usize = 32;

/// Default maximum encoded size of verified application events retained while
/// a certificate decision is pending.
///
/// This counts the sender and event-name strings plus compact serialized JSON.
/// It is an admission bound, not a measurement of resident heap memory:
/// [`serde_json::Value`] and its allocations can occupy several times their
/// encoded size.
pub const MAX_DEFERRED_EVENT_BYTES: usize = 256 * 1024;

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
    Arc<dyn Fn(String, Vec<VerifiableCertificate>) -> CertificateAuthorizerFuture + Send + Sync>;
/// Future returned by a [`VerifiedEventSink`].
pub type VerifiedEventSinkFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Async consumer for application events admitted by the certificate gate.
///
/// Register one with [`AuthSocketServer::set_verified_event_sink`] before
/// starting [`AuthSocketServer::run_connection_pump`]. The connection keeps a
/// strong clone of the sink until it is removed, so the caller may drop its
/// own [`Arc`] without stopping delivery. Both events admitted immediately and
/// events released after certificate authorization use this same sink. A
/// terminal certificate transition may invoke the sink with an empty batch so
/// an adapter can observe rejection and close its transport.
pub type VerifiedEventSink =
    Arc<dyn Fn(Vec<VerifiedEvent>) -> VerifiedEventSinkFuture + Send + Sync>;
type WeakVerifiedEventSink =
    Weak<dyn Fn(Vec<VerifiedEvent>) -> VerifiedEventSinkFuture + Send + Sync>;

/// A transport-agnostic connection pump could not be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionPumpError {
    /// The socket id no longer names a registered connection.
    ConnectionUnavailable(String),
    /// No admitted-event consumer was registered for the connection.
    VerifiedEventSinkNotRegistered(String),
}

impl std::fmt::Display for ConnectionPumpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionUnavailable(socket_id) => {
                write!(formatter, "connection is unavailable: {socket_id}")
            }
            Self::VerifiedEventSinkNotRegistered(socket_id) => write!(
                formatter,
                "verified-event sink is not registered for connection: {socket_id}"
            ),
        }
    }
}

impl std::error::Error for ConnectionPumpError {}

#[derive(Default)]
struct DeferredEvents {
    events: Vec<VerifiedEvent>,
    bytes: usize,
}

impl DeferredEvents {
    fn clear(&mut self) {
        self.events.clear();
        self.bytes = 0;
    }

    fn take(&mut self) -> Vec<VerifiedEvent> {
        self.bytes = 0;
        std::mem::take(&mut self.events)
    }
}

#[derive(Default)]
struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn deferred_event_bytes(event: &VerifiedEvent) -> usize {
    let mut counter = ByteCounter(event.sender.len().saturating_add(event.event_name.len()));
    // Serializing a serde_json::Value cannot fail with this infallible writer.
    serde_json::to_writer(&mut counter, &event.data).expect("Value serialization is infallible");
    counter.0
}

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
    max_deferred_events: usize,
    max_deferred_event_bytes: usize,
    /// Serializes short authorization transitions with pending-event deferral.
    /// It is never held across an await, so a hung authorizer cannot strand
    /// concurrent frame handlers behind it.
    ///
    /// Per-connection blocking locks follow one order: snapshot and release
    /// `session_peer_identity_key` first; then, when a transition needs more
    /// than one lock, take `deferred_events`, `certificate_authorization`,
    /// `identity_key`, and `certificate_deadline_task` in that order. Never
    /// nest the session-identity lock with any of the transition locks.
    deferred_events: Mutex<DeferredEvents>,
    /// Claims the one consumer-authorizer future allowed for this Pending
    /// decision. The claim is acquired under `deferred_events` before awaiting
    /// and cleared by every terminal transition.
    certificate_authorizer_in_flight: AtomicBool,
    /// Aborted when authorization resolves or the socket disconnects, so the
    /// deadline task does not retain the socket/server until the full timeout.
    certificate_deadline_task: RwLock<Option<JoinHandle<()>>>,
    /// SDK callback id for the bridge to the server-wide listener registry.
    certificate_request_bridge_id: RwLock<Option<u64>>,
    /// Installed by the socket adapter. The awaited SDK certificate listener
    /// uses it to dispatch state-released events without retaining the server.
    verified_event_sink: RwLock<Option<WeakVerifiedEventSink>>,
    /// Public registration owns the sink for the connection lifetime. Keeping
    /// this separate from the weak callback reference also lets internal test
    /// pumps retain their deliberately scoped sink ownership.
    owned_verified_event_sink: RwLock<Option<VerifiedEventSink>>,
    /// The SDK defers general dispatch until this connection's requested
    /// certificates validate.
    sdk_certificate_gate: bool,
    #[cfg(test)]
    test_pump: tokio::sync::Mutex<Option<TestPumpState>>,
}

struct CertificateAuthorizerInFlightGuard<W: WalletInterface + 'static> {
    conn: Weak<Connection<W>>,
}

impl<W: WalletInterface + 'static> CertificateAuthorizerInFlightGuard<W> {
    fn new(conn: &Arc<Connection<W>>) -> Self {
        Self {
            conn: Arc::downgrade(conn),
        }
    }
}

impl<W: WalletInterface + 'static> Drop for CertificateAuthorizerInFlightGuard<W> {
    fn drop(&mut self) {
        // Invariant: no cancellation of the authorizer, from any cause, may
        // leave `certificate_authorizer_in_flight` set.
        if let Some(conn) = self.conn.upgrade() {
            conn.certificate_authorizer_in_flight
                .store(false, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
struct TestPumpState {
    receivers: PeerPumpReceivers,
    released_rx: tokio::sync::mpsc::UnboundedReceiver<VerifiedEvent>,
    _sink: VerifiedEventSink,
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
    /// Awaited by the SDK's certificate listener. No deferred application
    /// event is released until it accepts.
    certificate_authorizer: RwLock<Option<CertificateAuthorizer>>,
    /// Snapshotted by each newly-created connection.
    certificate_authorization_timeout: RwLock<Duration>,
    /// Snapshotted by each newly-created connection.
    certificate_authorization_deferral_limits: RwLock<(usize, usize)>,
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
            certificate_authorization_deferral_limits: RwLock::new((
                MAX_DEFERRED_EVENTS,
                MAX_DEFERRED_EVENT_BYTES,
            )),
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

    /// Set the pending-event admission limits for subsequently-created
    /// connections. Existing connections retain their snapshotted limits.
    ///
    /// The defaults are [`MAX_DEFERRED_EVENTS`] and
    /// [`MAX_DEFERRED_EVENT_BYTES`]. A pending peer is terminally rejected when
    /// either limit would be exceeded. The standard client sends a verified
    /// `authenticated` keepalive every 10 seconds even before
    /// `authenticationSuccess`, so authorization timeouts around 320 seconds
    /// or longer can require a larger event limit. Raising either limit trades
    /// a larger per-connection resource budget for a longer pending window.
    /// The byte limit counts encoded JSON, not the larger resident footprint
    /// of the retained [`serde_json::Value`] tree.
    pub fn set_certificate_authorization_deferral_limits(
        &self,
        max_events: usize,
        max_encoded_bytes: usize,
    ) {
        assert!(max_events > 0, "maximum deferred events must be non-zero");
        assert!(
            max_encoded_bytes > 0,
            "maximum deferred encoded bytes must be non-zero"
        );
        *self.certificate_authorization_deferral_limits.write() = (max_events, max_encoded_bytes);
    }

    /// Register the async accept/reject decision for received certificates.
    ///
    /// The future is awaited by the SDK certificate listener. While a requested
    /// certificate decision is pending, verified application events are
    /// suppressed. Rejection is terminal for the core connection and is also
    /// exposed through [`Self::certificate_authorization`]; [`crate::server_io::attach`]
    /// closes the corresponding socket immediately.
    ///
    /// The authorizer receives only batches delivered by bsv-sdk 0.8's awaited
    /// certificate listeners. Before delivery, the SDK verifies the response's
    /// nonce, active session (including idle TTL), response signature and
    /// replay nonce, then verifies each certificate's subject and certificate
    /// signature, requested certifier/type, and selectively disclosed fields.
    /// Each [`VerifiableCertificate`] retains the verifier keyring, so the
    /// authorizer can call `decrypt_fields` with the verifier wallet instead of
    /// losing the disclosure proof before applying policy such as revocation.
    ///
    /// Configure both the request and authorizer before connections are added
    /// (normally before [`crate::server_io::attach`]); configuration is
    /// snapshotted at connect time and never retrofits existing sockets. An
    /// accepted socket does not re-run this authorizer for later certificate
    /// responses: renewal, rotation, and step-up require a new connection.
    /// Exactly one batch can invoke the authorizer for that decision; concurrent
    /// or later certificate responses do not start additional authorizer
    /// futures.
    ///
    /// Verified application events received while the decision is pending are
    /// retained only up to [`MAX_DEFERRED_EVENTS`] and
    /// [`MAX_DEFERRED_EVENT_BYTES`] by default. See
    /// [`Self::set_certificate_authorization_deferral_limits`] when configuring
    /// a long authorization timeout. The byte limit is based on compact JSON
    /// size and does not represent the larger in-memory size of
    /// [`serde_json::Value`].
    ///
    /// Configuring an authorizer without [`Self::set_certificates_to_request`]
    /// still gates every new connection as `Pending`; the peer must provide a
    /// session-bound certificate response before the deadline. The inverse
    /// configuration (a requested set without an authorizer) is rejected when
    /// the connection is created and logged as an error.
    pub fn set_certificate_authorizer<F, Fut>(&self, authorizer: F)
    where
        F: Fn(String, Vec<VerifiableCertificate>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = CertificateAuthorizationDecision> + Send + 'static,
    {
        *self.certificate_authorizer.write() = Some(Arc::new(move |identity, certificates| {
            Box::pin(authorizer(identity, certificates))
        }));
    }

    /// Register a freshly-connected socket with its own BRC-103 session.
    /// `wallet` is the server wallet (e.g. a `ProtoWallet` over the server key).
    ///
    /// # Panics
    ///
    /// Panics outside a Tokio runtime because bsv-sdk starts the per-connection
    /// Peer's background receive task during construction.
    pub fn add_connection(&self, socket_id: impl Into<String>, wallet: W) {
        let socket_id = socket_id.into();
        let requested = self.certificates_to_request.read().clone();
        let sdk_certificate_gate = requested
            .as_ref()
            .is_some_and(|requested| !requested.certifiers.is_empty());
        let authorizer = self.certificate_authorizer.read().clone();
        let has_authorizer = authorizer.is_some();
        let authorization_timeout = *self.certificate_authorization_timeout.read();
        let (max_deferred_events, max_deferred_event_bytes) =
            *self.certificate_authorization_deferral_limits.read();
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
            handle: PeerHandle::new_for_server(wallet, requested),
            identity_key: RwLock::new(None),
            session_peer_identity_key: RwLock::new(None),
            certificate_authorization: RwLock::new(authorization),
            certificate_deadline,
            certificate_timeout: has_authorizer.then_some(authorization_timeout),
            max_deferred_events,
            max_deferred_event_bytes,
            deferred_events: Mutex::new(DeferredEvents::default()),
            certificate_authorizer_in_flight: AtomicBool::new(false),
            certificate_deadline_task: RwLock::new(None),
            certificate_request_bridge_id: RwLock::new(None),
            verified_event_sink: RwLock::new(None),
            owned_verified_event_sink: RwLock::new(None),
            sdk_certificate_gate,
            #[cfg(test)]
            test_pump: tokio::sync::Mutex::new(None),
        });
        let weak_conn: Weak<Connection<W>> = Arc::downgrade(&conn);
        conn.handle.listen_for_certificates_received(Arc::new(
            move |identity_key, certificates| {
                let weak_conn = weak_conn.clone();
                let authorizer = authorizer.clone();
                Box::pin(async move {
                    // The SDK awaits this callback under its own short listener
                    // deadline. Policy may legitimately run for minutes, so the
                    // callback only transfers ownership to a detached task.
                    let _authorization_task = tokio::spawn(async move {
                        let events = Self::authorize_verified_certificates_with(
                            weak_conn.clone(),
                            authorizer,
                            identity_key,
                            certificates,
                        )
                        .await;
                        let Some(conn) = weak_conn.upgrade() else {
                            return;
                        };
                        let sink = Self::registered_verified_event_sink(&conn);
                        drop(conn);
                        if let Some(sink) = sink {
                            sink(events).await;
                        } else {
                            tracing::error!(
                                count = events.len(),
                                "authsocket: admitted certificate-gated events have no registered sink"
                            );
                        }
                    });
                    Ok(())
                })
            },
        ));
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
        Self::expire_connection(&conn, true);
        let authorization = conn.certificate_authorization.read().clone();
        Some(authorization)
    }

    /// Transition an overdue `Pending` connection to terminal rejection.
    /// Returns `true` only when this call performed the transition.
    pub fn expire_certificate_authorization(&self, socket_id: &str) -> bool {
        let Some(conn) = self.conn(socket_id) else {
            return false;
        };
        Self::expire_connection(&conn, true)
    }

    pub(crate) fn expire_certificate_authorization_from_deadline(&self, socket_id: &str) -> bool {
        let Some(conn) = self.conn(socket_id) else {
            return false;
        };
        // Skip aborting here so the task can reach the adapter's cleanup. The
        // subsequent remove_connection takes and aborts this task's own handle;
        // that is safe because Tokio cancellation is cooperative and the
        // adapter performs both removal and SocketRef::disconnect synchronously,
        // with no await at which the self-abort could take effect.
        Self::expire_connection(&conn, false)
    }

    fn expire_connection(conn: &Connection<W>, abort_deadline_task: bool) -> bool {
        if !matches!(conn.certificate_deadline, Some(deadline) if Instant::now() >= deadline) {
            return false;
        }
        let mut deferred = conn.deferred_events.lock();
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
        conn.certificate_authorizer_in_flight
            .store(false, Ordering::SeqCst);
        deferred.clear();
        drop(authorization);
        drop(deferred);
        if abort_deadline_task {
            Self::abort_certificate_deadline_task(conn);
        }
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

    /// Send a certificate response on one connection. Its pump emits the
    /// signed BRC-103 frame as `authMessage`.
    pub async fn send_certificate_response(
        &self,
        socket_id: &str,
        identity_key: &str,
        certificates: Vec<VerifiableCertificate>,
    ) -> Result<(), AuthError> {
        let conn = self.conn(socket_id).ok_or_else(|| {
            AuthError::SessionNotFound(format!("socket connection not found: {socket_id}"))
        })?;
        conn.handle
            .send_certificate_response_existing(identity_key, certificates)
            .await
    }

    /// Feed one inbound `"authMessage"` to the SDK-owned receive task.
    pub async fn on_auth_message(&self, socket_id: &str, msg: AuthMessage) {
        let Some(conn) = self.conn(socket_id) else {
            return;
        };
        Self::expire_connection(&conn, true);

        if matches!(
            *conn.certificate_authorization.read(),
            CertificateAuthorization::Rejected { .. }
        ) {
            return;
        }
        conn.handle.feed(msg).await;
    }

    /// Take the SDK observer channels for this connection exactly once.
    ///
    /// After [`Self::add_connection`], taking these receivers and continuously
    /// running [`Self::run_connection_pump`] is mandatory. If no pump drains
    /// them, the bounded outbound channel fills after 32 queued frames and SDK
    /// sends wait indefinitely while the connection appears live. Draining
    /// `general` directly exposes verified but not yet certificate-admitted
    /// payloads and therefore is not a substitute for the pump's event sink.
    pub fn take_pump_receivers(&self, socket_id: &str) -> Option<PeerPumpReceivers> {
        self.conn(socket_id)?.handle.take_pump_receivers()
    }

    /// Register the admitted-event consumer for a connection.
    ///
    /// The connection strongly owns a clone until [`Self::remove_connection`],
    /// so dropping the caller's [`Arc`] does not silently stop event delivery.
    /// Register before feeding inbound frames and before starting
    /// [`Self::run_connection_pump`]. A missing connection is logged as an
    /// error; the pump independently refuses to start without a registered
    /// sink.
    pub fn set_verified_event_sink(&self, socket_id: &str, sink: &VerifiedEventSink) {
        if let Some(conn) = self.conn(socket_id) {
            *conn.verified_event_sink.write() = Some(Arc::downgrade(sink));
            *conn.owned_verified_event_sink.write() = Some(sink.clone());
        } else {
            tracing::error!(socket = %socket_id,
                "authsocket: cannot register verified-event sink for missing connection");
        }
    }

    fn registered_verified_event_sink(conn: &Connection<W>) -> Option<VerifiedEventSink> {
        conn.owned_verified_event_sink.read().clone().or_else(|| {
            conn.verified_event_sink
                .read()
                .as_ref()
                .and_then(Weak::upgrade)
        })
    }

    /// Run both halves of a connection's SDK observer pump without assuming a
    /// transport implementation.
    ///
    /// `emit` receives each wire-ready [`AuthMessage`] after outbound
    /// normalization and session bookkeeping. SDK-verified general messages
    /// are decoded and passed through the certificate gate; only admitted
    /// [`VerifiedEvent`] batches reach the sink registered with
    /// [`Self::set_verified_event_sink`]. Deferred events released by a later
    /// certificate decision reach that same sink.
    ///
    /// The pump returns [`ConnectionPumpError::VerifiedEventSinkNotRegistered`]
    /// before draining either receiver when no sink is registered. Removing
    /// the connection closes the SDK senders and ends the pump successfully.
    pub async fn run_connection_pump<F, Fut>(
        &self,
        socket_id: &str,
        mut receivers: PeerPumpReceivers,
        emit: F,
    ) -> Result<(), ConnectionPumpError>
    where
        W: Send + Sync,
        F: Fn(AuthMessage) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let conn = self
            .conn(socket_id)
            .ok_or_else(|| ConnectionPumpError::ConnectionUnavailable(socket_id.to_string()))?;
        let event_sink = Self::registered_verified_event_sink(&conn).ok_or_else(|| {
            ConnectionPumpError::VerifiedEventSinkNotRegistered(socket_id.to_string())
        })?;
        drop(conn);

        let mut outgoing_open = true;
        let mut general_open = true;
        let mut emitting: Option<Pin<Box<Fut>>> = None;
        let mut dispatching: Option<VerifiedEventSinkFuture> = None;
        while outgoing_open || general_open || emitting.is_some() || dispatching.is_some() {
            if receivers.outgoing.is_closed() && receivers.general.is_closed() {
                break;
            }
            tokio::select! {
                message = receivers.outgoing.recv(), if outgoing_open && emitting.is_none() => {
                    match message {
                        Some(message) => {
                            let message = PeerHandle::<W>::normalize_outbound(message);
                            self.record_outbound_session_peer_identity(socket_id, &message).await;
                            emitting = Some(Box::pin(emit(message)));
                        }
                        None => outgoing_open = false,
                    }
                }
                message = receivers.general.recv(), if general_open && dispatching.is_none() => {
                    match message {
                        Some((sender, payload)) => {
                            let Some((event_name, data)) = crate::wire::decode_event(&payload) else {
                                continue;
                            };
                            let events = self.admit_verified_event(
                                socket_id,
                                VerifiedEvent { sender, event_name, data },
                            );
                            if !events.is_empty() {
                                dispatching = Some(event_sink(events));
                            }
                        }
                        None => general_open = false,
                    }
                }
                () = async {
                    emitting
                        .as_mut()
                        .expect("emit branch is guarded")
                        .as_mut()
                        .await;
                }, if emitting.is_some() => {
                    emitting = None;
                }
                () = async {
                    dispatching
                        .as_mut()
                        .expect("dispatch branch is guarded")
                        .as_mut()
                        .await;
                }, if dispatching.is_some() => {
                    dispatching = None;
                }
            }
        }
        Ok(())
    }

    /// Bind an emitted responder handshake to the identity held by the SDK
    /// session identified by the nonce this server issued.
    pub(crate) async fn record_outbound_session_peer_identity(
        &self,
        socket_id: &str,
        message: &AuthMessage,
    ) {
        if message.message_type != MessageType::InitialResponse {
            return;
        }
        let Some(session_nonce) = message.initial_nonce.as_deref() else {
            return;
        };
        let Some(conn) = self.conn(socket_id) else {
            return;
        };
        if let Some(identity_key) = conn
            .handle
            .peer()
            .session_peer_identity_for(session_nonce)
            .await
        {
            Self::record_session_peer_identity(&conn, identity_key);
        }
    }

    /// Apply authorization state to one SDK-verified general event.
    pub(crate) fn admit_verified_event(
        &self,
        socket_id: &str,
        event: VerifiedEvent,
    ) -> Vec<VerifiedEvent> {
        let Some(conn) = self.conn(socket_id) else {
            return Vec::new();
        };
        Self::expire_connection(&conn, true);
        let mut events = vec![event];
        self.gate_or_defer_events(socket_id, &conn, &mut events);
        Self::record_admitted_identities(&conn, &events);
        events
    }

    fn record_admitted_identities(conn: &Connection<W>, events: &[VerifiedEvent]) {
        for event in events {
            if is_valid_identity_key(&event.sender) {
                *conn.identity_key.write() = Some(event.sender.clone());
            }
        }
    }

    fn reject_pending_certificate_response(conn: &Connection<W>, reason: String) {
        let mut deferred = conn.deferred_events.lock();
        Self::reject_pending_with_deferred(conn, &mut deferred, reason);
    }

    fn record_session_peer_identity(conn: &Connection<W>, identity_key: String) {
        // Never call a transition while holding the session lock. In
        // particular, rejection takes deferred_events; authorize takes its
        // session snapshot before deferred_events, so nesting these would
        // recreate a session/deferred lock-order cycle.
        let identity_changed = {
            let mut session_identity = conn.session_peer_identity_key.write();
            match session_identity.as_ref() {
                None => {
                    *session_identity = Some(identity_key);
                    false
                }
                Some(identity) => identity != &identity_key,
            }
        };
        if identity_changed {
            Self::reject_pending_certificate_response(
                conn,
                "BRC-103 session identity changed on one socket".into(),
            );
        }
    }

    fn reject_pending_with_deferred(
        conn: &Connection<W>,
        deferred: &mut DeferredEvents,
        reason: String,
    ) {
        let mut authorization = conn.certificate_authorization.write();
        if matches!(*authorization, CertificateAuthorization::Pending) {
            *authorization = CertificateAuthorization::Rejected {
                identity_key: conn.identity_key.read().clone().unwrap_or_default(),
                reason,
            };
            conn.certificate_authorizer_in_flight
                .store(false, Ordering::SeqCst);
            deferred.clear();
            drop(authorization);
            Self::abort_certificate_deadline_task(conn);
        }
    }

    fn gate_or_defer_events(
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

        // The same short-held mutex covers the pending queue and authorization
        // transitions. The consumer authorizer runs without this lock.
        let mut deferred = conn.deferred_events.lock();
        let authorization = conn.certificate_authorization.read().clone();
        match authorization {
            CertificateAuthorization::NotRequired => {}
            CertificateAuthorization::Accepted { identity_key } => {
                if events.iter().any(|event| event.sender != identity_key) {
                    *conn.certificate_authorization.write() = CertificateAuthorization::Rejected {
                        identity_key,
                        reason: "certificate identity does not match general-message sender".into(),
                    };
                    conn.certificate_authorizer_in_flight
                        .store(false, Ordering::SeqCst);
                    deferred.clear();
                    events.clear();
                    Self::abort_certificate_deadline_task(conn);
                }
            }
            CertificateAuthorization::Pending => {
                let incoming_bytes = events.iter().fold(0usize, |bytes, event| {
                    bytes.saturating_add(deferred_event_bytes(event))
                });
                let exceeds_count =
                    deferred.events.len().saturating_add(events.len()) > conn.max_deferred_events;
                let exceeds_bytes =
                    deferred.bytes.saturating_add(incoming_bytes) > conn.max_deferred_event_bytes;
                if exceeds_count || exceeds_bytes {
                    let reason = format!(
                        "certificate authorization deferral limit exceeded (max {} events / {} encoded bytes)",
                        conn.max_deferred_events, conn.max_deferred_event_bytes
                    );
                    Self::reject_pending_with_deferred(conn, &mut deferred, reason);
                    events.clear();
                    return;
                }
                tracing::debug!(socket = %socket_id,
                    count = events.len(),
                    "authsocket: application events deferred pending certificate authorization");
                deferred.bytes += incoming_bytes;
                deferred.events.append(events);
            }
            CertificateAuthorization::Rejected { .. } => {
                deferred.clear();
                events.clear();
            }
        }
    }

    #[cfg(test)]
    async fn authorize_verified_certificates(
        &self,
        conn: &Arc<Connection<W>>,
        identity_key: String,
        certificates: Vec<VerifiableCertificate>,
    ) -> Vec<VerifiedEvent> {
        let authorizer = self.certificate_authorizer.read().clone();
        Self::authorize_verified_certificates_with(
            Arc::downgrade(conn),
            authorizer,
            identity_key,
            certificates,
        )
        .await
    }

    async fn authorize_verified_certificates_with(
        weak_conn: Weak<Connection<W>>,
        authorizer: Option<CertificateAuthorizer>,
        identity_key: String,
        certificates: Vec<VerifiableCertificate>,
    ) -> Vec<VerifiedEvent> {
        let Some(conn) = weak_conn.upgrade() else {
            return Vec::new();
        };
        // Session identity is deliberately snapshotted before deferred_events
        // and its guard is dropped immediately. No path may nest the session
        // lock with authorization-transition locks.
        let session_identity_matches =
            conn.session_peer_identity_key.read().as_deref() == Some(identity_key.as_str());
        {
            let mut deferred = conn.deferred_events.lock();
            if !matches!(
                *conn.certificate_authorization.read(),
                CertificateAuthorization::Pending
            ) {
                deferred.clear();
                return Vec::new();
            }

            if !session_identity_matches {
                Self::reject_pending_with_deferred(
                    &conn,
                    &mut deferred,
                    "certificate-response signer does not match the BRC-103 session peer".into(),
                );
                return Vec::new();
            }

            if conn.sdk_certificate_gate && certificates.is_empty() {
                Self::reject_pending_with_deferred(
                    &conn,
                    &mut deferred,
                    "certificate response contained no certificates".into(),
                );
                return Vec::new();
            }

            // Pending means no terminal decision exists, but it no longer
            // implies that no authorizer is running. Claim the single allowed
            // authorizer before releasing the transition mutex and awaiting.
            if conn
                .certificate_authorizer_in_flight
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return Vec::new();
            }
        }
        let _in_flight = CertificateAuthorizerInFlightGuard::new(&conn);

        let Some(authorizer) = authorizer else {
            Self::reject_pending_certificate_response(
                &conn,
                "SDK-verified certificates received but no certificate authorizer is configured"
                    .into(),
            );
            return Vec::new();
        };

        // `identity_key` and the batch come exclusively from the SDK's awaited
        // certificate listener after response and certificate authentication.
        let Some(deadline) = conn.certificate_deadline else {
            Self::reject_pending_certificate_response(
                &conn,
                "certificate authorizer has no authorization deadline".into(),
            );
            return Vec::new();
        };
        drop(conn);
        let decision =
            match tokio::time::timeout_at(deadline, authorizer(identity_key.clone(), certificates))
                .await
            {
                Ok(decision) => decision,
                Err(_) => {
                    // Dropping timeout_at's inner future cancels the consumer
                    // authorizer. The terminal transition also releases retained
                    // events even for transport-agnostic Connection owners.
                    if let Some(conn) = weak_conn.upgrade() {
                        Self::expire_connection(&conn, true);
                    }
                    return Vec::new();
                }
            };

        let Some(conn) = weak_conn.upgrade() else {
            return Vec::new();
        };

        // This is the sole post-await transition guard. A timeout/rejection that
        // won concurrently is terminal and cannot be revived by a late Accept.
        let mut deferred = conn.deferred_events.lock();
        let mut authorization = conn.certificate_authorization.write();
        if !matches!(*authorization, CertificateAuthorization::Pending) {
            conn.certificate_authorizer_in_flight
                .store(false, Ordering::SeqCst);
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
        conn.certificate_authorizer_in_flight
            .store(false, Ordering::SeqCst);
        drop(authorization);
        Self::abort_certificate_deadline_task(&conn);
        if accepted {
            let events = deferred.take();
            Self::record_admitted_identities(&conn, &events);
            events
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
    use bsv::auth::certificates::master::default_get_revocation_outpoint;
    use bsv::auth::certificates::{MasterCertificate, VerifiableCertificate};
    use bsv::auth::peer::Peer;
    use bsv::auth::types::{AuthMessage, MessageType, RequestedCertificateSet};
    use bsv::primitives::private_key::PrivateKey;
    use bsv::primitives::public_key::PublicKey;
    use bsv::wallet::interfaces::{CertificateType, SerialNumber};
    use bsv::wallet::proto_wallet::ProtoWallet;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;

    use crate::transport::ChannelTransport;
    use crate::wire::{decode_event, encode_event};

    impl AuthSocketServer<ProtoWallet> {
        async fn ensure_test_pump(&self, sid: &str) {
            let conn = self.conn(sid).expect("test connection");
            let mut state = conn.test_pump.lock().await;
            if state.is_some() {
                return;
            }
            let receivers = conn
                .handle
                .take_pump_receivers()
                .expect("test pump takes observers once");
            let (released_tx, released_rx) = tokio::sync::mpsc::unbounded_channel();
            let sink: VerifiedEventSink = Arc::new(move |events| {
                let released_tx = released_tx.clone();
                Box::pin(async move {
                    for event in events {
                        let _ = released_tx.send(event);
                    }
                })
            });
            *conn.verified_event_sink.write() = Some(Arc::downgrade(&sink));
            *state = Some(TestPumpState {
                receivers,
                released_rx,
                _sink: sink,
            });
        }

        async fn pump_once_for_test(&self, sid: &str) -> (Vec<AuthMessage>, Vec<VerifiedEvent>) {
            self.ensure_test_pump(sid).await;
            let conn = self.conn(sid).expect("test connection");
            let mut state = conn.test_pump.lock().await;
            let state = state.as_mut().expect("test pump state");
            let mut outbound = Vec::new();
            while let Ok(message) = state.receivers.outgoing.try_recv() {
                let message = PeerHandle::<ProtoWallet>::normalize_outbound(message);
                self.record_outbound_session_peer_identity(sid, &message)
                    .await;
                outbound.push(message);
            }
            let mut events = Vec::new();
            while let Ok((sender, payload)) = state.receivers.general.try_recv() {
                if let Some((event_name, data)) = decode_event(&payload) {
                    events.extend(self.admit_verified_event(
                        sid,
                        VerifiedEvent {
                            sender,
                            event_name,
                            data,
                        },
                    ));
                }
            }
            while let Ok(event) = state.released_rx.try_recv() {
                events.push(event);
            }
            (outbound, events)
        }

        async fn pump_until_for_test<F, T>(&self, sid: &str, mut found: F) -> T
        where
            F: FnMut(Vec<AuthMessage>, Vec<VerifiedEvent>) -> Option<T>,
        {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let (outbound, events) = self.pump_once_for_test(sid).await;
                    if let Some(value) = found(outbound, events) {
                        return value;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("test pump observation timed out")
        }
    }

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
        peer_identity: tokio::sync::Mutex<Option<String>>,
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
            peer_identity: tokio::sync::Mutex::new(None),
        }
    }

    /// Complete a full BRC-103 handshake + first general message between a
    /// client Peer and `server` socket `sid`, forwarding frames both ways.
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
        let peer_identity = client
            .peer_identity
            .lock()
            .await
            .clone()
            .unwrap_or_default();
        // send_message("") initiates the handshake and awaits the SDK-owned
        // receiver's initialResponse routing — forward frames concurrently.
        let send = tokio::spawn(async move { peer.send_message(&peer_identity, payload).await });
        server.ensure_test_pump(sid).await;

        // Forward frames until the send completes AND its frames are drained
        // (send_message enqueues the general frame before resolving, so one
        // more empty try_recv after observing completion is a true quiescence).
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut finished = false;
        let mut idle_after_finished = 0usize;
        let mut events = Vec::new();
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "handshake forwarding timed out"
            );
            // client -> server
            let frame = {
                let mut rx = client.out_rx.lock().await;
                rx.try_recv().ok()
            };
            let mut activity = false;
            if let Some(frame) = frame {
                server.on_auth_message(sid, frame).await;
                activity = true;
            }
            let (outbound, pumped_events) = server.pump_once_for_test(sid).await;
            activity |= !outbound.is_empty() || !pumped_events.is_empty();
            events.extend(pumped_events);
            for m in outbound {
                if m.message_type == MessageType::InitialResponse {
                    *client.peer_identity.lock().await = Some(m.identity_key.clone());
                }
                let _ = client.in_tx.send(m).await;
                activity = true;
            }
            finished |= send.is_finished();
            if finished && !activity {
                idle_after_finished += 1;
                if idle_after_finished >= 2 {
                    break;
                }
            } else {
                idle_after_finished = 0;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
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

    async fn membership_certificate(
        subject_scalar: u8,
        certifier_scalar: u8,
        verifier: &str,
    ) -> VerifiableCertificate {
        let subject_wallet = wallet(subject_scalar);
        let subject = PublicKey::from_string(&identity_for_scalar(subject_scalar).await)
            .expect("subject key");
        let certifier_wallet = wallet(certifier_scalar);
        let fields = [("membership".to_string(), "active".to_string())]
            .into_iter()
            .collect();
        let master = MasterCertificate::issue_certificate_for_subject(
            &CertificateType([7; 32]),
            &subject,
            fields,
            &certifier_wallet,
            default_get_revocation_outpoint,
            Some(SerialNumber([9; 32])),
        )
        .await
        .expect("issue membership certificate");
        let keyring = master
            .create_keyring_for_verifier(
                &PublicKey::from_string(verifier).expect("verifier key"),
                &["membership".to_string()],
                &master.certificate.certifier,
                &subject_wallet,
            )
            .await
            .expect("create verifier keyring");
        VerifiableCertificate::new(master.certificate, keyring)
    }

    async fn send_certificates(
        server: &AuthSocketServer<ProtoWallet>,
        sid: &str,
        client: &TestClient,
        server_identity: &str,
        certificates: Vec<VerifiableCertificate>,
    ) {
        let _ = send_certificates_collect(server, sid, client, server_identity, certificates).await;
    }

    async fn send_certificates_collect(
        server: &AuthSocketServer<ProtoWallet>,
        sid: &str,
        client: &TestClient,
        server_identity: &str,
        certificates: Vec<VerifiableCertificate>,
    ) -> Vec<VerifiedEvent> {
        let frame = certificate_response_frame(client, server_identity, certificates).await;
        server.on_auth_message(sid, frame).await;
        server
            .pump_until_for_test(sid, |_, events| {
                (!events.is_empty()
                    || !matches!(
                        server.certificate_authorization(sid),
                        Some(CertificateAuthorization::Pending)
                    ))
                .then_some(events)
            })
            .await
    }

    async fn certificate_response_frame(
        client: &TestClient,
        server_identity: &str,
        certificates: Vec<VerifiableCertificate>,
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

        let certificate = membership_certificate(0x22, 0x11, &server_identity).await;
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
    async fn acceptance_releases_events_deferred_while_pending() {
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

        let events = client_send_collect(
            &server,
            "sock1",
            &client,
            "queuedBeforeCertificate",
            &json!({ "sequence": 1 }),
        )
        .await;
        assert!(
            events.is_empty(),
            "pending event must initially be withheld"
        );

        let released = send_certificates_collect(
            &server,
            "sock1",
            &client,
            &server_identity,
            vec![membership_certificate(0x22, 0x11, &server_identity).await],
        )
        .await;
        assert_eq!(released.len(), 1, "accept must release the deferred event");
        assert_eq!(released[0].event_name, "queuedBeforeCertificate");
        assert_eq!(released[0].data, json!({ "sequence": 1 }));
    }

    #[tokio::test]
    async fn concurrent_certificate_responses_invoke_authorizer_once() {
        const RESPONSE_COUNT: usize = 8;

        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        client
            .peer
            .listen_for_certificates_requested(Arc::new(|_, _| {}));
        let server = Arc::new(AuthSocketServer::new());
        server.set_certificates_to_request(requested_certificates(server_identity.clone()));
        let invocations = Arc::new(AtomicUsize::new(0));
        let invocations_cb = invocations.clone();
        let started = Arc::new(tokio::sync::Notify::new());
        let started_cb = started.clone();
        let release = Arc::new(tokio::sync::Notify::new());
        let release_cb = release.clone();
        server.set_certificate_authorizer(move |_, _| {
            let invocations = invocations_cb.clone();
            let started = started_cb.clone();
            let release = release_cb.clone();
            async move {
                invocations.fetch_add(1, Ordering::SeqCst);
                started.notify_one();
                release.notified().await;
                CertificateAuthorizationDecision::Accept
            }
        });
        server.add_connection("sock1", wallet(0x11));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;

        let certificate = membership_certificate(0x22, 0x11, &server_identity).await;
        let mut frames = Vec::with_capacity(RESPONSE_COUNT);
        for _ in 0..RESPONSE_COUNT {
            frames.push(
                certificate_response_frame(&client, &server_identity, vec![certificate.clone()])
                    .await,
            );
        }

        let drives = frames.into_iter().map(|frame| {
            let server = server.clone();
            tokio::spawn(async move { server.on_auth_message("sock1", frame).await })
        });
        let drives = drives.collect::<Vec<_>>();
        started.notified().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            1,
            "one Pending decision must have exactly one in-flight authorizer"
        );

        release.notify_waiters();
        for drive in drives {
            drive.await.expect("certificate-response drive");
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while !matches!(
                server.certificate_authorization("sock1"),
                Some(CertificateAuthorization::Accepted { .. })
            ) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("authorizer must reach its terminal decision");
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Accepted { .. })
        ));
        assert!(
            !server
                .conn("sock1")
                .expect("connection")
                .certificate_authorizer_in_flight
                .load(Ordering::SeqCst),
            "the terminal transition must clear the in-flight claim"
        );
    }

    #[tokio::test]
    async fn session_identity_lock_is_released_before_pending_rejection() {
        let server = AuthSocketServer::new();
        server
            .set_certificate_authorizer(|_, _| async { CertificateAuthorizationDecision::Accept });
        server.add_connection("sock1", wallet(0x11));
        let conn = server.conn("sock1").expect("connection");
        *conn.session_peer_identity_key.write() = Some("original identity".into());

        // Hold both locks that reproduce the old inversion window. The worker
        // first blocks on session_identity. Once released, fixed code drops
        // that guard before it blocks on deferred_events for rejection.
        let deferred = conn.deferred_events.lock();
        let session = conn.session_peer_identity_key.read();
        let (attempting_tx, attempting_rx) = std::sync::mpsc::sync_channel(0);
        let conn_worker = conn.clone();
        let worker = std::thread::spawn(move || {
            attempting_tx.send(()).expect("signal lock attempt");
            AuthSocketServer::record_session_peer_identity(
                &conn_worker,
                "different identity".into(),
            );
        });
        attempting_rx.recv().expect("worker lock attempt");
        // The rendezvous only proves the worker sent, not that it has queued on
        // `session_peer_identity_key`. Without this park the main thread usually
        // re-acquires the lock in the handful of instructions after `drop`, and
        // the inversion is never exercised: restoring the pre-fix body of
        // `record_session_peer_identity` passed 27 of 40 runs, so a reintroduced
        // deadlock would clear CI roughly two times in three. Once the worker is
        // genuinely queued, parking_lot hands it the write on release, so the
        // buggy ordering holds the guard and the `try_write_for` below times out
        // deterministically.
        std::thread::sleep(Duration::from_millis(50));
        drop(session);

        let session = conn
            .session_peer_identity_key
            .try_write_for(Duration::from_secs(1))
            .expect("rejection must not hold session identity while waiting for deferred events");
        drop(session);
        drop(deferred);
        worker.join().expect("identity mismatch worker");

        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected { reason, .. })
                if reason.contains("session identity changed")
        ));
    }

    #[tokio::test]
    async fn pending_event_overflow_is_terminal_and_releases_retained_payloads() {
        let server = AuthSocketServer::new();
        server
            .set_certificate_authorizer(|_, _| async { CertificateAuthorizationDecision::Accept });
        server.add_connection("sock1", wallet(0x11));
        let conn = server.conn("sock1").expect("connection");
        let sender = identity_for_scalar(0x22).await;
        let mut events = (0..=MAX_DEFERRED_EVENTS)
            .map(|sequence| VerifiedEvent {
                sender: sender.clone(),
                event_name: "unauthorized".into(),
                data: json!({ "sequence": sequence }),
            })
            .collect::<Vec<_>>();

        server.gate_or_defer_events("sock1", &conn, &mut events);

        assert!(events.is_empty());
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected { reason, .. })
                if reason.contains("deferral limit exceeded")
        ));
        let deferred = conn.deferred_events.lock();
        assert!(deferred.events.is_empty());
        assert_eq!(deferred.bytes, 0);
    }

    #[tokio::test]
    async fn pending_event_byte_overflow_is_terminal() {
        let server = AuthSocketServer::new();
        server
            .set_certificate_authorizer(|_, _| async { CertificateAuthorizationDecision::Accept });
        server.add_connection("sock1", wallet(0x11));
        let conn = server.conn("sock1").expect("connection");
        let mut events = vec![VerifiedEvent {
            sender: identity_for_scalar(0x22).await,
            event_name: "oversizedUnauthorized".into(),
            data: json!({ "payload": "x".repeat(MAX_DEFERRED_EVENT_BYTES) }),
        }];

        server.gate_or_defer_events("sock1", &conn, &mut events);

        assert!(events.is_empty());
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected { reason, .. })
                if reason.contains("deferral limit exceeded")
        ));
        assert!(conn.deferred_events.lock().events.is_empty());
    }

    #[tokio::test]
    async fn configured_deferral_limits_are_snapshotted_by_new_connections() {
        let server = AuthSocketServer::new();
        server
            .set_certificate_authorizer(|_, _| async { CertificateAuthorizationDecision::Accept });
        server.set_certificate_authorization_deferral_limits(
            MAX_DEFERRED_EVENTS + 1,
            MAX_DEFERRED_EVENT_BYTES,
        );
        server.add_connection("sock1", wallet(0x11));
        let conn = server.conn("sock1").expect("connection");
        let mut events = (0..=MAX_DEFERRED_EVENTS)
            .map(|sequence| VerifiedEvent {
                sender: "pending peer".into(),
                event_name: "withinConfiguredLimit".into(),
                data: json!({ "sequence": sequence }),
            })
            .collect::<Vec<_>>();

        server.gate_or_defer_events("sock1", &conn, &mut events);

        assert!(events.is_empty());
        assert_eq!(conn.deferred_events.lock().events.len(), 33);
        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Pending)
        );
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
            vec![membership_certificate(0x22, 0x11, &server_identity).await],
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
        server.on_auth_message("sock1", rejected_frame).await;
        let (_, events) = server.pump_once_for_test("sock1").await;
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
            vec![membership_certificate(0x22, 0x11, &server_identity).await],
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
        server.ensure_test_pump("sock1").await;
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
        tokio::time::timeout(
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
        let outbound = server
            .pump_until_for_test("sock1", |outbound, _| {
                (!outbound.is_empty()).then_some(outbound)
            })
            .await;
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].message_type, MessageType::InitialResponse);
        assert!(
            outbound[0].requested_certificates.is_none(),
            "default-off must not add requestedCertificates to the wire"
        );
        assert!(outbound[0].certificates.is_none());
        assert!(outbound[0].payload.is_none());
        assert!(outbound[0].signature.is_some());
        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::NotRequired)
        );
        for response in outbound {
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
        tokio::time::timeout(
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
        let event = server
            .pump_until_for_test("sock1", |outbound, mut events| {
                assert!(outbound.is_empty(), "legacy event ordering is unchanged");
                (!events.is_empty()).then(|| events.remove(0))
            })
            .await;
        assert_eq!(event.event_name, "authenticated");
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
        let certificate = membership_certificate(0x22, 0x11, &server_identity).await;

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
        let certificate = membership_certificate(0x22, 0x11, &server_identity).await;

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

        let genuine = membership_certificate(0x22, 0x11, &server_identity).await;
        let mut tampered =
            certificate_response_frame(&client, &server_identity, vec![genuine]).await;
        tampered.certificates = Some(vec![
            membership_certificate(0x33, 0x11, &server_identity).await,
        ]);
        tampered.signature = Some(vec![0xde, 0xad, 0xbe, 0xef]);

        server.on_auth_message("sock1", tampered).await;
        tokio::task::yield_now().await;
        let (outbound, events) = server.pump_once_for_test("sock1").await;
        assert!(outbound.is_empty() && events.is_empty());
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            0,
            "only SDK-verified batches may reach the authorizer"
        );
        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Pending),
            "an SDK-rejected batch remains pending until the authorization deadline"
        );
    }

    #[tokio::test]
    async fn unsigned_pre_handshake_certificate_response_never_reaches_authorizer() {
        let server_identity = identity_for_scalar(0x11).await;
        let client_identity = identity_for_scalar(0x22).await;
        let invocations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let invocations_cb = invocations.clone();
        let server = AuthSocketServer::new();
        server.set_certificate_authorizer(move |_, _| {
            invocations_cb.fetch_add(1, Ordering::SeqCst);
            async { CertificateAuthorizationDecision::Accept }
        });
        server.add_connection("sock1", wallet(0x11));

        server
            .on_auth_message(
                "sock1",
                AuthMessage {
                    version: "0.1".into(),
                    message_type: MessageType::CertificateResponse,
                    identity_key: client_identity.clone(),
                    nonce: Some("attacker-nonce".into()),
                    your_nonce: Some("forged-session-nonce".into()),
                    initial_nonce: None,
                    certificates: Some(vec![
                        membership_certificate(0x22, 0x11, &server_identity).await,
                    ]),
                    requested_certificates: None,
                    payload: None,
                    signature: None,
                },
            )
            .await;
        server.ensure_test_pump("sock1").await;
        tokio::task::yield_now().await;
        let (outbound, events) = server.pump_once_for_test("sock1").await;
        assert!(outbound.is_empty() && events.is_empty());
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Pending)
        );

        // The invalid frame does not become an application decision. A later
        // genuine handshake can still proceed structurally while authorization
        // remains pending.
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
        server.on_auth_message("sock1", initial_request).await;
        let outbound = server
            .pump_until_for_test("sock1", |outbound, events| {
                assert!(events.is_empty());
                (!outbound.is_empty()).then_some(outbound)
            })
            .await;
        assert_eq!(outbound[0].message_type, MessageType::InitialResponse);
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
        let conn = server.conn("sock1").expect("pending connection");
        let mut events = vec![VerifiedEvent {
            sender: identity_for_scalar(0x22).await,
            event_name: "retainedUntilDeadline".into(),
            data: json!({ "payload": "pending" }),
        }];
        server.gate_or_defer_events("sock1", &conn, &mut events);
        assert_eq!(conn.deferred_events.lock().events.len(), 1);
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
        assert!(
            conn.deferred_events.lock().events.is_empty(),
            "deadline expiry must release retained pending events"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn authorization_deadline_cancels_a_hung_authorizer() {
        let started = Arc::new(tokio::sync::Notify::new());
        let started_cb = started.clone();
        let server = Arc::new(AuthSocketServer::new());
        server.set_certificate_authorization_timeout(Duration::from_secs(5));
        server.set_certificate_authorizer(move |_, _| {
            let started = started_cb.clone();
            async move {
                started.notify_one();
                std::future::pending::<CertificateAuthorizationDecision>().await
            }
        });
        server.add_connection("sock1", wallet(0x11));
        let conn = server.conn("sock1").expect("pending connection");
        let identity = identity_for_scalar(0x22).await;
        *conn.session_peer_identity_key.write() = Some(identity.clone());
        let mut events = vec![VerifiedEvent {
            sender: identity.clone(),
            event_name: "parked".into(),
            data: json!({ "payload": true }),
        }];
        server.gate_or_defer_events("sock1", &conn, &mut events);

        let server_drive = server.clone();
        let conn_drive = conn.clone();
        let drive = tokio::spawn(async move {
            server_drive
                .authorize_verified_certificates(&conn_drive, identity, Vec::new())
                .await
        });
        started.notified().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        let released = drive.await.expect("timed authorizer task must finish");

        assert!(released.is_empty());
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Rejected { reason, .. })
                if reason.contains("timed out")
        ));
        assert!(conn.deferred_events.lock().events.is_empty());
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
        let started = Arc::new(tokio::sync::Notify::new());
        let started_cb = started.clone();
        server.set_certificate_authorizer(move |_, _| {
            let started = started_cb.clone();
            async move {
                started.notify_one();
                tokio::time::sleep(Duration::from_millis(3_500)).await;
                CertificateAuthorizationDecision::Accept
            }
        });
        server.add_connection("sock1", wallet(0x11));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        let frame = certificate_response_frame(
            &client,
            &server_identity,
            vec![membership_certificate(0x22, 0x11, &server_identity).await],
        )
        .await;
        server.on_auth_message("sock1", frame).await;
        started.notified().await;
        tokio::time::advance(Duration::from_millis(3_500)).await;
        tokio::task::yield_now().await;
        assert!(matches!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Accepted { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn authorizer_outlives_sdk_listener_timeout_and_still_reaches_a_decision() {
        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        client
            .peer
            .listen_for_certificates_requested(Arc::new(|_, _| {}));
        let started = Arc::new(tokio::sync::Notify::new());
        let started_cb = started.clone();
        let invocations = Arc::new(AtomicUsize::new(0));
        let invocations_cb = invocations.clone();
        let server = AuthSocketServer::new();
        server.set_certificate_authorization_timeout(Duration::from_secs(60));
        server.set_certificates_to_request(requested_certificates(server_identity.clone()));
        server.set_certificate_authorizer(move |_, _| {
            let started = started_cb.clone();
            let invocations = invocations_cb.clone();
            async move {
                invocations.fetch_add(1, Ordering::SeqCst);
                started.notify_one();
                // Deliberately exceed bsv-sdk's 30-second certificate-listener
                // cap while remaining inside this crate's configured deadline.
                tokio::time::sleep(Duration::from_secs(31)).await;
                CertificateAuthorizationDecision::Accept
            }
        });
        server.add_connection("sock1", wallet(0x11));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        let certificate = membership_certificate(0x22, 0x11, &server_identity).await;
        let first =
            certificate_response_frame(&client, &server_identity, vec![certificate.clone()]).await;
        server.on_auth_message("sock1", first).await;
        started.notified().await;

        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            server.certificate_authorization("sock1"),
            Some(CertificateAuthorization::Pending),
            "the crate's 60-second policy deadline, not the SDK listener cap, owns the decision"
        );

        // A retry arriving after the SDK listener budget must not expose a
        // permanently stuck in-flight latch. The original long lookup may
        // still own the single-flight claim and must reach its terminal result.
        let retry = certificate_response_frame(&client, &server_identity, vec![certificate]).await;
        server.on_auth_message("sock1", retry).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert!(
            matches!(
                server.certificate_authorization("sock1"),
                Some(CertificateAuthorization::Accepted { .. })
            ),
            "long authorizer must reach its terminal decision"
        );
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            1,
            "a retry must not start a concurrent policy lookup"
        );
    }

    #[tokio::test]
    async fn cancelled_authorizer_releases_single_flight_latch_for_retry() {
        let server_identity = identity_for_scalar(0x11).await;
        let client = test_client(0x22).await;
        client
            .peer
            .listen_for_certificates_requested(Arc::new(|_, _| {}));
        let started = Arc::new(tokio::sync::Notify::new());
        let started_cb = started.clone();
        let invocations = Arc::new(AtomicUsize::new(0));
        let invocations_cb = invocations.clone();
        let server = Arc::new(AuthSocketServer::new());
        server.set_certificate_authorizer(move |_, _| {
            let started = started_cb.clone();
            let invocation = invocations_cb.fetch_add(1, Ordering::SeqCst);
            async move {
                if invocation == 0 {
                    started.notify_one();
                    std::future::pending::<CertificateAuthorizationDecision>().await
                } else {
                    CertificateAuthorizationDecision::Accept
                }
            }
        });
        server.add_connection("sock1", wallet(0x11));
        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        let conn = server.conn("sock1").expect("pending connection");
        let identity = client.identity.clone();
        let server_drive = server.clone();
        let conn_drive = conn.clone();
        let first = tokio::spawn(async move {
            server_drive
                .authorize_verified_certificates(&conn_drive, identity, Vec::new())
                .await
        });
        started.notified().await;
        first.abort();
        assert!(first
            .await
            .expect_err("first authorizer is cancelled")
            .is_cancelled());

        let retry = certificate_response_frame(&client, &server_identity, Vec::new()).await;
        server.on_auth_message("sock1", retry).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !matches!(
                server.certificate_authorization("sock1"),
                Some(CertificateAuthorization::Accepted { .. })
            ) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a subsequent certificateResponse must invoke the authorizer");
        assert_eq!(invocations.load(Ordering::SeqCst), 2);
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
            vec![membership_certificate(0x22, 0x11, &server_identity).await],
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
            vec![membership_certificate(0x22, 0x11, &server_identity).await],
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
        server.on_auth_message("sock1", frame).await;
        let events = server
            .pump_until_for_test("sock1", |outbound, events| {
                assert!(outbound.is_empty());
                (!matches!(
                    server.certificate_authorization("sock1"),
                    Some(CertificateAuthorization::Accepted { .. })
                ))
                .then_some(events)
            })
            .await;
        assert!(events.is_empty());
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
        server.ensure_test_pump("sock1").await;
        let (outbound, _) = server.pump_once_for_test("sock1").await;
        assert!(
            outbound.is_empty(),
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
        let peer = client.peer.clone();
        let handshake = tokio::spawn(async move { peer.get_authenticated_session("").await });
        let initial_request = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(frame) = client.out_rx.lock().await.try_recv() {
                    break frame;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("client initialRequest");
        server.ensure_test_pump("sock1").await;
        server.on_auth_message("sock1", initial_request).await;
        let outbound = server
            .pump_until_for_test("sock1", |outbound, _| {
                (!outbound.is_empty()).then_some(outbound)
            })
            .await;
        for response in outbound {
            let _ = client.in_tx.send(response).await;
        }
        handshake
            .await
            .expect("handshake task")
            .expect("certificate-request handshake");

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
                "handshake forwarding timed out"
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
                server.ensure_test_pump("sock1").await;
                server.on_auth_message("sock1", frame).await;
                let (outbound, events) = server.pump_once_for_test("sock1").await;
                if is_general {
                    assert!(
                        events.is_empty(),
                        "forged general message must not verify into an event"
                    );
                }
                for m in outbound {
                    let _ = client.in_tx.send(m).await;
                }
            } else {
                finished = send.is_finished();
            }
            let (outbound, events) = server.pump_once_for_test("sock1").await;
            assert!(
                events.is_empty(),
                "forged general message must not verify into an event"
            );
            for message in outbound {
                let _ = client.in_tx.send(message).await;
            }
            if finished {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
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
        server.ensure_test_pump("sock1").await;
        let (outbound, _) = server.pump_once_for_test("sock1").await;
        assert!(
            outbound.is_empty(),
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
                "handshake forwarding timed out"
            );
            let frame = {
                let mut rx = client.out_rx.lock().await;
                rx.try_recv().ok()
            };
            if let Some(frame) = frame {
                if frame.message_type == MessageType::General {
                    captured_general = Some(frame.clone());
                }
                server.ensure_test_pump("sockA").await;
                server.on_auth_message("sockA", frame).await;
                let (outbound, _) = server.pump_once_for_test("sockA").await;
                for m in outbound {
                    let _ = client.in_tx.send(m).await;
                }
            } else {
                finished = send.is_finished();
            }
            let (outbound, _) = server.pump_once_for_test("sockA").await;
            for message in outbound {
                let _ = client.in_tx.send(message).await;
            }
            if finished {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
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
        server.ensure_test_pump("sockB").await;
        server.on_auth_message("sockB", general).await;
        tokio::task::yield_now().await;
        let (_, events) = server.pump_once_for_test("sockB").await;
        assert!(
            events.is_empty(),
            "cross-socket replay must not verify into an event"
        );
        assert_eq!(
            server.identity_key("sockB"),
            None,
            "A1a backbone: a frame from another socket's session owns nothing here"
        );
    }

    #[tokio::test]
    async fn unmatched_general_errors_do_not_wedge_certificate_exchange_or_valid_event() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let server_identity = identity_for_scalar(0x11).await;
            let client = test_client(0x22).await;
            client
                .peer
                .listen_for_certificates_requested(Arc::new(|_, _| {}));
            let server = AuthSocketServer::new();
            server.set_certificates_to_request(requested_certificates(server_identity.clone()));
            server.set_certificate_authorizer(|_, _| async {
                CertificateAuthorizationDecision::Accept
            });
            server.add_connection("sock1", wallet(0x11));
            client_send(&server, "sock1", &client, "pending", &json!({})).await;

            for sequence in 0..200 {
                server
                    .on_auth_message(
                        "sock1",
                        AuthMessage {
                            version: "0.1".into(),
                            message_type: MessageType::General,
                            identity_key: client.identity.clone(),
                            nonce: Some(format!("unmatched-{sequence}")),
                            initial_nonce: None,
                            your_nonce: Some(format!("unresolvable-{sequence}")),
                            certificates: None,
                            requested_certificates: None,
                            payload: Some(encode_event("ignored", &json!(sequence))),
                            signature: Some(vec![0]),
                        },
                    )
                    .await;
            }

            send_certificates(
                &server,
                "sock1",
                &client,
                &server_identity,
                vec![membership_certificate(0x22, 0x11, &server_identity).await],
            )
            .await;
            let events = client_send_collect(
                &server,
                "sock1",
                &client,
                "afterErrorFlood",
                &json!({ "valid": true }),
            )
            .await;
            assert!(
                events
                    .iter()
                    .any(|event| event.event_name == "afterErrorFlood"),
                "the valid post-certificate frame must reach the pump"
            );
        })
        .await
        .expect("error-flood regression must not wedge");
    }

    #[tokio::test]
    async fn stray_general_before_handshake_does_not_consume_initial_response() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let server = AuthSocketServer::new();
            server.add_connection("sock1", wallet(0x11));
            server.ensure_test_pump("sock1").await;
            let client = test_client(0x22).await;
            server
                .on_auth_message(
                    "sock1",
                    AuthMessage {
                        version: "0.1".into(),
                        message_type: MessageType::General,
                        identity_key: client.identity.clone(),
                        nonce: Some("stray".into()),
                        initial_nonce: None,
                        your_nonce: Some("no-session".into()),
                        certificates: None,
                        requested_certificates: None,
                        payload: Some(encode_event("stray", &json!({}))),
                        signature: Some(vec![0]),
                    },
                )
                .await;
            let events =
                client_send_collect(&server, "sock1", &client, "handshakeStillWorks", &json!({}))
                    .await;
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].event_name, "handshakeStillWorks");
        })
        .await
        .expect("stray frame must not break the handshake");
    }

    #[tokio::test]
    async fn pump_preserves_general_arrival_order_without_sentinel_frame() {
        const EVENT_COUNT: usize = 8;

        tokio::time::timeout(Duration::from_secs(15), async {
            let server_identity = identity_for_scalar(0x11).await;
            let client = test_client(0x22).await;
            client
                .peer
                .listen_for_certificates_requested(Arc::new(|_, _| {}));
            let started = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let server = AuthSocketServer::new();
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
            client_send(&server, "sock1", &client, "handshake", &json!({})).await;

            let certificate = certificate_response_frame(
                &client,
                &server_identity,
                vec![membership_certificate(0x22, 0x11, &server_identity).await],
            )
            .await;
            server.on_auth_message("sock1", certificate).await;
            started.notified().await;

            for sequence in 0..EVENT_COUNT {
                let frame = client
                    .peer
                    .create_general_message(
                        &server_identity,
                        encode_event("ordered", &json!(sequence)),
                    )
                    .await
                    .expect("ordered frame");
                server.on_auth_message("sock1", frame).await;
            }
            server
                .pump_until_for_test("sock1", |_, events| {
                    assert!(events.is_empty());
                    (server
                        .conn("sock1")
                        .expect("connection")
                        .deferred_events
                        .lock()
                        .events
                        .len()
                        == EVENT_COUNT + 1)
                        .then_some(())
                })
                .await;
            release.notify_one();

            let mut observed = Vec::new();
            server
                .pump_until_for_test("sock1", |_, events| {
                    observed.extend(events);
                    matches!(
                        server.certificate_authorization("sock1"),
                        Some(CertificateAuthorization::Accepted { .. })
                    )
                    .then_some(())
                })
                .await;
            server
                .pump_until_for_test("sock1", |_, events| {
                    observed.extend(events);
                    (observed
                        .iter()
                        .filter(|event| event.event_name == "ordered")
                        .count()
                        == EVENT_COUNT)
                        .then_some(())
                })
                .await;

            let sequence: Vec<usize> = observed
                .iter()
                .filter(|event| event.event_name == "ordered")
                .map(|event| event.data.as_u64().expect("sequence number") as usize)
                .collect();
            assert_eq!(sequence, (0..EVENT_COUNT).collect::<Vec<_>>());
        })
        .await
        .expect("ordered events must arrive without an extra sentinel frame");
    }

    #[tokio::test]
    async fn empty_requested_certificate_batch_is_rejected_before_authorizer() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let server_identity = identity_for_scalar(0x11).await;
            let client = test_client(0x22).await;
            client
                .peer
                .listen_for_certificates_requested(Arc::new(|_, _| {}));
            let invocations = Arc::new(AtomicUsize::new(0));
            let invocations_cb = invocations.clone();
            let server = AuthSocketServer::new();
            server.set_certificates_to_request(requested_certificates(server_identity.clone()));
            server.set_certificate_authorizer(move |_, _| {
                invocations_cb.fetch_add(1, Ordering::SeqCst);
                async { CertificateAuthorizationDecision::Accept }
            });
            server.add_connection("sock1", wallet(0x11));
            client_send(&server, "sock1", &client, "pending", &json!({})).await;

            send_certificates(&server, "sock1", &client, &server_identity, Vec::new()).await;
            assert_eq!(invocations.load(Ordering::SeqCst), 0);
            assert!(matches!(
                server.certificate_authorization("sock1"),
                Some(CertificateAuthorization::Rejected { reason, .. })
                    if reason.contains("no certificates")
            ));
            assert_eq!(server.identity_key("sock1"), None);
        })
        .await
        .expect("empty certificate batch rejection must complete");
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
