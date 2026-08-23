//! Client backend over `rust_socketio` (feature `client`).
//!
//! Lifted from the working `rust-messagebox-client` transport half
//! (`socket_transport.rs` + the generic part of `websocket.rs`), with the
//! MessageBox application logic (payments, room app verbs, ack correlation)
//! left in the consumer. What lives here:
//!
//! - [`SocketIOTransport`] — the SDK `Transport` over a `rust_socketio` client.
//! - [`AuthSocketClient::connect`] — WebSocket-first connect, namespace
//!   connect-ack gate, client-initiated BRC-103 handshake
//!   (`peer.send_message("", authenticated-payload)`), `authenticationSuccess`
//!   oneshot.
//! - the background receive loop (drives `Peer::process_next`), the
//!   general-message dispatcher (verified events → `on(event)` handlers or the
//!   fallback), the keepalive probe and the read-deadline watchdog.
//! - PROMPT DEATH DETECTION: the Socket.IO `error` callback wakes the keepalive
//!   for an immediate probe emit, so `is_connected()` tells the truth within
//!   milliseconds of a peer that vanished without a protocol goodbye (SIGKILL,
//!   container restart, TCP reset) — see the `Event::Error` handler in
//!   [`AuthSocketClient::connect`].
//! - [`AuthSocketClient::emit`] / [`AuthSocketClient::join_room`] /
//!   [`AuthSocketClient::leave_room`] — every outbound event is signed as a
//!   BRC-103 general message; there are no raw application events.
//!
//! Reconnect is intentionally OFF for v1 (a reconnect needs a fresh Peer +
//! Transport); the consumer supervises and reconnects.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use rust_socketio::asynchronous::{Client as SocketClient, ClientBuilder};
use rust_socketio::{Event, Payload, TransportType};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, Mutex, Notify};

use async_trait::async_trait;
use bsv::auth::error::AuthError;
use bsv::auth::peer::Peer;
use bsv::auth::transports::Transport;
use bsv::auth::types::{AuthMessage, MessageType, RequestedCertificateSet};
use bsv::wallet::interfaces::{Certificate, WalletInterface};

use crate::wire::{decode_event, encode_event, AUTH_MESSAGE_EVENT};

/// Interval at which the keepalive task emits a probe to elicit inbound
/// traffic.
///
/// CRITICAL INVARIANT: this MUST be comfortably below [`READ_DEADLINE`]. The
/// keepalive probe is an `authenticated` event; the server replies with a
/// signed `authenticationSuccess` general message, which the dispatcher
/// decodes and uses to stamp `last_inbound_ms`. That round-trip is the
/// liveness signal keeping a *subscribed-but-idle* socket alive — without it
/// the watchdog would false-fire and force a reconnect storm. rust_socketio
/// 0.6 exposes no engine.io pong callback, so this application-level
/// round-trip is the only liveness signal available.
///
/// # Why 10s, and why this is a hub-scaling constant
///
/// The keepalive is NOT the dead-peer detector: `Event::Close`, a failed emit,
/// and the read-deadline watchdog are. Its only job is to generate inbound
/// traffic while a connection is idle, so the watchdog can tell "quiet" apart
/// from "dead" — which matters solely for the HALF-OPEN case, where a peer
/// vanishes without a FIN. A clean close is caught instantly without it.
///
/// Every probe is a SIGNED message the server must verify, so an idle fleet
/// costs the hub roughly `N / KEEPALIVE_INTERVAL` signature verifications per
/// second with nothing else happening. At the original 2s that is ~500/s per
/// thousand idle connections — pure overhead on the one component every vault
/// shares. 10s cuts that 5x while keeping half-open detection (30s, below) far
/// inside the ceremony round deadlines that actually depend on it.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Inbound read deadline for half-open detection. If NO frame of any kind
/// arrives within this window, the socket is declared dead (`is_connected()`
/// flips false) so the consumer's supervisor can reconnect. ~3x the keepalive
/// cycle: tolerates transient jitter without false-firing, still detects a
/// black-holed peer within ~30-32 s.
///
/// This and [`KEEPALIVE_INTERVAL`] move TOGETHER — the invariants asserted in
/// this module's tests tie them, and a client whose keepalive outruns a
/// server's tolerance disconnects in a loop with no error anywhere. The pair is
/// a graph-wide auth-boundary property (TR-011): change it in one release and
/// bump every consumer together.
pub const READ_DEADLINE: Duration = Duration::from_secs(30);

/// How often the watchdog checks the inbound read deadline. Scaled with the
/// pair above: a tick far below the deadline only burns wakeups.
const WATCHDOG_TICK: Duration = Duration::from_secs(2);

/// Maximum time to wait for the Socket.IO namespace connect-ack ("40{sid}")
/// before failing the connection.
const CONNECT_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Legacy servers complete authentication promptly because no certificate
/// authorization decision is involved. Preserve the pre-certificate failure
/// budget until an inbound handshake frame actually requests certificates.
const LEGACY_AUTHENTICATION_SUCCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Default maximum time to wait for the server's signed
/// `authenticationSuccess` after the BRC-103 handshake.
///
/// This matches the server's default certificate-authorization budget. Use
/// [`AuthSocketClientOptions::set_authentication_success_timeout`] when the
/// server is configured with a different budget.
pub const AUTHENTICATION_SUCCESS_TIMEOUT: Duration = Duration::from_secs(30);

fn authentication_success_wait_budget(
    certificate_requested: bool,
    configured_timeout: Duration,
) -> Duration {
    if certificate_requested {
        configured_timeout
    } else {
        configured_timeout.min(LEGACY_AUTHENTICATION_SUCCESS_TIMEOUT)
    }
}

/// Connection-time settings for [`AuthSocketClient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthSocketClientOptions {
    authentication_success_timeout: Duration,
}

impl Default for AuthSocketClientOptions {
    fn default() -> Self {
        Self {
            authentication_success_timeout: AUTHENTICATION_SUCCESS_TIMEOUT,
        }
    }
}

impl AuthSocketClientOptions {
    /// Set how long connection establishment waits for the server's signed
    /// `authenticationSuccess`, including any certificate authorization.
    pub fn set_authentication_success_timeout(&mut self, timeout: Duration) {
        assert!(
            !timeout.is_zero(),
            "authentication success timeout must be non-zero"
        );
        self.authentication_success_timeout = timeout;
    }

    /// The configured authentication-success timeout.
    pub fn authentication_success_timeout(&self) -> Duration {
        self.authentication_success_timeout
    }
}

/// Client-side errors.
#[derive(Debug)]
pub enum ClientError {
    /// Socket.IO / transport failure.
    WebSocket(String),
    /// BRC-103 handshake failure.
    Handshake(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::WebSocket(e) => write!(f, "authsocket websocket: {e}"),
            ClientError::Handshake(e) => write!(f, "authsocket handshake: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// Exact-match event handler: receives the verified event's `data`.
pub type EventHandler = Arc<dyn Fn(Value) + Send + Sync>;
/// Fallback handler for events without an exact-match handler:
/// `(event_name, data)`.
pub type FallbackHandler = Arc<dyn Fn(String, Value) + Send + Sync>;

/// Async client-side certificate provider. Arguments are the authenticated
/// verifier identity and its requested certificate set. Returning an error (or
/// an empty batch) fails the connection with certificate-specific diagnostics.
pub type CertificateProvider = Arc<
    dyn Fn(
            String,
            RequestedCertificateSet,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Certificate>, String>> + Send>>
        + Send
        + Sync,
>;

type HandlerMap = Arc<Mutex<HashMap<String, EventHandler>>>;
type AuthSuccessSender = Arc<Mutex<Option<oneshot::Sender<Result<(), String>>>>>;

/// Type-erased BRC-103 signer.
///
/// Captures `Arc<Peer<W>>` + the server identity key so the send path can sign
/// a general-message payload WITHOUT knowing the wallet type `W` and WITHOUT a
/// serializing command channel. `Peer::create_general_message` is `&self` —
/// N callers sign in parallel against one session.
type Signer = Arc<
    dyn Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = Result<AuthMessage, String>> + Send>>
        + Send
        + Sync,
>;

// ---------------------------------------------------------------------------
// SocketIOTransport
// ---------------------------------------------------------------------------

/// Socket.IO transport adapter implementing the SDK's `Transport` trait.
///
/// Bridges `authMessage` Socket.IO events to/from `mpsc` channels so the SDK's
/// `Peer` can use a Socket.IO connection for BRC-103 mutual authentication.
///
/// **Construction pattern:** receives an already-built `Client` (from
/// `ClientBuilder::connect().await`) and the rx end of a channel whose tx was
/// captured inside the `on("authMessage", ...)` callback during builder setup.
///
/// **Client sharing:** `rust_socketio::Client` is `Clone` — clones share the
/// same underlying connection, so the transport and the send path can emit on
/// one socket.
///
/// **subscribe() is take-once**, matching the SDK contract; create a fresh
/// `SocketIOTransport` on reconnect.
pub struct SocketIOTransport {
    client: SocketClient,
    incoming_rx: Arc<Mutex<Option<mpsc::Receiver<AuthMessage>>>>,
}

impl SocketIOTransport {
    /// Create a new `SocketIOTransport` from an already-connected client and
    /// the receive end of the `on("authMessage")` channel.
    pub fn new(client: SocketClient, incoming_rx: mpsc::Receiver<AuthMessage>) -> Self {
        Self {
            client,
            incoming_rx: Arc::new(Mutex::new(Some(incoming_rx))),
        }
    }
}

#[async_trait]
impl Transport for SocketIOTransport {
    /// Serialize `message` as JSON and emit it on the `authMessage` event.
    async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
        let json = serde_json::to_value(&message)
            .map_err(|e| AuthError::SerializationError(e.to_string()))?;
        self.client
            .emit(AUTH_MESSAGE_EVENT, json)
            .await
            .map_err(|e| AuthError::TransportError(e.to_string()))
    }

    /// Return the `mpsc::Receiver` for incoming `AuthMessage` events.
    ///
    /// Uses `try_lock` because the SDK trait method is non-async and
    /// `blocking_lock` panics inside a tokio runtime. Panics on second call.
    fn subscribe(&self) -> mpsc::Receiver<AuthMessage> {
        self.incoming_rx
            .try_lock()
            .expect("subscribe() mutex should not be contended")
            .take()
            .expect("subscribe() can only be called once per SocketIOTransport")
    }
}

/// Extract an `AuthMessage` from a rust_socketio `Payload` (first Text value).
pub fn parse_auth_message_from_payload(payload: &Payload) -> Option<AuthMessage> {
    match payload {
        Payload::Text(values) => {
            let first = values.first()?;
            serde_json::from_value::<AuthMessage>(first.clone()).ok()
        }
        _ => None,
    }
}

/// Monotonic milliseconds since an arbitrary fixed epoch, for read-deadline math.
fn now_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Serialize a signed `AuthMessage` and emit it as `authMessage` — the same
/// wire framing `SocketIOTransport::send` uses. Emitting directly (rather than
/// through the Peer's transport) lets the send path run concurrently with the
/// receive task's `process_next`.
async fn emit_auth_message(client: &SocketClient, message: &AuthMessage) -> Result<(), String> {
    let json = serde_json::to_value(message).map_err(|e| e.to_string())?;
    client
        .emit(AUTH_MESSAGE_EVENT, json)
        .await
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// AuthSocketClient
// ---------------------------------------------------------------------------

/// BRC-103 mutually-authenticated Socket.IO client.
///
/// Every application event, both directions, is a signed BRC-103 general
/// message carried on the single `authMessage` Socket.IO event. Verified
/// inbound events are dispatched to [`AuthSocketClient::on`] handlers (exact
/// event-name match) or the [`AuthSocketClient::set_fallback`] handler.
///
/// This high-level client has no API for observing certificates sent by the
/// server. The SDK can verify an inbound `certificateResponse` while advancing
/// the protocol, but `AuthSocketClient` drops the certificate receiver and the
/// delivered batch is discarded. The `connect_with_certificates` and
/// `connect_with_certificate_provider` families supply this client's
/// certificates to a requesting server; they do not expose server
/// certificates. Consumers that need the latter must drive a
/// [`Peer`](bsv::auth::peer::Peer) with [`SocketIOTransport`] directly and keep
/// its `on_certificates` receiver.
pub struct AuthSocketClient {
    /// Socket.IO client handle. `Client` is `Clone` (an `Arc` over the
    /// connection) and every emit takes `&self` — concurrent emits are safe.
    client: SocketClient,
    /// Type-erased BRC-103 signer over `Arc<Peer<W>>` + server identity key.
    signer: Signer,
    /// Exact-match handlers: event name → callback.
    handlers: HandlerMap,
    /// Fallback for events without an exact-match handler.
    fallback: Arc<Mutex<Option<FallbackHandler>>>,
    /// Rooms currently joined (idempotency on join_room; re-asserted in every
    /// keepalive probe so hub-side membership self-heals).
    joined_rooms: Arc<Mutex<HashSet<String>>>,
    /// True once the server sends authenticationSuccess AND the socket is
    /// live. Flipped false by the watchdog on read-deadline expiry, by the
    /// dispatcher on channel close, and by the Close lifecycle handler.
    connected: Arc<AtomicBool>,
    /// DEATH LATCH — set (never cleared) the moment any component declares the
    /// socket dead: watchdog read-deadline expiry, Close lifecycle event, a
    /// failed emit, keepalive failure (including the out-of-band probe the
    /// Socket.IO `error` callback triggers), dispatcher channel close, or an
    /// explicit `disconnect()`. `is_connected()` requires `!dead`, so a late
    /// `authenticationSuccess` (e.g. a draining server flushing stale keepalive
    /// replies) can re-store `connected` but can NEVER resurrect a client whose
    /// watchdog/keepalive tasks have already exited — that resurrection left a
    /// permanent zombie (`is_connected()` true, no watchdog running) the
    /// consumer's supervisor could never heal. A client is single-flight:
    /// once dead, the consumer must build a fresh one.
    dead: Arc<AtomicBool>,
    /// Monotonic millis of the last inbound frame of ANY kind (watchdog
    /// half-open detection).
    last_inbound_ms: Arc<AtomicU64>,
    /// Kept alive for the lifetime of the client so the Socket.IO `error`
    /// callback and the keepalive task keep sharing one waker.
    _transport_error: Arc<Notify>,
    /// The server's identity key captured during the BRC-103 handshake.
    server_identity_key: String,
}

impl AuthSocketClient {
    /// Connect to an authsocket server and complete the BRC-103 mutual
    /// authentication handshake before returning.
    ///
    /// `identity_key` is this client's own identity key (sent in the
    /// `authenticated` event payload and the keepalive probes); `wallet` signs
    /// as that identity.
    pub async fn connect<W>(url: &str, identity_key: &str, wallet: W) -> Result<Self, ClientError>
    where
        W: WalletInterface + Send + Sync + 'static,
    {
        Self::connect_with_options(
            url,
            identity_key,
            wallet,
            AuthSocketClientOptions::default(),
        )
        .await
    }

    /// Connect with explicit connection-time settings.
    pub async fn connect_with_options<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        options: AuthSocketClientOptions,
    ) -> Result<Self, ClientError>
    where
        W: WalletInterface + Send + Sync + 'static,
    {
        Self::connect_inner(url, identity_key, wallet, None, options).await
    }

    /// Connect and answer certificate requests with `certificates` before the
    /// first signed `authenticated` event is sent.
    pub async fn connect_with_certificates<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        certificates: Vec<Certificate>,
    ) -> Result<Self, ClientError>
    where
        W: WalletInterface + Send + Sync + 'static,
    {
        Self::connect_with_certificates_and_options(
            url,
            identity_key,
            wallet,
            certificates,
            AuthSocketClientOptions::default(),
        )
        .await
    }

    /// Connect with a fixed certificate batch and explicit connection-time
    /// settings.
    pub async fn connect_with_certificates_and_options<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        certificates: Vec<Certificate>,
        options: AuthSocketClientOptions,
    ) -> Result<Self, ClientError>
    where
        W: WalletInterface + Send + Sync + 'static,
    {
        let certificates = Arc::new(certificates);
        let provider: CertificateProvider = Arc::new(move |_, _| {
            let certificates = certificates.clone();
            Box::pin(async move { Ok((*certificates).clone()) })
        });
        Self::connect_inner(url, identity_key, wallet, Some(provider), options).await
    }

    /// Connect with an async certificate provider. Unlike the SDK's automatic
    /// wallet lookup, this path reports provider/send failures and guarantees
    /// the response is emitted before `authenticated`, so a certificate-gated
    /// server cannot suppress the only authentication acknowledgement trigger.
    pub async fn connect_with_certificate_provider<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        provider: CertificateProvider,
    ) -> Result<Self, ClientError>
    where
        W: WalletInterface + Send + Sync + 'static,
    {
        Self::connect_with_certificate_provider_and_options(
            url,
            identity_key,
            wallet,
            provider,
            AuthSocketClientOptions::default(),
        )
        .await
    }

    /// Connect with an async certificate provider and explicit
    /// connection-time settings.
    pub async fn connect_with_certificate_provider_and_options<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        provider: CertificateProvider,
        options: AuthSocketClientOptions,
    ) -> Result<Self, ClientError>
    where
        W: WalletInterface + Send + Sync + 'static,
    {
        Self::connect_inner(url, identity_key, wallet, Some(provider), options).await
    }

    async fn connect_inner<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        certificate_provider: Option<CertificateProvider>,
        options: AuthSocketClientOptions,
    ) -> Result<Self, ClientError>
    where
        W: WalletInterface + Send + Sync + 'static,
    {
        let certificate_provider_configured = certificate_provider.is_some();
        let handlers: HandlerMap = Arc::new(Mutex::new(HashMap::new()));
        let fallback: Arc<Mutex<Option<FallbackHandler>>> = Arc::new(Mutex::new(None));
        let joined_rooms: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let connected = Arc::new(AtomicBool::new(false));
        let dead = Arc::new(AtomicBool::new(false));
        // Read-deadline tracker: every inbound frame stamps this. Initialized
        // to "now" so the watchdog does not fire before the first frame.
        let last_inbound_ms = Arc::new(AtomicU64::new(now_ms()));
        let certificate_requested = Arc::new(AtomicBool::new(false));

        // Incoming BRC-103 authMessage events → SocketIOTransport → Peer.
        let (auth_msg_tx, auth_msg_rx) = mpsc::channel(64);
        // Server identity key captured from the handshake frames.
        let (server_key_tx, mut server_key_rx) = mpsc::channel::<String>(1);
        // authenticationSuccess oneshot (fired by the dispatcher).
        let (auth_success_tx, auth_success_rx) = oneshot::channel::<Result<(), String>>();
        let auth_success_shared: AuthSuccessSender = Arc::new(Mutex::new(Some(auth_success_tx)));

        // Raised by the Socket.IO `error` callback; consumed by the keepalive
        // task, which answers it with an IMMEDIATE probe emit. See
        // [`AuthSocketClient`]'s "prompt death detection" note.
        let transport_error: Arc<Notify> = Arc::new(Notify::new());

        let conn_clone = connected.clone();
        let conn_close_clone = connected.clone();
        let dead_close_clone = dead.clone();
        let auth_failure_close = auth_success_shared.clone();
        let transport_error_cb = transport_error.clone();

        // Socket.IO connect-ack gate. `rust_socketio::connect()` sends the
        // namespace CONNECT packet ("40") and returns immediately, without
        // waiting for the server's connect-ack ("40{sid}"). Emitting in that
        // window races the handshake; spec-strict servers (socketioxide)
        // reject an event received before the namespace is connected and
        // close the socket. Hold the first emit until Event::Connect.
        let (connect_ready_tx, mut connect_ready_rx) = mpsc::channel::<()>(1);
        let connect_ready_tx_cb = connect_ready_tx.clone();

        let auth_msg_tx_clone = auth_msg_tx.clone();
        let server_key_tx_clone = server_key_tx.clone();
        let last_inbound_for_auth = last_inbound_ms.clone();
        let certificate_requested_for_auth = certificate_requested.clone();

        // Handlers ONLY for `authMessage` + Connect/Close lifecycle. There is
        // deliberately no raw application-event handler: every application
        // message must arrive as a BRC-103-verified general message, never as
        // an unsigned raw event.
        let client = ClientBuilder::new(url)
            .on(AUTH_MESSAGE_EVENT, move |payload, _socket| {
                let tx = auth_msg_tx_clone.clone();
                let key_tx = server_key_tx_clone.clone();
                let last_inbound = last_inbound_for_auth.clone();
                let certificate_requested = certificate_requested_for_auth.clone();
                async move {
                    // Any inbound authMessage frame is proof of life.
                    last_inbound.store(now_ms(), Ordering::SeqCst);
                    if let Some(msg) = parse_auth_message_from_payload(&payload) {
                        if msg
                            .requested_certificates
                            .as_ref()
                            .is_some_and(|requested| {
                                !requested.is_empty() || !requested.certifiers.is_empty()
                            })
                        {
                            certificate_requested.store(true, Ordering::SeqCst);
                        }
                        // Capture the server identity key from the handshake
                        // frames so it can be retrieved after the handshake
                        // completes (the Peer itself verifies it during
                        // complete_handshake).
                        if msg.message_type == MessageType::InitialRequest
                            || msg.message_type == MessageType::InitialResponse
                        {
                            let _ = key_tx.send(msg.identity_key.clone()).await;
                        }
                        let _ = tx.send(msg).await;
                    }
                }
                .boxed()
            })
            // Connect: the namespace connect-ack arrived — release the gate.
            .on(Event::Connect, move |_payload, _socket| {
                let conn = conn_clone.clone();
                let ready = connect_ready_tx_cb.clone();
                async move {
                    conn.store(true, Ordering::SeqCst);
                    let _ = ready.try_send(());
                }
                .boxed()
            })
            // Close: transport went away — dead, terminally (a closed socket
            // never comes back; the consumer reconnects with a fresh client).
            .on(Event::Close, move |_payload, _socket| {
                let conn = conn_close_clone.clone();
                let dead = dead_close_clone.clone();
                let auth_failure = auth_failure_close.clone();
                async move {
                    dead.store(true, Ordering::SeqCst);
                    conn.store(false, Ordering::SeqCst);
                    if let Some(tx) = auth_failure.lock().await.take() {
                        let _ =
                            tx.send(Err("socket closed before authenticationSuccess".to_string()));
                    }
                }
                .boxed()
            })
            // Error: rust_socketio surfaces EVERY transport failure here, and
            // it is the ONLY prompt death signal the stack gives us —
            // `Event::Close` fires solely on a graceful Socket.IO `disconnect`
            // packet, which a SIGKILLed/restarted/reset peer never sends, and
            // `.reconnect(false)` makes the poller task exit in silence once
            // its stream ends. Measured: this callback runs within a
            // millisecond of the peer vanishing.
            //
            // It is NOT self-evidently terminal, though: rust_socketio also
            // routes a malformed inbound application frame here without
            // killing the socket. So this is a TRIGGER TO RE-VERIFY, not a
            // verdict — it wakes the keepalive, which emits a probe NOW. A
            // dead transport fails that write and latches death; a live one
            // sails through and nothing changes. Liveness is therefore always
            // decided by an actual write to the socket, never by a flag.
            .on(Event::Error, move |_payload, _socket| {
                let wake = transport_error_cb.clone();
                async move {
                    wake.notify_one();
                }
                .boxed()
            })
            // WebSocket-first: the EngineIO long-poll→WS upgrade exchanges
            // probe frames many reverse proxies forward unreliably; WS-first
            // runs the handshake directly over the WebSocket.
            .transport_type(TransportType::Websocket)
            // Reconnect OFF for v1 — reconnect requires fresh Peer + Transport;
            // the consumer supervises.
            .reconnect(false)
            .connect()
            .await
            .map_err(|e| ClientError::WebSocket(e.to_string()))?;

        // Peer over the connected socket. Does NOT self-drive; the receive
        // task below drives process_next().
        let transport = SocketIOTransport::new(client.clone(), auth_msg_rx);
        let peer = Arc::new(Peer::new(wallet, Arc::new(transport)));

        // Take and drop the SDK's bounded verified-certificate receiver. This
        // high-level client has no inbound-certificate observer, so verified
        // server batches are deliberately discarded; leaving the receiver
        // alive but unread would block process_next on response 33.
        drop(
            peer.on_certificates()
                .expect("on_certificates take-once: fresh Peer"),
        );

        // Provider mode takes control of the SDK callback before the handshake.
        // The callback itself is synchronous, so async certificate retrieval and
        // response sending run in a task and report completion through this
        // channel. The first app event is held until that report arrives.
        let (certificate_result_tx, mut certificate_result_rx) = mpsc::channel(1);
        if let Some(provider) = certificate_provider.clone() {
            let peer_for_certificates = peer.clone();
            let requested_flag = certificate_requested.clone();
            peer.listen_for_certificates_requested(Arc::new(move |verifier, requested| {
                requested_flag.store(true, Ordering::SeqCst);
                let provider = provider.clone();
                let peer = peer_for_certificates.clone();
                let result_tx = certificate_result_tx.clone();
                tokio::spawn(async move {
                    let result = match provider(verifier.clone(), requested).await {
                        Ok(certificates) if certificates.is_empty() => {
                            Err("certificate provider returned an empty batch".to_string())
                        }
                        Ok(certificates) => peer
                            .send_certificate_response(&verifier, certificates)
                            .await
                            .map_err(|error| error.to_string()),
                        Err(error) => Err(error),
                    };
                    let _ = result_tx.send(result).await;
                });
            }));
        }

        // Take-once, before any task can race for it.
        let general_msg_rx = peer
            .on_general_message()
            .expect("on_general_message take-once: fresh Peer");

        // Any post-socket failure below must tear the socket down before
        // returning: an errored connect that leaves the Socket.IO connection
        // open leaks a live socket (and its server-side session) per attempt.
        // `dead` is latched first so every spawned task exits promptly.
        let abandon = |client: SocketClient, connected: Arc<AtomicBool>, dead: Arc<AtomicBool>| async move {
            dead.store(true, Ordering::SeqCst);
            connected.store(false, Ordering::SeqCst);
            let _ = client.disconnect().await;
        };

        // Hold the first emit until the namespace connect-ack arrives, so the
        // BRC-103 InitialRequest is never delivered ahead of the namespace
        // handshake.
        match tokio::time::timeout(CONNECT_ACK_TIMEOUT, connect_ready_rx.recv()).await {
            Ok(Some(())) => {}
            _ => {
                abandon(client, connected, dead).await;
                return Err(ClientError::WebSocket(
                    "Socket.IO connect-ack not received before timeout".into(),
                ));
            }
        }

        // Client-initiated BRC-103 handshake. Legacy/default mode retains the
        // original single send_message("") path exactly. Provider mode first
        // establishes the session, waits for any requested response to be sent,
        // and only then sends the first `authenticated` general message.
        let auth_payload = encode_event("authenticated", &json!({ "identityKey": identity_key }));
        let handshake_result = if certificate_provider_configured {
            match peer.get_authenticated_session("").await {
                Ok(session) => {
                    if certificate_requested.load(Ordering::SeqCst) {
                        match tokio::time::timeout(
                            options.authentication_success_timeout,
                            certificate_result_rx.recv(),
                        )
                        .await
                        {
                            Ok(Some(Ok(()))) => {
                                peer.send_message(&session.peer_identity_key, auth_payload)
                                    .await
                            }
                            Ok(Some(Err(error))) => Err(AuthError::TransportError(format!(
                                "certificate provisioning failed: {error}"
                            ))),
                            Ok(None) => Err(AuthError::TransportError(
                                "certificate provider completion channel closed".into(),
                            )),
                            Err(_) => Err(AuthError::TransportError(format!(
                                "certificate response was not sent within {}s",
                                options.authentication_success_timeout.as_secs_f64()
                            ))),
                        }
                    } else {
                        peer.send_message(&session.peer_identity_key, auth_payload)
                            .await
                    }
                }
                Err(error) => Err(error),
            }
        } else {
            peer.send_message("", auth_payload).await
        };
        if let Err(e) = handshake_result {
            abandon(client, connected, dead).await;
            let message = if certificate_requested.load(Ordering::SeqCst)
                && !certificate_provider_configured
            {
                format!(
                    "certificate provisioning failed after the server requested certificates: {e}; configure connect_with_certificates or connect_with_certificate_provider"
                )
            } else if certificate_requested.load(Ordering::SeqCst) {
                format!(
                    "certificate provisioning failed after the server requested certificates: {e}"
                )
            } else {
                e.to_string()
            };
            return Err(ClientError::Handshake(message));
        }

        // The server identity key captured by the authMessage callback.
        let server_identity_key = match server_key_rx.try_recv() {
            Ok(k) => k,
            Err(_) => {
                abandon(client, connected, dead).await;
                return Err(ClientError::Handshake(
                    "handshake completed but server identity key not captured".into(),
                ));
            }
        };

        // Type-erased signer: N concurrent sends sign in parallel.
        let signer: Signer = {
            let peer_for_signer = peer.clone();
            let server_key = server_identity_key.clone();
            Arc::new(move |payload: Vec<u8>| {
                let peer = peer_for_signer.clone();
                let server_key = server_key.clone();
                Box::pin(async move {
                    peer.create_general_message(&server_key, payload)
                        .await
                        .map_err(|e| e.to_string())
                })
                    as Pin<Box<dyn Future<Output = Result<AuthMessage, String>> + Send>>
            })
        };

        // Receive task: drives process_next() until tear-down. `process_next`
        // returns Ok(false) both for "no message yet" AND a disconnected
        // transport, so it exits on the death latch (or on `connected`
        // flipping false — latched on the first observed true so it survives
        // the pre-auth window).
        {
            let peer_for_recv = peer.clone();
            let connected_for_recv = connected.clone();
            let dead_for_recv = dead.clone();
            tokio::spawn(async move {
                let mut was_connected = false;
                loop {
                    if dead_for_recv.load(Ordering::SeqCst) {
                        break;
                    }
                    match peer_for_recv.process_next().await {
                        Ok(true) => {}
                        Ok(false) => {
                            let live = connected_for_recv.load(Ordering::SeqCst);
                            was_connected |= live;
                            if was_connected && !live {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                        Err(_) => {
                            // Verification errors (stale session, replayed
                            // nonce) are non-fatal — the socket stays open.
                            let live = connected_for_recv.load(Ordering::SeqCst);
                            was_connected |= live;
                            if was_connected && !live {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }

        // Keepalive task: signed `authenticated` probe every KEEPALIVE_INTERVAL.
        // The server's signed authenticationSuccess reply refreshes the read
        // deadline — the only liveness signal for an idle subscriber. The probe
        // also carries a snapshot of our joined rooms: the server re-asserts
        // that membership on every keepalive (own-room check unchanged), so
        // hub-side routability self-heals within one keepalive interval even if
        // a join was ever lost server-side.
        {
            let keepalive_signer = signer.clone();
            let keepalive_client = client.clone();
            let identity_for_keepalive = identity_key.to_string();
            let connected_for_keepalive = connected.clone();
            let dead_for_keepalive = dead.clone();
            let rooms_for_keepalive = joined_rooms.clone();
            let transport_error_keepalive = transport_error.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(KEEPALIVE_INTERVAL);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                interval.tick().await; // skip the immediate first tick
                loop {
                    // Either the cadence came round, or the transport reported
                    // an error and we owe the caller an immediate verdict.
                    // `Notify::notified()` coalesces, so an error storm costs
                    // one probe, not one per error.
                    tokio::select! {
                        _ = interval.tick() => {}
                        _ = transport_error_keepalive.notified() => {}
                    }
                    if dead_for_keepalive.load(Ordering::SeqCst) {
                        break; // socket declared dead — stop pinging
                    }
                    if !connected_for_keepalive.load(Ordering::SeqCst) {
                        continue; // still coming up
                    }
                    let rooms: Vec<String> = {
                        let guard = rooms_for_keepalive.lock().await;
                        guard.iter().cloned().collect()
                    };
                    let ping = encode_event(
                        "authenticated",
                        &json!({ "identityKey": identity_for_keepalive, "rooms": rooms }),
                    );
                    match keepalive_signer(ping).await {
                        Ok(signed) => {
                            if emit_auth_message(&keepalive_client, &signed).await.is_err() {
                                dead_for_keepalive.store(true, Ordering::SeqCst);
                                connected_for_keepalive.store(false, Ordering::SeqCst);
                                break;
                            }
                        }
                        Err(_) => {
                            dead_for_keepalive.store(true, Ordering::SeqCst);
                            connected_for_keepalive.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            });
        }

        // Watchdog task: enforce the inbound read deadline (half-open
        // detection). Declares the socket dead within READ_DEADLINE of the
        // last inbound frame, so is_connected() reflects reality long before
        // the next write would fail.
        {
            let watchdog_last_inbound = last_inbound_ms.clone();
            let watchdog_connected = connected.clone();
            let watchdog_dead = dead.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(WATCHDOG_TICK);
                loop {
                    tick.tick().await;
                    if watchdog_dead.load(Ordering::SeqCst) {
                        break;
                    }
                    if !watchdog_connected.load(Ordering::SeqCst) {
                        continue;
                    }
                    let last = watchdog_last_inbound.load(Ordering::SeqCst);
                    let elapsed = now_ms().saturating_sub(last);
                    if elapsed >= READ_DEADLINE.as_millis() as u64 {
                        // Terminal verdict: latch the death flag FIRST so no
                        // late frame (a draining server flushing stale
                        // keepalive replies) can resurrect `connected` after
                        // this task exits.
                        watchdog_dead.store(true, Ordering::SeqCst);
                        watchdog_connected.store(false, Ordering::SeqCst);
                        tracing::warn!(
                            elapsed_ms = elapsed,
                            "authsocket: read deadline expired — socket declared half-open dead"
                        );
                        break;
                    }
                }
            });
        }

        // Dispatcher task: decoded, VERIFIED general messages → handlers.
        {
            let auth_success_shared = auth_success_shared.clone();
            let handlers = handlers.clone();
            let fallback = fallback.clone();
            let connected_for_dispatch = connected.clone();
            let dead_for_dispatch = dead.clone();
            let last_inbound_for_dispatch = last_inbound_ms.clone();
            let mut general_msg_rx = general_msg_rx;
            tokio::spawn(async move {
                loop {
                    match general_msg_rx.recv().await {
                        Some((_sender_key, payload_bytes)) => {
                            // Any decoded general message is proof of life.
                            last_inbound_for_dispatch.store(now_ms(), Ordering::SeqCst);
                            let Some((event_name, data)) = decode_event(&payload_bytes) else {
                                continue;
                            };
                            if event_name == "authenticationSuccess" {
                                // Up-latch only: `is_connected()` also requires
                                // `!dead`, so a stale reply arriving after the
                                // watchdog's verdict cannot resurrect a dead
                                // client.
                                connected_for_dispatch.store(true, Ordering::SeqCst);
                                let mut guard = auth_success_shared.lock().await;
                                if let Some(tx) = guard.take() {
                                    let _ = tx.send(Ok(()));
                                }
                            }
                            let handler = { handlers.lock().await.get(&event_name).cloned() };
                            if let Some(h) = handler {
                                h(data);
                            } else if let Some(f) = fallback.lock().await.clone() {
                                f(event_name, data);
                            }
                        }
                        None => {
                            // Peer dropped (socket died) — make is_connected()
                            // trustworthy.
                            dead_for_dispatch.store(true, Ordering::SeqCst);
                            connected_for_dispatch.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            });
        }

        // A legacy server gets the original short failure budget. A server
        // that requested certificates gets the configured authorization-sized
        // budget; the Socket.IO callback sets the flag before the handshake
        // frame reaches the Peer, so it is observable by this point.
        let authentication_success_timeout = authentication_success_wait_budget(
            certificate_requested.load(Ordering::SeqCst),
            options.authentication_success_timeout,
        );
        match tokio::time::timeout(authentication_success_timeout, auth_success_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(reason))) => {
                abandon(client, connected, dead).await;
                let message = if certificate_requested.load(Ordering::SeqCst)
                    && !certificate_provider_configured
                {
                    format!(
                        "{reason}; the server requested certificates, so configure connect_with_certificates or connect_with_certificate_provider and ensure the server accepts the batch"
                    )
                } else if certificate_requested.load(Ordering::SeqCst) {
                    format!(
                        "{reason}; the server closed before certificate authorization completed"
                    )
                } else {
                    reason
                };
                return Err(ClientError::Handshake(message));
            }
            Ok(Err(_)) => {
                abandon(client, connected, dead).await;
                return Err(ClientError::Handshake(
                    "auth success channel dropped".into(),
                ));
            }
            Err(_) => {
                abandon(client, connected, dead).await;
                let message = if certificate_requested.load(Ordering::SeqCst)
                    && !certificate_provider_configured
                {
                    format!(
                        "authenticationSuccess not received within {}s after the server requested certificates; configure connect_with_certificates or connect_with_certificate_provider and ensure the server accepts the batch",
                        authentication_success_timeout.as_secs_f64()
                    )
                } else if certificate_requested.load(Ordering::SeqCst) {
                    format!(
                        "authenticationSuccess not received within {}s after the certificate response was sent; align AuthSocketClientOptions with the server's certificate-authorization timeout",
                        authentication_success_timeout.as_secs_f64()
                    )
                } else {
                    format!(
                        "authenticationSuccess not received within {}s",
                        authentication_success_timeout.as_secs_f64()
                    )
                };
                return Err(ClientError::Handshake(message));
            }
        }

        Ok(Self {
            client,
            signer,
            handlers,
            fallback,
            joined_rooms,
            connected,
            dead,
            last_inbound_ms,
            _transport_error: transport_error,
            server_identity_key,
        })
    }

    /// True if the connection is currently authenticated and live. Once any
    /// component latches the death flag (watchdog, Close event, failed emit,
    /// `disconnect()`), this is false FOREVER — a client is single-flight; the
    /// consumer reconnects by building a fresh one.
    ///
    /// CONSUMER CONTRACT: a `true` here means "the last write to this socket
    /// succeeded and nothing since has said otherwise". Supervisors read it as
    /// "an emit will reach the hub", so every path that can learn the socket is
    /// gone must latch death BEFORE the next caller reads this — that is why
    /// the Socket.IO `error` callback forces an out-of-band probe rather than
    /// leaving the verdict to the next 10s keepalive tick. Note that a socket
    /// can still die in the window between this returning `true` and the
    /// caller's emit landing; callers must treat a send error as retryable,
    /// not as a violation of this contract.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst) && !self.dead.load(Ordering::SeqCst)
    }

    /// Milliseconds since the last inbound frame of any kind (the watchdog's
    /// read-deadline tracker).
    pub fn ms_since_last_inbound(&self) -> u64 {
        now_ms().saturating_sub(self.last_inbound_ms.load(Ordering::SeqCst))
    }

    /// The server's BRC-103 identity key captured during the handshake
    /// (66-char compressed pubkey hex).
    pub fn server_identity_key(&self) -> &str {
        &self.server_identity_key
    }

    /// Register an exact-match handler for a verified inbound event.
    pub async fn on(&self, event_name: impl Into<String>, handler: EventHandler) {
        self.handlers
            .lock()
            .await
            .insert(event_name.into(), handler);
    }

    /// Remove an exact-match handler.
    pub async fn off(&self, event_name: &str) {
        self.handlers.lock().await.remove(event_name);
    }

    /// Register the fallback handler for verified events with no exact-match
    /// handler (`(event_name, data)`), e.g. prefix-routed events like
    /// `sendMessage-{roomId}`.
    pub async fn set_fallback(&self, handler: FallbackHandler) {
        *self.fallback.lock().await = Some(handler);
    }

    /// Sign an application event as a BRC-103 general message and emit it.
    ///
    /// The single un-serialized send primitive: signs via the `&self` signer
    /// (lock-free against the shared session) and emits via the `&self`
    /// Socket.IO client — N concurrent callers run in parallel.
    pub async fn emit(&self, event_name: &str, data: &Value) -> Result<(), ClientError> {
        let payload = encode_event(event_name, data);
        let signed = (self.signer)(payload)
            .await
            .map_err(ClientError::WebSocket)?;
        if let Err(e) = emit_auth_message(&self.client, &signed).await {
            // A failed emit means the socket is dead — latch it so
            // is_connected() reflects reality and the supervisor reconnects.
            self.dead.store(true, Ordering::SeqCst);
            self.connected.store(false, Ordering::SeqCst);
            return Err(ClientError::WebSocket(e));
        }
        Ok(())
    }

    /// Join a room (idempotent). Sent as a signed `joinRoom` general message;
    /// the server only allows joining your own room.
    pub async fn join_room(&self, room_id: &str) -> Result<(), ClientError> {
        {
            let guard = self.joined_rooms.lock().await;
            if guard.contains(room_id) {
                return Ok(());
            }
        }
        self.emit("joinRoom", &json!(room_id)).await?;
        self.joined_rooms.lock().await.insert(room_id.to_string());
        Ok(())
    }

    /// Leave a room. Local state is torn down unconditionally before the wire
    /// emit, so a dead socket cannot leave stale membership behind.
    pub async fn leave_room(&self, room_id: &str) -> Result<(), ClientError> {
        self.joined_rooms.lock().await.remove(room_id);
        self.emit("leaveRoom", &json!(room_id)).await
    }

    /// Disconnect and clear all handlers/state (terminal — the death latch is
    /// set; this client can never report connected again).
    pub async fn disconnect(&self) -> Result<(), ClientError> {
        self.dead.store(true, Ordering::SeqCst);
        self.connected.store(false, Ordering::SeqCst);
        self.handlers.lock().await.clear();
        *self.fallback.lock().await = None;
        self.joined_rooms.lock().await.clear();
        self.client
            .disconnect()
            .await
            .map_err(|e| ClientError::WebSocket(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_cycles_inside_read_deadline() {
        assert!(
            KEEPALIVE_INTERVAL < READ_DEADLINE,
            "keepalive must refresh liveness before the watchdog fires"
        );
        assert!(
            KEEPALIVE_INTERVAL * 2 <= READ_DEADLINE,
            "deadline must tolerate at least one missed keepalive round-trip"
        );
        assert!(
            READ_DEADLINE <= Duration::from_secs(60),
            "half-open detection must stay well inside the ceremony round deadlines \
             that depend on it (600s), with room to spare"
        );
        assert!(
            WATCHDOG_TICK < KEEPALIVE_INTERVAL,
            "the watchdog must sample faster than the signal it watches"
        );
    }

    #[test]
    fn authentication_timeout_defaults_to_server_budget_and_is_configurable() {
        let mut options = AuthSocketClientOptions::default();
        assert_eq!(
            options.authentication_success_timeout(),
            Duration::from_secs(30)
        );
        options.set_authentication_success_timeout(Duration::from_secs(45));
        assert_eq!(
            options.authentication_success_timeout(),
            Duration::from_secs(45)
        );
        assert_eq!(
            authentication_success_wait_budget(false, AUTHENTICATION_SUCCESS_TIMEOUT),
            Duration::from_secs(5),
            "legacy servers retain the pre-certificate failure latency"
        );
        assert_eq!(
            authentication_success_wait_budget(true, AUTHENTICATION_SUCCESS_TIMEOUT),
            Duration::from_secs(30),
            "a certificate request extends the wait to the authorization budget"
        );
        assert_eq!(
            authentication_success_wait_budget(false, Duration::from_secs(3)),
            Duration::from_secs(3),
            "an explicitly shorter consumer timeout still wins"
        );
    }

    #[test]
    fn parse_auth_message_valid_and_invalid() {
        let valid = serde_json::json!({
            "version": "0.1",
            "messageType": "initialRequest",
            "identityKey": "03abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        });
        let msg = parse_auth_message_from_payload(&Payload::Text(vec![valid]))
            .expect("valid AuthMessage parses");
        assert_eq!(msg.message_type, MessageType::InitialRequest);

        assert!(
            parse_auth_message_from_payload(&Payload::Text(vec![serde_json::json!({"x": 1})]))
                .is_none()
        );
        assert!(parse_auth_message_from_payload(&Payload::Text(vec![])).is_none());
        assert!(parse_auth_message_from_payload(&Payload::from(b"bin".to_vec())).is_none());
    }
}
