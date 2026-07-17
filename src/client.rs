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
use tokio::sync::{mpsc, oneshot, Mutex};

use async_trait::async_trait;
use bsv::auth::error::AuthError;
use bsv::auth::peer::Peer;
use bsv::auth::transports::Transport;
use bsv::auth::types::{AuthMessage, MessageType};
use bsv::wallet::interfaces::WalletInterface;

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
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);

/// Inbound read deadline for half-open detection. If NO frame of any kind
/// arrives within this window, the socket is declared dead (`is_connected()`
/// flips false) so the consumer's supervisor can reconnect. ~3x the keepalive
/// cycle: tolerates transient jitter without false-firing, still detects a
/// black-holed peer within ~6-7 s.
const READ_DEADLINE: Duration = Duration::from_secs(6);

/// How often the watchdog checks the inbound read deadline.
const WATCHDOG_TICK: Duration = Duration::from_secs(1);

/// Maximum time to wait for the Socket.IO namespace connect-ack ("40{sid}")
/// before failing the connection.
const CONNECT_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time to wait for the server's signed `authenticationSuccess` after
/// the BRC-103 handshake.
const AUTH_SUCCESS_TIMEOUT: Duration = Duration::from_secs(5);

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

type HandlerMap = Arc<Mutex<HashMap<String, EventHandler>>>;

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
    /// Rooms currently joined (idempotency on join_room).
    joined_rooms: Arc<Mutex<HashSet<String>>>,
    /// True once the server sends authenticationSuccess AND the socket is
    /// live. Flipped false by the watchdog on read-deadline expiry, by the
    /// dispatcher on channel close, and by the Close lifecycle handler.
    connected: Arc<AtomicBool>,
    /// Monotonic millis of the last inbound frame of ANY kind (watchdog
    /// half-open detection).
    last_inbound_ms: Arc<AtomicU64>,
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
        let handlers: HandlerMap = Arc::new(Mutex::new(HashMap::new()));
        let fallback: Arc<Mutex<Option<FallbackHandler>>> = Arc::new(Mutex::new(None));
        let joined_rooms: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let connected = Arc::new(AtomicBool::new(false));
        // Read-deadline tracker: every inbound frame stamps this. Initialized
        // to "now" so the watchdog does not fire before the first frame.
        let last_inbound_ms = Arc::new(AtomicU64::new(now_ms()));

        // Incoming BRC-103 authMessage events → SocketIOTransport → Peer.
        let (auth_msg_tx, auth_msg_rx) = mpsc::channel(64);
        // Server identity key captured from the handshake frames.
        let (server_key_tx, mut server_key_rx) = mpsc::channel::<String>(1);
        // authenticationSuccess oneshot (fired by the dispatcher).
        let (auth_success_tx, auth_success_rx) = oneshot::channel::<()>();
        let auth_success_shared: Arc<Mutex<Option<oneshot::Sender<()>>>> =
            Arc::new(Mutex::new(Some(auth_success_tx)));

        let conn_clone = connected.clone();
        let conn_close_clone = connected.clone();

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

        // Handlers ONLY for `authMessage` + Connect/Close lifecycle. There is
        // deliberately no raw application-event handler: every application
        // message must arrive as a BRC-103-verified general message, never as
        // an unsigned raw event.
        let client = ClientBuilder::new(url)
            .on(AUTH_MESSAGE_EVENT, move |payload, _socket| {
                let tx = auth_msg_tx_clone.clone();
                let key_tx = server_key_tx_clone.clone();
                let last_inbound = last_inbound_for_auth.clone();
                async move {
                    // Any inbound authMessage frame is proof of life.
                    last_inbound.store(now_ms(), Ordering::SeqCst);
                    if let Some(msg) = parse_auth_message_from_payload(&payload) {
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
            // Close: transport went away — mark disconnected.
            .on(Event::Close, move |_payload, _socket| {
                let conn = conn_close_clone.clone();
                async move {
                    conn.store(false, Ordering::SeqCst);
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

        // Take-once, before any task can race for it.
        let general_msg_rx = peer
            .on_general_message()
            .expect("on_general_message take-once: fresh Peer");

        // Hold the first emit until the namespace connect-ack arrives, so the
        // BRC-103 InitialRequest is never delivered ahead of the namespace
        // handshake.
        match tokio::time::timeout(CONNECT_ACK_TIMEOUT, connect_ready_rx.recv()).await {
            Ok(Some(())) => {}
            _ => {
                return Err(ClientError::WebSocket(
                    "Socket.IO connect-ack not received before timeout".into(),
                ))
            }
        }

        // Client-initiated BRC-103 handshake: send_message("") initiates the
        // handshake (InitialRequest → poll for InitialResponse → mutual auth)
        // and then delivers the signed `authenticated` general message. The ""
        // identity is resolved to the server's real key during the handshake.
        let auth_payload = encode_event("authenticated", &json!({ "identityKey": identity_key }));
        peer.send_message("", auth_payload)
            .await
            .map_err(|e| ClientError::Handshake(e.to_string()))?;

        // The server identity key captured by the authMessage callback.
        let server_identity_key = server_key_rx.try_recv().map_err(|_| {
            ClientError::Handshake(
                "handshake completed but server identity key not captured".into(),
            )
        })?;

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
        // transport, so it exits on `connected` flipping false — latched on
        // the first observed true so it survives the pre-auth window.
        {
            let peer_for_recv = peer.clone();
            let connected_for_recv = connected.clone();
            tokio::spawn(async move {
                let mut was_connected = false;
                loop {
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
        // deadline — the only liveness signal for an idle subscriber.
        {
            let keepalive_signer = signer.clone();
            let keepalive_client = client.clone();
            let identity_for_keepalive = identity_key.to_string();
            let connected_for_keepalive = connected.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(KEEPALIVE_INTERVAL);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                interval.tick().await; // skip the immediate first tick
                let mut was_connected = false;
                loop {
                    interval.tick().await;
                    let live = connected_for_keepalive.load(Ordering::SeqCst);
                    was_connected |= live;
                    if !live {
                        if was_connected {
                            break; // socket declared dead — stop pinging
                        }
                        continue; // still coming up
                    }
                    let ping = encode_event(
                        "authenticated",
                        &json!({ "identityKey": identity_for_keepalive }),
                    );
                    match keepalive_signer(ping).await {
                        Ok(signed) => {
                            if emit_auth_message(&keepalive_client, &signed).await.is_err() {
                                connected_for_keepalive.store(false, Ordering::SeqCst);
                                break;
                            }
                        }
                        Err(_) => {
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
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(WATCHDOG_TICK);
                let mut was_connected = false;
                loop {
                    tick.tick().await;
                    let live = watchdog_connected.load(Ordering::SeqCst);
                    was_connected |= live;
                    if !live {
                        if was_connected {
                            break;
                        }
                        continue;
                    }
                    let last = watchdog_last_inbound.load(Ordering::SeqCst);
                    let elapsed = now_ms().saturating_sub(last);
                    if elapsed >= READ_DEADLINE.as_millis() as u64 {
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
                                connected_for_dispatch.store(true, Ordering::SeqCst);
                                let mut guard = auth_success_shared.lock().await;
                                if let Some(tx) = guard.take() {
                                    let _ = tx.send(());
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
                            connected_for_dispatch.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            });
        }

        // Wait for the server's signed authenticationSuccess.
        tokio::time::timeout(AUTH_SUCCESS_TIMEOUT, auth_success_rx)
            .await
            .map_err(|_| {
                ClientError::Handshake("authenticationSuccess not received within 5s".into())
            })?
            .map_err(|_| ClientError::Handshake("auth success channel dropped".into()))?;

        Ok(Self {
            client,
            signer,
            handlers,
            fallback,
            joined_rooms,
            connected,
            last_inbound_ms,
            server_identity_key,
        })
    }

    /// True if the connection is currently authenticated and live.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
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
            // A failed emit means the socket is dead — flip connected so
            // is_connected() reflects reality and the supervisor reconnects.
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

    /// Disconnect and clear all handlers/state.
    pub async fn disconnect(&self) -> Result<(), ClientError> {
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
            READ_DEADLINE <= Duration::from_secs(8),
            "half-open detection target is <~8s"
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
