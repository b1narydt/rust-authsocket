//! socketioxide adapter — wires [`AuthSocketServer`] to a real Socket.IO
//! namespace (feature `server`).
//!
//! Ported from `rust-messagebox-server/src/ws.rs::setup_handlers`, minus the
//! application logic. The adapter owns exactly the protocol plumbing:
//!
//! - connect → [`AuthSocketServer::add_connection`] (fresh per-socket wallet
//!   from the caller-supplied factory).
//! - `"authMessage"` → parse → feed [`AuthSocketServer::on_auth_message`]. A
//!   per-connection pump emits outbound frames and handles **generic room verbs**
//!   (`authenticated`, `joinRoom` — including the "a client may only join its
//!   own room" check — and `leaveRoom`), and hand every other verified event to
//!   the caller-supplied [`AppDispatcher`].
//! - disconnect → [`AuthSocketServer::remove_connection`].
//!
//! Application verbs (e.g. the MessageBox `sendMessage`) stay in the consumer,
//! implemented on its [`AppDispatcher`]. Server→client pushes go through
//! [`emit_signed_to_socket`] / [`emit_signed_to_room`] — every one is a signed
//! BRC-103 general message; there are NO raw Socket.IO application events in
//! either direction (a raw event would be an authentication-bypass surface).

use std::sync::Arc;

use bsv::auth::certificates::VerifiableCertificate;
use bsv::auth::types::AuthMessage;
use bsv::wallet::interfaces::WalletInterface;
use serde_json::Value;
use socketioxide::extract::{Data, SocketRef};
use socketioxide::SocketIo;
use tracing::{debug, info, warn};

use crate::peer_session::{PeerHandle, PeerPumpReceivers, VerifiedEvent};
use crate::server::{AuthSocketServer, SharedAuthSocketServer, VerifiedEventSink};
use crate::wire::{decode_event, AUTH_MESSAGE_EVENT};

/// Consumer hook for verified application events the adapter does not handle
/// itself (everything except `authenticated`/`joinRoom`/`leaveRoom`).
///
/// `event.sender` is the cryptographically verified sender key, and the
/// socket's identity has already been recorded from it — so
/// `server.identity_key(socket_id)` is safe to trust inside the dispatcher.
#[async_trait::async_trait]
pub trait AppDispatcher<W: WalletInterface + 'static>: Send + Sync {
    async fn dispatch(
        &self,
        io: &SocketIo,
        server: &AuthSocketServer<W>,
        socket: &SocketRef,
        event: VerifiedEvent,
    );
}

/// Attach the authsocket protocol to the root (`"/"`) namespace.
///
/// `wallet_factory` builds the per-connection server wallet (e.g. a
/// `ProtoWallet` over the server private key). `dispatcher` receives verified
/// app events. To require peer certificates, call
/// [`AuthSocketServer::set_certificates_to_request`] and
/// [`AuthSocketServer::set_certificate_authorizer`] on `server` before calling
/// `attach` (along with any authorization-timeout override). These settings are
/// snapshotted when this adapter adds each connection; changing them after
/// `attach` can leave already-connected sockets on their original policy. The
/// transport-agnostic core suppresses verified events (including `authenticated`)
/// until acceptance; this adapter observes terminal rejection and disconnects
/// the socket before any event can be dispatched.
pub fn attach<W, F, D>(
    io: &SocketIo,
    server: SharedAuthSocketServer<W>,
    wallet_factory: F,
    dispatcher: Arc<D>,
) where
    W: WalletInterface + Send + Sync + 'static,
    F: Fn() -> Result<W, String> + Send + Sync + 'static,
    D: AppDispatcher<W> + ?Sized + 'static,
{
    let io_handle = io.clone();
    let wallet_factory = Arc::new(wallet_factory);

    io.ns("/", move |socket: SocketRef| {
        let sid = socket.id.to_string();
        info!(sid = %sid, "authsocket: new Socket.IO connection");

        // Register the BRC-103 session for this socket up front, so the first
        // inbound frame always finds its PeerHandle.
        match wallet_factory() {
            Ok(wallet) => server.add_connection(&sid, wallet),
            Err(e) => {
                warn!(sid = %sid, error = %e, "authsocket: wallet factory failed — closing socket");
                socket.disconnect().ok();
                return;
            }
        }

        let Some(receivers) = server.take_pump_receivers(&sid) else {
            warn!(sid = %sid, "authsocket: connection pump receivers unavailable");
            server.remove_connection(&sid);
            socket.disconnect().ok();
            return;
        };
        let weak_server = Arc::downgrade(&server);
        let sink_io = io_handle.clone();
        let sink_sid = sid.clone();
        let sink_dispatcher = Arc::downgrade(&dispatcher);
        let sink_server = weak_server.clone();
        let sink: VerifiedEventSink = Arc::new(move |events| {
            let io = sink_io.clone();
            let sid = sink_sid.clone();
            let dispatcher = sink_dispatcher.clone();
            let server = sink_server.clone();
            Box::pin(async move {
                let Some(dispatcher) = dispatcher.upgrade() else {
                    return;
                };
                dispatch_admitted_events(&io, &server, &sid, events, dispatcher.as_ref()).await;
            })
        });
        server.set_verified_event_sink(&sid, &sink);
        tokio::spawn(run_connection_pump(
            io_handle.clone(),
            weak_server,
            sid.clone(),
            receivers,
            Arc::downgrade(&dispatcher),
            sink,
        ));

        // Half-configuration is a connection-time terminal error, and Pending
        // has a bounded lifetime. Close here (or from the deadline task) without
        // waiting for another inbound frame to make the outcome observable.
        if let Some(authorization) = server.certificate_authorization(&sid) {
            if let Some(reason) = authorization.rejection_reason() {
                warn!(sid = %sid, reason = %reason,
                    "authsocket: certificate configuration rejected connection — closing socket");
                server.remove_connection(&sid);
                socket.disconnect().ok();
                return;
            }
        }
        if let Some(deadline) = server.certificate_authorization_deadline(&sid) {
            let server_timeout = server.clone();
            let socket_timeout = socket.clone();
            let sid_timeout = sid.clone();
            let deadline_task = tokio::spawn(async move {
                tokio::time::sleep_until(deadline).await;
                if server_timeout
                    .expire_certificate_authorization_from_deadline(&sid_timeout)
                {
                    warn!(sid = %sid_timeout,
                        "authsocket: certificate authorization deadline expired — closing socket");
                    server_timeout.remove_connection(&sid_timeout);
                    socket_timeout.disconnect().ok();
                }
            });
            server.set_certificate_authorization_deadline_task(&sid, deadline_task);
        }

        let server_msg = server.clone();
        let server_dc = server.clone();

        // --- authMessage (BRC-103 mutual auth + general message routing) ---
        //
        // The ONLY inbound event the server acts on. Every application action
        // (authenticate, join/leave a room, send a message) must arrive as a
        // BRC-103-signed general message, which the Peer verifies before it
        // reaches the dispatcher. Accepting raw Socket.IO events would be an
        // authentication-bypass surface — a client could join another
        // identity's room or send as someone else without proving its key.
        socket.on(
            AUTH_MESSAGE_EVENT,
            move |socket: SocketRef, Data(data): Data<Value>| {
                let server = server_msg.clone();
                async move {
                    let sid = socket.id.to_string();
                    let incoming: AuthMessage = match serde_json::from_value(data) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!(sid = %sid, error = %e, "authsocket: invalid authMessage payload");
                            return;
                        }
                    };

                    server.on_auth_message(&sid, incoming).await;
                }
            },
        );

        // --- disconnect ---
        socket.on_disconnect(
            move |socket: SocketRef, reason: socketioxide::socket::DisconnectReason| {
                let server = server_dc.clone();
                async move {
                    let sid = socket.id.to_string();
                    server.remove_connection(&sid);
                    info!(sid = %sid, reason = ?reason, "authsocket: client disconnected");
                }
            },
        );
    });
}

async fn run_connection_pump<W, D>(
    io: SocketIo,
    server: std::sync::Weak<AuthSocketServer<W>>,
    sid: String,
    mut receivers: PeerPumpReceivers,
    dispatcher: std::sync::Weak<D>,
    _certificate_sink: VerifiedEventSink,
) where
    W: WalletInterface + Send + Sync + 'static,
    D: AppDispatcher<W> + ?Sized + 'static,
{
    let mut outgoing_open = true;
    let mut general_open = true;
    let mut dispatching: Option<
        std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    > = None;
    while outgoing_open || general_open || dispatching.is_some() {
        // Connection removal drops the Peer and closes both SDK senders. Exit
        // even if an application dispatcher is still pending; dropping that
        // future prevents a handler from extending the pump lifetime.
        if receivers.outgoing.is_closed() && receivers.general.is_closed() {
            break;
        }
        tokio::select! {
            message = receivers.outgoing.recv(), if outgoing_open => match message {
                Some(message) => {
                    let message = PeerHandle::<W>::normalize_outbound(message);
                    let Some(server) = server.upgrade() else { break };
                    server.record_outbound_session_peer_identity(&sid, &message).await;
                    let socket = sid
                        .parse()
                        .ok()
                        .and_then(|id| io.of("/").and_then(|ns| ns.get_socket(id)));
                    let Some(socket) = socket else { continue };
                    emit_frame(&socket, &sid, &message);
                }
                None => outgoing_open = false,
            },
            message = receivers.general.recv(), if general_open && dispatching.is_none() => match message {
                Some((sender, payload)) => {
                    let Some((event_name, data)) = decode_event(&payload) else {
                        continue;
                    };
                    let Some(server_ref) = server.upgrade() else { break };
                    let events = server_ref.admit_verified_event(
                        &sid,
                        VerifiedEvent { sender, event_name, data },
                    );
                    drop(server_ref);
                    let Some(dispatcher) = dispatcher.upgrade() else { break };
                    let dispatch_io = io.clone();
                    let dispatch_server = server.clone();
                    let dispatch_sid = sid.clone();
                    dispatching = Some(Box::pin(async move {
                        dispatch_admitted_events(
                            &dispatch_io,
                            &dispatch_server,
                            &dispatch_sid,
                            events,
                            dispatcher.as_ref(),
                        )
                        .await;
                    }));
                }
                None => general_open = false,
            },
            () = async {
                dispatching
                    .as_mut()
                    .expect("dispatch branch is guarded")
                    .as_mut()
                    .await;
            }, if dispatching.is_some() => {
                dispatching = None;
            },
        }
    }
}

async fn dispatch_admitted_events<W>(
    io: &SocketIo,
    server: &std::sync::Weak<AuthSocketServer<W>>,
    sid: &str,
    events: Vec<VerifiedEvent>,
    dispatcher: &(impl AppDispatcher<W> + ?Sized),
) where
    W: WalletInterface + Send + Sync + 'static,
{
    let Some(server) = server.upgrade() else {
        return;
    };
    let socket = sid
        .parse()
        .ok()
        .and_then(|id| io.of("/").and_then(|ns| ns.get_socket(id)));
    let Some(socket) = socket else {
        return;
    };
    if let Some(authorization) = server.certificate_authorization(sid) {
        if let Some(reason) = authorization.rejection_reason() {
            warn!(sid = %sid, reason = %reason,
                "authsocket: certificate authorization rejected — closing socket");
            server.remove_connection(sid);
            socket.disconnect().ok();
            return;
        }
    }
    for event in events {
        handle_verified_event(io, &server, &socket, sid, event, dispatcher).await;
    }
}

/// Route one verified event: generic room verbs here, the rest to the consumer.
/// The own-room rule: a socket may only ever be placed in `{identityKey}` or
/// `{identityKey}-{messageBox}`.
///
/// Anchored on the `-` delimiter rather than a bare prefix test. A bare
/// `room_id.starts_with(identity)` authorizes any room whose id merely BEGINS
/// with the key — `{key}evil` passes — which is not the invariant the rest of
/// the stack relies on when it decides that a room's name proves its owner.
/// 66-hex compressed keys cannot prefix one another today, so this is defence
/// in depth rather than a live hole; it is written this way because both
/// downstream forks already deviate from upstream to enforce it, and a rule
/// every consumer has to re-harden belongs in the crate.
///
/// Used by BOTH the `joinRoom` verb and the keepalive presence re-assert, so
/// the two can never drift: a keepalive must never be able to place a socket
/// somewhere `joinRoom` would have refused it.
fn owns_room(identity: &str, room_id: &str) -> bool {
    !identity.is_empty() && (room_id == identity || room_id.starts_with(&format!("{identity}-")))
}

async fn handle_verified_event<W>(
    io: &SocketIo,
    server: &AuthSocketServer<W>,
    socket: &SocketRef,
    sid: &str,
    ev: VerifiedEvent,
    dispatcher: &(impl AppDispatcher<W> + ?Sized),
) where
    W: WalletInterface + Send + Sync + 'static,
{
    match ev.event_name.as_str() {
        "authenticated" => {
            // Identity was recorded from the verified sender before dispatch.
            // Confirm with a signed authenticationSuccess (the authsocket
            // contract — never a raw event). Also serves as the keepalive
            // reply that refreshes the client's read deadline.
            let identity = server.identity_key(sid).unwrap_or_default();
            // Presence self-heal: the keepalive carries the rooms the client
            // believes it belongs to; re-assert each membership (same own-room
            // rule as joinRoom, and join_room is idempotent), so server-side
            // routability can never silently rot while the socket is live —
            // any skew heals within one keepalive interval.
            if let Some(rooms) = ev.data.get("rooms").and_then(Value::as_array) {
                for room_id in rooms.iter().filter_map(Value::as_str) {
                    if room_id.is_empty() {
                        continue;
                    }
                    if !owns_room(&identity, room_id) {
                        warn!(sid = %sid, room = %room_id,
                            "authsocket: keepalive room re-assert rejected — identity mismatch");
                        continue;
                    }
                    server.join_room(sid, room_id);
                }
            }
            emit_signed_to_socket(
                socket,
                server,
                "authenticationSuccess",
                &serde_json::json!({ "status": "success", "identityKey": identity }),
            )
            .await;
            debug!(sid = %sid, "authsocket: signed authenticationSuccess sent");
        }
        "joinRoom" => {
            let room_id = ev.data.as_str().unwrap_or("").to_string();
            if room_id.is_empty() {
                warn!(sid = %sid, "authsocket: joinRoom with empty room id");
                return;
            }
            // A client may only join its OWN room ({identityKey}-{messageBox}).
            // Fail closed: no verified identity -> no join. (`ev.sender` is that
            // identity, but read it back from the server so the check can never
            // drift from what emit_to_room will trust.)
            let admitted = server
                .identity_key(sid)
                .is_some_and(|key| owns_room(&key, &room_id));
            if !admitted {
                warn!(sid = %sid, room = %room_id,
                    "authsocket: joinRoom rejected — identity mismatch");
                return;
            }
            server.join_room(sid, &room_id);
            debug!(sid = %sid, room = %room_id, "authsocket: joined room");
            emit_signed_to_socket(
                socket,
                server,
                "joinedRoom",
                &serde_json::json!({ "roomId": room_id }),
            )
            .await;
        }
        "leaveRoom" => {
            let room_id = ev.data.as_str().unwrap_or("").to_string();
            if room_id.is_empty() {
                return;
            }
            server.leave_room(sid, &room_id);
            debug!(sid = %sid, room = %room_id, "authsocket: left room");
            emit_signed_to_socket(
                socket,
                server,
                "leftRoom",
                &serde_json::json!({ "roomId": room_id }),
            )
            .await;
        }
        _ => dispatcher.dispatch(io, server, socket, ev).await,
    }
}

/// Serialize one signed frame and emit it as `"authMessage"` on `socket`.
/// Returns `true` on a successful emit.
fn emit_frame(socket: &SocketRef, sid: &str, msg: &AuthMessage) -> bool {
    match serde_json::to_value(msg) {
        Ok(json) => match socket.emit(AUTH_MESSAGE_EVENT, &json) {
            Ok(()) => true,
            Err(e) => {
                warn!(sid = %sid, error = %e,
                    "authsocket: emit failed — signed frame not delivered");
                false
            }
        },
        Err(e) => {
            warn!(sid = %sid, error = %e, "authsocket: failed to serialize signed frame");
            false
        }
    }
}

/// Sign an app event for this socket's authenticated session and emit it.
///
/// Fails closed (returns `false`, emits nothing) when the socket has no
/// authenticated session — signing uses the non-mutating
/// `create_general_message`, so this can never initiate a handshake.
pub async fn emit_signed_to_socket<W>(
    socket: &SocketRef,
    server: &AuthSocketServer<W>,
    event_name: &str,
    data: &Value,
) -> bool
where
    W: WalletInterface + Send + Sync + 'static,
{
    let sid = socket.id.to_string();
    let msgs = server.emit_to_socket(&sid, event_name, data).await;
    if msgs.is_empty() {
        return false;
    }
    msgs.iter().all(|m| emit_frame(socket, &sid, m))
}

/// Send a BRC-103 certificate response on `socket_id`. The connection pump
/// emits the signed frame through the socketioxide namespace.
///
/// This is the response half for callbacks registered with
/// [`AuthSocketServer::listen_for_certificates_requested`]. It returns `false`
/// if the socket/session is unavailable or response production fails.
pub async fn send_certificate_response<W>(
    io: &SocketIo,
    server: &AuthSocketServer<W>,
    socket_id: &str,
    identity_key: &str,
    certificates: Vec<VerifiableCertificate>,
) -> bool
where
    W: WalletInterface + Send + Sync + 'static,
{
    let socket_exists = socket_id
        .parse()
        .ok()
        .and_then(|id| io.of("/").and_then(|namespace| namespace.get_socket(id)))
        .is_some();
    if !socket_exists {
        return false;
    }
    match server
        .send_certificate_response(socket_id, identity_key, certificates)
        .await
    {
        Ok(()) => true,
        Err(error) => {
            warn!(sid = %socket_id, error = %error,
                "authsocket: certificate response signing failed");
            false
        }
    }
}

/// Sign an app event for every authenticated member of `room_id` and emit each
/// frame over its socket (the `socket_id → io.get_socket().emit` sink).
///
/// Returns the number of members the signed frame was successfully emitted to.
/// Best-effort: failures are logged, and a non-empty room that delivers to
/// zero members is logged at `warn` as a degradation signal.
pub async fn emit_signed_to_room<W>(
    io: &SocketIo,
    server: &AuthSocketServer<W>,
    room_id: &str,
    event_name: &str,
    data: &Value,
) -> usize
where
    W: WalletInterface + Send + Sync + 'static,
{
    let member_count = server.room_members(room_id).len();
    let pairs = server.emit_to_room(room_id, event_name, data).await;

    let mut delivered = 0usize;
    for (sid, msg) in &pairs {
        let socket = match sid.parse() {
            Ok(id) => io.of("/").and_then(|ns| ns.get_socket(id)),
            Err(e) => {
                warn!(sid = %sid, error = %e,
                    "authsocket: unparseable socket id in room registry");
                None
            }
        };
        let Some(socket) = socket else { continue };
        let json = match serde_json::to_value(msg) {
            Ok(v) => v,
            Err(e) => {
                warn!(sid = %sid, error = %e, "authsocket: failed to serialize signed frame");
                continue;
            }
        };
        // Count only successful emits — a full send buffer / mid-teardown
        // socket must not be reported as delivered.
        match socket.emit(AUTH_MESSAGE_EVENT, &json) {
            Ok(()) => delivered += 1,
            Err(e) => warn!(sid = %sid, room = %room_id, error = %e,
                "authsocket: room emit failed — recipient misses this live push"),
        }
    }

    if member_count > 0 && delivered == 0 {
        warn!(room = %room_id, members = member_count,
            "authsocket: signed broadcast reached 0 of {member_count} room members — live push may be broken");
    }
    debug!(room = %room_id, event = %event_name, delivered, "authsocket: signed broadcast to room");
    delivered
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::proto_wallet::ProtoWallet;

    struct NoopDispatcher;

    #[async_trait::async_trait]
    impl AppDispatcher<ProtoWallet> for NoopDispatcher {
        async fn dispatch(
            &self,
            _io: &SocketIo,
            _server: &AuthSocketServer<ProtoWallet>,
            _socket: &SocketRef,
            _event: VerifiedEvent,
        ) {
        }
    }

    fn wallet() -> ProtoWallet {
        ProtoWallet::new(
            PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000011",
            )
            .expect("test key"),
        )
    }

    /// A key is 66-hex, so no real key can prefix another — but the rule must
    /// not DEPEND on that. A bare `starts_with` would admit `{key}evil`, and
    /// every downstream fork already re-hardened this by hand rather than
    /// inherit it. Pinned so it cannot regress back into the crate.
    #[test]
    fn own_room_is_anchored_on_the_delimiter_not_a_bare_prefix() {
        let key = "02aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

        // The two legitimate shapes.
        assert!(owns_room(key, key), "the bare identity room is your own");
        assert!(
            owns_room(key, &format!("{key}-mpc_inbox")),
            "{{key}}-{{messageBox}} is your own"
        );

        // The bare-prefix hole this rule exists to close.
        assert!(
            !owns_room(key, &format!("{key}evil")),
            "a room merely BEGINNING with the key is not your own"
        );
        assert!(
            !owns_room(key, &format!("{key}0-inbox")),
            "an extra character before the delimiter is not your own"
        );

        // Someone else's rooms.
        assert!(!owns_room(key, "03deadbeef-inbox"));
        assert!(!owns_room(key, "-mpc_inbox"));

        // Fail closed with no verified identity: an empty key must never own
        // anything, or an unauthenticated socket would own every room whose id
        // starts with the empty string — which is all of them.
        assert!(!owns_room("", "anything"));
        assert!(!owns_room("", ""));
    }

    #[tokio::test]
    async fn connection_pump_exits_after_connection_removal() {
        let server = Arc::new(AuthSocketServer::new());
        server.add_connection("sock1", wallet());
        let receivers = server
            .take_pump_receivers("sock1")
            .expect("fresh pump receivers");
        let (_layer, io) = SocketIo::new_layer();
        let dispatcher = Arc::new(NoopDispatcher);
        let sink: VerifiedEventSink = Arc::new(|_| Box::pin(async {}));
        server.set_verified_event_sink("sock1", &sink);
        let pump = tokio::spawn(run_connection_pump(
            io,
            Arc::downgrade(&server),
            "sock1".into(),
            receivers,
            Arc::downgrade(&dispatcher),
            sink,
        ));

        server.remove_connection("sock1");
        tokio::time::timeout(std::time::Duration::from_secs(1), pump)
            .await
            .expect("pump must exit after connection removal")
            .expect("pump task must not panic");
    }
}
