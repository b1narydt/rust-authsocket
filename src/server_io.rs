//! socketioxide adapter — wires [`AuthSocketServer`] to a real Socket.IO
//! namespace (feature `server`).
//!
//! Ported from `rust-messagebox-server/src/ws.rs::setup_handlers`, minus the
//! application logic. The adapter owns exactly the protocol plumbing:
//!
//! - connect → [`AuthSocketServer::add_connection`] (fresh per-socket wallet
//!   from the caller-supplied factory).
//! - `"authMessage"` → parse → [`AuthSocketServer::on_auth_message`] → emit the
//!   outbound frames back over the socket, handle the **generic room verbs**
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

use bsv::auth::types::AuthMessage;
use bsv::wallet::interfaces::WalletInterface;
use serde_json::Value;
use socketioxide::extract::{Data, SocketRef};
use socketioxide::SocketIo;
use tracing::{debug, info, warn};

use crate::peer_session::VerifiedEvent;
use crate::server::{AuthSocketServer, SharedAuthSocketServer};
use crate::wire::AUTH_MESSAGE_EVENT;

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
/// app events.
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

        let server_msg = server.clone();
        let server_dc = server.clone();
        let dispatcher = dispatcher.clone();
        let io_for_msg = io_handle.clone();

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
                let dispatcher = dispatcher.clone();
                let io = io_for_msg.clone();
                async move {
                    let sid = socket.id.to_string();
                    let incoming: AuthMessage = match serde_json::from_value(data) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!(sid = %sid, error = %e, "authsocket: invalid authMessage payload");
                            return;
                        }
                    };

                    // Drive the Peer: verifies signatures, runs handshake steps.
                    // The socket identity is recorded from the VERIFIED sender
                    // inside on_auth_message, before events are returned.
                    let driven = server.on_auth_message(&sid, incoming).await;

                    // Handshake responses / signed replies back over this socket.
                    for msg in driven.outbound {
                        emit_frame(&socket, &sid, &msg);
                    }

                    // Verified app events: generic room verbs in the adapter,
                    // everything else to the consumer.
                    for ev in driven.events {
                        handle_verified_event(&io, &server, &socket, &sid, ev, dispatcher.as_ref())
                            .await;
                    }
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

/// Route one verified event: generic room verbs here, the rest to the consumer.
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
                    if identity.is_empty() || !room_id.starts_with(&identity) {
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
            let owns_room = server
                .identity_key(sid)
                .is_some_and(|key| room_id.starts_with(&key));
            if !owns_room {
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
