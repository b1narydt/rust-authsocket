//! End-to-end: a real socketioxide server (behind axum, loopback TCP) and the
//! rust_socketio-based [`AuthSocketClient`], exercising the full BRC-103
//! handshake, room verbs, app-event dispatch, and the signed room broadcast.
//!
//! Requires `--features server,client`.
#![cfg(all(feature = "server", feature = "client"))]

use std::sync::Arc;

use serde_json::{json, Value};
use socketioxide::extract::SocketRef;
use socketioxide::SocketIo;
use tokio::sync::mpsc;

use authsocket::client::AuthSocketClient;
use authsocket::peer_session::VerifiedEvent;
use authsocket::server::{AuthSocketServer, SharedAuthSocketServer};
use authsocket::server_io::{attach, emit_signed_to_room, AppDispatcher};

use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
use bsv::wallet::proto_wallet::ProtoWallet;

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000011";
const CLIENT_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000022";

async fn identity_of(key_hex: &str) -> String {
    let w = ProtoWallet::new(PrivateKey::from_hex(key_hex).expect("key"));
    w.get_public_key(
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
    .expect("identity")
    .public_key
    .to_der_hex()
}

/// Test dispatcher: records every dispatched verified event; on `appPing`
/// it broadcasts a signed `appPong` to the room named in the payload.
struct TestDispatcher {
    seen: mpsc::UnboundedSender<VerifiedEvent>,
}

#[async_trait::async_trait]
impl AppDispatcher<ProtoWallet> for TestDispatcher {
    async fn dispatch(
        &self,
        io: &SocketIo,
        server: &AuthSocketServer<ProtoWallet>,
        _socket: &SocketRef,
        event: VerifiedEvent,
    ) {
        let _ = self.seen.send(event.clone());
        if event.event_name == "appPing" {
            if let Some(room) = event.data.get("room").and_then(Value::as_str) {
                emit_signed_to_room(io, server, room, "appPong", &event.data).await;
            }
        }
    }
}

/// Boot a full authsocket server on an ephemeral loopback port. Returns the
/// URL, the shared core, and the dispatched-events receiver.
async fn boot_server() -> (
    String,
    SharedAuthSocketServer<ProtoWallet>,
    mpsc::UnboundedReceiver<VerifiedEvent>,
) {
    let (layer, io) = SocketIo::new_layer();
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    let (seen_tx, seen_rx) = mpsc::unbounded_channel();

    attach(
        &io,
        core.clone(),
        || {
            Ok(ProtoWallet::new(
                PrivateKey::from_hex(SERVER_KEY).expect("server key"),
            ))
        },
        Arc::new(TestDispatcher { seen: seen_tx }),
    );

    let app = axum::Router::new().layer(layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    (format!("http://{addr}"), core, seen_rx)
}

#[tokio::test]
async fn full_handshake_room_and_signed_broadcast() {
    let (url, _core, mut seen_rx) = boot_server().await;
    let client_identity = identity_of(CLIENT_KEY).await;
    let server_identity = identity_of(SERVER_KEY).await;

    // Connect + BRC-103 mutual auth (blocks until signed authenticationSuccess).
    let wallet = ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("key"));
    let client = AuthSocketClient::connect(&url, &client_identity, wallet)
        .await
        .expect("connect + handshake");
    assert!(client.is_connected());
    assert_eq!(
        client.server_identity_key(),
        server_identity,
        "server identity captured during handshake"
    );

    // Verified inbound events land on registered handlers.
    let (joined_tx, mut joined_rx) = mpsc::unbounded_channel::<Value>();
    client
        .on(
            "joinedRoom",
            Arc::new(move |data| {
                let _ = joined_tx.send(data);
            }),
        )
        .await;
    let (pong_tx, mut pong_rx) = mpsc::unbounded_channel::<Value>();
    client
        .on(
            "appPong",
            Arc::new(move |data| {
                let _ = pong_tx.send(data);
            }),
        )
        .await;

    // Join OUR OWN room — allowed; server confirms with a signed joinedRoom.
    let room = format!("{client_identity}-test_inbox");
    client.join_room(&room).await.expect("join_room");
    let joined = tokio::time::timeout(std::time::Duration::from_secs(5), joined_rx.recv())
        .await
        .expect("joinedRoom within 5s")
        .expect("joinedRoom data");
    assert_eq!(
        joined.get("roomId").and_then(Value::as_str),
        Some(room.as_str())
    );

    // App verb: reaches the consumer dispatcher with the VERIFIED sender…
    client
        .emit("appPing", &json!({ "room": room, "n": 7 }))
        .await
        .expect("emit appPing");
    let ev = tokio::time::timeout(std::time::Duration::from_secs(5), seen_rx.recv())
        .await
        .expect("dispatched within 5s")
        .expect("event");
    assert_eq!(ev.event_name, "appPing");
    assert_eq!(
        ev.sender, client_identity,
        "dispatcher sees the cryptographically verified sender"
    );

    // …and the dispatcher's signed room broadcast arrives on the client's
    // authenticated primary path.
    let pong = tokio::time::timeout(std::time::Duration::from_secs(5), pong_rx.recv())
        .await
        .expect("appPong within 5s")
        .expect("appPong data");
    assert_eq!(pong.get("n").and_then(Value::as_i64), Some(7));

    client.disconnect().await.expect("disconnect");
}

/// Presence self-heal: the keepalive probe re-asserts the client's room
/// membership, so even if the server loses it (deploy skew, missed join),
/// routability is restored within one keepalive interval — without any
/// reconnect.
#[tokio::test]
async fn keepalive_reasserts_lost_room_membership() {
    let (url, core, _seen_rx) = boot_server().await;
    let client_identity = identity_of(CLIENT_KEY).await;

    let wallet = ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("key"));
    let client = AuthSocketClient::connect(&url, &client_identity, wallet)
        .await
        .expect("connect + handshake");

    let room = format!("{client_identity}-test_inbox");
    client.join_room(&room).await.expect("join_room");

    // Wait for the join to register server-side.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while core.room_members(&room).is_empty() {
        assert!(std::time::Instant::now() < deadline, "join never registered");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let sid = core.room_members(&room)[0].clone();

    // Server-side membership loss (the skew a deploy can produce).
    core.leave_room(&sid, &room);
    assert!(core.room_members(&room).is_empty(), "membership force-dropped");

    // The next keepalive probe (≤2s + processing) must re-assert it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
    loop {
        if core.room_members(&room).contains(&sid) {
            break; // healed
        }
        assert!(
            std::time::Instant::now() < deadline,
            "keepalive did not re-assert room membership within 6s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    client.disconnect().await.expect("disconnect");
}

/// The server must reject joining a room the client's verified identity does
/// not own: no membership, no signed broadcast reaches the client.
#[tokio::test]
async fn join_foreign_room_is_rejected() {
    let (url, core, _seen_rx) = boot_server().await;
    let client_identity = identity_of(CLIENT_KEY).await;

    let wallet = ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("key"));
    let client = AuthSocketClient::connect(&url, &client_identity, wallet)
        .await
        .expect("connect + handshake");

    let (joined_tx, mut joined_rx) = mpsc::unbounded_channel::<Value>();
    client
        .on(
            "joinedRoom",
            Arc::new(move |data| {
                let _ = joined_tx.send(data);
            }),
        )
        .await;

    // A room owned by a DIFFERENT identity.
    let foreign_identity = identity_of(SERVER_KEY).await;
    let foreign_room = format!("{foreign_identity}-test_inbox");
    client
        .join_room(&foreign_room)
        .await
        .expect("emit joinRoom");

    // No joinedRoom confirmation…
    let confirmed =
        tokio::time::timeout(std::time::Duration::from_millis(1500), joined_rx.recv()).await;
    assert!(confirmed.is_err(), "foreign joinRoom must not be confirmed");
    // …and no membership was recorded server-side.
    assert!(
        core.room_members(&foreign_room).is_empty(),
        "server must not record membership in a foreign room"
    );

    client.disconnect().await.expect("disconnect");
}
