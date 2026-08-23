//! End-to-end: a real socketioxide server (behind axum, loopback TCP) and the
//! rust_socketio-based [`AuthSocketClient`], exercising the full BRC-103
//! handshake, room verbs, app-event dispatch, and the signed room broadcast.
//!
//! Requires `--features server,client`.
#![cfg(all(feature = "server", feature = "client"))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_util::FutureExt;
use rust_socketio::{Event, TransportType};
use serde_json::{json, Value};
use socketioxide::extract::SocketRef;
use socketioxide::SocketIo;
use tokio::sync::mpsc;

use authsocket::client::{parse_auth_message_from_payload, AuthSocketClient, SocketIOTransport};
use authsocket::peer_session::VerifiedEvent;
use authsocket::server::{
    AuthSocketServer, CertificateAuthorizationDecision, SharedAuthSocketServer,
};
use authsocket::server_io::{attach, emit_signed_to_room, AppDispatcher};
use authsocket::{wire::encode_event, AUTH_MESSAGE_EVENT};

use bsv::auth::peer::Peer;
use bsv::auth::types::RequestedCertificateSet;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::interfaces::{
    Certificate, CertificateType, GetPublicKeyArgs, SerialNumber, WalletInterface,
};
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
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    boot_server_with_core(core).await
}

async fn boot_server_with_core(
    core: SharedAuthSocketServer<ProtoWallet>,
) -> (
    String,
    SharedAuthSocketServer<ProtoWallet>,
    mpsc::UnboundedReceiver<VerifiedEvent>,
) {
    let (layer, io) = SocketIo::new_layer();
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

fn membership_request(certifier: String) -> RequestedCertificateSet {
    let mut requested = RequestedCertificateSet {
        certifiers: vec![certifier],
        ..RequestedCertificateSet::default()
    };
    requested.insert(
        "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".to_string(),
        vec!["membership".to_string()],
    );
    requested
}

fn membership_certificate(subject: &str, certifier: &str) -> Certificate {
    Certificate {
        cert_type: CertificateType([7; 32]),
        serial_number: SerialNumber([9; 32]),
        subject: PublicKey::from_string(subject).expect("subject key"),
        certifier: PublicKey::from_string(certifier).expect("certifier key"),
        revocation_outpoint: Some("00".repeat(32)),
        fields: None,
        signature: Some(vec![1, 2, 3]),
    }
}

#[tokio::test]
async fn rejected_certificate_closes_socket_before_authentication_success() {
    let server_identity = identity_of(SERVER_KEY).await;
    let client_identity = identity_of(CLIENT_KEY).await;
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    core.set_certificates_to_request(membership_request(server_identity.clone()));
    let authorizer_called = Arc::new(AtomicBool::new(false));
    let authorizer_called_cb = authorizer_called.clone();
    core.set_certificate_authorizer(move |_, _| {
        let called = authorizer_called_cb.clone();
        async move {
            called.store(true, Ordering::SeqCst);
            CertificateAuthorizationDecision::Reject("membership denied".into())
        }
    });
    let (url, _core, mut dispatched) = boot_server_with_core(core).await;

    let (auth_tx, auth_rx) = mpsc::channel(64);
    let auth_tx_cb = auth_tx.clone();
    let (ready_tx, mut ready_rx) = mpsc::channel(1);
    let closed = Arc::new(AtomicBool::new(false));
    let closed_cb = closed.clone();
    let socket = rust_socketio::asynchronous::ClientBuilder::new(&url)
        .on(AUTH_MESSAGE_EVENT, move |payload, _| {
            let tx = auth_tx_cb.clone();
            async move {
                if let Some(message) = parse_auth_message_from_payload(&payload) {
                    let _ = tx.send(message).await;
                }
            }
            .boxed()
        })
        .on(Event::Connect, move |_, _| {
            let tx = ready_tx.clone();
            async move {
                let _ = tx.try_send(());
            }
            .boxed()
        })
        .on(Event::Close, move |_, _| {
            let closed = closed_cb.clone();
            async move {
                closed.store(true, Ordering::SeqCst);
            }
            .boxed()
        })
        .transport_type(TransportType::Websocket)
        .reconnect(false)
        .connect()
        .await
        .expect("raw Socket.IO connect");
    tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx.recv())
        .await
        .expect("namespace connect ack")
        .expect("connect channel");

    let peer = Arc::new(Peer::new(
        ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("client key")),
        Arc::new(SocketIOTransport::new(socket.clone(), auth_rx)),
    ));
    let peer_for_response = peer.clone();
    let certificate = membership_certificate(&client_identity, &server_identity);
    peer.listen_for_certificates_requested(Arc::new(move |verifier, _| {
        let peer = peer_for_response.clone();
        let certificate = certificate.clone();
        tokio::spawn(async move {
            let _ = peer
                .send_certificate_response(&verifier, vec![certificate])
                .await;
        });
    }));

    // The general message may race the spawned certificate response, but the
    // server gate suppresses it while Pending and closes as soon as Reject is
    // returned. It must never reach the application dispatcher.
    let _ = peer
        .send_message(
            "",
            encode_event("authenticated", &json!({ "identityKey": client_identity })),
        )
        .await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !closed.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "rejected certificate did not close the socket"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        authorizer_called.load(Ordering::SeqCst),
        "certificate authorizer must run before close"
    );
    assert!(
        dispatched.try_recv().is_err(),
        "rejected connection must not dispatch an application event"
    );
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
        assert!(
            std::time::Instant::now() < deadline,
            "join never registered"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let sid = core.room_members(&room)[0].clone();

    // Server-side membership loss (the skew a deploy can produce).
    core.leave_room(&sid, &room);
    assert!(
        core.room_members(&room).is_empty(),
        "membership force-dropped"
    );

    // The next keepalive probe must re-assert it. The bound is DERIVED from the
    // cadence (two intervals plus slack for processing), never a magic number:
    // a hardcoded one silently becomes either flaky or vacuous the moment
    // KEEPALIVE_INTERVAL changes, which is exactly what it did.
    let heal_bound = authsocket::KEEPALIVE_INTERVAL * 2 + std::time::Duration::from_secs(5);
    let deadline = std::time::Instant::now() + heal_bound;
    loop {
        if core.room_members(&room).contains(&sid) {
            break; // healed
        }
        assert!(
            std::time::Instant::now() < deadline,
            "keepalive did not re-assert room membership within {heal_bound:?}"
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
