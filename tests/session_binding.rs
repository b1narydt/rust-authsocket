//! rust-mpc#458 D3/D4: a client is bound to the one server it connected to,
//! and a server admits only the identities it allows.
//!
//! Invariants:
//! - the client never opens a BRC-103 session it did not initiate, so a frame
//!   on its socket that only claims an identity cannot change the session its
//!   own events are signed under;
//! - the client hands its handlers only events whose verified sender is the
//!   server it connected to, and says who that sender was;
//! - a server with an identity authorizer disconnects a refused identity on
//!   its first verified event, and its connection caps hold.
//!
//! Requires `--features server,client`. Loopback sockets only.
#![cfg(all(feature = "server", feature = "client"))]

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use socketioxide::extract::SocketRef;
use socketioxide::SocketIo;
use tokio::sync::mpsc;

use authsocket::client::AuthSocketClient;
use authsocket::peer_session::VerifiedEvent;
use authsocket::server::{AuthSocketServer, SharedAuthSocketServer};
use authsocket::server_io::{attach, emit_signed_to_socket, AppDispatcher};
use authsocket::AUTH_MESSAGE_EVENT;

use bsv::auth::types::{AuthMessage, MessageType};
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
use bsv::wallet::proto_wallet::ProtoWallet;

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000011";
const CLIENT_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000022";
const OTHER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000044";

async fn identity_of(key_hex: &str) -> String {
    ProtoWallet::new(PrivateKey::from_hex(key_hex).expect("key"))
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
        .expect("identity")
        .public_key
        .to_der_hex()
}

/// Records every dispatched event and answers `appPing` with a signed `appPong`.
struct Recorder {
    seen: mpsc::UnboundedSender<VerifiedEvent>,
}

#[async_trait::async_trait]
impl AppDispatcher<ProtoWallet> for Recorder {
    async fn dispatch(
        &self,
        _io: &SocketIo,
        server: &AuthSocketServer<ProtoWallet>,
        socket: &SocketRef,
        event: VerifiedEvent,
    ) {
        if event.event_name == "appPing" {
            emit_signed_to_socket(socket, server, "appPong", &event.data).await;
        }
        let _ = self.seen.send(event);
    }
}

async fn boot(
    core: SharedAuthSocketServer<ProtoWallet>,
) -> (String, SocketIo, mpsc::UnboundedReceiver<VerifiedEvent>) {
    let (layer, io) = SocketIo::new_layer();
    let (seen_tx, seen_rx) = mpsc::unbounded_channel();
    attach(
        &io,
        core,
        || {
            Ok(ProtoWallet::new(
                PrivateKey::from_hex(SERVER_KEY).expect("server key"),
            ))
        },
        Arc::new(Recorder { seen: seen_tx }),
    );
    let app = axum::Router::new().layer(layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (format!("http://{addr}"), io, seen_rx)
}

/// An unsigned handshake frame that only claims `identity`.
fn claimed_initial_request(identity: &str) -> Value {
    serde_json::to_value(AuthMessage {
        version: "0.1".into(),
        message_type: MessageType::InitialRequest,
        identity_key: identity.to_owned(),
        nonce: None,
        initial_nonce: Some("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".into()),
        your_nonce: None,
        certificates: None,
        requested_certificates: None,
        payload: None,
        signature: None,
    })
    .expect("serialize")
}

async fn next_ping(seen: &mut mpsc::UnboundedReceiver<VerifiedEvent>) -> Option<VerifiedEvent> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let event = seen.recv().await?;
            if event.event_name == "appPing" {
                return Some(event);
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Invariant: frames on the client's socket that only claim an identity (the
/// server's or any other) cannot change the session the client signs under.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claimed_initial_request_never_replaces_the_clients_session() {
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    let (url, io, mut seen) = boot(core).await;
    let client_identity = identity_of(CLIENT_KEY).await;
    let client = AuthSocketClient::connect(
        &url,
        &client_identity,
        ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("key")),
    )
    .await
    .expect("connect");
    for claimed in [identity_of(SERVER_KEY).await, identity_of(OTHER_KEY).await] {
        for socket in io.of("/").expect("ns").sockets().expect("sockets") {
            let _ = socket.emit(AUTH_MESSAGE_EVENT, &claimed_initial_request(&claimed));
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    client
        .emit("appPing", &json!({ "n": 2 }))
        .await
        .expect("emit");
    let second = next_ping(&mut seen).await;
    assert!(
        second.is_some(),
        "the client's signed event must still verify after claimed handshake frames"
    );
    assert!(client.is_connected());
    client.disconnect().await.expect("disconnect");
}

/// Invariant: a handler can learn the verified sender, and it is the server
/// the client connected to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handlers_receive_the_verified_server_identity() {
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    let (url, _io, _seen) = boot(core).await;
    let client_identity = identity_of(CLIENT_KEY).await;
    let client = AuthSocketClient::connect(
        &url,
        &client_identity,
        ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("key")),
    )
    .await
    .expect("connect");
    let (tx, mut rx) = mpsc::unbounded_channel();
    client
        .on_verified(
            "appPong",
            Arc::new(move |sender, _data| {
                let _ = tx.send(sender);
            }),
        )
        .await;
    client.emit("appPing", &json!({})).await.expect("emit");
    let sender = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("pong within 3 s")
        .expect("sender");
    assert_eq!(sender, identity_of(SERVER_KEY).await);
    assert_eq!(client.server_identity_key(), sender);
}

/// Invariant (D4): a refused identity holds no connection past its first
/// verified event, and no event of it is dispatched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_identity_is_disconnected_on_its_first_verified_event() {
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    let allowed = identity_of(OTHER_KEY).await;
    core.set_identity_authorizer(move |identity| identity == allowed);
    let (url, _io, mut seen) = boot(Arc::clone(&core)).await;
    let refused = identity_of(CLIENT_KEY).await;
    let started = std::time::Instant::now();
    let outcome = AuthSocketClient::connect(
        &url,
        &refused,
        ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("key")),
    )
    .await;
    if let Ok(client) = &outcome {
        tokio::time::timeout(authsocket::KEEPALIVE_INTERVAL, async {
            while client.is_connected() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("a refused identity is disconnected within one keepalive interval");
    }
    assert!(started.elapsed() < authsocket::KEEPALIVE_INTERVAL);
    tokio::time::timeout(Duration::from_secs(2), async {
        while core.connection_count() > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the server holds no connection for a refused identity");
    assert!(
        seen.try_recv().is_err(),
        "no event of a refused identity is dispatched"
    );
}

/// Invariant (D4): the per-identity and total connection caps hold, and a
/// refused extra connection does not disturb the admitted one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_caps_hold() {
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    core.set_connection_limits(authsocket::ConnectionLimits {
        max_total: 2,
        max_per_identity: 1,
    });
    let (url, _io, mut seen) = boot(Arc::clone(&core)).await;
    let wallet = |key: &str| ProtoWallet::new(PrivateKey::from_hex(key).expect("key"));
    let client_identity = identity_of(CLIENT_KEY).await;
    let first = AuthSocketClient::connect(&url, &client_identity, wallet(CLIENT_KEY))
        .await
        .expect("first connection");
    let second = AuthSocketClient::connect(&url, &client_identity, wallet(CLIENT_KEY)).await;
    assert!(
        second.is_err(),
        "a second connection of the same identity is refused"
    );
    let other = AuthSocketClient::connect(&url, &identity_of(OTHER_KEY).await, wallet(OTHER_KEY))
        .await
        .expect("another identity fits the total cap");
    let third_key = "0000000000000000000000000000000000000000000000000000000000000055";
    let third =
        AuthSocketClient::connect(&url, &identity_of(third_key).await, wallet(third_key)).await;
    assert!(third.is_err(), "the total cap refuses a third socket");
    first
        .emit("appPing", &json!({ "n": 1 }))
        .await
        .expect("emit");
    let ping = next_ping(&mut seen)
        .await
        .expect("the admitted connection still works");
    assert_eq!(ping.sender, client_identity);
    assert!(other.is_connected());
}
