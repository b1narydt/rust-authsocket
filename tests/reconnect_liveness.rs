//! Abrupt-peer-death liveness: `is_connected()` must stop reporting `true`
//! promptly when the server goes away WITHOUT a Socket.IO disconnect packet
//! (process SIGKILL, container restart, TCP reset).
//!
//! This is the property the reconnect supervisor of every consumer is built on:
//! `is_connected()` is read as "an emit on this client will reach the hub". A
//! stale `true` makes the supervisor sit still and makes the next application
//! send fail hard on a socket nobody is watching.
#![cfg(all(feature = "server", feature = "client"))]

use std::sync::Arc;
use std::time::{Duration, Instant};

use socketioxide::extract::SocketRef;
use socketioxide::SocketIo;

use authsocket::client::AuthSocketClient;
use authsocket::peer_session::VerifiedEvent;
use authsocket::server::{AuthSocketServer, SharedAuthSocketServer};
use authsocket::server_io::{attach, AppDispatcher};

use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
use bsv::wallet::proto_wallet::ProtoWallet;

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000031";
const CLIENT_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000032";

/// How long a consumer may be told "connected" after the peer has vanished.
/// One supervisor tick's worth of slack — anything longer and the ceremony
/// driver sends into a hole instead of waiting for the reconnect.
const PROMPT: Duration = Duration::from_secs(2);

struct NullDispatcher;

#[async_trait::async_trait]
impl AppDispatcher<ProtoWallet> for NullDispatcher {
    async fn dispatch(
        &self,
        _io: &SocketIo,
        _server: &AuthSocketServer<ProtoWallet>,
        _socket: &SocketRef,
        _event: VerifiedEvent,
    ) {
    }
}

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

/// Boot the server on its OWN runtime, on its OWN OS thread, and hand back a
/// kill switch. Dropping that runtime aborts every task and drops every open
/// socket — the in-process equivalent of SIGKILLing the relay process: the peer
/// vanishes with no Socket.IO `disconnect` packet and no application goodbye.
///
/// (Aborting an `axum::serve` future is NOT equivalent: axum spawns each
/// accepted connection as its own task, so established sockets keep serving.)
fn boot_killable_server() -> (String, std::sync::mpsc::Sender<()>) {
    let (url_tx, url_rx) = std::sync::mpsc::channel::<String>();
    let (kill_tx, kill_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("server runtime");
        rt.block_on(async {
            let (layer, io) = SocketIo::new_layer();
            let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
            attach(
                &io,
                core,
                || {
                    Ok(ProtoWallet::new(
                        PrivateKey::from_hex(SERVER_KEY).expect("server key"),
                    ))
                },
                Arc::new(NullDispatcher),
            );
            let app = axum::Router::new().layer(layer);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            url_tx.send(format!("http://{addr}")).expect("send url");
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
        });
        // Park this thread (and its live runtime) until the kill switch fires;
        // returning drops the runtime, which aborts every task and closes every
        // socket without a protocol-level goodbye.
        let _ = kill_rx.recv();
        rt.shutdown_background();
    });
    (url_rx.recv().expect("server booted"), kill_tx)
}

#[tokio::test]
async fn is_connected_goes_false_promptly_when_the_server_vanishes() {
    let (url, kill) = boot_killable_server();
    let client_identity = identity_of(CLIENT_KEY).await;
    let wallet = ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("client key"));

    let client = AuthSocketClient::connect(&url, &client_identity, wallet)
        .await
        .expect("handshake completes");
    assert!(client.is_connected(), "a fresh client is connected");

    // The relay dies. No Socket.IO `disconnect` packet is sent, exactly as
    // when the process is SIGKILLed.
    kill.send(()).expect("kill switch");
    drop(kill);

    let died_at = Instant::now();
    while client.is_connected() {
        assert!(
            died_at.elapsed() < PROMPT,
            "is_connected() still reported true {:?} after the server vanished — a consumer \
             reading it as 'an emit will reach the hub' sends into a dead socket",
            died_at.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    eprintln!("death observed after {:?}", died_at.elapsed());

    // And the emit that a consumer would have made must fail too (it does
    // today — the point of the assertion above is that it fails AFTER the
    // client already admitted it was dead, not before).
    assert!(
        client.emit("anything", &serde_json::json!({})).await.is_err(),
        "an emit on a dead socket must fail"
    );
}
