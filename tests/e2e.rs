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
use socketioxide::extract::{Data, SocketRef};
use socketioxide::SocketIo;
use tokio::sync::mpsc;

use authsocket::client::{parse_auth_message_from_payload, AuthSocketClient, SocketIOTransport};
use authsocket::peer_session::VerifiedEvent;
use authsocket::server::{
    AuthSocketServer, CertificateAuthorizationDecision, SharedAuthSocketServer,
};
use authsocket::server_io::{
    attach, emit_signed_to_room, emit_signed_to_socket, send_certificate_response, AppDispatcher,
};
use authsocket::{wire::decode_event, wire::encode_event, AUTH_MESSAGE_EVENT};

use bsv::auth::certificates::AuthCertificate;
use bsv::auth::peer::Peer;
use bsv::auth::types::{AuthMessage, MessageType, RequestedCertificateSet};
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::interfaces::{
    Certificate, CertificateType, GetPublicKeyArgs, SerialNumber, WalletInterface,
};
use bsv::wallet::proto_wallet::ProtoWallet;

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000011";
const CLIENT_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000022";
const CERTIFIER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000033";

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
        socket: &SocketRef,
        event: VerifiedEvent,
    ) {
        let _ = self.seen.send(event.clone());
        if event.event_name == "certificateFlood" {
            let server_identity = identity_of(SERVER_KEY).await;
            let certificate = membership_certificate(&server_identity, CERTIFIER_KEY).await;
            let sid = socket.id.to_string();
            for _ in 0..33 {
                if !send_certificate_response(
                    io,
                    server,
                    &sid,
                    &event.sender,
                    vec![certificate.clone()],
                )
                .await
                {
                    return;
                }
            }
            emit_signed_to_socket(
                socket,
                server,
                "afterCertificateFlood",
                &json!({ "processed": 33 }),
            )
            .await;
        }
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

/// Complete BRC-103 framing but intentionally discard the verified
/// `authenticated` event, modeling a legacy integration that never emits the
/// signed `authenticationSuccess` acknowledgement.
async fn boot_handshake_only_server() -> String {
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    let (layer, io) = SocketIo::new_layer();
    io.ns("/", move |socket: SocketRef| {
        let sid = socket.id.to_string();
        core.add_connection(
            &sid,
            ProtoWallet::new(PrivateKey::from_hex(SERVER_KEY).expect("server key")),
        );
        let core = core.clone();
        socket.on(
            AUTH_MESSAGE_EVENT,
            move |socket: SocketRef, Data(data): Data<Value>| {
                let core = core.clone();
                async move {
                    let message: AuthMessage =
                        serde_json::from_value(data).expect("valid test authMessage");
                    let driven = core.on_auth_message(&socket.id.to_string(), message).await;
                    for outbound in driven.outbound {
                        let json = serde_json::to_value(outbound).expect("serialize authMessage");
                        socket
                            .emit(AUTH_MESSAGE_EVENT, &json)
                            .expect("emit handshake response");
                    }
                    // Deliberately do not dispatch driven.events.
                }
            },
        );
    });

    let app = axum::Router::new().layer(layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{addr}")
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

async fn membership_certificate(subject: &str, certifier_key: &str) -> Certificate {
    let certifier_wallet =
        ProtoWallet::new(PrivateKey::from_hex(certifier_key).expect("certifier"));
    let mut certificate = Certificate {
        cert_type: CertificateType([7; 32]),
        serial_number: SerialNumber([9; 32]),
        subject: PublicKey::from_string(subject).expect("subject key"),
        certifier: PublicKey::from_string(&identity_of(certifier_key).await)
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

/// Deterministic stand-in for the consumer's network-backed revocation query.
async fn membership_is_revoked(revocation_outpoint: &str) -> bool {
    assert!(!revocation_outpoint.is_empty());
    false
}

async fn raw_socket_close_observer(
    url: &str,
) -> (
    rust_socketio::asynchronous::Client,
    mpsc::UnboundedReceiver<()>,
) {
    let (closed_tx, closed_rx) = mpsc::unbounded_channel();
    let socket = rust_socketio::asynchronous::ClientBuilder::new(url)
        .on(Event::Close, move |_, _| {
            let closed = closed_tx.clone();
            async move {
                let _ = closed.send(());
            }
            .boxed()
        })
        .transport_type(TransportType::Websocket)
        .reconnect(false)
        .connect()
        .await
        .expect("raw Socket.IO connect");
    (socket, closed_rx)
}

#[tokio::test]
async fn silent_pending_socket_is_disconnected_at_configured_deadline() {
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    core.set_certificate_authorization_timeout(std::time::Duration::from_millis(100));
    core.set_certificate_authorizer(|_, _| async { CertificateAuthorizationDecision::Accept });
    let (url, _core, _dispatched) = boot_server_with_core(core).await;
    let (_socket, mut closed) = raw_socket_close_observer(&url).await;

    tokio::time::timeout(std::time::Duration::from_secs(5), closed.recv())
        .await
        .expect("deadline task must disconnect a silent Pending socket")
        .expect("close observer");
}

#[tokio::test]
async fn half_configured_socket_is_disconnected_at_connect_time() {
    let server_identity = identity_of(SERVER_KEY).await;
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    core.set_certificates_to_request(membership_request(server_identity));
    let (url, _core, _dispatched) = boot_server_with_core(core).await;
    let (_socket, mut closed) = raw_socket_close_observer(&url).await;

    tokio::time::timeout(std::time::Duration::from_secs(5), closed.recv())
        .await
        .expect("connect-time half-configuration must disconnect the socket")
        .expect("close observer");
}

#[tokio::test]
async fn legacy_server_missing_authentication_success_fails_within_five_seconds() {
    let url = boot_handshake_only_server().await;
    let client_identity = identity_of(CLIENT_KEY).await;
    let wallet = ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("client key"));
    let started = tokio::time::Instant::now();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        AuthSocketClient::connect(&url, &client_identity, wallet),
    )
    .await
    .expect("legacy failure budget regressed toward the 30-second default");
    let error = match result {
        Ok(client) => {
            let _ = client.disconnect().await;
            panic!("server intentionally omits authenticationSuccess");
        }
        Err(error) => error,
    };
    let elapsed = started.elapsed();

    assert!(
        error
            .to_string()
            .contains("authenticationSuccess not received within 5s"),
        "legacy timeout must report its five-second budget: {error}"
    );
    assert!(
        elapsed >= std::time::Duration::from_secs(5)
            && elapsed < std::time::Duration::from_secs(10),
        "legacy failure must occur near five seconds, observed {elapsed:?}"
    );
}

#[tokio::test]
async fn exported_server_certificate_response_reaches_client_verified_channel() {
    let server_identity = identity_of(SERVER_KEY).await;
    let certifier_identity = identity_of(CERTIFIER_KEY).await;
    let server_certificate = membership_certificate(&server_identity, CERTIFIER_KEY).await;
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    let (layer, io) = SocketIo::new_layer();
    let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
    let callback_core = core.clone();
    let callback_io = io.clone();
    core.listen_for_certificates_requested(Arc::new(move |sid, requester, _| {
        let core = callback_core.clone();
        let io = callback_io.clone();
        let certificate = server_certificate.clone();
        let sent = sent_tx.clone();
        tokio::spawn(async move {
            let emitted =
                send_certificate_response(&io, &core, &sid, &requester, vec![certificate]).await;
            let _ = sent.send(emitted);
        });
    }));
    let (seen_tx, _seen_rx) = mpsc::unbounded_channel();
    attach(
        &io,
        core,
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

    let (auth_tx, auth_rx) = mpsc::channel(64);
    let (ready_tx, mut ready_rx) = mpsc::channel(1);
    let socket = rust_socketio::asynchronous::ClientBuilder::new(format!("http://{addr}"))
        .on(AUTH_MESSAGE_EVENT, move |payload, _| {
            let tx = auth_tx.clone();
            async move {
                if let Some(message) = parse_auth_message_from_payload(&payload) {
                    let _ = tx.send(message).await;
                }
            }
            .boxed()
        })
        .on(Event::Connect, move |_, _| {
            let ready = ready_tx.clone();
            async move {
                let _ = ready.try_send(());
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
    let peer = Peer::new(
        ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("client key")),
        Arc::new(SocketIOTransport::new(socket.clone(), auth_rx)),
    );
    peer.set_certificates_to_request(membership_request(certifier_identity));
    let mut certificates = peer.on_certificates().expect("fresh certificate receiver");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        peer.get_authenticated_session(""),
    )
    .await
    .expect("client handshake timeout")
    .expect("client handshake");

    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), sent_rx.recv())
            .await
            .expect("server response helper completion")
            .expect("response result channel"),
        "exported helper must emit the SDK-signed server response"
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), peer.process_pending())
        .await
        .expect("client certificate-response processing timeout")
        .expect("client must verify the server certificate response");
    let (signer, batch) =
        tokio::time::timeout(std::time::Duration::from_secs(5), certificates.recv())
            .await
            .expect("verified server certificate delivery")
            .expect("certificate channel");
    assert_eq!(signer, server_identity);
    assert_eq!(batch.len(), 1);
    socket.disconnect().await.expect("disconnect");
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

    #[derive(Debug)]
    enum Observed {
        Frame(Box<AuthMessage>),
        Closed,
    }

    let (auth_tx, auth_rx) = mpsc::channel(64);
    let auth_tx_cb = auth_tx.clone();
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let observed_frame_tx = observed_tx.clone();
    let (ready_tx, mut ready_rx) = mpsc::channel(1);
    let observed_close_tx = observed_tx.clone();
    let socket = rust_socketio::asynchronous::ClientBuilder::new(&url)
        .on(AUTH_MESSAGE_EVENT, move |payload, _| {
            let tx = auth_tx_cb.clone();
            let observed = observed_frame_tx.clone();
            async move {
                if let Some(message) = parse_auth_message_from_payload(&payload) {
                    let _ = observed.send(Observed::Frame(Box::new(message.clone())));
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
            let observed = observed_close_tx.clone();
            async move {
                let _ = observed.send(Observed::Closed);
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
    let (request_tx, mut request_rx) = mpsc::unbounded_channel();
    peer.listen_for_certificates_requested(Arc::new(move |verifier, _| {
        let _ = request_tx.send(verifier);
    }));

    let session = peer
        .get_authenticated_session("")
        .await
        .expect("establish BRC-103 session without an app event");
    let verifier = request_rx
        .recv()
        .await
        .expect("server certificate request callback");

    // Exercise both adapter-owned and consumer-dispatched events while Pending.
    // If core suppression or close-before-dispatch ordering regresses, the test
    // observes authenticationSuccess on the wire and/or appPing in `dispatched`.
    peer.send_message(
        &session.peer_identity_key,
        encode_event("authenticated", &json!({ "identityKey": client_identity })),
    )
    .await
    .expect("send authenticated while pending");
    peer.send_message(
        &session.peer_identity_key,
        encode_event("appPing", &json!({ "probe": "must-not-dispatch" })),
    )
    .await
    .expect("send app event while pending");
    peer.send_certificate_response(
        &verifier,
        vec![membership_certificate(&client_identity, SERVER_KEY).await],
    )
    .await
    .expect("send rejecting certificate response");

    let sequence = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut names_before_close = Vec::new();
        loop {
            match observed_rx.recv().await.expect("observation channel") {
                Observed::Frame(message) => {
                    if message.message_type == MessageType::General {
                        if let Some((name, _)) =
                            decode_event(message.payload.as_deref().unwrap_or_default())
                        {
                            names_before_close.push(name);
                        }
                    }
                }
                Observed::Closed => break names_before_close,
            }
        }
    })
    .await
    .expect("rejected certificate must close the socket");
    assert!(
        !sequence.iter().any(|name| name == "authenticationSuccess"),
        "authenticationSuccess was emitted before rejection close; sequence={sequence:?}"
    );
    assert!(
        authorizer_called.load(Ordering::SeqCst),
        "certificate authorizer must run before close"
    );
    assert!(
        dispatched.try_recv().is_err(),
        "pending/rejected connection dispatched appPing before close"
    );
}

#[tokio::test]
async fn authsocket_client_completes_with_slow_accepting_certificate_authorizer() {
    let server_identity = identity_of(SERVER_KEY).await;
    let client_identity = identity_of(CLIENT_KEY).await;
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    core.set_certificates_to_request(membership_request(server_identity.clone()));
    let authorizer_called = Arc::new(AtomicBool::new(false));
    let authorizer_called_cb = authorizer_called.clone();
    let expected_client = client_identity.clone();
    let trusted_certifier = server_identity.clone();
    let requested_type = CertificateType([7; 32]);
    core.set_certificate_authorizer(move |identity, certificates| {
        let called = authorizer_called_cb.clone();
        let expected_client = expected_client.clone();
        let trusted_certifier = trusted_certifier.clone();
        let requested_type = requested_type.clone();
        async move {
            called.store(true, Ordering::SeqCst);
            // Model a network-backed revocation lookup. The authenticated app
            // event may arrive while this decision is still pending.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            // bsv-sdk has already authenticated `identity`, the response
            // signature/replay nonce, and each certificate's subject,
            // and signature. bsv-sdk 0.7.1 does not constrain certificate type
            // on this response path, so application policy checks the requested
            // type, certifier trust, and live revocation status here.
            let certificate = certificates.first();
            let trusted_metadata = certificates.len() == 1
                && identity == expected_client
                && certificate.is_some_and(|certificate| {
                    certificate.cert_type == requested_type
                        && certificate.certifier.to_der_hex() == trusted_certifier
                        && certificate.revocation_outpoint.is_some()
                });
            let is_revoked = match certificate.and_then(|cert| cert.revocation_outpoint.as_deref())
            {
                Some(outpoint) => membership_is_revoked(outpoint).await,
                None => true,
            };
            if trusted_metadata && !is_revoked {
                CertificateAuthorizationDecision::Accept
            } else {
                CertificateAuthorizationDecision::Reject(
                    "untrusted certifier or revoked membership".into(),
                )
            }
        }
    });
    let (url, _core, _dispatched) = boot_server_with_core(core).await;

    let wallet = ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("client key"));
    let client = AuthSocketClient::connect_with_certificates(
        &url,
        &client_identity,
        wallet,
        vec![membership_certificate(&client_identity, SERVER_KEY).await],
    )
    .await
    .expect("crate client must complete certificate-gated authentication");
    assert!(client.is_connected());
    assert!(authorizer_called.load(Ordering::SeqCst));
    client.disconnect().await.expect("disconnect");
}

#[tokio::test]
async fn authsocket_client_does_not_wedge_on_33rd_certificate_response() {
    let (url, _core, _dispatched) = boot_server().await;
    let client_identity = identity_of(CLIENT_KEY).await;
    let wallet = ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("client key"));
    let client = AuthSocketClient::connect(&url, &client_identity, wallet)
        .await
        .expect("connect + handshake");
    let (processed_tx, mut processed_rx) = mpsc::unbounded_channel();
    client
        .on(
            "afterCertificateFlood",
            Arc::new(move |data| {
                let _ = processed_tx.send(data);
            }),
        )
        .await;

    client
        .emit("certificateFlood", &json!({}))
        .await
        .expect("request server certificate responses");
    let processed = tokio::time::timeout(std::time::Duration::from_secs(10), processed_rx.recv())
        .await
        .expect("client wedged on or before certificateResponse 33")
        .expect("processed event channel");
    assert_eq!(processed, json!({ "processed": 33 }));

    client.disconnect().await.expect("disconnect");
}

#[tokio::test]
async fn client_reports_certificate_requirement_instead_of_generic_timeout() {
    let server_identity = identity_of(SERVER_KEY).await;
    let client_identity = identity_of(CLIENT_KEY).await;
    let core: SharedAuthSocketServer<ProtoWallet> = Arc::new(AuthSocketServer::new());
    core.set_certificates_to_request(membership_request(server_identity));
    core.set_certificate_authorizer(|_, _| async { CertificateAuthorizationDecision::Accept });
    let (url, _core, _dispatched) = boot_server_with_core(core).await;

    let wallet = ProtoWallet::new(PrivateKey::from_hex(CLIENT_KEY).expect("client key"));
    let error = match AuthSocketClient::connect(&url, &client_identity, wallet).await {
        Ok(client) => {
            let _ = client.disconnect().await;
            panic!("client without certificate provider must fail closed");
        }
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("server requested certificates"),
        "certificate failure must be diagnostic: {error}"
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
