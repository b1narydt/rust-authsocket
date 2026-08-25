#![cfg(feature = "server")]

use std::sync::Arc;
use std::time::Duration;

use authsocket::bsv::auth::peer::Peer;
use authsocket::bsv::auth::types::RequestedCertificateSet;
use authsocket::bsv::primitives::private_key::PrivateKey;
use authsocket::bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
use authsocket::bsv::wallet::proto_wallet::ProtoWallet;
use authsocket::server::{
    AuthSocketServer, CertificateAuthorization, CertificateAuthorizationDecision,
    ConnectionPumpError, VerifiedEventSink,
};
use authsocket::transport::ChannelTransport;
use authsocket::wire::encode_event;
use authsocket::VerifiedEvent;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const SID: &str = "channel-consumer";
const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000011";
const CLIENT_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000022";

fn wallet(key: &str) -> ProtoWallet {
    ProtoWallet::new(PrivateKey::from_hex(key).expect("test key"))
}

async fn identity_of(key: &str) -> String {
    wallet(key)
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

struct ChannelConsumer {
    server: Arc<AuthSocketServer<ProtoWallet>>,
    peer: Arc<Peer<ProtoWallet>>,
    events: mpsc::UnboundedReceiver<VerifiedEvent>,
    pump: JoinHandle<Result<(), ConnectionPumpError>>,
    inbound: JoinHandle<()>,
}

impl ChannelConsumer {
    async fn start(server: Arc<AuthSocketServer<ProtoWallet>>) -> Self {
        server.add_connection(SID, wallet(SERVER_KEY));
        let receivers = server
            .take_pump_receivers(SID)
            .expect("fresh connection pump receivers");

        let (event_tx, events) = mpsc::unbounded_channel();
        let event_sink: VerifiedEventSink = Arc::new(move |events| {
            let event_tx = event_tx.clone();
            Box::pin(async move {
                for event in events {
                    event_tx.send(event).expect("event consumer remains open");
                }
            })
        });
        server.set_verified_event_sink(SID, &event_sink);

        let (transport, client_in, mut client_out) = ChannelTransport::new();
        let peer = Arc::new(Peer::new(wallet(CLIENT_KEY), Arc::new(transport)));

        let pump_server = server.clone();
        let pump = tokio::spawn(async move {
            pump_server
                .run_connection_pump(SID, receivers, move |message| {
                    let client_in = client_in.clone();
                    async move {
                        assert!(
                            !message
                                .requested_certificates
                                .as_ref()
                                .is_some_and(RequestedCertificateSet::is_empty),
                            "the consumer callback must receive normalized frames"
                        );
                        client_in
                            .send(message)
                            .await
                            .expect("client transport remains open");
                    }
                })
                .await
        });

        let inbound_server = server.clone();
        let inbound = tokio::spawn(async move {
            while let Some(message) = client_out.recv().await {
                inbound_server.on_auth_message(SID, message).await;
            }
        });

        Self {
            server,
            peer,
            events,
            pump,
            inbound,
        }
    }

    async fn stop(self) {
        self.server.remove_connection(SID);
        tokio::time::timeout(Duration::from_secs(2), self.pump)
            .await
            .expect("pump stops after connection removal")
            .expect("pump task does not panic")
            .expect("pump exits successfully");
        self.inbound.abort();
    }
}

#[tokio::test]
async fn channel_consumer_completes_handshake_and_receives_verified_events() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = Arc::new(AuthSocketServer::new());
        let mut consumer = ChannelConsumer::start(server).await;

        consumer
            .peer
            .send_message(
                "",
                encode_event("channelEvent", &json!({ "transport": "channel" })),
            )
            .await
            .expect("complete BRC-103 handshake and send event");
        let event = consumer.events.recv().await.expect("verified event");
        assert_eq!(event.event_name, "channelEvent");
        assert_eq!(event.data, json!({ "transport": "channel" }));
        assert_eq!(event.sender, identity_of(CLIENT_KEY).await);

        consumer.stop().await;
    })
    .await
    .expect("channel-only consumer test must not hang");
}

#[tokio::test]
async fn public_sink_holds_pending_event_until_certificate_acceptance() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let server = Arc::new(AuthSocketServer::new());
        server.set_certificate_authorizer(|_, _| async move {
            CertificateAuthorizationDecision::Accept
        });
        let mut consumer = ChannelConsumer::start(server.clone()).await;

        consumer
            .peer
            .send_message(
                "",
                encode_event("heldUntilAuthorized", &json!({ "sequence": 1 })),
            )
            .await
            .expect("complete handshake and send pending event");
        assert_eq!(
            server.certificate_authorization(SID),
            Some(CertificateAuthorization::Pending)
        );
        assert_eq!(server.identity_key(SID), None);
        assert!(
            tokio::time::timeout(Duration::from_millis(250), consumer.events.recv())
                .await
                .is_err(),
            "the public sink must receive nothing while authorization is Pending"
        );

        consumer
            .peer
            .send_certificate_response(&identity_of(SERVER_KEY).await, Vec::new())
            .await
            .expect("send session-bound certificate decision input");

        let released = consumer
            .events
            .recv()
            .await
            .expect("deferred event is released to the public sink");
        assert_eq!(released.event_name, "heldUntilAuthorized");
        assert_eq!(released.data, json!({ "sequence": 1 }));
        assert!(matches!(
            server.certificate_authorization(SID),
            Some(CertificateAuthorization::Accepted { .. })
        ));

        consumer.stop().await;
    })
    .await
    .expect("certificate-gate public-path test must not hang");
}

#[tokio::test]
async fn connection_pump_without_verified_event_sink_is_a_loud_error() {
    let server = AuthSocketServer::new();
    server.add_connection(SID, wallet(SERVER_KEY));
    let receivers = server
        .take_pump_receivers(SID)
        .expect("fresh connection pump receivers");

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        server.run_connection_pump(SID, receivers, |_| async {}),
    )
    .await
    .expect("missing-sink error is immediate")
    .expect_err("a pump without an event sink must fail");
    assert_eq!(
        error,
        ConnectionPumpError::VerifiedEventSinkNotRegistered(SID.to_string())
    );
}

#[tokio::test]
async fn replacement_survives_old_pump_teardown_and_still_receives_frames() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = Arc::new(AuthSocketServer::new());
        let old_id = server.add_connection(SID, wallet(SERVER_KEY));
        let old_receivers = server.take_pump_receivers(SID).expect("old pump receivers");
        let old_sink: VerifiedEventSink = Arc::new(|_| Box::pin(async {}));
        server.set_verified_event_sink(SID, &old_sink);
        let old_server = server.clone();
        let old_pump = tokio::spawn(async move {
            old_server
                .run_connection_pump(SID, old_receivers, |_| async {})
                .await
        });

        let mut replacement = ChannelConsumer::start(server.clone()).await;
        tokio::time::timeout(Duration::from_secs(2), old_pump)
            .await
            .expect("replacing the connection closes the old pump")
            .expect("old pump task does not panic")
            .expect("old pump exits successfully");

        assert!(
            !server.remove_connection_if_current(&old_id),
            "old teardown must not remove the replacement"
        );
        replacement
            .peer
            .send_message(
                "",
                encode_event("replacementLive", &json!({ "generation": "new" })),
            )
            .await
            .expect("replacement still receives pump frames");
        let event = replacement.events.recv().await.expect("replacement event");
        assert_eq!(event.event_name, "replacementLive");
        assert_eq!(event.data, json!({ "generation": "new" }));

        replacement.stop().await;
    })
    .await
    .expect("replacement teardown regression must not hang");
}

#[tokio::test]
async fn deferred_events_from_a_superseded_connection_are_dropped_before_any_sink() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let server = Arc::new(AuthSocketServer::new());
        let authorizer_started = Arc::new(tokio::sync::Notify::new());
        let release_authorizer = Arc::new(tokio::sync::Notify::new());
        let started = authorizer_started.clone();
        let release = release_authorizer.clone();
        server.set_certificate_authorizer(move |_, _| {
            let started = started.clone();
            let release = release.clone();
            async move {
                started.notify_one();
                release.notified().await;
                CertificateAuthorizationDecision::Accept
            }
        });

        let mut old = ChannelConsumer::start(server.clone()).await;
        old.peer
            .send_message(
                "",
                encode_event("oldDeferred", &json!({ "generation": "old" })),
            )
            .await
            .expect("old connection sends deferred event");
        assert!(
            tokio::time::timeout(Duration::from_millis(250), old.events.recv())
                .await
                .is_err(),
            "the old event must be buffered while authorization is pending"
        );
        old.peer
            .send_certificate_response(&identity_of(SERVER_KEY).await, Vec::new())
            .await
            .expect("old connection starts authorization");
        authorizer_started.notified().await;

        let mut replacement = ChannelConsumer::start(server.clone()).await;
        release_authorizer.notify_one();

        let old_delivery =
            tokio::time::timeout(Duration::from_millis(300), old.events.recv()).await;
        assert!(
            !matches!(old_delivery, Ok(Some(_))),
            "a superseded connection must not invoke even its retained sink: {old_delivery:?}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(300), replacement.events.recv())
                .await
                .is_err(),
            "old deferred events must not reach replacement state"
        );

        old.inbound.abort();
        tokio::time::timeout(Duration::from_secs(2), old.pump)
            .await
            .expect("old pump exits after authorization releases")
            .expect("old pump task does not panic")
            .expect("old pump exits successfully");
        replacement.stop().await;
    })
    .await
    .expect("superseded deferred-event regression must not hang");
}

#[tokio::test]
async fn transport_agnostic_pump_enforces_certificate_deadline() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = Arc::new(AuthSocketServer::new());
        server.set_certificate_authorizer(|_, _| async move {
            CertificateAuthorizationDecision::Accept
        });
        server.set_certificate_authorization_timeout(Duration::from_millis(50));
        let connection_id = server.add_connection(SID, wallet(SERVER_KEY));
        let receivers = server
            .take_pump_receivers(SID)
            .expect("deadline pump receivers");
        let sink: VerifiedEventSink = Arc::new(|_| Box::pin(async {}));
        server.set_verified_event_sink(SID, &sink);

        tokio::time::timeout(
            Duration::from_secs(1),
            server.run_connection_pump(SID, receivers, |_| async {}),
        )
        .await
        .expect("pump exits when no certificate response arrives")
        .expect("deadline is a normal pump teardown");
        assert!(
            !server.is_current_connection(&connection_id),
            "deadline removes the transport-agnostic connection"
        );
    })
    .await
    .expect("transport-agnostic deadline regression must not hang");
}

#[tokio::test]
async fn transport_agnostic_pump_keeps_connection_that_answers_before_deadline() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = Arc::new(AuthSocketServer::new());
        server.set_certificate_authorizer(|_, _| async move {
            CertificateAuthorizationDecision::Accept
        });
        server.set_certificate_authorization_timeout(Duration::from_secs(1));
        let mut consumer = ChannelConsumer::start(server.clone()).await;

        consumer
            .peer
            .send_message(
                "",
                encode_event("answered", &json!({ "before": "deadline" })),
            )
            .await
            .expect("send deferred event");
        consumer
            .peer
            .send_certificate_response(&identity_of(SERVER_KEY).await, Vec::new())
            .await
            .expect("answer before deadline");
        let admitted = consumer.events.recv().await.expect("authorized event");
        assert_eq!(admitted.event_name, "answered");

        tokio::time::sleep(Duration::from_millis(1100)).await;
        consumer
            .peer
            .send_message(
                &identity_of(SERVER_KEY).await,
                encode_event("stillLive", &json!({ "after": "deadline" })),
            )
            .await
            .expect("accepted connection remains live after original deadline");
        let live = consumer.events.recv().await.expect("post-deadline event");
        assert_eq!(live.event_name, "stillLive");

        consumer.stop().await;
    })
    .await
    .expect("answered-deadline regression must not hang");
}
