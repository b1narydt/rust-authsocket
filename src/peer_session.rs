//! Per-connection BRC-103 session lifecycle, shared by server and client.
//!
//! [`PeerHandle`] owns one bsv-sdk [`Peer`] plus the channel ends of its
//! [`ChannelTransport`], and exposes the operations both Socket.IO sides need:
//!  - [`PeerHandle::drive`] — feed one inbound `AuthMessage` to the Peer's
//!    background receiver, await its dispatch result, and return (a) outbound
//!    `AuthMessage`s to `emit` over the socket and
//!    (b) decoded, *verified* application events, each tagged with the
//!    cryptographically verified sender key.
//!  - [`PeerHandle::emit_existing`] — sign an application event for an
//!    **already-authenticated** session and return the `AuthMessage` to emit.
//!    Fails closed (`SessionNotFound`) if no authenticated session exists;
//!    never initiates a handshake. This is the ONLY correct primitive for
//!    server→client emits and room broadcasts.
//!  - [`PeerHandle::emit`] — sign an event via `Peer::send_message`, which
//!    **initiates a handshake** when no session exists. Client-side only (the
//!    initial `authenticated` emit is what starts the handshake); a server
//!    must never call this on a broadcast path.
//!
//! The bsv-sdk `Peer` owns its receive task. `PeerHandle::drive` only bridges a
//! socket callback to that task and correlates the resulting observer event.
//!
//! [`Peer`]: bsv::auth::peer::Peer
//! [`ChannelTransport`]: crate::transport::ChannelTransport

#[cfg(feature = "server")]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bsv::auth::certificates::VerifiableCertificate;
use bsv::auth::error::AuthError;
#[cfg(feature = "server")]
use bsv::auth::peer::OnCertificateRequestReceived;
use bsv::auth::peer::Peer;
use bsv::auth::types::AuthMessage;
#[cfg(feature = "server")]
use bsv::auth::types::RequestedCertificateSet;
use bsv::wallet::interfaces::WalletInterface;
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};

use crate::transport::ChannelTransport;
use crate::wire::{decode_event, encode_event};

/// A verified application event decoded from a BRC-103 general message.
///
/// `sender` is the general message's envelope `identity_key` field — but by the
/// time it reaches here it is **self-proving**, not a bare claim. The bsv-sdk
/// `Peer` pushes onto its general-message channel only after
/// `verify_general_message` succeeds, and that verification derives its check
/// key from this exact field (`counterparty = msg.identity_key`) — so a valid
/// signature proves the sender holds the private key behind `sender`. A frame
/// with a forged `identity_key` verifies under a key the attacker cannot sign
/// for, fails, and produces no event. This is the ONLY sender value that may be
/// trusted; the same field on a *raw*, undriven `AuthMessage` is unverified.
#[derive(Debug, Clone)]
pub struct VerifiedEvent {
    /// Verified sender identity key (compressed pubkey, hex).
    pub sender: String,
    /// Application event name (e.g. `sendMessage`, `joinRoom`).
    pub event_name: String,
    /// Application event data.
    pub data: Value,
}

type VerifiedCertificateBatch = (String, Vec<VerifiableCertificate>);

#[cfg(feature = "server")]
pub(crate) struct CertificateDrive {
    pub outbound: Vec<AuthMessage>,
    pub events: Vec<VerifiedEvent>,
    pub certificates: Vec<VerifiedCertificateBatch>,
    pub error: Option<AuthError>,
}

#[derive(Default)]
struct InboundCompletion {
    outbound: Vec<AuthMessage>,
    events: Vec<VerifiedEvent>,
    #[cfg(feature = "server")]
    certificates: Vec<VerifiedCertificateBatch>,
    error: Option<AuthError>,
}

impl InboundCompletion {
    fn error(error: AuthError) -> Self {
        tracing::warn!(error = %error, "authsocket: background frame dispatch failed");
        Self {
            error: Some(error),
            ..Self::default()
        }
    }
}

/// Owns a `Peer` and the channels bridging it to a Socket.IO connection.
pub struct PeerHandle<W: WalletInterface + 'static> {
    /// The SDK Peer is cloneable and internally synchronized.
    peer: Peer<W>,
    /// Push inbound `"authMessage"` frames here (Socket.IO → Peer).
    incoming_tx: mpsc::Sender<AuthMessage>,
    /// Drain Peer → Socket.IO frames here (then `emit` each as `"authMessage"`).
    outgoing_rx: Mutex<mpsc::Receiver<AuthMessage>>,
    /// Decoded, verified BRC-103 general-message payloads with their verified
    /// sender key (app events).
    general_rx: Mutex<mpsc::Receiver<(String, Vec<u8>)>>,
    /// Pure observer used to correlate certificate-request dispatch.
    certificate_request_rx:
        Mutex<mpsc::Receiver<(String, bsv::auth::types::RequestedCertificateSet)>>,
    /// Background dispatch failures surfaced by the SDK error observer.
    error_rx: Mutex<mpsc::Receiver<bsv::auth::peer::BackgroundError>>,
    /// Serializes inbound handoff so observer results stay associated with the
    /// `on_auth_message` call whose public API returns them.
    drive_io: Mutex<()>,
    /// Serializes certificate-aware driving with server-side certificate
    /// responses so neither operation can drain the other's outbound frames.
    #[cfg(feature = "server")]
    certificate_io: Mutex<()>,
    /// SDK-verified certificate batches delivered by the awaited 0.8 listener.
    certificate_rx: Mutex<mpsc::UnboundedReceiver<VerifiedCertificateBatch>>,
    #[cfg(feature = "server")]
    receive_certificates: bool,
    #[cfg(feature = "server")]
    certificate_request_listener_count: AtomicUsize,
    #[cfg(feature = "server")]
    certificate_request_handled_rx: Mutex<mpsc::UnboundedReceiver<()>>,
    #[cfg(feature = "server")]
    certificate_request_handled_tx: mpsc::UnboundedSender<()>,
    /// General frames held by the SDK until certificate validation succeeds.
    #[cfg(feature = "server")]
    deferred_general_count: AtomicUsize,
}

impl<W: WalletInterface + 'static> PeerHandle<W> {
    /// Build a fresh session for one connection.
    ///
    /// Must be called from inside a Tokio runtime because bsv-sdk starts the
    /// Peer's background receive task during construction.
    pub fn new(wallet: W) -> Self {
        #[cfg(feature = "server")]
        {
            Self::build(wallet, None, false)
        }
        #[cfg(not(feature = "server"))]
        {
            Self::build(wallet)
        }
    }

    /// Internal server construction path. `receive_certificates` controls
    /// whether verified batches are returned to the server authorizer.
    #[cfg(feature = "server")]
    pub(crate) fn new_for_server(
        wallet: W,
        requested: Option<RequestedCertificateSet>,
        receive_certificates: bool,
    ) -> Self {
        Self::build(wallet, requested, receive_certificates)
    }

    fn build(
        wallet: W,
        #[cfg(feature = "server")] requested: Option<RequestedCertificateSet>,
        #[cfg(feature = "server")] receive_certificates: bool,
    ) -> Self {
        let (transport, incoming_tx, outgoing_rx) = ChannelTransport::new();
        let transport = Arc::new(transport);
        let peer = Peer::new(wallet, transport.clone());
        #[cfg(feature = "server")]
        if let Some(requested) = requested {
            peer.set_certificates_to_request(requested);
        }
        // Take-once: must be called on the fresh Peer before it is stored.
        let general_rx = peer
            .on_general_message()
            .expect("on_general_message must succeed on a fresh Peer");
        let (certificate_tx, certificate_rx) = mpsc::unbounded_channel();
        peer.listen_for_certificates_received(Arc::new(move |identity_key, certificates| {
            let certificate_tx = certificate_tx.clone();
            Box::pin(async move {
                certificate_tx
                    .send((identity_key, certificates))
                    .map_err(|_| {
                        AuthError::TransportError(
                            "authsocket certificate listener closed during dispatch".into(),
                        )
                    })
            })
        }));
        let certificate_request_rx = peer
            .on_certificate_request()
            .expect("on_certificate_request must succeed on a fresh Peer");
        let error_rx = peer
            .on_error()
            .expect("on_error must succeed on a fresh Peer");
        #[cfg(feature = "server")]
        let (certificate_request_handled_tx, certificate_request_handled_rx) =
            mpsc::unbounded_channel();
        Self {
            peer,
            incoming_tx,
            outgoing_rx: Mutex::new(outgoing_rx),
            general_rx: Mutex::new(general_rx),
            certificate_request_rx: Mutex::new(certificate_request_rx),
            error_rx: Mutex::new(error_rx),
            drive_io: Mutex::new(()),
            #[cfg(feature = "server")]
            certificate_io: Mutex::new(()),
            certificate_rx: Mutex::new(certificate_rx),
            #[cfg(feature = "server")]
            receive_certificates,
            #[cfg(feature = "server")]
            certificate_request_listener_count: AtomicUsize::new(0),
            #[cfg(feature = "server")]
            certificate_request_handled_rx: Mutex::new(certificate_request_handled_rx),
            #[cfg(feature = "server")]
            certificate_request_handled_tx,
            #[cfg(feature = "server")]
            deferred_general_count: AtomicUsize::new(0),
        }
    }

    /// Feed one inbound `AuthMessage`, advance the protocol, and collect results.
    ///
    /// Returns `(outbound, events)`:
    ///  - `outbound`: `AuthMessage`s the Peer produced (handshake responses and/or
    ///    signed replies) — `emit` each over the socket as `"authMessage"`.
    ///  - `events`: verified application events decoded from BRC-103 general
    ///    messages. Each carries the **verified** sender key (see
    ///    [`VerifiedEvent`]); a frame that fails verification produces no event.
    pub async fn drive(&self, inbound: AuthMessage) -> (Vec<AuthMessage>, Vec<VerifiedEvent>) {
        let _guard = self.drive_io.lock().await;
        let mut completion = self.process_inbound(inbound).await;
        completion.outbound.extend(self.drain_outbound().await);
        completion.events.extend(self.drain_events().await);
        (completion.outbound, completion.events)
    }

    /// Certificate-aware variant of [`PeerHandle::drive`]. It has identical
    /// protocol behavior, but serializes outbound production/draining with
    /// [`PeerHandle::send_certificate_response_existing`]. The legacy server
    /// path does not call this method and therefore gains no additional await.
    #[cfg(feature = "server")]
    pub(crate) async fn drive_certificate_aware(&self, inbound: AuthMessage) -> CertificateDrive {
        let _guard = self.certificate_io.lock().await;
        let _drive_guard = self.drive_io.lock().await;
        let mut completion = self.process_inbound(inbound).await;
        completion.outbound.extend(self.drain_outbound().await);
        completion.events.extend(self.drain_events().await);
        completion
            .certificates
            .extend(self.drain_certificates().await);
        CertificateDrive {
            outbound: completion.outbound,
            events: completion.events,
            certificates: completion.certificates,
            error: completion.error,
        }
    }

    async fn process_inbound(&self, inbound: AuthMessage) -> InboundCompletion {
        let message_type = inbound.message_type.clone();
        let requested = inbound.requested_certificates.clone();
        if self.incoming_tx.send(inbound).await.is_err() {
            return InboundCompletion::error(AuthError::TransportError(
                "authsocket transport input closed".into(),
            ));
        }

        match message_type {
            bsv::auth::types::MessageType::InitialRequest => self.await_outbound().await,
            bsv::auth::types::MessageType::General => self.await_general().await,
            bsv::auth::types::MessageType::CertificateResponse => {
                let completion = self.await_certificates().await;
                #[cfg(feature = "server")]
                let mut completion = completion;
                #[cfg(feature = "server")]
                if completion.error.is_none() {
                    let deferred = self.deferred_general_count.swap(0, Ordering::SeqCst);
                    for _ in 0..deferred {
                        let released = self.await_general().await;
                        if let Some(error) = released.error {
                            tracing::warn!(error = %error,
                                "authsocket: certificate-gated general frame was rejected");
                        }
                        completion.events.extend(released.events);
                    }
                }
                completion
            }
            bsv::auth::types::MessageType::CertificateRequest => {
                let has_requested_certifiers = requested
                    .as_ref()
                    .is_some_and(|requested| !requested.certifiers.is_empty());
                #[cfg(feature = "server")]
                if has_requested_certifiers
                    && self
                        .certificate_request_listener_count
                        .load(Ordering::SeqCst)
                        > 0
                {
                    return self.await_certificate_request_handler().await;
                }
                let completion = self.await_certificate_request().await;
                if completion.error.is_some() || !has_requested_certifiers {
                    completion
                } else {
                    self.await_outbound().await
                }
            }
            // Initial responses are routed directly to an SDK handshake waiter;
            // a server PeerHandle never initiates that handshake direction.
            bsv::auth::types::MessageType::InitialResponse => {
                tokio::task::yield_now().await;
                InboundCompletion::default()
            }
        }
    }

    /// Sign an application event for an **already-authenticated** session and
    /// return the `AuthMessage`s to `emit`. Fails closed: if the session for
    /// `identity_key` does not exist or is not authenticated, this returns
    /// `Err(SessionNotFound | NotAuthenticated)` and NEVER initiates a
    /// handshake — so a server emit/broadcast can only ever reach a peer that
    /// has completed mutual auth.
    pub async fn emit_existing(
        &self,
        identity_key: &str,
        event_name: &str,
        data: &Value,
    ) -> Result<Vec<AuthMessage>, AuthError> {
        let payload = encode_event(event_name, data);
        let msg = self
            .peer
            .create_general_message(identity_key, payload)
            .await?;
        Ok(vec![msg])
    }

    /// Sign an application event via [`Peer::send_message`], which initiates a
    /// BRC-103 handshake if no session exists yet. **Client-side only** — this
    /// is how the client's first `authenticated` emit starts the handshake.
    /// Server emit/broadcast paths must use [`PeerHandle::emit_existing`]
    /// instead, so they can never be tricked into initiating a handshake
    /// toward an unauthenticated socket.
    pub async fn emit(
        &self,
        identity_key: &str,
        event_name: &str,
        data: &Value,
    ) -> Result<Vec<AuthMessage>, AuthError> {
        let payload = encode_event(event_name, data);
        self.peer.send_message(identity_key, payload).await?;
        Ok(self.drain_outbound().await)
    }

    /// Direct access to the owned, internally synchronized `Peer`.
    pub fn peer(&self) -> &Peer<W> {
        &self.peer
    }

    /// Register a handler for certificate requests received by this peer.
    #[cfg(feature = "server")]
    pub(crate) fn listen_for_certificates_requested(
        &self,
        callback: Arc<OnCertificateRequestReceived>,
    ) -> u64 {
        let handled = self.certificate_request_handled_tx.clone();
        let callback = Arc::new(move |identity_key, requested| {
            callback(identity_key, requested);
            let _ = handled.send(());
        });
        let id = self.peer.listen_for_certificates_requested(callback);
        self.certificate_request_listener_count
            .fetch_add(1, Ordering::SeqCst);
        id
    }

    /// Stop a certificate-request handler registered on this peer.
    #[cfg(feature = "server")]
    pub(crate) fn stop_listening_for_certificates_requested(&self, callback_id: u64) {
        self.peer
            .stop_listening_for_certificates_requested(callback_id);
        self.certificate_request_listener_count
            .fetch_sub(1, Ordering::SeqCst);
    }

    /// Send certificates only when `identity_key` already resolves an
    /// authenticated session, and return exactly the frames produced by this
    /// call. This method cannot initiate a handshake: the TTL-honoring
    /// `create_general_message` preflight fails before the SDK's potentially
    /// initiating certificate-response API is called.
    #[cfg(feature = "server")]
    pub(crate) async fn send_certificate_response_existing(
        &self,
        identity_key: &str,
        certificates: Vec<VerifiableCertificate>,
    ) -> Result<Vec<AuthMessage>, AuthError> {
        let _guard = self.certificate_io.lock().await;
        // Use the same active-session lookup as SDK verification/signing paths.
        // The discarded message refreshes session activity and proves that the
        // following SDK call cannot take its missing-session handshake fallback.
        self.peer
            .create_general_message(identity_key, Vec::new())
            .await?;
        self.peer
            .send_certificate_response(identity_key, certificates)
            .await?;
        Ok(self.drain_outbound().await)
    }

    /// Push one inbound frame to the SDK-owned background receive task.
    pub async fn feed(&self, inbound: AuthMessage) {
        let _ = self.incoming_tx.send(inbound).await;
    }

    /// Enqueue a general frame whose sequential SDK worker is waiting for
    /// certificate validation. The releasing certificate response collects it.
    #[cfg(feature = "server")]
    pub(crate) async fn feed_certificate_gated_general(&self, inbound: AuthMessage) {
        self.deferred_general_count.fetch_add(1, Ordering::SeqCst);
        if self.incoming_tx.send(inbound).await.is_err() {
            self.deferred_general_count.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Drain any outbound frames produced by the Peer.
    pub async fn drain_outbound(&self) -> Vec<AuthMessage> {
        let mut out = Vec::new();
        let mut rx = self.outgoing_rx.lock().await;
        while let Ok(m) = rx.try_recv() {
            out.push(Self::normalize_outbound(m));
        }
        out
    }

    async fn drain_events(&self) -> Vec<VerifiedEvent> {
        let mut events = Vec::new();
        let mut rx = self.general_rx.lock().await;
        while let Ok((sender, payload)) = rx.try_recv() {
            if let Some((event_name, data)) = decode_event(&payload) {
                events.push(VerifiedEvent {
                    sender,
                    event_name,
                    data,
                });
            }
        }
        events
    }

    async fn await_outbound(&self) -> InboundCompletion {
        let mut outgoing = self.outgoing_rx.lock().await;
        let mut errors = self.error_rx.lock().await;
        tokio::select! {
            message = outgoing.recv() => match message {
                Some(message) => InboundCompletion {
                    outbound: vec![Self::normalize_outbound(message)],
                    ..InboundCompletion::default()
                },
                None => InboundCompletion::error(AuthError::TransportError(
                    "authsocket transport output closed".into(),
                )),
            },
            error = errors.recv() => Self::background_error_completion(error),
        }
    }

    async fn await_general(&self) -> InboundCompletion {
        let mut general = self.general_rx.lock().await;
        let mut errors = self.error_rx.lock().await;
        tokio::select! {
            message = general.recv() => match message {
                Some((sender, payload)) => InboundCompletion {
                    events: decode_event(&payload)
                        .map(|(event_name, data)| vec![VerifiedEvent {
                            sender,
                            event_name,
                            data,
                        }])
                        .unwrap_or_default(),
                    ..InboundCompletion::default()
                },
                None => InboundCompletion::error(AuthError::TransportError(
                    "authsocket general-message observer closed".into(),
                )),
            },
            error = errors.recv() => Self::background_error_completion(error),
        }
    }

    async fn await_certificate_request(&self) -> InboundCompletion {
        let mut requests = self.certificate_request_rx.lock().await;
        let mut errors = self.error_rx.lock().await;
        tokio::select! {
            request = requests.recv() => match request {
                Some(_) => InboundCompletion::default(),
                None => InboundCompletion::error(AuthError::TransportError(
                    "authsocket certificate-request observer closed".into(),
                )),
            },
            error = errors.recv() => Self::background_error_completion(error),
        }
    }

    #[cfg(feature = "server")]
    async fn await_certificate_request_handler(&self) -> InboundCompletion {
        let mut handled = self.certificate_request_handled_rx.lock().await;
        let mut errors = self.error_rx.lock().await;
        tokio::select! {
            result = handled.recv() => match result {
                Some(()) => InboundCompletion::default(),
                None => InboundCompletion::error(AuthError::TransportError(
                    "authsocket certificate-request listener bridge closed".into(),
                )),
            },
            error = errors.recv() => Self::background_error_completion(error),
        }
    }

    async fn await_certificates(&self) -> InboundCompletion {
        let mut certificates = self.certificate_rx.lock().await;
        let mut errors = self.error_rx.lock().await;
        loop {
            tokio::select! {
                batch = certificates.recv() => return match batch {
                    Some(batch) => {
                        #[cfg(feature = "server")]
                        {
                            InboundCompletion {
                                certificates: self.receive_certificates.then_some(batch).into_iter().collect(),
                                ..InboundCompletion::default()
                            }
                        }
                        #[cfg(not(feature = "server"))]
                        {
                            let _ = batch;
                            InboundCompletion::default()
                        }
                    },
                    None => InboundCompletion::error(AuthError::TransportError(
                        "authsocket certificate listener closed".into(),
                    )),
                },
                error = errors.recv() => match error {
                    Some(background)
                        if background.message_type
                            == Some(bsv::auth::types::MessageType::CertificateResponse) =>
                    {
                        return InboundCompletion::error(background.error);
                    }
                    Some(background) => {
                        #[cfg(feature = "server")]
                        if background.message_type
                            == Some(bsv::auth::types::MessageType::General)
                        {
                            let _ = self.deferred_general_count.fetch_update(
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                                |count| count.checked_sub(1),
                            );
                        }
                        tracing::warn!(
                            message_type = ?background.message_type,
                            error = %background.error,
                            "authsocket: unrelated background dispatch failed during certificate processing"
                        );
                    }
                    None => return InboundCompletion::error(AuthError::TransportError(
                        "authsocket background-error observer closed".into(),
                    )),
                },
            }
        }
    }

    fn background_error_completion(
        error: Option<bsv::auth::peer::BackgroundError>,
    ) -> InboundCompletion {
        match error {
            Some(error) => InboundCompletion::error(error.error),
            None => InboundCompletion::error(AuthError::TransportError(
                "authsocket background-error observer closed".into(),
            )),
        }
    }

    fn normalize_outbound(mut message: AuthMessage) -> AuthMessage {
        if message
            .requested_certificates
            .as_ref()
            .is_some_and(bsv::auth::types::RequestedCertificateSet::is_empty)
        {
            message.requested_certificates = None;
        }
        message
    }

    #[cfg(feature = "server")]
    async fn drain_certificates(&self) -> Vec<VerifiedCertificateBatch> {
        if !self.receive_certificates {
            return Vec::new();
        }
        let mut certificates = Vec::new();
        let mut rx = self.certificate_rx.lock().await;
        while let Ok(batch) = rx.try_recv() {
            certificates.push(batch);
        }
        certificates
    }

    #[cfg(all(test, feature = "server"))]
    pub(crate) async fn lock_certificate_io_for_test(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.certificate_io.lock().await
    }
}
