//! Server-side authenticated room core.
//!
//! This is deliberately **Socket.IO-implementation-agnostic**: it owns the
//! per-connection [`PeerHandle`]s and room membership, and turns "emit/broadcast
//! an app event" into a list of signed `AuthMessage`s tagged with the socket id
//! to send them over. The consumer (e.g. `rust-messagebox-server`, using
//! `socketioxide`) wires the actual socket I/O to these calls:
//!
//! - on a new connection: [`AuthSocketServer::add_connection`].
//! - on an inbound `"authMessage"` event: [`AuthSocketServer::on_auth_message`],
//!   then `emit` each returned `AuthMessage` back over that socket and dispatch
//!   the returned verified events to your handlers.
//! - on disconnect: [`AuthSocketServer::remove_connection`].
//! - to push a live message to a room: [`AuthSocketServer::emit_to_room`], then
//!   `emit` each `(socket_id, AuthMessage)` over the matching socket.
//!
//! ## Security invariants
//!
//! - **Identity comes only from the verified sender.** A socket's identity key
//!   is set exclusively from [`VerifiedEvent::sender`] — the general message's
//!   `identity_key` field *after* the bsv-sdk `Peer` verified the signature
//!   against a key derived from that same field. A valid signature therefore
//!   proves the sender holds that key's private half; a forged envelope
//!   `identity_key` fails verification, yields no event, and never owns a room.
//!   The same field on a raw, undriven `AuthMessage` is an unverified claim.
//! - **Per-socket `Peer` isolation is the backbone.** Each connection gets its
//!   own `Peer` + `SessionManager` ([`Self::add_connection`]), so a genuine
//!   signed frame from one socket's session cannot be replayed onto another
//!   (its `your_nonce` resolves no session there). Do NOT consolidate to a
//!   shared `Peer` — the `genuine_general_frame_does_not_replay_onto_another_socket`
//!   test locks this.
//! - **Broadcasts fail closed.** [`AuthSocketServer::emit_to_room`] /
//!   [`AuthSocketServer::emit_to_socket`] sign via
//!   [`PeerHandle::emit_existing`], which requires an existing authenticated
//!   session and never initiates a handshake — an emit can only reach a socket
//!   that completed mutual auth.
//! - **No global lock across crypto.** Connection and room maps are behind
//!   brief `parking_lot::RwLock`s; per-socket handles are `Arc`s cloned out
//!   under the lock, and all Peer work (drive/sign) runs outside any map lock.
//!   Fan-out signs run concurrently (`join_all`), not in a sequential loop.
//!
//! **The fix this replaces:** the old server `broadcast_to_room` did a RAW,
//! unsigned `io.to(room).emit(...)`, which only hit the client's fallback
//! receive path. Here every broadcast is a per-recipient **signed** general
//! message, so it lands on the client's authenticated primary path — instant
//! and authenticated.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bsv::auth::types::AuthMessage;
use bsv::wallet::interfaces::WalletInterface;
use futures_util::future::join_all;
use parking_lot::RwLock;
use serde_json::Value;

use crate::peer_session::{PeerHandle, VerifiedEvent};

/// Result of advancing one socket's protocol on an inbound frame.
pub struct Driven {
    /// `AuthMessage`s to `emit` back over the same socket as `"authMessage"`.
    pub outbound: Vec<AuthMessage>,
    /// Verified app events to dispatch to your handlers. Each carries the
    /// cryptographically verified sender key; the socket's identity has
    /// already been recorded from it before dispatch.
    pub events: Vec<VerifiedEvent>,
}

struct Connection<W: WalletInterface + 'static> {
    handle: PeerHandle<W>,
    /// Set exclusively from a verified general-message sender — never from the
    /// unverified envelope claim.
    identity_key: RwLock<Option<String>>,
}

/// `true` iff `key` has the shape of a compressed secp256k1 pubkey
/// (66 hex chars, `02`/`03` prefix). Defense-in-depth on top of the SDK's
/// signature verification.
fn is_valid_identity_key(key: &str) -> bool {
    key.len() == 66
        && (key.starts_with("02") || key.starts_with("03"))
        && key.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Owns all authenticated connections + room membership for one server.
pub struct AuthSocketServer<W: WalletInterface + 'static> {
    /// socket id -> connection. Brief lock only — handles are cloned out as
    /// `Arc`s and all Peer work happens outside this lock.
    conns: RwLock<HashMap<String, Arc<Connection<W>>>>,
    /// room id -> set of socket ids.
    rooms: RwLock<HashMap<String, HashSet<String>>>,
}

impl<W: WalletInterface + 'static> Default for AuthSocketServer<W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: WalletInterface + 'static> AuthSocketServer<W> {
    pub fn new() -> Self {
        Self {
            conns: RwLock::new(HashMap::new()),
            rooms: RwLock::new(HashMap::new()),
        }
    }

    /// Register a freshly-connected socket with its own BRC-103 session.
    /// `wallet` is the server wallet (e.g. a `ProtoWallet` over the server key).
    pub fn add_connection(&self, socket_id: impl Into<String>, wallet: W) {
        self.conns.write().insert(
            socket_id.into(),
            Arc::new(Connection {
                handle: PeerHandle::new(wallet),
                identity_key: RwLock::new(None),
            }),
        );
    }

    /// Drop a socket and its room memberships.
    pub fn remove_connection(&self, socket_id: &str) {
        self.conns.write().remove(socket_id);
        let mut rooms = self.rooms.write();
        for members in rooms.values_mut() {
            members.remove(socket_id);
        }
        rooms.retain(|_, m| !m.is_empty());
    }

    /// Look up a connection handle (brief lock, `Arc` cloned out).
    fn conn(&self, socket_id: &str) -> Option<Arc<Connection<W>>> {
        self.conns.read().get(socket_id).cloned()
    }

    /// Advance a socket's protocol on an inbound `"authMessage"`.
    ///
    /// Records the socket's identity from the **verified sender** of each
    /// decoded general message (never from the frame's unverified
    /// `identity_key` claim), *before* returning the events for dispatch — so
    /// room-ownership / sender checks in the consumer always see the verified
    /// identity.
    pub async fn on_auth_message(&self, socket_id: &str, msg: AuthMessage) -> Driven {
        let Some(conn) = self.conn(socket_id) else {
            return Driven {
                outbound: vec![],
                events: vec![],
            };
        };
        // Peer work outside any map lock — other sockets proceed concurrently.
        let (outbound, events) = conn.handle.drive(msg).await;
        for ev in &events {
            if is_valid_identity_key(&ev.sender) {
                *conn.identity_key.write() = Some(ev.sender.clone());
            }
        }
        Driven { outbound, events }
    }

    /// This socket's verified identity key, if a verified general message has
    /// established one.
    pub fn identity_key(&self, socket_id: &str) -> Option<String> {
        self.conn(socket_id)
            .and_then(|c| c.identity_key.read().clone())
    }

    pub fn join_room(&self, socket_id: impl Into<String>, room_id: impl Into<String>) {
        self.rooms
            .write()
            .entry(room_id.into())
            .or_default()
            .insert(socket_id.into());
    }

    pub fn leave_room(&self, socket_id: &str, room_id: &str) {
        let mut rooms = self.rooms.write();
        if let Some(members) = rooms.get_mut(room_id) {
            members.remove(socket_id);
            if members.is_empty() {
                rooms.remove(room_id);
            }
        }
    }

    /// Socket ids currently joined to `room_id`.
    pub fn room_members(&self, room_id: &str) -> Vec<String> {
        self.rooms
            .read()
            .get(room_id)
            .map(|m| m.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Sign `event`/`data` for every **authenticated** member of `room_id` and
    /// return `(socket_id, AuthMessage)` pairs to `emit` as `"authMessage"`.
    /// THE signed broadcast — replaces the raw `io.to(room).emit`.
    ///
    /// Fails closed per member: a socket without a verified identity or
    /// without an authenticated session is skipped (`emit_existing` never
    /// initiates a handshake). Signs run concurrently across members — the
    /// signs are independent (distinct sockets), so fan-out is O(sign), not
    /// O(members x sign).
    pub async fn emit_to_room(
        &self,
        room_id: &str,
        event_name: &str,
        data: &Value,
    ) -> Vec<(String, AuthMessage)> {
        let member_ids = self.room_members(room_id);

        // Snapshot (socket id, connection, identity) under brief locks…
        let members: Vec<(String, Arc<Connection<W>>, String)> = {
            let conns = self.conns.read();
            member_ids
                .into_iter()
                .filter_map(|sid| {
                    let conn = conns.get(&sid)?.clone();
                    let key = conn.identity_key.read().clone()?; // not yet authed -> skip
                    Some((sid, conn, key))
                })
                .collect()
        };

        // …then sign for all members concurrently, outside every map lock.
        let signs = members.iter().map(|(sid, conn, key)| async move {
            (sid, conn.handle.emit_existing(key, event_name, data).await)
        });
        let mut out = Vec::new();
        for (sid, result) in join_all(signs).await {
            match result {
                Ok(msgs) => out.extend(msgs.into_iter().map(|m| (sid.clone(), m))),
                Err(e) => tracing::warn!(
                    socket = %sid, room = %room_id, error = %e,
                    "emit_to_room: sign failed (no authenticated session or signer error) — member skipped"
                ),
            }
        }
        out
    }

    /// Sign an app event for a single **authenticated** socket; returns the
    /// `AuthMessage`s to emit. Fails closed like [`Self::emit_to_room`].
    pub async fn emit_to_socket(
        &self,
        socket_id: &str,
        event_name: &str,
        data: &Value,
    ) -> Vec<AuthMessage> {
        let Some(conn) = self.conn(socket_id) else {
            return vec![];
        };
        let Some(key) = conn.identity_key.read().clone() else {
            return vec![];
        };
        match conn.handle.emit_existing(&key, event_name, data).await {
            Ok(msgs) => msgs,
            Err(e) => {
                tracing::debug!(socket = %socket_id, error = %e,
                    "emit_to_socket: no authenticated session, skipping");
                vec![]
            }
        }
    }
}

/// Convenience alias for sharing the server across socketioxide handlers.
pub type SharedAuthSocketServer<W> = Arc<AuthSocketServer<W>>;

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::auth::peer::Peer;
    use bsv::auth::types::{AuthMessage, MessageType};
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use serde_json::json;

    use crate::transport::ChannelTransport;
    use crate::wire::encode_event;

    fn wallet(scalar_hex_byte: u8) -> ProtoWallet {
        let mut hex = String::new();
        for _ in 0..31 {
            hex.push_str("00");
        }
        hex.push_str(&format!("{scalar_hex_byte:02x}"));
        ProtoWallet::new(PrivateKey::from_hex(&hex).expect("test key"))
    }

    /// A client-side Peer wired to raw channels, plus its identity key.
    struct TestClient {
        peer: Arc<Peer<ProtoWallet>>,
        /// Frames the client produced (to hand to the server).
        out_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<AuthMessage>>,
        /// Feed server->client frames here.
        in_tx: tokio::sync::mpsc::Sender<AuthMessage>,
        identity: String,
    }

    async fn test_client(scalar: u8) -> TestClient {
        use bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
        let w = wallet(scalar);
        let identity = w
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
            .to_der_hex();
        let (transport, in_tx, out_rx) = ChannelTransport::new();
        let peer = Arc::new(Peer::new(w, Arc::new(transport)));
        TestClient {
            peer,
            out_rx: tokio::sync::Mutex::new(out_rx),
            in_tx,
            identity,
        }
    }

    /// Complete a full BRC-103 handshake + first general message between a
    /// client Peer and `server` socket `sid`, by pumping frames both ways.
    /// Returns once the client's `send_message` future resolves.
    async fn client_send(
        server: &AuthSocketServer<ProtoWallet>,
        sid: &str,
        client: &TestClient,
        event: &str,
        data: &Value,
    ) {
        let payload = encode_event(event, data);
        let peer = client.peer.clone();
        // send_message("") initiates the handshake and blocks polling the
        // transport until the initialResponse arrives — pump concurrently.
        let send = tokio::spawn(async move { peer.send_message("", payload).await });

        // Pump frames until the send completes AND its frames are drained
        // (send_message enqueues the general frame before resolving, so one
        // more empty try_recv after observing completion is a true quiescence).
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut finished = false;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "handshake pump timed out"
            );
            // client -> server
            let frame = {
                let mut rx = client.out_rx.lock().await;
                rx.try_recv().ok()
            };
            if let Some(frame) = frame {
                let driven = server.on_auth_message(sid, frame).await;
                // server -> client
                for m in driven.outbound {
                    let _ = client.in_tx.send(m).await;
                }
            } else if finished {
                break;
            } else {
                finished = send.is_finished();
                if !finished {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
        }
        send.await.expect("send task").expect("client send_message");
    }

    #[tokio::test]
    async fn verified_sender_sets_identity() {
        let server = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        let client = test_client(0x22).await;

        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;

        assert_eq!(
            server.identity_key("sock1").as_deref(),
            Some(client.identity.as_str()),
            "identity must be the cryptographically verified sender"
        );
    }

    /// A1a: a general message whose envelope `identity_key` is forged (differs
    /// from the actual signer) must NOT set the room identity — the signature
    /// does not verify under the forged key, so the frame yields no event and
    /// no identity.
    #[tokio::test]
    async fn forged_envelope_identity_does_not_own_the_socket() {
        let server = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        let client = test_client(0x22).await;
        // The victim key the attacker claims to be.
        let victim = test_client(0x33).await;
        assert_ne!(client.identity, victim.identity);

        let payload = encode_event("authenticated", &json!({}));
        let peer = client.peer.clone();
        let send = tokio::spawn(async move { peer.send_message("", payload).await });

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_general = false;
        let mut finished = false;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "handshake pump timed out"
            );
            let frame = {
                let mut rx = client.out_rx.lock().await;
                rx.try_recv().ok()
            };
            if let Some(mut frame) = frame {
                let is_general = frame.message_type == MessageType::General;
                if is_general {
                    // Forge the unverified envelope claim.
                    frame.identity_key = victim.identity.clone();
                    saw_general = true;
                }
                let driven = server.on_auth_message("sock1", frame).await;
                if is_general {
                    assert!(
                        driven.events.is_empty(),
                        "forged general message must not verify into an event"
                    );
                }
                for m in driven.outbound {
                    let _ = client.in_tx.send(m).await;
                }
            } else if finished {
                break;
            } else {
                finished = send.is_finished();
                if !finished {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
        }
        let _ = send.await.expect("send task"); // client-side send may report success
        assert!(saw_general, "test must exercise the forged general frame");

        // The forged claim must not have become the socket identity.
        assert_ne!(
            server.identity_key("sock1").as_deref(),
            Some(victim.identity.as_str()),
            "A1a: forged envelope identity_key must never own the socket"
        );
        assert_eq!(
            server.identity_key("sock1"),
            None,
            "no verified general message -> no identity at all"
        );
    }

    /// A1b: an emit/broadcast to a socket that has not completed mutual auth
    /// must produce nothing — and must NOT initiate a handshake toward it.
    #[tokio::test]
    async fn emit_to_unauthenticated_socket_fails_closed() {
        let server = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        // Socket joined a room but never authenticated.
        server.join_room("sock1", "roomA");

        let msgs = server
            .emit_to_room("roomA", "sendMessage-roomA", &json!({"x": 1}))
            .await;
        assert!(
            msgs.is_empty(),
            "no signed frames for unauthenticated members"
        );

        let msgs = server.emit_to_socket("sock1", "hello", &json!({})).await;
        assert!(
            msgs.is_empty(),
            "no signed frames for unauthenticated socket"
        );

        // Crucially: nothing was queued toward the socket — no handshake was
        // initiated by the broadcast path (send_message would have produced an
        // initialRequest on the outbound channel).
        let conn = server.conn("sock1").expect("conn");
        assert!(
            conn.handle.drain_outbound().await.is_empty(),
            "A1b: broadcast must never initiate a handshake"
        );
    }

    /// A1a backbone — per-socket `Peer`/`SessionManager` isolation. A genuine,
    /// fully-signed general frame captured from one socket's completed handshake
    /// must NOT verify when replayed onto a *different* socket: its `your_nonce`
    /// names a session that lives only in the origin socket's independent
    /// `Peer`, so the replay resolves no session and yields no event/identity.
    /// This is the invariant the forged-envelope test does not exercise, and the
    /// one a future consolidation to a shared `Peer` (e.g. for per-server memory
    /// at scale) would silently break — this test fails if that ever happens.
    #[tokio::test]
    async fn genuine_general_frame_does_not_replay_onto_another_socket() {
        let server = AuthSocketServer::new();
        // Same server key on both sockets — only the per-socket Peer/session
        // isolation (not a key difference) stops the replay.
        server.add_connection("sockA", wallet(0x11));
        server.add_connection("sockB", wallet(0x11));
        let client = test_client(0x22).await;

        // Drive the client's handshake against sockA, capturing the signed
        // General frame it emits after the handshake completes.
        let payload = encode_event("authenticated", &json!({}));
        let peer = client.peer.clone();
        let send = tokio::spawn(async move { peer.send_message("", payload).await });

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut captured_general: Option<AuthMessage> = None;
        let mut finished = false;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "handshake pump timed out"
            );
            let frame = {
                let mut rx = client.out_rx.lock().await;
                rx.try_recv().ok()
            };
            if let Some(frame) = frame {
                if frame.message_type == MessageType::General {
                    captured_general = Some(frame.clone());
                }
                let driven = server.on_auth_message("sockA", frame).await;
                for m in driven.outbound {
                    let _ = client.in_tx.send(m).await;
                }
            } else if finished {
                break;
            } else {
                finished = send.is_finished();
                if !finished {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
        }
        let _ = send.await.expect("send task");

        let general = captured_general.expect("must capture a signed general frame");
        // Sanity: on its origin socket the frame genuinely established identity.
        assert_eq!(
            server.identity_key("sockA").as_deref(),
            Some(client.identity.as_str()),
            "the captured frame is a genuine, identity-establishing general message"
        );

        // Replay the exact signed frame onto sockB's independent Peer/session.
        let driven = server.on_auth_message("sockB", general).await;
        assert!(
            driven.events.is_empty(),
            "cross-socket replay must not verify into an event"
        );
        assert_eq!(
            server.identity_key("sockB"),
            None,
            "A1a backbone: a frame from another socket's session owns nothing here"
        );
    }

    /// A1b (positive): after real mutual auth, emit_to_room signs exactly one
    /// frame for the member, bound to its verified identity.
    #[tokio::test]
    async fn emit_to_authenticated_room_member_signs() {
        let server = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        let client = test_client(0x22).await;

        client_send(&server, "sock1", &client, "authenticated", &json!({})).await;
        server.join_room("sock1", "roomA");

        let msgs = server
            .emit_to_room("roomA", "sendMessage-roomA", &json!({"x": 1}))
            .await;
        assert_eq!(msgs.len(), 1, "one signed frame for the authed member");
        assert_eq!(msgs[0].0, "sock1");
        assert_eq!(msgs[0].1.message_type, MessageType::General);
        assert!(msgs[0].1.signature.is_some(), "broadcast frame is signed");
    }

    #[tokio::test]
    async fn room_membership_lifecycle() {
        let server: AuthSocketServer<ProtoWallet> = AuthSocketServer::new();
        server.add_connection("sock1", wallet(0x11));
        server.add_connection("sock2", wallet(0x11));

        server.join_room("sock1", "room");
        server.join_room("sock2", "room");
        let mut members = server.room_members("room");
        members.sort();
        assert_eq!(members, vec!["sock1".to_string(), "sock2".to_string()]);

        server.leave_room("sock1", "room");
        assert_eq!(server.room_members("room"), vec!["sock2".to_string()]);

        // Disconnect clears membership + connection.
        server.remove_connection("sock2");
        assert!(server.room_members("room").is_empty());
        assert!(server.conn("sock2").is_none());
    }

    #[test]
    fn identity_key_shape_check() {
        let good = format!("02{}", "a".repeat(64));
        assert!(is_valid_identity_key(&good));
        assert!(!is_valid_identity_key(""));
        assert!(!is_valid_identity_key("02abc"));
        assert!(!is_valid_identity_key(&format!("04{}", "a".repeat(64))));
        assert!(!is_valid_identity_key(&format!("02{}", "g".repeat(64))));
    }
}
