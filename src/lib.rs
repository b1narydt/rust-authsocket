//! # authsocket
//!
//! BRC-103 mutually-authenticated Socket.IO for Rust — a faithful port of the
//! TypeScript `@bsv` `authsocket` (server) and `authsocket-client` packages.
//!
//! ## Why this crate exists
//!
//! The Rust MessageBox server and client each hand-rolled their own glue between
//! Socket.IO and a bsv-sdk BRC-103 [`Peer`](bsv::auth::peer::Peer). That glue
//! drifted: the **server broadcasts live room messages as RAW, unsigned
//! Socket.IO events**, which only reach the client's *fallback* receive path —
//! so live push is unreliable and delivery falls back to a slow ~2s HTTP poll.
//! This crate provides one shared, authenticated abstraction both sides use, so
//! every application event — including room broadcasts — is signed and verified
//! through the Peer and arrives on the client's *primary* path: instant **and**
//! authenticated.
//!
//! ## The contract (matches the TS stack byte-for-byte)
//!
//! - One Socket.IO event, [`wire::AUTH_MESSAGE_EVENT`] (`"authMessage"`), carries
//!   every BRC-103 `AuthMessage`.
//! - Application events are `{"eventName","data"}` JSON → UTF-8 bytes → the
//!   `payload` of a signed BRC-103 *general* message. There is **no** per-room or
//!   per-event Socket.IO event; the event name lives inside the signed payload.
//! - Rooms are `{identityKey}-{messageBox}`; a listener joins its OWN key, a
//!   sender targets the RECIPIENT's key.
//!
//! ## Layout
//!
//! - [`wire`] / [`transport`] / [`peer_session`] — transport-agnostic core
//!   (always built).
//! - `server` + `server_io` (feature `server`) — [`AuthSocketServer`] (the
//!   Socket.IO-agnostic room core) and the `socketioxide` adapter
//!   ([`server_io::attach`], [`server_io::emit_signed_to_room`]).
//! - `client` (feature `client`, over `rust_socketio`) — [`AuthSocketClient`]
//!   and [`client::SocketIOTransport`].
//!
//! A consumer normally enables exactly one of `server` / `client` (the crate's
//! own e2e tests enable both).

pub mod peer_session;
pub mod transport;
pub mod wire;

/// The exact bsv-sdk crate version used by authsocket, re-exported so consumers
/// can name the types appearing in this crate's public API without adding a
/// potentially divergent direct dependency.
pub use bsv;
pub use peer_session::{PeerHandle, VerifiedEvent};

/// The client's liveness cadence, exposed so a consumer can size its own
/// timeouts from the real value instead of a magic number that silently rots
/// when the cadence changes. `KEEPALIVE_INTERVAL` is how often an idle client
/// proves it is alive; `READ_DEADLINE` is how long a peer may be silent before
/// the watchdog declares it dead.
#[cfg(feature = "client")]
pub use client::{
    AuthSocketClientOptions, AUTHENTICATION_SUCCESS_TIMEOUT, KEEPALIVE_INTERVAL, READ_DEADLINE,
};
pub use wire::{room_id, split_room_id, AUTH_MESSAGE_EVENT};

#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod server_io;
#[cfg(feature = "server")]
pub use server::{
    AuthSocketServer, CertificateAuthorization, CertificateAuthorizationDecision,
    OnCertificatesRequested, SharedAuthSocketServer,
};
#[cfg(feature = "server")]
pub use server_io::{
    attach, emit_signed_to_room, emit_signed_to_socket, send_certificate_response, AppDispatcher,
};

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub use client::{AuthSocketClient, CertificateProvider, SocketIOTransport};
