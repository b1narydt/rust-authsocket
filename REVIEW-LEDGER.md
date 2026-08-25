# Review Ledger

Deferred findings from the verified-event pump review. Line references describe
the post-fix source in this branch.

## Open

- **C-2 — Sev-3 — deferred-event ordering** (`src/server.rs:529-530`,
  `src/server.rs:848`, `src/server.rs:1160-1178`): the certificate task and the
  pump can invoke the same sink concurrently. After authorization becomes
  `Accepted` but before the released batch reaches the sink, a newly admitted
  event can dispatch first. This can expose `joinedRoom` before an earlier
  `authenticationSuccess`.
- **C-4 — Sev-3 — empty-batch guard is narrower than authorizer mode**
  (`src/server.rs:460-462`, `src/server.rs:1088-1095`): the empty-certificate
  rejection is conditional on `sdk_certificate_gate`, so an authorizer configured
  without `set_certificates_to_request` still receives an empty verified batch.
- **C-5 — Sev-4 — SDK-error fast-fail removed** (`src/server.rs:732-744`): the
  parent implementation's authorization fast-fail after an SDK-rejected
  `certificateResponse` is absent. The authorization deadline still bounds the
  pending state.
- **C-6 — Sev-4 — post-frame rejection re-check removed**
  (`src/server_io.rs:187-203`): the adapter feeds an inbound frame without the
  parent implementation's immediate post-frame certificate-rejection re-check.
  The authorization deadline still bounds the pending state.
- **B-4 — Sev-4 — closed-channel exit drops buffered frames**
  (`src/server.rs:822-825`): `Receiver::is_closed()` does not mean its buffer is
  empty, so the pump can exit without draining frames already queued before the
  senders closed. The misleading inline comment reported against `bcb6b3b` was
  removed by `ec5f50b`; the buffered-frame behavior remains.
- **B-6 — Sev-4 — asymmetric receiver take** (`src/peer_session.rs:232-235`):
  `outgoing` is taken before `general`; if the latter were unexpectedly `None`,
  the outgoing receiver would be dropped and the transport permanently closed.
  This is unreachable under current construction but is a trap for future edits.
- **E-4 — Sev-4 — feed-only tests overstate what they prove**
  (`src/server.rs:2141-2160`, `src/server.rs:2163-2182`):
  `default_server_drains_unsolicited_verified_certificate_batches` and
  `late_certificate_listener_does_not_wedge_response_processing` only establish
  that feed-only `on_auth_message` calls remain bounded; neither test observes a
  drain or completed response processing.

## Closed in this round

- **C-3 — Sev-3 — deferred-batch truncation** (`src/server.rs:512-537`): closed
  as a consequence of FIX 1. The SDK listener now only spawns the authorization
  task and returns. Authorization and the full released-batch sink future run
  outside the SDK's 30-second listener deadline, so that deadline can no longer
  cancel the loop partway through the batch.
