# Platform HTTP API (cloud service)

This reference is for developers implementing a Platform HTTP client or debugging interoperability. It describes the server's `/api/v1/` endpoints. For normal agent integration, use the [Agent Comm SDK and local helper](../../agent-comm/docs/README.md). The helper also has `/api/v1/mq/...` paths, but it is a **different, local API** with different request bodies and authentication. [中文版](API.md).

This is a hand-maintained description of the current implementation, not a generated OpenAPI specification. Use the HTTPS base URL of your deployment, such as `https://agent-communication.online`. See [security configuration](SECURITY.md).

## Endpoints

| Method and path | Purpose | Authentication |
| --- | --- | --- |
| `GET /healthz` | Liveness | None |
| `GET /api/v1/bootstrap` | Platform Peer ID and storage policy | None |
| `GET /api/v1/status` | Registry URN count | None |
| `POST /api/v1/registry/register` | Register or renew a URN | Ed25519 body signature plus record signature in JSON |
| `GET /api/v1/registry/resolve?urn=...` | Resolve a URN | None |
| `GET /api/v1/registry/list` | List valid URNs | None |
| `POST /api/v1/mq/store` | Store a signed encrypted envelope | Ed25519 body signature |
| `GET /api/v1/mq/retrieve` | Fetch a batch of unread envelopes | Recipient read signature headers |
| `GET /api/v1/mq/subscribe` | SSE notification stream | Recipient read signature headers |
| `POST /api/v1/mq/ack` | Mark messages as read | Ed25519 body signature |

The libp2p Registry, Relay and MQ protocols are separate from these HTTP endpoints. Admin endpoints are listed below.

## Authentication and signatures

For `register`, `store` and `ack`, sign the **exact UTF-8 JSON body bytes being sent** with the caller's Ed25519 private key. Send `Content-Type: application/json` and:

```http
Authorization: Ed25519 <64-byte signature as hex>:<32-byte public key as hex>
```

Changing JSON whitespace or field order after signing invalidates the signature. The middleware caps signed request bodies at 20 MiB; MQ envelopes have a lower size limit. The HTTP signing key must match the registered `ed25519_pubkey`, the envelope `sender_urn`, or the ACK `recipient_urn`, respectively.

`register` also carries a **separate record signature** in its JSON `signature` field. To construct it, sign `UTF-8(urn + "|" + peer_id + "|" + hex(x25519_pubkey) + "|" + (stores_user_data ? "1" : "0") + "|")` followed by the `timestamp` as an **8-byte big-endian** integer. Use the same Ed25519 identity key. The SDK implements this in [`registry.BuildSignedMsg`](../../agent-comm/registry/client.go). Address hints are not covered by that record signature; still verify peer identity when connecting.

For `retrieve` and `subscribe`, send `X-URN` (recipient URN), `X-Timestamp` (decimal Unix seconds), `X-Pubkey` (recipient Ed25519 public key as hex), and `X-Signature` (signature as hex). Sign `UTF-8("mq-retrieve|" + urn + "|")` followed by the timestamp as **8 big-endian bytes**. Both endpoints use this same prefix. The key must match the recipient URN. Timestamps must be no older than 300 seconds and no more than 60 seconds in the future. See the [SDK HTTP MQ client](../../agent-comm/mq/client.go).

## Registry

### `POST /api/v1/registry/register`

The JSON body has `urn` (self-certifying identity URN), `peer_id` (canonical libp2p Peer ID derived from the same Ed25519 key), `addrs` and `relay_addrs` (arrays of address hints), `x25519_pubkey` (32 bytes), `ed25519_pubkey` (32 bytes), `stores_user_data` (boolean), `timestamp` (Unix seconds), and `signature` (64-byte record signature). Go `[]byte` JSON fields are **base64 strings**. Each address list accepts at most 64 entries, each at most 2048 bytes. The URN fingerprint, Peer ID and HTTP signing key must match the identity key. Timestamp window: past 300 seconds through future 60 seconds.

Success: `200 {"ok":true}`. Missing signature/key/timestamp or mismatched HTTP signing key: `401`. Invalid record, stale timestamp, address limits or registration older than an existing valid record: `400`. A fresh valid registration renews the lease. Registry TTL is deployment-configured (default 24 hours).

### `GET /api/v1/registry/resolve?urn=<URL-encoded URN>`

`200` returns `found:true`, `urn`, `peer_id`, `addrs`, `relay_addrs`, both public keys, `signature`, `timestamp`, `stores_user_data`, and `expires_at`. Binary fields are base64; `expires_at` is a **decimal Unix-seconds string**. Missing/expired/invalid records: `404 {"found":false}`. Missing `urn`: `400`. Forwarding security policy may return `403`. Clients should verify the resolved record signature again.

### `GET /api/v1/registry/list`

Returns `200 {"urns":["..."],"count":1}` containing only unexpired, authenticated records; storage errors may yield `500`.

## MQ (cloud encrypted mailbox)

Platform stores serialized SDK protobuf `EncryptedEnvelope` bytes. The envelope contains sender and recipient URNs, message ID, ciphertext and its own signature. Build and verify it with the matching SDK; the local helper's plaintext `text` body cannot be posted directly to Platform. Platform verifies signatures and identities but does not decrypt the business payload.

### `POST /api/v1/mq/store`

```json
{"recipient_urn":"<URN>","expiry_unix":0,"payload_proto":"<base64 protobuf EncryptedEnvelope>"}
```

`expiry_unix` is Unix seconds; `0` selects the configured default TTL (default 7 days). A later expiry is capped at that TTL; negative or expired times are rejected. Envelope limit: 1 MiB; message ID limit: 256 bytes. `200 {"ok":true,"message_id":"..."}` means **stored**, not read, ACKed or processed by the recipient. The HTTP signing key must match the envelope sender; envelope signature and recipient must also validate.

Storage disabled: `400`; blocked recipient by forwarding policy: `403`; sender key mismatch: `401`; invalid envelope/expiry: `400`. A full unread mailbox returns `429` and `Retry-After: 5` (default 500 messages per URN). HTTP rate limiting may also return `429`. Retrying the same ID, recipient and envelope is idempotent while that database row exists; reusing an ID for different content conflicts.

### `GET /api/v1/mq/retrieve`

Send the recipient read signature headers. `200` returns `{"messages":[{"message_id":"...","payload_proto":"<base64 protobuf EncryptedEnvelope>"}],"count":1}`. A batch contains at most 500 unread messages and about 4 MiB of serialized data. **Retrieval does not delete or acknowledge messages**. Process them, call `ack`, then retrieve the next batch. Empty mailbox: `{"messages":[],"count":0}`. Missing `X-URN`: `400`; missing/invalid signature: `401`; storage errors may yield `400`/`500`.

### `GET /api/v1/mq/subscribe`

Uses the same read signature headers. A successful response is `text/event-stream`; each new envelope arrives as `data: {"message_id":"...","payload_proto":"<base64 ...>"}`. Comment frames open the stream and keep it alive at roughly 30-second intervals. Notifications can be missed by a slow client; use `retrieve` and explicit `ack` for durable processing. Limits: 4 subscriptions per URN, 1024 in total; exceeding them returns `429` with `Retry-After: 5`.

### `POST /api/v1/mq/ack`

```json
{"recipient_urn":"<recipient URN>","timestamp":1730000000,"message_ids":["<message ID>"]}
```

Sign the exact JSON body as described above. Timestamp window: past 300 seconds through future 60 seconds. At most 1000 IDs per request. `200 {"ok":true,"deleted":N}` uses the historical field name `deleted`: **N is the number newly marked read**, not physically removed. The database sets `read_at` and later cleans up according to expiry/history retention (default 30 days). Repeated ACKs do not increment the count. Recipient/signing key mismatch: `401`; invalid ID list: `400`.

## Admin API

Every `/api/v1/admin/...` request requires `X-Admin-Token: <configured token>`. An unconfigured token returns `403`; an absent/wrong token returns `401`. Responses set `Cache-Control: no-store`. Restrict this API to trusted networks and never pass the token in a URL. See [security configuration](SECURITY.md).

| Method and path | Parameters | Result/effect |
| --- | --- | --- |
| `GET /api/v1/admin/overview` | None | Runtime, memory, connections, Registry/MQ and policies; `restart_pending` reports an admin-settings restart yet to complete, while `registry_ttl_hours` and `mq_max_msgs_per_urn` expose configured capacities |
| `GET /api/v1/admin/registry` | None | `entries`, `count` |
| `DELETE /api/v1/admin/registry` | Required `urn` query | Remove a registration; `{"ok":true}` |
| `GET /api/v1/admin/mq` | None | Unread `queues`, `count` |
| `GET /api/v1/admin/mq/summary` | None | `pending`, `history`, and `expired` with `messages`, `bytes`, and `queues`; disjoint groups, with `expired` meaning unread and expired |
| `GET /api/v1/admin/mq/messages/page` | Required `urn`; `status` is `pending` (default) or `history`; `limit` 1–200 (default 25); `offset` 0–1000000 (default 0) | `{entries,total,limit,offset}`; metadata only, no ciphertext payload; invalid parameters return `400` |
| `GET /api/v1/admin/mq/messages/detail` | Required `urn` and `id` | One mailbox-scoped message with metadata and hex-encoded ciphertext `payload`; missing from that mailbox returns `404` |
| `GET /api/v1/admin/mq/messages` | Required `urn`; `status` is `pending` or `history` | Legacy details array capped at 100 rows and a 2 MiB stored-envelope payload budget; other status values default to pending; new clients should use the paged endpoint |
| `DELETE /api/v1/admin/mq/messages` | Required `urn` and `id` | Remove only the matching message from that mailbox; `{ok:true,deleted:0 or 1}` is safe to repeat and actual deletion is audited |
| `DELETE /api/v1/admin/mq/clear` | Required `urn` | Remove both pending and read-history messages for a recipient; `deleted` count |
| `GET /api/v1/admin/config` | None | Config with admin token redacted as `******` |
| `GET /api/v1/admin/config/editable` | None | Six effective editable resource settings, `revision`, `restart_pending`, and `fields` metadata (type, bounds, restart requirement, and impact descriptions) |
| `POST /api/v1/admin/config/editable/preview` | JSON `{ "expected_revision": "...", "changes": {"mq.max_msgs_per_urn": 1000} }` | Read-only preview of current and target values, impact descriptions, current `affected` counts, `restart_required`, a `confirmation_token`, and its Unix-seconds `confirmation_expires_at`; restart is required only when values change |
| `PUT /api/v1/admin/config/editable` | JSON `{ "expected_revision": "...", "changes": {...}, "confirmation_token": "..." }` | Apply changed previewed settings and restart; returns `ok`, `changed`, `restart_pending`, and `settings`; a no-op still requires preview and confirmation but does not restart |
| `PUT /api/v1/admin/config/storage` | JSON `{ "store_user_data": true or false }` | Set an exact storage policy; unchanged value returns `changed:false`, a change clears Registry and restarts; response includes `restart_pending` |
| `POST /api/v1/admin/config/toggle-storage` | None | Toggle storage, clear Registry and restart Platform |
| `PUT /api/v1/admin/config/forwarding` | JSON `{ "forward_to_storage_platforms": true or false }` | Set an exact forwarding policy; response includes `changed`; changes take effect immediately and persist |
| `POST /api/v1/admin/config/toggle-forwarding` | None | Legacy toggle of forwarding policy; changes take effect immediately and persist |
| `POST /api/v1/admin/config/set-retention` | Integer `days` from 0 to 36500 | Set read-history retention days; `0` removes history on the next cleanup |
| `GET /api/v1/admin/peers` | None | Connected non-Registry peers; no remote storage-policy claim |
| `GET /api/v1/admin/logs` | Optional `limit` (1–500, default 100), `offset` (non-negative, default 0), `level`, `source`, `search` | `entries`, `total`, `limit`, `offset`; search matches message text |

Storage policy changes, message or queue deletion, and Registry eviction change live state; follow the [deployment and backup guide](DEPLOYMENT.md). The three managed policies `store_user_data`, `forward_to_storage_platforms`, and `history_retention_days` are atomically written to `platform.data_dir/admin-policies.yaml` and override those fields from the main config on restart; old override files without forwarding preserve the main config value. A failed write returns `500` and leaves the live policy unchanged. During a pending storage-policy restart, further storage policy or `set-retention` requests return `409` with `restart_pending:true`; forwarding may be updated independently without clearing the pending marker.

The resource editor accepts only the six settings below. The ranges constrain **new admin-submitted values**; an older base config outside these ranges is not rewritten merely by upgrading. For example, an existing `mq.max_msgs_per_urn: 0` keeps its legacy behavior, but the editor cannot submit `0` as a new target. The six settings take effect after restart. Editing them does not delete existing messages, registrations, or platform identity. The restart briefly disconnects peers; disabling Relay also affects NAT connectivity and existing relayed sessions.

| Setting key | Allowed value | Effect |
| --- | --- | --- |
| `registry.ttl_hours` | Integer 1–8760 | TTL for future registrations and renewals; existing expiry timestamps remain unchanged |
| `mq.default_ttl_days` | Integer 1–3650 | Default and maximum TTL for future messages; existing expiry timestamps remain unchanged |
| `mq.max_msgs_per_urn` | Integer 1–100000 | Unread mailbox limit checked on future writes; lowering it does not delete existing messages |
| `relay.enabled` | Boolean | Start or stop Relay; disabling it can disrupt connections relayed through this platform |
| `relay.max_reservations` | Integer 1–100000 | Relay reservation capacity |
| `relay.max_circuit_duration` | Go duration string from 10 seconds to 24 hours, e.g. `"2m"` | Per-circuit Relay duration limit |

The `revision` from `GET /config/editable` identifies the six settings loaded by the current process. Direct edits to the main config or override file are reflected only after restart. Read the revision, call `preview`, review its `changes` and `affected` snapshot (`registry_entries`, `mq_queues`, `mq_messages`, `connected_peers`, `mq_queues_at_or_above_target_limit`), then submit the same `changes` key set, target values, and `confirmation_token` before `confirmation_expires_at`. The server-issued token binds the current revision, target settings, requested key set, and expiry; it expires after five minutes, so preview again when it expires. Unchanged fields are not written as new overrides. Counts can change after the preview. A stale revision returns `409`; a missing, mismatched, or expired confirmation token returns `400`. Preview and apply return `409` with `restart_pending:true` while a restart is pending. The six settings and three managed policies share `admin-policies.yaml`, leaving the main config read-only. `platform.mode` is a display label; `libp2p.external_addrs`, `registry.http_enabled`, and `mq.http_enabled` currently have no runtime effect. Identity, data paths, listeners, TLS, the admin token, proxy trust, and HTTP rate limits remain server-managed.

## Common responses and troubleshooting

`GET /healthz`: `200 {"status":"ok"}`. `GET /api/v1/bootstrap`: `peer_id` and `stores_user_data`. `GET /api/v1/status`: `registry_urns`. These endpoints do not prove end-to-end agent message delivery.

Check HTTP status first: `400` invalid request/message, `401` invalid signature or admin token, `403` security policy/disabled admin, `404` Registry miss, `429` capacity or rate limit, `500` server error. **Error bodies vary** between `{"error":"..."}` and plain text from `http.Error`; do not assume all errors are JSON. Wrong methods usually return `405`. If time-based signatures fail, compare client and server clocks.

More details: [Registry ownership](../architecture/REGISTRY_SECURITY.md) · [MQ protocol upgrade](MESSAGE_UPGRADE.md) · [code structure](../architecture/OVERVIEW.md).
