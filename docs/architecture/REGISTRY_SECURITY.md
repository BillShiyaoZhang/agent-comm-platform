# Registry ownership and upgrade notes

Registration requires proof from the owner of the claimed URN on every insert,
update, and renewal. Both the SQLite store and the SDK in-memory store use the
SDK's `registry.ValidateRegistration`; the libp2p handler also validates before
calling a custom store. HTTP retains its signed-request authentication and calls
the same SQLite write boundary.

The proof must contain a 32-byte Ed25519 public key, a 32-byte X25519 public key,
a 64-byte Ed25519 record signature, and a positive Unix timestamp within five
minutes in the past or one minute in the future. The URN fingerprint must match
the Ed25519 key (including custom namespaces), and the PeerID must be derived
from that key and use the canonical `peer.ID.String()` encoding. The signature
uses the existing `registry.BuildSignedMsg` format:
URN, PeerID, X25519 key, storage policy, and timestamp. Failed validation occurs
before any row, address, expiry, or update timestamp changes. Re-publishing a
valid owner-signed record within the admission window is allowed and renews its
lease; the window is not a monotonic-update or one-use nonce guarantee.

## Migrating callers

Unsigned `Store.Register`, libp2p `Client.Register`, and `HandleRegister` entry
points reject registration. Use `RegisterWithSignature` and sign
`registry.BuildSignedMsg` with the URN owner's private key. `HandleRegister` now
returns an error; implementations or interfaces using its old method signature
must be updated. HTTP `HTTPClient.Register` already signs its requests and
continues to work when its URN and PeerID correspond to the supplied identity.
Platform self-registration and renewal produce fresh owner signatures.

libp2p permits another peer to publish a valid owner-signed record; the transport
peer need not equal the owner. The publisher's own signature never authorizes
another identity's URN. HTTP additionally requires the Authorization key to equal
the owner key in the record. The existing record signature does not cover address
or relay-address lists, so P2P publication does not prove owner approval of those
lists. Keep libp2p peer identity verification enabled when connecting. This change
does not introduce a general delegation or address-attestation format.

## Existing database records

Back up the Registry SQLite database using the normal deployment backup process
before upgrading. Do not clear the Registry to work around legacy records.

`ResolveEntry`, `Resolve`, `ResolveExtended`, `ListURNs`, and `ListEntries` verify
stored ownership and signature data. Invalid or unsigned rows are logically
quarantined: they are omitted from responses and logged with
`[registry] quarantined unauthenticated record`, the quoted URN, and a reason.
The read does not mutate or delete the original row, which remains available for
database inspection until ordinary expiry cleanup or an authorized update.
Retain application logs and the database backup for an audit record. Listing the
Registry after upgrade checks all currently unexpired entries.

The owner can restore an affected URN by submitting a fresh valid registration.
Recovery uses cryptographic ownership, never the key already stored in the row,
so previous poisoning or squatting cannot lock out the actual owner. Valid
records remain resolvable until their TTL expires even when their signed
timestamp is older than the registration freshness window.

For first contact on one Platform, a client can use an exact URN to resolve and
verify its Ed25519 key, derived PeerID, signed X25519 key, and record. That
establishes cryptographic control of the URN, not who the agent represents in
the real world. The Platform does not accept or reject friend requests, assign
contact trust, or grant collaboration authority; those decisions remain with
the agents and their owners. Cross-Platform discovery and routing are not
provided by this Registry.

## Verification

Run `go test ./...` in this repository and separately in its `agent-comm` SDK
submodule. Registry regressions exercise real loopback HTTP and libp2p handlers
and direct stores, with both first-registration and overwrite attempts, unchanged
database snapshots on rejection, custom namespaces, owner recovery, and message
preparation after a rejected overwrite. SDK tests retain rejection of poisoned
recipient records supplied by a deliberately malicious test registry.
