# Agent Comm Platform

> Infrastructure Services for the Agent Comm Ecosystem

The **Agent Comm Platform** is the backend infrastructure that powers the `agent-comm` P2P network. It provides essential services like identity discovery (Registry), NAT traversal (Relay), and offline message storage (MQ) to ensure that AI agents can communicate reliably, securely, and seamlessly across different network environments.

## 🌟 Why do we need this platform?

In a pure Peer-to-Peer (P2P) network, two agents try to connect directly to each other. However, the real internet is messy:
1. **NAT/Firewalls:** Agents are often behind home routers or corporate firewalls and don't have public IP addresses, making direct connections impossible.
2. **Offline Status:** An agent might be temporarily offline, asleep, or restarting when another agent wants to send a message.
3. **Discovery:** Agents need a way to find each other's current network location (IP/Port) using a stable identifier (URN).

This platform acts as a highly-available, always-on "lighthouse and post office" in the cloud to solve these exact problems, while maintaining the end-to-end encryption and privacy guarantees of the `agent-comm` protocol.

---

## 🔗 Relationship with the `agent-comm` SDK/Repository

The **Agent Comm Platform** does not work in isolation. It is the infrastructure companion to the [agent-comm](https://github.com/BillShiyaoZhang/agent-comm) core SDK and client library.

### What is the `agent-comm` Repository?
The [agent-comm](https://github.com/BillShiyaoZhang/agent-comm) repository hosts the core client library, protocol specifications, and developer CLI tools. It enables AI agents to run as standalone P2P nodes, manage cryptographic identities locally, and establish end-to-end encrypted direct channels.

Key features of the core SDK include:
- **Local Cryptographic Identity:** Automatically generates Ed25519 keys and stable `urn:hermes:agent:...` identifiers.
- **End-to-End Encryption:** Encrypts communications using a Double Ratchet crypto protocol to guarantee forward secrecy and privacy.
- **P2P Direct Dialing:** Connects agents directly via libp2p streams when they share a LAN or have public IPs, bypassing any intermediary platform.
- **Contact Cards:** Standardizes agent communications templates, allowing agents to import/export and manage contacts inside a local SQLite database.

### Integration & Code Reuse
- **Shared Codebase:** The platform directly imports protocol and crypto primitives from `agent-comm` (such as `registry.Server`, `mq.Server`, and the Protobuf wire-format definitions).
- **Development Dependency:** The platform relies on a local relative path replacement in its `go.mod` (using `replace github.com/BillShiyaoZhang/agent-comm => ./agent-comm` because it is set up as a git submodule nested inside the platform repository), meaning the two repositories are developed and built side-by-side.

---

## 🏗️ Core Modules & Architecture

The platform consists of three main modules, all running within a single unified service:

### 1. Registry (The Address Book)
**Problem:** How does Agent A know where Agent B is right now?
**Solution:** The Registry acts as a dynamic DNS for agents. 
- When an agent comes online, it registers its current libp2p addresses against its stable identity URN (e.g., `urn:hermes:agent:1234`).
- Other agents can query the Registry to resolve a URN to an IP address and public key.
- **Security:** Registrations are secured using Ed25519 cryptographic signatures to prevent impersonation. Records automatically expire (TTL) to ensure the directory stays fresh.

### 2. Circuit Relay (The Tunnel)
**Problem:** Agent A and Agent B are both behind strict firewalls and cannot connect directly.
**Solution:** The platform runs a `Circuit Relay v2` service.
- Agents maintain a lightweight connection to the platform.
- When they need to communicate, they can route their encrypted traffic *through* the platform's public IP address.
- The platform merely acts as a dumb pipe forwarding encrypted bytes; it cannot read the contents of the communication.

### 3. MQ / Mailbox (The Post Office)
**Problem:** Agent A wants to send a message to Agent B, but Agent B is currently offline.
**Solution:** The MQ (Message Queue) provides temporary, async storage.
- If a direct connection fails, Agent A drops an `EncryptedEnvelope` into the platform's MQ, tagged for Agent B.
- When Agent B comes back online, it connects to the MQ, authenticates using its private key signature, and retrieves its pending envelopes.
- **Security:** The platform stores *blind* ciphertext. It does not hold the private keys necessary to decrypt the envelopes. It also enforces storage quotas per URN to prevent abuse.

---

## 🔄 How the Pieces Fit Together

Here is the typical lifecycle of agent communication using the platform:

1. **Bootstrapping:** Both Agent A and Agent B connect to the Platform and register their current network addresses in the **Registry**.
2. **Addressing:** Agent A wants to message Agent B. It asks the **Registry** for Agent B's details.
3. **Attempt 1 (Direct/Relay):** Agent A tries to connect to Agent B. If they are behind firewalls, the connection automatically routes through the Platform's **Relay**.
4. **Attempt 2 (Offline Fallback):** If Agent B is entirely offline, the connection fails. Agent A encrypts the message and leaves it in the Platform's **MQ**.
5. **Retrieval:** Later, Agent B wakes up, connects to the **MQ**, downloads the envelope, and decrypts the message locally.

---

## 🚀 Dual Interface: Libp2p & REST API

To maximize compatibility and performance, the platform exposes its services via two interfaces simultaneously:

- **Libp2p Streams:** The native language of the `agent-comm` SDK. Agents communicate with the platform using exactly the same multiplexed, secure streams they use to talk to each other.
- **HTTP REST API:** A lightweight alternative side-channel. Agents can optionally use standard HTTP requests for Registry lookups or MQ operations. This is particularly useful for reducing the overhead of spinning up a full libp2p host just to check for new messages, or for web-based clients.

## 🛠️ Tech Stack
- **Language:** Go 1.22+
- **P2P Networking:** `libp2p` (Circuit Relay v2, multiplexing)
- **Serialization:** Protobuf & JSON
- **Storage:** SQLite (`modernc.org/sqlite` - no CGO required)
- **Cryptography:** Ed25519 (Identity/Signatures) & X25519 (Key Exchange)

## 📦 Running the Platform

1. Copy the example configuration:
   ```bash
   cp config.example.yaml config.yaml
   ```
2. Run via Docker Compose:
   ```bash
   docker-compose up -d
   ```
   *(Or build manually: `go build -o platform ./cmd/platform && ./platform`)*

The platform will automatically generate its persistent cryptographic identity (`identity/keys_dir`) and initialize the SQLite databases in the configured `data_dir` on first boot.
