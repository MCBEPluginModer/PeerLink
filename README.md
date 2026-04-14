# PeerLink — Secure P2P Messenger

PeerLink is a peer-to-peer encrypted messenger designed for decentralized communication without central servers.

The project focuses on strong identity verification, trust management, and resilient peer-to-peer networking.

Built entirely in C++ using WinSock and Windows CryptoAPI.

---

# Features

## Networking

- Direct peer-to-peer TCP connections
- Bootstrap node discovery
- Known peer exchange
- Heartbeat and reconnect logic
- Relay fallback support
- Basic NAT traversal logic

---

## Identity System

- Persistent node identity
- RSA public/private key pairs
- Identity fingerprint verification
- Key pinning per contact
- Identity migration support
- Device replacement flow

---

## Trust Model

- Trusted / Untrusted contacts
- Block / Unblock contacts
- Manual trust management
- Key mismatch detection
- Manual re-pin workflow
- Manual distrust on mismatch

---

## Messaging

- End-to-end encrypted private messages
- RSA key exchange
- AES encrypted payloads
- Message signature verification
- Delivery acknowledgements
- Offline relay message queue

---

## Session Management

Private session state machine:

- pending-outgoing-invite
- pending-incoming-invite
- awaiting-key
- active
- mismatch
- closed

Session lifecycle control:

- Session reset
- Session rekey
- Session recovery

---

## Storage

Local-only storage model:

- Contacts database
- Identity store
- Message history
- Relay spool
- Trust metadata

No central storage is used.

---

# Commands

Core CLI commands:
MCBEPluginModer
