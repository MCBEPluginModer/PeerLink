
# PeerLink — Secure P2P Messenger

PeerLink is a decentralized peer-to-peer encrypted messenger designed for secure communication without centralized servers.

The system focuses on:

- Strong cryptographic identity
- Trust-based peer verification
- Resilient networking
- Secure local-only storage
- Crash-safe messaging

Built entirely in **C++** using:

- WinSock
- Windows API
- Windows CryptoAPI
- DPAPI (secure storage)

---

# Status

**Current Version: Beta 1.0**

PeerLink has reached full Beta stage with:

- Protocol Versioning (v3)
- Journal Replay Recovery
- Secure Key Storage
- Peer Reputation System
- NAT traversal
- Relay fallback
- Multi-device identity support
- Rate limiting
- Crash recovery
- Fuzz testing

This version is stable enough for:

- Multi-node testing
- Real-world experimentation
- Network resilience testing

Not recommended yet for critical production environments.

---

# Architecture Overview

PeerLink operates without centralized messaging servers.

Each node:

- Owns its identity
- Stores its own history
- Verifies peers cryptographically
- Maintains trust metadata
- Protects against abuse

All communication occurs directly between peers or through optional relays.

---

# Features

## Networking

- Direct peer-to-peer TCP connections
- Bootstrap node discovery
- Known peer exchange
- NAT traversal logic
- Relay fallback support
- Multi-device connection support
- Heartbeat and reconnect logic
- Timeout and retry handling
- Rate limiting protection
- Protocol Versioning (v3)

---

## Security & Identity

- Persistent node identity
- RSA public/private key pairs
- Identity fingerprint verification
- Secure key lifecycle management
- Key rotation support
- Key revocation support
- Key backup metadata export
- Secure Key Storage (DPAPI)
- Identity migration support
- Device replacement flow

---

## Trust Model

- Trusted / Untrusted contacts
- Block / Unblock contacts
- Manual trust management
- Key mismatch detection
- Manual re-pin workflow
- Peer Reputation System
- Reputation penalty logic
- Abuse detection
- Automatic bad-peer rejection

---

## Messaging

- End-to-end encrypted private messages
- RSA key exchange
- AES encrypted payloads
- Message signature verification
- Delivery acknowledgements
- Retry logic
- Resume logic
- Offline relay message queue
- Message journal persistence

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
- Session resume after restart

---

## Reliability

PeerLink includes advanced recovery mechanisms:

- Crash Recovery Logging
- Journal Replay Recovery
- Message persistence
- State validation
- Timeout handling
- Retry mechanisms
- Resume support
- Structured logging
- Fuzz testing framework

---

## Storage

Local-only storage model:

- Contacts database
- Identity store
- Message history
- Relay spool
- Trust metadata
- Peer reputation data
- Message journal logs
- Secure key metadata

No central storage is used.

All data belongs to the node owner.

---

## Commands

Core CLI commands:

/help  
/status  
/users  
/contacts  
/connect <ip> <port>  

# Chat control
/chat <n>  
/leave  
/sessions  

# Trust control
/invite <n>  
/accept <n>  
/reject <n>  

# Messaging
/all <text>  

# Identity
/keys  
/keyrotate  
/keybackup  
/keyrevoke  

# System
/config  
/reputation  
/exit  

---

## Configuration

Config file:

messenger.cfg

Example:

listen_port=4000  
nickname=node1  

log_level=info  
log_to_console=true  

rate_limit_messages=20  
rate_limit_connections=10  

---

## Build

Using xmake:

xmake

Run:

xmake run messenger

---

## Requirements

Windows:

- Windows 10+
- MSVC (Visual Studio Build Tools)
- WinSock
- Windows CryptoAPI
- Windows DPAPI
- xmake (recommended)

---

## Roadmap

Next milestones:

- Beta 1.1 — Stress testing
- Beta 1.2 — Performance tuning
- Release Candidate — GUI prototype
- Release — Stable multi-platform version

---

# Project Name

PeerLink — Secure Decentralized Communication
