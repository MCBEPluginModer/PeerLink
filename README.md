# PeerLink

**PeerLink** is a decentralized peer-to-peer messenger written in C++, designed as a foundation for a resilient communication network without a mandatory central message server.

The project is being developed with long-term mass adoption in mind. The current builds are early-stage and intended for testing, feedback, and iterative improvement of the network architecture, delivery reliability, and peer discovery mechanisms.

## Current goals

PeerLink is focused on building a practical distributed messaging system that can operate in real-world network conditions, including unstable direct connectivity, partial peer availability, and offline message delivery scenarios.

## Current features

- direct peer-to-peer messaging
- persistent local node identity
- local chat history storage
- history restoration after application restart
- private chat session recovery
- NAT traversal improvements
- reverse connect fallback
- UDP hole punching fallback
- relay-based message delivery
- offline delivery through relay nodes
- ACK-based delivery confirmation
- retry with backoff
- history synchronization after reconnect
- bootstrap nodes support
- automatic private chat close when direct peer disconnects
- local chat history deletion

## Project status

**Status:** Early Alpha / Active Development

PeerLink is under active development. The current version is suitable for testing, network experiments, and small-scale usage by technical users, but it is not yet a production-ready массовый messenger.

---

# Build requirements

PeerLink currently targets **Windows**.

Required tools and components:

- Windows 10/11
- a modern C++ compiler
- **xmake**
- WinSock / WinAPI
- CryptoAPI
- Visual Studio Build Tools or Visual Studio with C++ toolchain

## Check xmake

```bash
xmake --version
