# Secure P2P Chat

Desktop chat (Tauri + Rust) for **encrypted point-to-point** conversations over **HTTP**.
No central server: each peer listens locally and dials the other peer’s URL.

## GraphPact

This repository includes [GraphPact](https://github.com/heartbit-ai/graphpact) `0.2.0`
(`.agents/skills/development-lifecycle`, `.lifecycle/check.py`). Validate the bootstrap
contract with:

```bash
python3 .lifecycle/check.py .lifecycle/changes/bootstrap-p2p-chat/change.json
```

## Protocol

1. Each peer starts an HTTP listener (`/identity`, `/handshake`, `/message`, `/health`).
2. Initiator connects to the peer URL and performs an X25519 handshake (includes its own listen URL for dial-back).
3. Messages are AES-256-GCM encrypted with directional keys derived via HKDF-SHA256.
4. Inbound ciphertext is rejected unless it matches the session peer public key.

## Develop

```bash
npm install
cd src-tauri && cargo test --lib crypto && cargo test --test p2p_http
cd ..
npm run tauri dev
```

Run two instances on different ports, paste the second peer’s `http://host:port` into the first, then chat.

## Organization

Maintained under [heartbit-ai](https://github.com/heartbit-ai).
