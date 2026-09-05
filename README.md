# Secure P2P Chat

Desktop chat (Tauri + Rust) for **encrypted point-to-point** conversations over **HTTP**.
No central server: each peer listens locally and dials the other peer’s URL.

## GraphPact project management

This repository is managed with [GraphPact](https://github.com/heartbit-ai/graphpact) `0.2.0`.

| Path | Role |
|---|---|
| `.agents/skills/development-lifecycle/` | Lifecycle skill for coding agents |
| `.lifecycle/check.py` | Contract checker |
| `.lifecycle/changes/<id>/change.json` | Active change contracts |
| `AGENTS.md` | Standing agent instructions |

### How agents should work here

1. **Classify** the change (simple / structured / critical) and the field (greenfield / brownfield).
2. For structured or critical work, **grill** then open or update a contract under `.lifecycle/changes/`.
3. Keep one contract per change; validate often:
   ```bash
   python3 .lifecycle/check.py .lifecycle/changes/<id>/change.json
   python3 .lifecycle/check.py --repo . .lifecycle/changes/<id>/change.json
   ```
4. Record **evidence** with real commands, exit codes, and commit revisions — claims are not evidence.
5. Critical changes need an **independent review** before `state: done`.

Bootstrap contract: `.lifecycle/changes/bootstrap-p2p-chat/change.json`.

## Protocol

1. Each peer starts an HTTP listener (`/identity`, `/handshake`, `/message`, `/health`).
2. Initiator fetches `/identity`, then posts a handshake with an **ECDH proof-of-possession** (AES-GCM over a canonical transcript) and its listen URL for dial-back.
3. Responder verifies the proof (so a claimed public key without the private key is rejected), answers with its own proof, and locks a single peer session.
4. Messages are AES-256-GCM encrypted with directional keys from HKDF-SHA256.
5. Inbound ciphertext is rejected unless `from_public_key_b64` matches the session peer.

First-connect trust is TOFU over cleartext HTTP (no PKI yet).

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
