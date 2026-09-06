# Secure P2P Chat

Desktop chat (Tauri + Rust) for **encrypted point-to-point** conversations over **HTTP**.
No central chat server: peers talk directly. On the internet, **at least one peer must be reachable**.

## Internet setup (2 remote PCs)

1. **Host PC** (needs inbound reachability):
   - Open/forward a TCP port (example `7420`), **or** use Tailscale/ZeroTier, **or** a tunnel.
   - Start the app, click **Detect**, set **Public host** to your public IP / Tailscale name / DNS.
   - Click **Listen**, then **Copy my URL** and send that URL to the other person.
2. **Client PC** (can stay behind NAT):
   - Start **Listen** (local port is enough; no public host required).
   - Paste the host URL → **Connect**.
3. Chat both ways. If the client is not dialable, replies are stored in an encrypted **mailbox** on the host and pulled by the client (`POST /pull`).

Security notes:
- Messages and mailbox pulls are AES-256-GCM under the session keys.
- First contact is still TOFU over cleartext HTTP — prefer Tailscale/VPN or a trusted path when possible.

## GraphPact

Managed with [GraphPact](https://github.com/heartbit-ai/graphpact) `0.2.0`.

```bash
python3 .lifecycle/check.py .lifecycle/changes/internet-reachability/change.json
python3 .lifecycle/check.py --repo . .lifecycle/changes/internet-reachability/change.json
```

## Protocol

- `GET /identity`, `POST /handshake` (mutual ECDH proof-of-possession)
- `POST /message` (direct encrypted delivery)
- `POST /pull` (encrypted mailbox drain for NAT reverse path)
- `GET /health`

## Develop

```bash
npm install
cd src-tauri && cargo test && cargo check
cd ..
npm run tauri dev
```

## Organization

Maintained under [heartbit-ai](https://github.com/heartbit-ai).
