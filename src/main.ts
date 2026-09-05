import { invoke } from "@tauri-apps/api/core";

type ChatMessage = {
  id: string;
  direction: string;
  body: string;
  at: string;
};

type PeerSnapshot = {
  listen_addr: string;
  public_key_b64: string;
  peer_url: string | null;
  peer_public_key_b64: string | null;
  connected: boolean;
  messages: ChatMessage[];
};

const els = {
  port: document.querySelector<HTMLInputElement>("#port")!,
  startBtn: document.querySelector<HTMLButtonElement>("#start-btn")!,
  peerUrl: document.querySelector<HTMLInputElement>("#peer-url")!,
  connectBtn: document.querySelector<HTMLButtonElement>("#connect-btn")!,
  localUrl: document.querySelector<HTMLElement>("#local-url")!,
  localKey: document.querySelector<HTMLElement>("#local-key")!,
  sessionState: document.querySelector<HTMLElement>("#session-state")!,
  status: document.querySelector<HTMLElement>("#status")!,
  messages: document.querySelector<HTMLElement>("#messages")!,
  compose: document.querySelector<HTMLFormElement>("#compose")!,
  messageInput: document.querySelector<HTMLInputElement>("#message-input")!,
  sendBtn: document.querySelector<HTMLButtonElement>("#send-btn")!,
};

let knownMessageIds = new Set<string>();
let pollTimer: number | undefined;

function setStatus(text: string, isError = false) {
  els.status.textContent = text;
  els.status.classList.toggle("error", isError);
}

function renderSnapshot(snap: PeerSnapshot) {
  els.localUrl.textContent = snap.listen_addr;
  els.localKey.textContent = snap.public_key_b64;
  els.sessionState.textContent = snap.connected ? "chiffrée · active" : "inactive";
  els.messageInput.disabled = !snap.connected;
  els.sendBtn.disabled = !snap.connected;

  if (snap.messages.length === 0) {
    els.messages.innerHTML = `<p class="empty">Aucun message pour l’instant. Démarrez l’écoute, connectez un pair, puis écrivez.</p>`;
    knownMessageIds = new Set();
    return;
  }

  const nextIds = new Set(snap.messages.map((m) => m.id));
  const changed =
    nextIds.size !== knownMessageIds.size ||
    [...nextIds].some((id) => !knownMessageIds.has(id));
  if (!changed) return;

  knownMessageIds = nextIds;
  els.messages.innerHTML = "";
  for (const msg of snap.messages) {
    const bubble = document.createElement("article");
    bubble.className = `bubble ${msg.direction === "out" ? "out" : "in"}`;
    bubble.innerHTML = `
      <div class="who">${msg.direction === "out" ? "Vous" : "Pair"}</div>
      <div class="body"></div>
    `;
    bubble.querySelector(".body")!.textContent = msg.body;
    els.messages.appendChild(bubble);
  }
  els.messages.scrollTop = els.messages.scrollHeight;
}

async function refresh() {
  try {
    const snap = await invoke<PeerSnapshot>("get_status");
    renderSnapshot(snap);
  } catch {
    // Listener not started yet.
  }
}

function startPolling() {
  window.clearInterval(pollTimer);
  pollTimer = window.setInterval(() => {
    void refresh();
  }, 1000);
}

els.startBtn.addEventListener("click", async () => {
  const port = Number(els.port.value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    setStatus("Choisissez un port entre 1024 et 65535.", true);
    return;
  }
  try {
    els.startBtn.disabled = true;
    const snap = await invoke<PeerSnapshot>("start_listener", { port });
    renderSnapshot(snap);
    setStatus(`Écoute sur ${snap.listen_addr}`);
    startPolling();
  } catch (err) {
    els.startBtn.disabled = false;
    setStatus(String(err), true);
  }
});

els.connectBtn.addEventListener("click", async () => {
  const peerUrl = els.peerUrl.value.trim();
  if (!peerUrl) {
    setStatus("Indiquez l’URL HTTP du pair.", true);
    return;
  }
  try {
    const snap = await invoke<PeerSnapshot>("connect_peer", { peerUrl });
    renderSnapshot(snap);
    setStatus("Session chiffrée établie.");
  } catch (err) {
    setStatus(String(err), true);
  }
});

els.compose.addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = els.messageInput.value;
  if (!body.trim()) return;
  try {
    const snap = await invoke<PeerSnapshot>("send_chat_message", { body });
    els.messageInput.value = "";
    renderSnapshot(snap);
    setStatus("Message envoyé (chiffré).");
  } catch (err) {
    setStatus(String(err), true);
  }
});

window.addEventListener("DOMContentLoaded", () => {
  setStatus("Démarrez l’écoute pour publier votre endpoint HTTP.");
});
