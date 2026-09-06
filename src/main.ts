import { invoke } from "@tauri-apps/api/core";

type ChatMessage = {
  id: string;
  direction: string;
  body: string;
  at: string;
};

type PeerSnapshot = {
  listen_addr: string;
  share_url: string;
  public_key_b64: string;
  advertise_host: string | null;
  candidate_urls: string[];
  peer_url: string | null;
  peer_public_key_b64: string | null;
  safety_number: string | null;
  trust_state: string;
  connected: boolean;
  peer_dialable: boolean;
  messages: ChatMessage[];
};

type NetworkHints = {
  local_urls: string[];
  stun_public_ip: string | null;
  suggested_share_url: string | null;
};

const els = {
  port: document.querySelector<HTMLInputElement>("#port")!,
  advertiseHost: document.querySelector<HTMLInputElement>("#advertise-host")!,
  discoverBtn: document.querySelector<HTMLButtonElement>("#discover-btn")!,
  startBtn: document.querySelector<HTMLButtonElement>("#start-btn")!,
  copyUrlBtn: document.querySelector<HTMLButtonElement>("#copy-url-btn")!,
  peerUrl: document.querySelector<HTMLInputElement>("#peer-url")!,
  connectBtn: document.querySelector<HTMLButtonElement>("#connect-btn")!,
  verifyBtn: document.querySelector<HTMLButtonElement>("#verify-btn")!,
  shareUrl: document.querySelector<HTMLElement>("#share-url")!,
  candidates: document.querySelector<HTMLElement>("#candidates")!,
  localKey: document.querySelector<HTMLElement>("#local-key")!,
  sessionState: document.querySelector<HTMLElement>("#session-state")!,
  safetyNumber: document.querySelector<HTMLElement>("#safety-number")!,
  trustState: document.querySelector<HTMLElement>("#trust-state")!,
  status: document.querySelector<HTMLElement>("#status")!,
  messages: document.querySelector<HTMLElement>("#messages")!,
  compose: document.querySelector<HTMLFormElement>("#compose")!,
  messageInput: document.querySelector<HTMLInputElement>("#message-input")!,
  sendBtn: document.querySelector<HTMLButtonElement>("#send-btn")!,
};

let knownMessageIds = new Set<string>();
let pollTimer: number | undefined;
let lastShareUrl = "";

function setStatus(text: string, isError = false) {
  els.status.textContent = text;
  els.status.classList.toggle("error", isError);
}

function trustLabel(state: string): string {
  if (state === "verified") return "vérifié (épinglé)";
  if (state === "unverified") return "non vérifié — comparez le safety number";
  return "aucune";
}

function renderSnapshot(snap: PeerSnapshot) {
  lastShareUrl = snap.share_url;
  els.shareUrl.textContent = snap.share_url;
  els.candidates.textContent = snap.candidate_urls.join(" · ") || "—";
  els.localKey.textContent = snap.public_key_b64;
  els.sessionState.textContent = snap.connected
    ? snap.peer_dialable
      ? "chiffrée · active (direct)"
      : "chiffrée · active (mailbox NAT)"
    : "inactive";
  els.safetyNumber.textContent = snap.safety_number || "—";
  els.trustState.textContent = trustLabel(snap.trust_state);
  els.trustState.classList.toggle("verified", snap.trust_state === "verified");
  els.trustState.classList.toggle(
    "unverified",
    snap.trust_state === "unverified",
  );
  els.messageInput.disabled = !snap.connected || snap.trust_state !== "verified";
  els.sendBtn.disabled = !snap.connected || snap.trust_state !== "verified";
  els.copyUrlBtn.disabled = !snap.share_url;
  els.verifyBtn.disabled = !snap.connected || snap.trust_state === "verified";

  if (snap.messages.length === 0) {
    els.messages.innerHTML = `<p class="empty">Aucun message. Partagez votre URL, connectez un pair, puis écrivez.</p>`;
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

els.discoverBtn.addEventListener("click", async () => {
  const port = Number(els.port.value);
  try {
    const hints = await invoke<NetworkHints>("discover_network", {
      port,
      advertiseHost: els.advertiseHost.value.trim() || null,
    });
    if (!els.advertiseHost.value.trim() && hints.stun_public_ip) {
      els.advertiseHost.value = hints.stun_public_ip;
    }
    const summary = [
      hints.suggested_share_url
        ? `Suggestion: ${hints.suggested_share_url}`
        : null,
      hints.stun_public_ip ? `STUN: ${hints.stun_public_ip}` : "STUN indisponible",
      hints.local_urls.length ? `LAN: ${hints.local_urls.join(", ")}` : null,
    ]
      .filter(Boolean)
      .join(" · ");
    setStatus(summary || "Aucune adresse détectée.");
  } catch (err) {
    setStatus(String(err), true);
  }
});

els.startBtn.addEventListener("click", async () => {
  const port = Number(els.port.value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    setStatus("Choisissez un port entre 1024 et 65535.", true);
    return;
  }
  try {
    els.startBtn.disabled = true;
    const snap = await invoke<PeerSnapshot>("start_listener", {
      port,
      advertiseHost: els.advertiseHost.value.trim() || null,
    });
    renderSnapshot(snap);
    setStatus(
      snap.advertise_host
        ? `Écoute publiée sur ${snap.share_url}`
        : `Écoute locale. Pour Internet, renseignez un hôte public puis redémarrez, ou connectez-vous vers un pair déjà joignable.`,
    );
    startPolling();
  } catch (err) {
    els.startBtn.disabled = false;
    setStatus(String(err), true);
  }
});

els.copyUrlBtn.addEventListener("click", async () => {
  if (!lastShareUrl) return;
  try {
    await navigator.clipboard.writeText(lastShareUrl);
    setStatus("URL copiée.");
  } catch {
    setStatus(`Copiez manuellement: ${lastShareUrl}`);
  }
});

els.connectBtn.addEventListener("click", async () => {
  const peerUrl = els.peerUrl.value.trim();
  if (!peerUrl) {
    setStatus("Indiquez l’URL HTTP du pair distant.", true);
    return;
  }
  try {
    const snap = await invoke<PeerSnapshot>("connect_peer", { peerUrl });
    renderSnapshot(snap);
    setStatus(
      "Session chiffrée établie. Comparez le safety number, puis vérifiez l’interlocuteur.",
    );
  } catch (err) {
    setStatus(String(err), true);
  }
});

els.verifyBtn.addEventListener("click", async () => {
  try {
    const snap = await invoke<PeerSnapshot>("verify_contact");
    renderSnapshot(snap);
    setStatus("Interlocuteur vérifié — clé publique épinglée.");
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
    setStatus("Message envoyé (chiffré, Double Ratchet).");
  } catch (err) {
    setStatus(String(err), true);
  }
});

window.addEventListener("DOMContentLoaded", () => {
  setStatus(
    "Astuce Internet: un PC ouvre le port / utilise Tailscale et partage son URL; l’autre se connecte. Vérifiez toujours le safety number.",
  );
});
