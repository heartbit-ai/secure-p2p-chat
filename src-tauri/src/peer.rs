//! HTTP peer protocol for point-to-point encrypted chat (LAN + internet/NAT).

use crate::crypto::{
    handshake_transcript, EncryptedPayload, Identity, SessionKeys,
};
use crate::net::{candidate_base_urls, stun_public_ipv4};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ChatMessage {
    pub id: String,
    pub direction: String,
    pub body: String,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Serialize)]
pub struct PeerSnapshot {
    pub listen_addr: String,
    pub share_url: String,
    pub public_key_b64: String,
    pub advertise_host: Option<String>,
    pub candidate_urls: Vec<String>,
    pub peer_url: Option<String>,
    pub peer_public_key_b64: Option<String>,
    pub connected: bool,
    pub peer_dialable: bool,
    pub messages: Vec<ChatMessage>,
}

#[derive(Clone, Serialize)]
pub struct NetworkHints {
    pub local_urls: Vec<String>,
    pub stun_public_ip: Option<String>,
    pub suggested_share_url: Option<String>,
}

#[derive(Clone)]
struct Session {
    peer_url: String,
    peer_public_key_b64: String,
    keys: SessionKeys,
    #[allow(dead_code)]
    local_is_initiator: bool,
    peer_dialable: bool,
}

struct PeerInner {
    identity: Identity,
    listen_addr: SocketAddr,
    advertise_host: Option<String>,
    session: Option<Session>,
    messages: Vec<ChatMessage>,
    outbox: VecDeque<WireMessage>,
}

#[derive(Clone)]
pub struct PeerNode {
    inner: Arc<RwLock<PeerInner>>,
    io_lock: Arc<Mutex<()>>,
    poller: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[derive(Serialize, Deserialize)]
struct IdentityResponse {
    public_key_b64: String,
}

#[derive(Serialize, Deserialize)]
struct HandshakeRequest {
    public_key_b64: String,
    /// Reachable dial-back URL, or empty when the peer is not dialable (NAT).
    listen_url: String,
    proof: EncryptedPayload,
}

#[derive(Serialize, Deserialize)]
struct HandshakeResponse {
    public_key_b64: String,
    proof: EncryptedPayload,
}

#[derive(Clone, Serialize, Deserialize)]
struct WireMessage {
    from_public_key_b64: String,
    payload: EncryptedPayload,
}

#[derive(Serialize, Deserialize)]
struct PullRequest {
    from_public_key_b64: String,
    proof: EncryptedPayload,
}

#[derive(Serialize, Deserialize)]
struct PullResponse {
    messages: Vec<WireMessage>,
}

impl PeerNode {
    pub fn new(listen_addr: SocketAddr, advertise_host: Option<String>) -> Self {
        let advertise_host = advertise_host
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self {
            inner: Arc::new(RwLock::new(PeerInner {
                identity: Identity::generate(),
                listen_addr,
                advertise_host,
                session: None,
                messages: Vec::new(),
                outbox: VecDeque::new(),
            })),
            io_lock: Arc::new(Mutex::new(())),
            poller: Arc::new(Mutex::new(None)),
        }
    }

    pub fn router(self) -> Router {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);
        Router::new()
            .route("/health", get(health))
            .route("/identity", get(identity))
            .route("/handshake", post(handshake))
            .route("/message", post(message))
            .route("/pull", post(pull))
            .with_state(self)
            .layer(cors)
    }

    fn share_url_locked(inner: &PeerInner) -> String {
        let port = inner.listen_addr.port();
        candidate_base_urls(port, inner.advertise_host.as_deref())
            .into_iter()
            .next()
            .unwrap_or_else(|| format!("http://127.0.0.1:{port}"))
    }

    fn dialable_listen_url_locked(inner: &PeerInner) -> String {
        if inner.advertise_host.is_some() {
            Self::share_url_locked(inner)
        } else {
            String::new()
        }
    }

    pub async fn set_advertise_host(&self, host: Option<String>) {
        let mut g = self.inner.write().await;
        g.advertise_host = host
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }

    pub async fn snapshot(&self) -> PeerSnapshot {
        let g = self.inner.read().await;
        let port = g.listen_addr.port();
        let share_url = Self::share_url_locked(&g);
        PeerSnapshot {
            listen_addr: share_url.clone(),
            share_url,
            public_key_b64: g.identity.public_key_b64(),
            advertise_host: g.advertise_host.clone(),
            candidate_urls: candidate_base_urls(port, g.advertise_host.as_deref()),
            peer_url: g.session.as_ref().map(|s| s.peer_url.clone()),
            peer_public_key_b64: g.session.as_ref().map(|s| s.peer_public_key_b64.clone()),
            connected: g.session.is_some(),
            peer_dialable: g.session.as_ref().map(|s| s.peer_dialable).unwrap_or(false),
            messages: g.messages.clone(),
        }
    }

    pub fn network_hints(port: u16, advertise_host: Option<&str>) -> NetworkHints {
        let local_urls = candidate_base_urls(port, advertise_host);
        let stun_public_ip = stun_public_ipv4(Duration::from_secs(2)).map(|ip| ip.to_string());
        let suggested_share_url =
            if let Some(host) = advertise_host.map(str::trim).filter(|h| !h.is_empty()) {
                candidate_base_urls(port, Some(host)).into_iter().next()
            } else {
                stun_public_ip
                    .as_ref()
                    .map(|ip| format!("http://{ip}:{port}"))
            };
        NetworkHints {
            local_urls,
            stun_public_ip,
            suggested_share_url,
        }
    }

    pub async fn connect_to(&self, peer_url: &str) -> Result<PeerSnapshot, PeerError> {
        let _guard = self.io_lock.lock().await;
        let peer_url = peer_url.trim_end_matches('/').to_string();
        if !(peer_url.starts_with("http://") || peer_url.starts_with("https://")) {
            return Err(PeerError::Message("peer URL must be http(s)".into()));
        }
        let client = reqwest::Client::new();

        {
            let g = self.inner.read().await;
            if let Some(existing) = &g.session {
                if !existing.peer_url.is_empty() && existing.peer_url != peer_url {
                    return Err(PeerError::Message(
                        "already connected to another peer".into(),
                    ));
                }
                if existing.peer_url == peer_url {
                    return Ok(self.snapshot().await);
                }
            }
        }

        let identity: IdentityResponse = client
            .get(format!("{peer_url}/identity"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let (local_public, listen_url, shared, initiator_keys) = {
            let g = self.inner.read().await;
            let shared = g.identity.shared_secret_with(&identity.public_key_b64)?;
            let keys = SessionKeys::derive(&shared, true);
            (
                g.identity.public_key_b64(),
                Self::dialable_listen_url_locked(&g),
                shared,
                keys,
            )
        };

        let transcript = handshake_transcript(&local_public, &identity.public_key_b64);
        let proof = initiator_keys.encrypt(&transcript)?;

        let resp: HandshakeResponse = client
            .post(format!("{peer_url}/handshake"))
            .json(&HandshakeRequest {
                public_key_b64: local_public,
                listen_url,
                proof,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if resp.public_key_b64 != identity.public_key_b64 {
            return Err(PeerError::Message(
                "handshake public key mismatch with /identity".into(),
            ));
        }

        let proved = initiator_keys.decrypt(&resp.proof)?;
        if proved != transcript {
            return Err(PeerError::Message(
                "responder handshake proof mismatch".into(),
            ));
        }

        {
            let mut g = self.inner.write().await;
            g.session = Some(Session {
                peer_url: peer_url.clone(),
                peer_public_key_b64: resp.public_key_b64,
                keys: SessionKeys::derive(&shared, true),
                local_is_initiator: true,
                peer_dialable: true,
            });
        }

        self.ensure_poller().await;
        Ok(self.snapshot().await)
    }

    pub async fn send_text(&self, body: &str) -> Result<ChatMessage, PeerError> {
        let _guard = self.io_lock.lock().await;
        if body.trim().is_empty() {
            return Err(PeerError::Message("message must not be empty".into()));
        }
        if body.len() > 8_192 {
            return Err(PeerError::Message("message too long".into()));
        }

        let (peer_url, peer_dialable, wire) = {
            let g = self.inner.read().await;
            let session = g
                .session
                .as_ref()
                .ok_or_else(|| PeerError::Message("not connected to a peer".into()))?;
            let payload = session.keys.encrypt(body.as_bytes())?;
            (
                session.peer_url.clone(),
                session.peer_dialable,
                WireMessage {
                    from_public_key_b64: g.identity.public_key_b64(),
                    payload,
                },
            )
        };

        let mut delivered = false;
        if peer_dialable && !peer_url.is_empty() {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?;
            if let Ok(resp) = client
                .post(format!("{peer_url}/message"))
                .json(&wire)
                .send()
                .await
            {
                delivered = resp.status().is_success();
            }
        }

        if !delivered {
            let mut g = self.inner.write().await;
            if g.outbox.len() >= 256 {
                return Err(PeerError::Message("outbox full; peer is not pulling".into()));
            }
            g.outbox.push_back(wire);
        }

        let msg = ChatMessage {
            id: Uuid::new_v4().to_string(),
            direction: "out".into(),
            body: body.to_string(),
            at: Utc::now(),
        };
        {
            let mut g = self.inner.write().await;
            g.messages.push(msg.clone());
        }
        Ok(msg)
    }

    async fn ensure_poller(&self) {
        let mut guard = self.poller.lock().await;
        if guard.is_some() {
            return;
        }
        let node = self.clone();
        *guard = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                let connected = node.inner.read().await.session.is_some();
                if !connected {
                    break;
                }
                let _ = node.poll_once().await;
            }
        }));
    }

    async fn poll_once(&self) -> Result<(), PeerError> {
        let (peer_url, proof, from_key) = {
            let g = self.inner.read().await;
            let session = match &g.session {
                Some(s) => s,
                None => return Ok(()),
            };
            if session.peer_url.is_empty() {
                return Ok(());
            }
            (
                session.peer_url.clone(),
                session.keys.encrypt(b"pull-v1")?,
                g.identity.public_key_b64(),
            )
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let resp = client
            .post(format!("{peer_url}/pull"))
            .json(&PullRequest {
                from_public_key_b64: from_key,
                proof,
            })
            .send()
            .await?;
        if !resp.status().is_success() {
            return Ok(());
        }
        let PullResponse { messages } = resp.json().await?;
        if messages.is_empty() {
            return Ok(());
        }

        let _guard = self.io_lock.lock().await;
        let mut g = self.inner.write().await;
        let session = match g.session.as_ref() {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut accepted = Vec::new();
        for wire in messages {
            if session.peer_public_key_b64 != wire.from_public_key_b64 {
                continue;
            }
            if let Ok(plain) = session.keys.decrypt(&wire.payload) {
                if let Ok(body) = String::from_utf8(plain) {
                    if !body.is_empty() && body.len() <= 8_192 {
                        accepted.push(ChatMessage {
                            id: Uuid::new_v4().to_string(),
                            direction: "in".into(),
                            body,
                            at: Utc::now(),
                        });
                    }
                }
            }
        }
        g.messages.extend(accepted);
        Ok(())
    }

    async fn accept_handshake(
        &self,
        req: HandshakeRequest,
    ) -> Result<HandshakeResponse, (StatusCode, String)> {
        if req.public_key_b64.trim().is_empty() {
            return Err((StatusCode::BAD_REQUEST, "missing public key".into()));
        }
        let peer_listen = req.listen_url.trim().trim_end_matches('/').to_string();
        let peer_dialable = !peer_listen.is_empty();
        if peer_dialable
            && !(peer_listen.starts_with("http://") || peer_listen.starts_with("https://"))
        {
            return Err((
                StatusCode::BAD_REQUEST,
                "listen_url must be http(s) or empty".into(),
            ));
        }

        let _guard = self.io_lock.lock().await;
        let mut g = self.inner.write().await;

        if let Some(existing) = &g.session {
            if existing.peer_public_key_b64 != req.public_key_b64 {
                return Err((
                    StatusCode::CONFLICT,
                    "already connected to another peer".into(),
                ));
            }
            let shared = g
                .identity
                .shared_secret_with(&req.public_key_b64)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let responder_keys = SessionKeys::derive(&shared, false);
            let transcript =
                handshake_transcript(&req.public_key_b64, &g.identity.public_key_b64());
            let proof = responder_keys
                .encrypt(&transcript)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            return Ok(HandshakeResponse {
                public_key_b64: g.identity.public_key_b64(),
                proof,
            });
        }

        let shared = g
            .identity
            .shared_secret_with(&req.public_key_b64)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let responder_keys = SessionKeys::derive(&shared, false);
        let transcript = handshake_transcript(&req.public_key_b64, &g.identity.public_key_b64());
        let proved = responder_keys
            .decrypt(&req.proof)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid handshake proof".into()))?;
        if proved != transcript {
            return Err((StatusCode::UNAUTHORIZED, "handshake proof mismatch".into()));
        }
        let proof = responder_keys
            .encrypt(&transcript)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        g.session = Some(Session {
            peer_url: peer_listen,
            peer_public_key_b64: req.public_key_b64,
            keys: SessionKeys::derive(&shared, false),
            local_is_initiator: false,
            peer_dialable,
        });

        Ok(HandshakeResponse {
            public_key_b64: g.identity.public_key_b64(),
            proof,
        })
    }

    async fn accept_message(&self, wire: WireMessage) -> Result<(), (StatusCode, String)> {
        let _guard = self.io_lock.lock().await;
        let mut g = self.inner.write().await;
        let session = g
            .session
            .as_ref()
            .ok_or((StatusCode::CONFLICT, "no active session".into()))?;
        if session.peer_public_key_b64 != wire.from_public_key_b64 {
            return Err((StatusCode::FORBIDDEN, "unknown peer public key".into()));
        }
        let plain = session
            .keys
            .decrypt(&wire.payload)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let body = String::from_utf8(plain)
            .map_err(|_| (StatusCode::BAD_REQUEST, "plaintext is not utf-8".into()))?;
        if body.len() > 8_192 {
            return Err((StatusCode::BAD_REQUEST, "message too long".into()));
        }
        g.messages.push(ChatMessage {
            id: Uuid::new_v4().to_string(),
            direction: "in".into(),
            body,
            at: Utc::now(),
        });
        Ok(())
    }

    async fn accept_pull(
        &self,
        req: PullRequest,
    ) -> Result<PullResponse, (StatusCode, String)> {
        let _guard = self.io_lock.lock().await;
        let mut g = self.inner.write().await;
        let session = g
            .session
            .as_ref()
            .ok_or((StatusCode::CONFLICT, "no active session".into()))?;
        if session.peer_public_key_b64 != req.from_public_key_b64 {
            return Err((StatusCode::FORBIDDEN, "unknown peer public key".into()));
        }
        let plain = session
            .keys
            .decrypt(&req.proof)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid pull proof".into()))?;
        if plain.as_slice() != b"pull-v1" {
            return Err((StatusCode::UNAUTHORIZED, "pull proof mismatch".into()));
        }
        let messages: Vec<WireMessage> = g.outbox.drain(..).collect();
        Ok(PullResponse { messages })
    }
}

async fn health() -> &'static str {
    "ok"
}

async fn identity(State(node): State<PeerNode>) -> Json<IdentityResponse> {
    let g = node.inner.read().await;
    Json(IdentityResponse {
        public_key_b64: g.identity.public_key_b64(),
    })
}

async fn handshake(
    State(node): State<PeerNode>,
    Json(req): Json<HandshakeRequest>,
) -> Result<Json<HandshakeResponse>, (StatusCode, String)> {
    let resp = node.accept_handshake(req).await?;
    node.ensure_poller().await;
    Ok(Json(resp))
}

async fn message(
    State(node): State<PeerNode>,
    Json(wire): Json<WireMessage>,
) -> Result<StatusCode, (StatusCode, String)> {
    node.accept_message(wire).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn pull(
    State(node): State<PeerNode>,
    Json(req): Json<PullRequest>,
) -> Result<Json<PullResponse>, (StatusCode, String)> {
    Ok(Json(node.accept_pull(req).await?))
}

pub async fn bind_and_serve(
    addr: SocketAddr,
    advertise_host: Option<String>,
) -> Result<(PeerNode, SocketAddr, tokio::task::JoinHandle<()>), PeerError> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let node = PeerNode::new(local, advertise_host);
    let app = node.clone().router();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((node, local, handle))
}
