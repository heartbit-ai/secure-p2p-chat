//! HTTP peer protocol for point-to-point encrypted chat.

use crate::crypto::{EncryptedPayload, Identity, SessionKeys};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
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
    pub public_key_b64: String,
    pub peer_url: Option<String>,
    pub peer_public_key_b64: Option<String>,
    pub connected: bool,
    pub messages: Vec<ChatMessage>,
}

#[derive(Clone)]
struct Session {
    peer_url: String,
    peer_public_key_b64: String,
    keys: SessionKeys,
    #[allow(dead_code)]
    local_is_initiator: bool,
}

struct PeerInner {
    identity: Identity,
    listen_addr: SocketAddr,
    session: Option<Session>,
    messages: Vec<ChatMessage>,
}

#[derive(Clone)]
pub struct PeerNode {
    inner: Arc<RwLock<PeerInner>>,
    /// Serializes outbound connect/send against inbound handshake/message.
    io_lock: Arc<Mutex<()>>,
}

#[derive(Serialize, Deserialize)]
struct IdentityResponse {
    public_key_b64: String,
}

#[derive(Serialize, Deserialize)]
struct HandshakeRequest {
    public_key_b64: String,
    /// Initiator's reachable HTTP base URL so the responder can dial back.
    listen_url: String,
    initiator: bool,
}

#[derive(Serialize, Deserialize)]
struct HandshakeResponse {
    public_key_b64: String,
}

#[derive(Serialize, Deserialize)]
struct WireMessage {
    from_public_key_b64: String,
    payload: EncryptedPayload,
}

impl PeerNode {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            inner: Arc::new(RwLock::new(PeerInner {
                identity: Identity::generate(),
                listen_addr,
                session: None,
                messages: Vec::new(),
            })),
            io_lock: Arc::new(Mutex::new(())),
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
            .with_state(self)
            .layer(cors)
    }

    pub async fn snapshot(&self) -> PeerSnapshot {
        let g = self.inner.read().await;
        let host = if g.listen_addr.ip().is_unspecified() {
            "127.0.0.1".to_string()
        } else {
            g.listen_addr.ip().to_string()
        };
        PeerSnapshot {
            listen_addr: format!("http://{}:{}", host, g.listen_addr.port()),
            public_key_b64: g.identity.public_key_b64(),
            peer_url: g.session.as_ref().map(|s| s.peer_url.clone()),
            peer_public_key_b64: g.session.as_ref().map(|s| s.peer_public_key_b64.clone()),
            connected: g.session.is_some(),
            messages: g.messages.clone(),
        }
    }

    pub async fn connect_to(&self, peer_url: &str) -> Result<PeerSnapshot, PeerError> {
        let _guard = self.io_lock.lock().await;
        let peer_url = peer_url.trim_end_matches('/').to_string();
        let client = reqwest::Client::new();

        let identity: IdentityResponse = client
            .get(format!("{peer_url}/identity"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let (local_public, listen_url) = {
            let g = self.inner.read().await;
            let host = if g.listen_addr.ip().is_unspecified() {
                "127.0.0.1".to_string()
            } else {
                g.listen_addr.ip().to_string()
            };
            (
                g.identity.public_key_b64(),
                format!("http://{}:{}", host, g.listen_addr.port()),
            )
        };

        let resp: HandshakeResponse = client
            .post(format!("{peer_url}/handshake"))
            .json(&HandshakeRequest {
                public_key_b64: local_public,
                listen_url,
                initiator: true,
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

        {
            let mut g = self.inner.write().await;
            let shared = g.identity.shared_secret_with(&resp.public_key_b64)?;
            g.session = Some(Session {
                peer_url: peer_url.clone(),
                peer_public_key_b64: resp.public_key_b64,
                keys: SessionKeys::derive(&shared, true),
                local_is_initiator: true,
            });
        }

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

        let (peer_url, payload, from_key) = {
            let g = self.inner.read().await;
            let session = g
                .session
                .as_ref()
                .ok_or_else(|| PeerError::Message("not connected to a peer".into()))?;
            let payload = session.keys.encrypt(body.as_bytes())?;
            (
                session.peer_url.clone(),
                payload,
                g.identity.public_key_b64(),
            )
        };

        let client = reqwest::Client::new();
        client
            .post(format!("{peer_url}/message"))
            .json(&WireMessage {
                from_public_key_b64: from_key,
                payload,
            })
            .send()
            .await?
            .error_for_status()?;

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

    async fn accept_handshake(
        &self,
        req: HandshakeRequest,
    ) -> Result<HandshakeResponse, (StatusCode, String)> {
        if req.public_key_b64.trim().is_empty() {
            return Err((StatusCode::BAD_REQUEST, "missing public key".into()));
        }
        let peer_listen = req.listen_url.trim().trim_end_matches('/').to_string();
        if peer_listen.is_empty() || !(peer_listen.starts_with("http://") || peer_listen.starts_with("https://")) {
            return Err((StatusCode::BAD_REQUEST, "listen_url must be http(s)".into()));
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
            return Ok(HandshakeResponse {
                public_key_b64: g.identity.public_key_b64(),
            });
        }

        let shared = g
            .identity
            .shared_secret_with(&req.public_key_b64)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        // Remote claims initiator → we are responder (local_is_initiator = false).
        let local_is_initiator = !req.initiator;
        g.session = Some(Session {
            peer_url: peer_listen,
            peer_public_key_b64: req.public_key_b64,
            keys: SessionKeys::derive(&shared, local_is_initiator),
            local_is_initiator,
        });

        Ok(HandshakeResponse {
            public_key_b64: g.identity.public_key_b64(),
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
        g.messages.push(ChatMessage {
            id: Uuid::new_v4().to_string(),
            direction: "in".into(),
            body,
            at: Utc::now(),
        });
        Ok(())
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
    Ok(Json(node.accept_handshake(req).await?))
}

async fn message(
    State(node): State<PeerNode>,
    Json(wire): Json<WireMessage>,
) -> Result<StatusCode, (StatusCode, String)> {
    node.accept_message(wire).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn bind_and_serve(
    addr: SocketAddr,
) -> Result<(PeerNode, SocketAddr, tokio::task::JoinHandle<()>), PeerError> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let node = PeerNode::new(local);
    let app = node.clone().router();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((node, local, handle))
}
