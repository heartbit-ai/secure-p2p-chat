pub mod crypto;
pub mod net;
pub mod peer;

use peer::{bind_and_serve, NetworkHints, PeerNode, PeerSnapshot};
use std::net::SocketAddr;
use std::sync::Arc;
use tauri::State;
use tokio::sync::Mutex;

struct AppState {
    node: Mutex<Option<PeerNode>>,
    server: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            node: Mutex::new(None),
            server: Mutex::new(None),
        }
    }
}

#[tauri::command]
async fn start_listener(
    state: State<'_, Arc<AppState>>,
    port: u16,
    advertise_host: Option<String>,
) -> Result<PeerSnapshot, String> {
    let mut node_slot = state.node.lock().await;
    if node_slot.is_some() {
        return Err("listener already started".into());
    }
    if !(1024..=65535).contains(&port) {
        return Err("port must be between 1024 and 65535".into());
    }
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let (node, _local, handle) = bind_and_serve(addr, advertise_host)
        .await
        .map_err(|e| e.to_string())?;
    let snap = node.snapshot().await;
    *node_slot = Some(node);
    *state.server.lock().await = Some(handle);
    Ok(snap)
}

#[tauri::command]
async fn get_status(state: State<'_, Arc<AppState>>) -> Result<PeerSnapshot, String> {
    let node_slot = state.node.lock().await;
    let node = node_slot
        .as_ref()
        .ok_or_else(|| "listener not started".to_string())?;
    Ok(node.snapshot().await)
}

#[tauri::command]
async fn set_advertise_host(
    state: State<'_, Arc<AppState>>,
    advertise_host: Option<String>,
) -> Result<PeerSnapshot, String> {
    let node_slot = state.node.lock().await;
    let node = node_slot
        .as_ref()
        .ok_or_else(|| "listener not started".to_string())?;
    node.set_advertise_host(advertise_host).await;
    Ok(node.snapshot().await)
}

#[tauri::command]
async fn discover_network(
    port: u16,
    advertise_host: Option<String>,
) -> Result<NetworkHints, String> {
    Ok(PeerNode::network_hints(
        port,
        advertise_host.as_deref(),
    ))
}

#[tauri::command]
async fn connect_peer(
    state: State<'_, Arc<AppState>>,
    peer_url: String,
) -> Result<PeerSnapshot, String> {
    let node_slot = state.node.lock().await;
    let node = node_slot
        .as_ref()
        .ok_or_else(|| "listener not started".to_string())?;
    node.connect_to(&peer_url)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn send_chat_message(
    state: State<'_, Arc<AppState>>,
    body: String,
) -> Result<PeerSnapshot, String> {
    let node_slot = state.node.lock().await;
    let node = node_slot
        .as_ref()
        .ok_or_else(|| "listener not started".to_string())?;
    node.send_text(&body).await.map_err(|e| e.to_string())?;
    Ok(node.snapshot().await)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Arc::new(AppState::default()))
        .invoke_handler(tauri::generate_handler![
            start_listener,
            get_status,
            set_advertise_host,
            discover_network,
            connect_peer,
            send_chat_message
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
