use secure_p2p_chat_lib::peer::bind_and_serve;
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::test]
async fn two_peers_handshake_and_exchange_encrypted_message() {
    let addr_a = SocketAddr::from(([127, 0, 0, 1], 0));
    let addr_b = SocketAddr::from(([127, 0, 0, 1], 0));

    let (peer_a, local_a, _ha) = bind_and_serve(addr_a).await.expect("bind a");
    let (peer_b, local_b, _hb) = bind_and_serve(addr_b).await.expect("bind b");

    // Give servers a tick to accept connections.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url_b = format!("http://{local_b}");
    peer_a.connect_to(&url_b).await.expect("connect");

    peer_a
        .send_text("bonjour chiffre")
        .await
        .expect("send from a");

    // Allow request to land.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let snap_b = peer_b.snapshot().await;
    assert!(snap_b.connected);
    assert_eq!(snap_b.messages.len(), 1);
    assert_eq!(snap_b.messages[0].direction, "in");
    assert_eq!(snap_b.messages[0].body, "bonjour chiffre");

    peer_b.send_text("ack").await.expect("send from b");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let snap_a = peer_a.snapshot().await;
    assert_eq!(snap_a.messages.len(), 2);
    assert!(snap_a
        .messages
        .iter()
        .any(|m| m.direction == "in" && m.body == "ack"));

    // Sanity: listen addresses are loopback.
    assert!(local_a.ip().is_loopback());
}
