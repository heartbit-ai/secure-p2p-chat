use secure_p2p_chat_lib::peer::bind_and_serve;
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::test]
async fn two_peers_handshake_and_exchange_encrypted_message() {
    let addr_a = SocketAddr::from(([127, 0, 0, 1], 0));
    let addr_b = SocketAddr::from(([127, 0, 0, 1], 0));

    let (peer_a, local_a, _ha) = bind_and_serve(addr_a).await.expect("bind a");
    let (peer_b, local_b, _hb) = bind_and_serve(addr_b).await.expect("bind b");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let url_b = format!("http://{local_b}");
    peer_a.connect_to(&url_b).await.expect("connect");

    peer_a
        .send_text("bonjour chiffre")
        .await
        .expect("send from a");

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

    assert!(local_a.ip().is_loopback());
}

#[tokio::test]
async fn spoofed_handshake_without_private_key_is_rejected() {
    let addr_b = SocketAddr::from(([127, 0, 0, 1], 0));
    let (peer_b, local_b, _hb) = bind_and_serve(addr_b).await.expect("bind b");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = reqwest::Client::new();
    let url_b = format!("http://{local_b}");

    // Victim identity published elsewhere; attacker does not hold the private key.
    let victim = secure_p2p_chat_lib::crypto::Identity::generate();
    let attacker = secure_p2p_chat_lib::crypto::Identity::generate();
    let bob_identity: serde_json::Value = client
        .get(format!("{url_b}/identity"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_pk = bob_identity["public_key_b64"].as_str().unwrap();

    let transcript = secure_p2p_chat_lib::crypto::handshake_transcript(
        &victim.public_key_b64(),
        bob_pk,
    );
    // Attacker derives against Bob using *attacker* secret but claims victim's public key.
    let shared = attacker.shared_secret_with(bob_pk).unwrap();
    let fake_keys = secure_p2p_chat_lib::crypto::SessionKeys::derive(&shared, true);
    let fake_proof = fake_keys.encrypt(&transcript).unwrap();

    let resp = client
        .post(format!("{url_b}/handshake"))
        .json(&serde_json::json!({
            "public_key_b64": victim.public_key_b64(),
            "listen_url": "http://127.0.0.1:9",
            "proof": fake_proof,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let snap = peer_b.snapshot().await;
    assert!(!snap.connected);
}

#[tokio::test]
async fn message_from_unknown_peer_key_is_forbidden() {
    let addr_a = SocketAddr::from(([127, 0, 0, 1], 0));
    let addr_b = SocketAddr::from(([127, 0, 0, 1], 0));
    let (peer_a, _local_a, _ha) = bind_and_serve(addr_a).await.expect("bind a");
    let (peer_b, local_b, _hb) = bind_and_serve(addr_b).await.expect("bind b");
    tokio::time::sleep(Duration::from_millis(50)).await;

    peer_a
        .connect_to(&format!("http://{local_b}"))
        .await
        .expect("connect");

    let stranger = secure_p2p_chat_lib::crypto::Identity::generate();
    let shared = stranger
        .shared_secret_with(&peer_b.snapshot().await.public_key_b64)
        .unwrap();
    // Stranger encrypts with initiator keys against Bob — still wrong peer key on the wire.
    let keys = secure_p2p_chat_lib::crypto::SessionKeys::derive(&shared, true);
    let payload = keys.encrypt(b"intrusion").unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{local_b}/message"))
        .json(&serde_json::json!({
            "from_public_key_b64": stranger.public_key_b64(),
            "payload": payload,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}
