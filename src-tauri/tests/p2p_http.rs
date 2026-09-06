use secure_p2p_chat_lib::crypto::{HandshakeInitiator, Identity};
use secure_p2p_chat_lib::peer::bind_and_serve;
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::test]
async fn two_peers_handshake_and_exchange_encrypted_message() {
    let addr_a = SocketAddr::from(([127, 0, 0, 1], 0));
    let addr_b = SocketAddr::from(([127, 0, 0, 1], 0));

    let (peer_a, _local_a, _ha) = bind_and_serve(addr_a, Some("127.0.0.1".into()))
        .await
        .expect("bind a");
    let (peer_b, local_b, _hb) = bind_and_serve(addr_b, Some("127.0.0.1".into()))
        .await
        .expect("bind b");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let url_b = format!("http://{local_b}");
    peer_a.connect_to(&url_b).await.expect("connect");
    peer_a.verify_contact().await.expect("verify a");
    peer_b.verify_contact().await.expect("verify b");

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
    assert!(snap_b.safety_number.is_some());
    assert_eq!(snap_b.trust_state, "verified");

    peer_b.send_text("ack").await.expect("send from b");
    // B may queue to outbox if dial-back fails; A polls.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let snap_a = peer_a.snapshot().await;
    assert!(snap_a
        .messages
        .iter()
        .any(|m| m.direction == "in" && m.body == "ack"));
}

#[tokio::test]
async fn mailbox_delivers_when_dialback_unreachable() {
    let addr_host = SocketAddr::from(([127, 0, 0, 1], 0));
    let addr_nat = SocketAddr::from(([127, 0, 0, 1], 0));

    let (host, local_host, _hh) = bind_and_serve(addr_host, Some("127.0.0.1".into()))
        .await
        .expect("bind host");
    let (nat, _local_nat, _hn) = bind_and_serve(addr_nat, None).await.expect("bind nat");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let host_url = format!("http://{local_host}");
    nat.connect_to(&host_url).await.expect("nat dials host");
    nat.verify_contact().await.expect("verify nat");
    host.verify_contact().await.expect("verify host");

    host.send_text("hello from host")
        .await
        .expect("host send");
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let snap_nat = nat.snapshot().await;
    assert!(
        snap_nat
            .messages
            .iter()
            .any(|m| m.direction == "in" && m.body == "hello from host"),
        "NAT peer should receive mailbox reply via /pull, got: {:?}",
        snap_nat.messages
    );
}

#[tokio::test]
async fn advertise_host_used_in_listen_url() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let (peer, local, _h) = bind_and_serve(addr, Some("203.0.113.50".into()))
        .await
        .expect("bind");
    let snap = peer.snapshot().await;
    let expected = format!("http://203.0.113.50:{}", local.port());
    assert_eq!(snap.share_url, expected);
    assert_eq!(snap.listen_addr, expected);
    assert!(snap.candidate_urls.iter().any(|u| u == &expected));
}

#[tokio::test]
async fn spoofed_handshake_without_private_key_is_rejected() {
    let addr_b = SocketAddr::from(([127, 0, 0, 1], 0));
    let (peer_b, local_b, _hb) = bind_and_serve(addr_b, Some("127.0.0.1".into()))
        .await
        .expect("bind b");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = reqwest::Client::new();
    let url_b = format!("http://{local_b}");
    let victim = Identity::generate();
    let mallory = Identity::generate();
    let bob_identity: serde_json::Value = client
        .get(format!("{url_b}/identity"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_pk = bob_identity["public_key_b64"].as_str().unwrap();

    let (_init, mut offer) =
        HandshakeInitiator::start(&mallory, bob_pk, "http://127.0.0.1:9").unwrap();
    // Claim victim's identity while proofs were built with Mallory's secrets.
    offer.identity_public_key_b64 = victim.public_key_b64();

    let resp = client
        .post(format!("{url_b}/handshake"))
        .json(&serde_json::json!({ "offer": offer }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(!peer_b.snapshot().await.connected);
}

#[tokio::test]
async fn message_from_unknown_peer_key_is_forbidden() {
    let addr_a = SocketAddr::from(([127, 0, 0, 1], 0));
    let addr_b = SocketAddr::from(([127, 0, 0, 1], 0));
    let (peer_a, _local_a, _ha) = bind_and_serve(addr_a, Some("127.0.0.1".into()))
        .await
        .expect("bind a");
    let (_peer_b, local_b, _hb) = bind_and_serve(addr_b, Some("127.0.0.1".into()))
        .await
        .expect("bind b");
    tokio::time::sleep(Duration::from_millis(50)).await;

    peer_a
        .connect_to(&format!("http://{local_b}"))
        .await
        .expect("connect");

    let stranger = Identity::generate();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{local_b}/message"))
        .json(&serde_json::json!({
            "from_public_key_b64": stranger.public_key_b64(),
            "message": {
                "header": {
                    "dh_public_b64": stranger.public_key_b64(),
                    "pn": 0,
                    "n": 0
                },
                "payload": {
                    "nonce_b64": "AAAAAAAAAAAAAAAA",
                    "ciphertext_b64": "AAAA"
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn verify_contact_pins_trust_state() {
    let addr_a = SocketAddr::from(([127, 0, 0, 1], 0));
    let addr_b = SocketAddr::from(([127, 0, 0, 1], 0));
    let (peer_a, _local_a, _ha) = bind_and_serve(addr_a, Some("127.0.0.1".into()))
        .await
        .expect("bind a");
    let (_peer_b, local_b, _hb) = bind_and_serve(addr_b, Some("127.0.0.1".into()))
        .await
        .expect("bind b");
    tokio::time::sleep(Duration::from_millis(50)).await;

    peer_a
        .connect_to(&format!("http://{local_b}"))
        .await
        .expect("connect");
    let before = peer_a.snapshot().await;
    assert_eq!(before.trust_state, "unverified");
    assert!(before.safety_number.is_some());

    let after = peer_a.verify_contact().await.expect("verify");
    assert_eq!(after.trust_state, "verified");
    assert_eq!(after.safety_number, before.safety_number);
}
