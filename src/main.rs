// PortsidePeer relay
//
// Env variables:
//   RELAY_KEY_PATH
//   RELAY_LISTEN_ADDR       Listen multiaddr (default: /ip4/0.0.0.0/tcp/4001)
//   RELAY_PUBLIC_MULTIADDR  Your public address, e.g. /ip4/public_ip/tcp/4001
//                          (Optional also learned automatically from Identify)
//   RELAY_ALLOWLIST_PATH    Allowlist file (default: ./allowed_peers.txt)
//   RELAY_ENFORCE_ALLOWLIST "1" to enforce the allowlist (default: log only)

use env_logger::Env;
use futures::StreamExt;
use libp2p::{
    core::transport::Transport,
    core::upgrade::Version,
    identify, kad, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId,
};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

fn load_or_create_identity() -> libp2p::identity::Keypair {
    let path = PathBuf::from(
        std::env::var("RELAY_KEY_PATH").unwrap_or_else(|_| "relay_secret.key".to_string()),
    );

    if path.exists() {
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
                log::debug!("Loaded persistent relay identity from {}", path.display());
                return kp;
            }
        }
        log::debug!(
            "Could not read a valid key from {} — generating a fresh identity (file replaced)",
            path.display()
        );
    }

    let kp = libp2p::identity::Keypair::generate_ed25519();
    match kp.to_protobuf_encoding() {
        Ok(bytes) => {
            let _ = fs::write(&path, &bytes);
            log::debug!(
                "Generated and persisted new relay identity to {}",
                path.display()
            );
        }
        Err(e) => log::debug!("Could not persist relay identity: {e}"),
    }
    kp
}

// Load allowed_peers.txt one PeerId per line `#` comments allowed).
fn load_allowed_peers(path: &str) -> HashSet<PeerId> {
    let mut out = HashSet::new();
    if let Ok(text) = fs::read_to_string(path) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match PeerId::from_str(line) {
                Ok(pid) => {
                    out.insert(pid);
                }
                Err(_) => log::debug!("Allowlist: not a valid PeerId: {line}"),
            }
        }
    }
    out
}

fn peer_allowed(allowlist: &HashSet<PeerId>, peer: &PeerId) -> bool {
    allowlist.is_empty() || allowlist.contains(peer)
}

#[derive(NetworkBehaviour)]
struct RelayBehavior {
    relay_server: relay::Behaviour,
    relay_client: relay::client::Behaviour,
    identify: identify::Behaviour,
    dcutr: libp2p::dcutr::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // Stable identity
    let keypair = load_or_create_identity();
    let peer_id = PeerId::from(keypair.public());
    log::info!("Relay starting with PeerId: {}", peer_id);

    // Allowlist
    let enforce_allowlist = std::env::var("RELAY_ENFORCE_ALLOWLIST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let allowlist_path =
        std::env::var("RELAY_ALLOWLIST_PATH").unwrap_or_else(|_| "allowed_peers.txt".to_string());
    let allowed_peers = load_allowed_peers(&allowlist_path);

    log::info!("==================================================");
    log::info!("Relay PeerId (configure this in every client):");
    log::info!("{peer_id}");
    log::info!("==================================================");
    log::info!(
        "Allowlist: {} peer(s) in {allowlist_path}: {}",
        allowed_peers.len(),
        if enforce_allowlist {
            "ON"
        } else {
            "OFF (log only)"
        }
    );

    // Transport stack
    let (relay_client_transport, relay_client_behavior) = relay::client::new(peer_id);

    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::new().nodelay(true));

    let noise_config = libp2p::noise::Config::new(&keypair)?;

    let mut explicit_yamux_config = yamux::Config::default();
    explicit_yamux_config.set_max_num_streams(8192);

    let transport = tcp_transport
        .or_transport(relay_client_transport)
        .upgrade(Version::V1)
        .authenticate(noise_config)
        .multiplex(explicit_yamux_config)
        .map(|(peer_id, muxer), _| (peer_id, libp2p::core::muxing::StreamMuxerBox::new(muxer)))
        .boxed();

    // Relay tuned for sustained chat
    let relay_config = relay::Config {
        max_reservations: 1024,
        max_reservations_per_peer: 16,
        reservation_duration: Duration::from_secs(3600),
        max_circuits: 512,
        max_circuits_per_peer: 16,
        max_circuit_duration: Duration::from_secs(3600),
        max_circuit_bytes: 64 * 1024 * 1024,
        ..Default::default()
    };

    let kad_protocol = libp2p::StreamProtocol::new("/accord-kad/1.0.0");

    let kad_config = kad::Config::new(kad_protocol);

    let store = kad::store::MemoryStore::new(peer_id);
    let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);
    kademlia.set_mode(Some(kad::Mode::Server));

    let identify_config =
        identify::Config::new("/accord-relay/1.0.0".to_string(), keypair.public());

    let behaviour = RelayBehavior {
        relay_server: relay::Behaviour::new(peer_id, relay_config),
        relay_client: relay_client_behavior,
        identify: identify::Behaviour::new(identify_config),
        dcutr: libp2p::dcutr::Behaviour::new(peer_id),
        kademlia,
    };

    let swarm_config = libp2p::swarm::Config::with_tokio_executor()
        .with_idle_connection_timeout(Duration::from_secs(60));

    let mut swarm = libp2p::Swarm::new(transport, behaviour, peer_id, swarm_config);

    // Listeners
    let listen_addr: Multiaddr = std::env::var("RELAY_LISTEN_ADDR")
        .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/4001".to_string())
        .parse()?;
    swarm.listen_on(listen_addr)?;

    if let Ok(public) = std::env::var("RELAY_PUBLIC_MULTIADDR") {
        match public.parse::<Multiaddr>() {
            Ok(addr) => {
                swarm.add_external_address(addr);
            }
            Err(_) => log::debug!("RELAY_PUBLIC_MULTIADDR is not a valid Multiaddr: {public}"),
        }
    }

    // Event loop
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                log::info!("Relay listening on {address}/p2p/{peer_id}");
                log::info!("(Share the full address above as the client's relay endpoint)");
            }

            SwarmEvent::ConnectionEstablished {
                peer_id: remote, ..
            } => {
                log::info!("Peer connected: {remote}");
            }

            SwarmEvent::ConnectionClosed {
                peer_id: remote,
                num_established,
                ..
            } => {
                log::debug!("Peer disconnected: {remote} ({num_established} connection(s) left)");
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                log::debug!("Outgoing connection error ({peer_id:?}): {error:?}");
            }

            SwarmEvent::Behaviour(event) => match event {
                // Relay server events
                RelayBehaviorEvent::RelayServer(event) => match event {
                    relay::Event::ReservationReqAccepted {
                        src_peer_id,
                        renewed,
                    } => {
                        log::info!(
                            "Reservation {} for {src_peer_id}",
                            if renewed { "renewed" } else { "accepted" }
                        );

                        // Enforce the allowlist on new reservations
                        if !peer_allowed(&allowed_peers, &src_peer_id) {
                            if enforce_allowlist {
                                log::info!("{src_peer_id} is not in the allowlist — disconnecting (enforcement ON)");
                                let _ = swarm.disconnect_peer_id(src_peer_id);
                            } else {
                                log::info!("{src_peer_id} is NOT in the allowlist, but enforcement is OFF (set RELAY_ENFORCE_ALLOWLIST=1)");
                            }
                        }
                    }

                    relay::Event::CircuitReqAccepted {
                        src_peer_id,
                        dst_peer_id,
                    } => {
                        log::debug!("Circuit established: {src_peer_id} -> {dst_peer_id}");

                        if enforce_allowlist
                            && !(peer_allowed(&allowed_peers, &src_peer_id)
                                && peer_allowed(&allowed_peers, &dst_peer_id))
                        {
                            log::debug!("Circuit {src_peer_id} -> {dst_peer_id} blocked by allowlist — disconnecting source");
                            let _ = swarm.disconnect_peer_id(src_peer_id);
                        }
                    }
                    other => {
                        log::debug!("Relay server event: {other:?}");
                    }
                },

                RelayBehaviorEvent::RelayClient(event) => {
                    log::debug!("Relay client event: {event:?}");
                }

                // Identify and learn our own public address and register clients in the DHT
                RelayBehaviorEvent::Identify(identify::Event::Received {
                    peer_id: remote,
                    info,
                    ..
                }) => {
                    swarm.add_external_address(info.observed_addr.clone());

                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kademlia.add_address(&remote, addr);
                    }
                }
                RelayBehaviorEvent::Identify(_) => {}

                RelayBehaviorEvent::Kademlia(event) => {
                    log::debug!("Kademlia event: {event:?}");
                }

                RelayBehaviorEvent::Dcutr(event) => {
                    log::debug!("DCUtR event: {event:?}");
                }
            },

            _ => {}
        }
    }
}
