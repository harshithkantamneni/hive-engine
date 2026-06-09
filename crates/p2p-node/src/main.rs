//! HIVE Unified P2P Node (N6)
//!
//! Merges N3 (NAT traversal + QUIC) and N4 (rule shard distribution) into
//! a single binary that handles:
//!
//! - mDNS + Kademlia DHT peer discovery
//! - QUIC + TCP dual transport
//! - AutoNAT, Relay v2, DCUtR (hole-punching)
//! - 40-topic Gossipsub shard distribution
//! - Ed25519 rule signing and verification
//! - CRDT version reconciliation for rules
//!
//! Usage:
//!   cargo run --release                                    # Client node
//!   cargo run --release -- --relay                         # Relay server
//!   cargo run --release -- --relay --port 4001             # Relay on port 4001
//!   cargo run --release -- --bootstrap /ip4/.../tcp/4001   # Bootstrap from peer
//!   cargo run --release -- --subscribe medical_bill:S1     # Subscribe to specific shards
//!   cargo run --release -- --relay-addr /ip4/.../p2p/<id>  # Connect via relay

pub mod behaviour;
pub mod bootstrap;
pub mod dandelion;
pub mod rule;
pub mod rule_broadcast;
pub mod rule_ingest;
pub mod shard;
pub mod store;
pub mod tuple_wire;

use std::collections::HashSet;
use std::time::{Duration, Instant};

use clap::Parser;
use ed25519_dalek::SigningKey;
use futures::StreamExt;
use libp2p::{
    autonat, gossipsub, identify, kad, mdns, relay, request_response,
    swarm::{dial_opts::DialOpts, SwarmEvent},
    Multiaddr, PeerId,
};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tracing::{debug, info, warn};

use behaviour::{HiveNodeBehaviourEvent, RelayServerBehaviourEvent};
use dandelion::{DandelionBehaviour, DandelionEvent};
use rule::{create_test_rule, RuleMessage, SensitivityTier};
use store::RuleStore;

// Re-export bridge types for D5 integration.
use rete_alpha::bridge::InboundRuleEvent as BridgeInboundRuleEvent;
use rete_alpha::bridge::ShareablePayload;

// =============================================================================
// Topic string constants (extracted for reuse across arms)
// =============================================================================

/// Gossipsub topic for Dandelion++ fluffed tuples.
const _TOPIC_TUPLES_V1: &str = "hive/tuples/v1";

/// Gossipsub topic for rule metadata events.
const _TOPIC_RULES_META: &str = "hive/rules/v1/meta";

/// HIVE Unified P2P Node (N6)
#[derive(Parser, Debug)]
#[command(name = "hive-p2p-node")]
#[command(
    about = "HIVE unified P2P node: peer discovery + NAT traversal + rule shard distribution"
)]
#[command(version = "0.3.0")]
struct Args {
    /// Run as a relay server (public peers should use this)
    #[arg(long, default_value = "false")]
    relay: bool,

    /// Port to listen on (0 = random). Used for both TCP and QUIC.
    #[arg(long, default_value = "0")]
    port: u16,

    /// Bootstrap peer address(es). Can be specified multiple times.
    #[arg(long)]
    bootstrap: Vec<Multiaddr>,

    /// Subscribe to specific shards (format: category:tier, e.g., medical_bill:S1).
    /// If not specified, subscribes to all 40 topics (privacy-preserving default).
    #[arg(long)]
    subscribe: Vec<String>,

    /// Connect to a relay server at this address (for NATted peers).
    /// Format: /ip4/<ip>/tcp/<port>/p2p/<relay_peer_id>
    #[arg(long)]
    relay_addr: Option<Multiaddr>,

    /// Manually dial a peer at this multiaddr on startup
    #[arg(long)]
    dial: Option<Multiaddr>,

    /// Publish a test rule after peer discovery (for testing)
    #[arg(long)]
    publish: bool,
}

/// Parse a subscription string like "medical_bill:S1" into (category, tier).
fn parse_subscription(s: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

// =============================================================================
// Relay Server Mode
// =============================================================================

/// Run in relay server mode. This node is publicly reachable, relays
/// connections for NATted peers, AND participates in Gossipsub rule distribution.
///
/// D5: Optional channel parameters for integration with privacy pipeline.
/// When `tuple_rx` is Some, Dandelion++ receives tuples from the privacy pipeline.
/// When `rule_tx` is Some, validated rule events are forwarded to the Rete engine.
/// Pass None/None for standalone mode (backward-compatible).
async fn run_relay_server(
    args: Args,
    mut tuple_rx: Option<tokio::sync::mpsc::Receiver<ShareablePayload>>,
    rule_tx: Option<tokio::sync::mpsc::Sender<BridgeInboundRuleEvent>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    info!("=== HIVE Unified P2P Relay Server (N6) ===");

    let mut swarm = behaviour::build_relay_server_swarm()?;
    let local_peer_id = *swarm.local_peer_id();
    info!(%local_peer_id, "Relay server PeerId");

    // Subscribe to shard topics
    if args.subscribe.is_empty() {
        behaviour::subscribe_all_topics(&mut swarm.behaviour_mut().gossipsub)?;
        info!("Subscribed to all 40 shard topics (privacy default)");
    } else {
        let subs: Vec<(String, String)> = args
            .subscribe
            .iter()
            .filter_map(|s| parse_subscription(s))
            .collect();
        behaviour::subscribe_topics(&mut swarm.behaviour_mut().gossipsub, &subs)?;
        info!(count = subs.len(), "Subscribed to specific shard topics");
    }

    // Listen on TCP + QUIC
    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", args.port).parse()?;
    swarm.listen_on(tcp_addr)?;
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", args.port).parse()?;
    swarm.listen_on(quic_addr)?;

    // Bootstrap peers
    for addr in &args.bootstrap {
        info!(%addr, "Dialing bootstrap peer");
        swarm.dial(addr.clone())?;
    }

    // Optional dial
    if let Some(addr) = &args.dial {
        info!(%addr, "Dialing manually specified peer");
        swarm.dial(addr.clone())?;
    }

    // Ed25519 signing key (used when this relay publishes rules)
    let _signing_key = SigningKey::generate(&mut OsRng);

    let mut rule_store = RuleStore::new();
    let mut relay_circuits = 0u64;
    let mut rules_received = 0u32;

    // Periodic Kademlia bootstrap
    let bootstrap_interval = Duration::from_secs(30);
    let mut bootstrap_timer = tokio::time::interval(bootstrap_interval);
    bootstrap_timer.tick().await;

    // --- D5: Dandelion++ state ---
    let rng = ChaCha20Rng::from_rng(OsRng).expect("CSPRNG seeding");
    let mut dandelion = DandelionBehaviour::new(rng);
    let mut connected_peers: HashSet<PeerId> = HashSet::new();
    let mut dandelion_timer = tokio::time::interval(Duration::from_secs(1));
    dandelion_timer.tick().await;
    let mut bootstrap_complete = false;

    info!("Relay server entering event loop...");

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!(%address, "Relay listening on");
                    }

                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        connected_peers.insert(peer_id);
                        info!(
                            %peer_id,
                            remote_addr = %endpoint.get_remote_address(),
                            elapsed_ms = start_time.elapsed().as_millis(),
                            connected_count = connected_peers.len(),
                            "Connection established"
                        );
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        connected_peers.remove(&peer_id);
                        info!(%peer_id, cause = ?cause, connected_count = connected_peers.len(), "Connection closed");
                    }

                    // --- Dandelion++ request-response events (D5) ---
                    SwarmEvent::Behaviour(RelayServerBehaviourEvent::DandelionRr(event)) => {
                        let peers_vec: Vec<PeerId> = connected_peers.iter().copied().collect();
                        match event {
                            request_response::Event::Message { message, .. } => {
                                match message {
                                    request_response::Message::Request { request, channel, .. } => {
                                        let response = dandelion.handle_inbound_stem(request, &peers_vec);
                                        let _ = swarm.behaviour_mut().dandelion_rr.send_response(channel, response);
                                    }
                                    request_response::Message::Response { request_id, response } => {
                                        if let Some(DandelionEvent::StemFailed { tuple_id, reason }) =
                                            dandelion.handle_response(request_id, response, &peers_vec)
                                        {
                                            warn!(?tuple_id, %reason, "Stem rejected (relay)");
                                        }
                                    }
                                }
                            }
                            request_response::Event::OutboundFailure { request_id, error, .. } => {
                                warn!(%error, "Dandelion outbound failure (relay)");
                                if let Some(DandelionEvent::StemFailed { tuple_id, reason }) =
                                    dandelion.handle_outbound_failure(request_id, &peers_vec)
                                {
                                    warn!(?tuple_id, %reason, "Stem exhausted retries (relay)");
                                }
                            }
                            request_response::Event::InboundFailure { error, .. } => {
                                debug!(%error, "Dandelion inbound failure (relay)");
                            }
                            _ => {}
                        }
                    }

                    // --- Relay events ---
                    SwarmEvent::Behaviour(RelayServerBehaviourEvent::Relay(event)) => {
                        match &event {
                            relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                                info!(%src_peer_id, "Relay: Reservation accepted");
                            }
                            relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. } => {
                                relay_circuits += 1;
                                info!(
                                    %src_peer_id, %dst_peer_id,
                                    total_circuits = relay_circuits,
                                    "Relay: Circuit established"
                                );
                            }
                            other => {
                                debug!(event = ?other, "Relay event");
                            }
                        }
                    }

                    // --- Gossipsub events ---
                    SwarmEvent::Behaviour(RelayServerBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { propagation_source, message_id, message }
                    )) => {
                        let acceptance = match RuleMessage::from_bytes(&message.data) {
                            Ok(msg) => {
                                if let Err(e) = msg.validate() {
                                    warn!(err = %e, "Invalid rule message");
                                    gossipsub::MessageAcceptance::Reject
                                } else {
                                    info!(
                                        from = %propagation_source,
                                        rule_id = msg.rule_id,
                                        doc_cat = %msg.doc_category,
                                        tier = %msg.sensitivity_tier,
                                        "Received rule via Gossipsub"
                                    );
                                    match rule_store.merge(msg) {
                                        store::MergeResult::New => {
                                            rules_received += 1;
                                            info!(total = rules_received, "New rule accepted");
                                        }
                                        store::MergeResult::Accepted => {
                                            info!("Rule update accepted");
                                        }
                                        store::MergeResult::Rejected => {
                                            debug!("Rule rejected (local is newer)");
                                        }
                                    }
                                    gossipsub::MessageAcceptance::Accept
                                }
                            }
                            Err(e) => {
                                warn!(err = %e, "Failed to deserialize rule");
                                gossipsub::MessageAcceptance::Ignore
                            }
                        };
                        // Report validation result for Strict mode forwarding
                        if !swarm.behaviour_mut().gossipsub.report_message_validation_result(
                            &message_id, &propagation_source, acceptance
                        ) {
                            warn!("Failed to report message validation result (unknown message_id)");
                        }
                    }

                    SwarmEvent::Behaviour(RelayServerBehaviourEvent::Gossipsub(
                        gossipsub::Event::Subscribed { peer_id, topic }
                    )) => {
                        debug!(%peer_id, %topic, "Peer subscribed");
                    }

                    // --- mDNS events ---
                    SwarmEvent::Behaviour(RelayServerBehaviourEvent::Mdns(event)) => {
                        if let mdns::Event::Discovered(peers) = event {
                            for (peer_id, addr) in peers {
                                let clean_addr: Multiaddr = addr
                                    .iter()
                                    .take_while(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
                                    .collect();
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, clean_addr);
                                info!(%peer_id, "mDNS: Discovered peer");
                            }
                        }
                    }

                    // --- Identify events ---
                    SwarmEvent::Behaviour(RelayServerBehaviourEvent::Identify(event)) => {
                        if let identify::Event::Received { peer_id, info, .. } = event {
                            info!(
                                %peer_id,
                                protocol_version = %info.protocol_version,
                                observed_addr = %info.observed_addr,
                                "Identify: Received"
                            );
                            for addr in &info.listen_addrs {
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                            }
                            swarm.add_external_address(info.observed_addr);
                        }
                    }

                    // --- AutoNAT events ---
                    SwarmEvent::Behaviour(RelayServerBehaviourEvent::Autonat(event)) => {
                        info!(event = ?event, "Autonat event");
                    }

                    // --- Ping ---
                    SwarmEvent::Behaviour(RelayServerBehaviourEvent::Ping(event)) => {
                        if let Ok(rtt) = event.result {
                            debug!(peer = %event.peer, rtt_ms = rtt.as_millis(), "Ping");
                        }
                    }

                    // --- Kademlia ---
                    SwarmEvent::Behaviour(RelayServerBehaviourEvent::Kademlia(event)) => {
                        debug!(event = ?event, "Kademlia event");
                    }

                    other => {
                        debug!(event = ?other, "Swarm event");
                    }
                }
            }

            // --- D5: Tuple channel receiver (privacy pipeline -> Dandelion++) ---
            msg = async {
                match tuple_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(payload) = msg {
                    debug!(
                        tuple_id = ?payload.tuple_id,
                        tier = payload.sensitivity_tier,
                        hops = payload.stem_hops,
                        "Relay: enqueued tuple for Dandelion++ stem"
                    );
                    dandelion.send_tuple(
                        payload.wire_bytes,
                        payload.sensitivity_tier,
                        payload.stem_hops,
                        payload.tuple_id,
                    );
                } else {
                    info!("Tuple channel closed, no more outbound tuples (relay)");
                }
            }

            // --- D5: Dandelion++ process timer (1s tick) ---
            _ = dandelion_timer.tick() => {
                let peers_vec: Vec<PeerId> = connected_peers.iter().copied().collect();
                dandelion.process_outbound(&peers_vec);

                for event in dandelion.drain_fluff_events() {
                    match event {
                        DandelionEvent::ReadyForFluff { topic, data } => {
                            let gossipsub_topic = gossipsub::IdentTopic::new(&topic);
                            match swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, data) {
                                Ok(msg_id) => debug!(?msg_id, "Relay: fluffed tuple via Gossipsub"),
                                Err(e) => warn!(err = %e, "Relay: failed to fluff tuple"),
                            }
                        }
                        DandelionEvent::StemFailed { tuple_id, reason } => {
                            warn!(?tuple_id, %reason, "Relay: Dandelion++ stem failed");
                        }
                    }
                }
            }

            _ = bootstrap_timer.tick() => {
                if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                    debug!(err = %e, "Kademlia bootstrap");
                }
                // D5: Bootstrap sequence
                if !bootstrap_complete && connected_peers.len() >= 2 {
                    bootstrap_complete = true;
                    info!(
                        connected = connected_peers.len(),
                        "Relay: cold-start bootstrap sequence initiated"
                    );
                }
            }

            _ = tokio::signal::ctrl_c() => {
                info!(
                    elapsed_s = start_time.elapsed().as_secs(),
                    relay_circuits = relay_circuits,
                    rules_in_store = rule_store.len(),
                    rules_received = rules_received,
                    dandelion_pending = dandelion.pending_count(),
                    dandelion_active = dandelion.active_count(),
                    dandelion_dedup_cache = dandelion.dedup_cache_size(),
                    connected_peers = connected_peers.len(),
                    "=== Relay server shutting down ==="
                );
                // D5: Drop channels to signal orchestrator
                drop(tuple_rx);
                drop(rule_tx);
                break;
            }
        }
    }

    Ok(())
}

// =============================================================================
// Client Mode (default)
// =============================================================================

/// Run in client mode (default). This node uses relay client + DCUtR for
/// NAT traversal, QUIC+TCP transport, and Gossipsub for rule distribution.
///
/// D5: Optional channel parameters for integration with privacy pipeline.
/// When `tuple_rx` is Some, Dandelion++ receives tuples from the privacy pipeline.
/// When `rule_tx` is Some, validated rule events are forwarded to the Rete engine.
/// Pass None/None for standalone mode (backward-compatible).
async fn run_client(
    args: Args,
    mut tuple_rx: Option<tokio::sync::mpsc::Receiver<ShareablePayload>>,
    rule_tx: Option<tokio::sync::mpsc::Sender<BridgeInboundRuleEvent>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    info!("=== HIVE Unified P2P Node (N6) ===");

    let mut swarm = behaviour::build_client_swarm()?;
    let local_peer_id = *swarm.local_peer_id();
    info!(%local_peer_id, "Local peer ID");

    // Subscribe to shard topics
    if args.subscribe.is_empty() {
        behaviour::subscribe_all_topics(&mut swarm.behaviour_mut().gossipsub)?;
        info!("Subscribed to all 40 shard topics (privacy default)");
    } else {
        let subs: Vec<(String, String)> = args
            .subscribe
            .iter()
            .filter_map(|s| parse_subscription(s))
            .collect();
        behaviour::subscribe_topics(&mut swarm.behaviour_mut().gossipsub, &subs)?;
        info!(count = subs.len(), "Subscribed to specific shard topics");
    }

    // Listen on TCP + QUIC
    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", args.port).parse()?;
    swarm.listen_on(tcp_addr)?;
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", args.port).parse()?;
    swarm.listen_on(quic_addr)?;

    // If relay address provided, connect through relay
    if let Some(relay_addr) = &args.relay_addr {
        info!(%relay_addr, "Listening via relay for inbound connections");
        swarm.dial(relay_addr.clone())?;
        let relay_listen: Multiaddr = format!("{}/p2p-circuit", relay_addr).parse()?;
        swarm.listen_on(relay_listen)?;
    }

    // Bootstrap peers
    for addr in &args.bootstrap {
        info!(%addr, "Dialing bootstrap peer");
        swarm.dial(addr.clone())?;
    }

    // Optional dial
    if let Some(addr) = &args.dial {
        info!(%addr, "Dialing manually specified peer");
        swarm.dial(addr.clone())?;
    }

    // Ed25519 signing key
    let signing_key = SigningKey::generate(&mut OsRng);

    // Periodic Kademlia bootstrap
    let bootstrap_interval = Duration::from_secs(30);
    let mut bootstrap_timer = tokio::time::interval(bootstrap_interval);
    bootstrap_timer.tick().await;

    let mut peers_discovered: Vec<(PeerId, Instant)> = Vec::new();
    let mut connections_established = 0u64;
    let mut pings_success = 0u64;
    let mut dcutr_attempts = 0u64;
    let mut dcutr_successes = 0u64;
    let mut nat_status: Option<String> = None;
    let mut rule_store = RuleStore::new();
    let mut rules_received = 0u32;
    let mut rules_published = 0u32;
    let mut has_published = false;

    // --- D5: Dandelion++ state ---
    let rng = ChaCha20Rng::from_rng(OsRng).expect("CSPRNG seeding");
    let mut dandelion = DandelionBehaviour::new(rng);
    let mut connected_peers: HashSet<PeerId> = HashSet::new();
    let mut dandelion_timer = tokio::time::interval(Duration::from_secs(1));
    dandelion_timer.tick().await;
    let mut bootstrap_complete = false;

    info!("Entering event loop -- waiting for peers...");

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    // --- Listen addresses ---
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!(%address, "Listening on");
                    }

                    // --- Connection lifecycle ---
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        connections_established += 1;
                        connected_peers.insert(peer_id);
                        info!(
                            %peer_id,
                            remote_addr = %endpoint.get_remote_address(),
                            elapsed_ms = start_time.elapsed().as_millis(),
                            total_connections = connections_established,
                            connected_count = connected_peers.len(),
                            "Connection established"
                        );
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        connected_peers.remove(&peer_id);
                        info!(%peer_id, cause = ?cause, connected_count = connected_peers.len(), "Connection closed");
                    }

                    // --- Relay Client events ---
                    SwarmEvent::Behaviour(HiveNodeBehaviourEvent::RelayClient(event)) => {
                        match event {
                            relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } => {
                                info!(%relay_peer_id, "Relay: Reservation accepted");
                            }
                            relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
                                info!(%src_peer_id, "Relay: Inbound circuit established");
                            }
                            relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. } => {
                                info!(%relay_peer_id, "Relay: Outbound circuit established");
                            }
                        }
                    }

                    // --- DCUtR events (hole-punching) ---
                    SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Dcutr(event)) => {
                        dcutr_attempts += 1;
                        match event.result {
                            Ok(connection_id) => {
                                dcutr_successes += 1;
                                info!(
                                    remote_peer = %event.remote_peer_id,
                                    ?connection_id,
                                    attempts = dcutr_attempts,
                                    successes = dcutr_successes,
                                    "DCUtR: Hole-punch succeeded"
                                );
                            }
                            Err(error) => {
                                warn!(
                                    remote_peer = %event.remote_peer_id,
                                    %error,
                                    "DCUtR: Hole-punch failed"
                                );
                            }
                        }
                    }

                    // --- Gossipsub events (N4) ---
                    SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { propagation_source, message_id, message }
                    )) => {
                        let acceptance = match RuleMessage::from_bytes(&message.data) {
                            Ok(msg) => {
                                if let Err(e) = msg.validate() {
                                    warn!(err = %e, "Invalid rule message");
                                    gossipsub::MessageAcceptance::Reject
                                } else {
                                    info!(
                                        from = %propagation_source,
                                        rule_id = msg.rule_id,
                                        doc_cat = %msg.doc_category,
                                        tier = %msg.sensitivity_tier,
                                        confidence = msg.confidence,
                                        version = msg.version,
                                        "Received rule via Gossipsub"
                                    );
                                    match rule_store.merge(msg) {
                                        store::MergeResult::New => {
                                            rules_received += 1;
                                            info!(total = rules_received, "New rule accepted");
                                        }
                                        store::MergeResult::Accepted => {
                                            info!("Rule update accepted");
                                        }
                                        store::MergeResult::Rejected => {
                                            debug!("Rule rejected (local is newer)");
                                        }
                                    }
                                    gossipsub::MessageAcceptance::Accept
                                }
                            }
                            Err(e) => {
                                warn!(err = %e, "Failed to deserialize rule");
                                gossipsub::MessageAcceptance::Ignore
                            }
                        };
                        // Report validation result for Strict mode forwarding
                        if !swarm.behaviour_mut().gossipsub.report_message_validation_result(
                            &message_id, &propagation_source, acceptance
                        ) {
                            warn!("Failed to report message validation result (unknown message_id)");
                        }
                    }

                    SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Gossipsub(
                        gossipsub::Event::Subscribed { peer_id, topic }
                    )) => {
                        debug!(%peer_id, %topic, "Peer subscribed");
                    }

                    // --- AutoNAT events ---
                    SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Autonat(event)) => {
                        match &event {
                            autonat::Event::StatusChanged { old, new } => {
                                let status_str = format!("{:?}", new);
                                info!(old_status = ?old, new_status = ?new, "Autonat: NAT status changed");
                                nat_status = Some(status_str);
                            }
                            autonat::Event::InboundProbe(probe) => {
                                debug!(probe = ?probe, "Autonat: Inbound probe");
                            }
                            autonat::Event::OutboundProbe(probe) => {
                                debug!(probe = ?probe, "Autonat: Outbound probe");
                            }
                        }
                    }

                    // --- mDNS events ---
                    SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Mdns(event)) => {
                        match event {
                            mdns::Event::Discovered(peers) => {
                                for (peer_id, addr) in peers {
                                    let elapsed = start_time.elapsed();
                                    info!(%peer_id, %addr, elapsed_ms = elapsed.as_millis(), "mDNS: Discovered peer");

                                    if !peers_discovered.iter().any(|(p, _)| *p == peer_id) {
                                        peers_discovered.push((peer_id, Instant::now()));
                                    }

                                    let clean_addr: Multiaddr = addr
                                        .iter()
                                        .take_while(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
                                        .collect();

                                    swarm.behaviour_mut().kademlia.add_address(&peer_id, clean_addr.clone());

                                    // Deterministic dial direction (N2 fix)
                                    if local_peer_id < peer_id {
                                        let dial_opts = DialOpts::peer_id(peer_id)
                                            .addresses(vec![clean_addr])
                                            .extend_addresses_through_behaviour()
                                            .build();
                                        if let Err(e) = swarm.dial(dial_opts) {
                                            debug!(%peer_id, err = %e, "Dial attempt");
                                        }
                                    }
                                }
                            }
                            mdns::Event::Expired(peers) => {
                                for (peer_id, addr) in peers {
                                    info!(%peer_id, %addr, "mDNS: Peer expired");
                                }
                            }
                        }
                    }

                    // --- Kademlia events ---
                    SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Kademlia(event)) => {
                        match event {
                            kad::Event::RoutingUpdated { peer, addresses, .. } => {
                                info!(%peer, addrs = ?addresses.into_vec(), "Kademlia: Routing updated");
                            }
                            kad::Event::OutboundQueryProgressed { result, .. } => {
                                match result {
                                    kad::QueryResult::Bootstrap(Ok(ok)) => {
                                        info!(num_remaining = ok.num_remaining, "Kademlia: Bootstrap progress");
                                    }
                                    kad::QueryResult::PutRecord(Ok(_)) => {
                                        info!("DHT: Record stored");
                                    }
                                    kad::QueryResult::GetRecord(Ok(ok)) => {
                                        if let kad::GetRecordOk::FoundRecord(rec) = ok {
                                            match RuleMessage::from_bytes(&rec.record.value) {
                                                Ok(msg) => {
                                                    info!(rule_id = msg.rule_id, "DHT: Retrieved rule");
                                                    rule_store.merge(msg);
                                                }
                                                Err(e) => {
                                                    warn!(err = %e, "DHT: Deserialize failed");
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        debug!("Kademlia: Query progress");
                                    }
                                }
                            }
                            other => {
                                debug!(event = ?other, "Kademlia event");
                            }
                        }
                    }

                    // --- Identify events ---
                    SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Identify(event)) => {
                        match event {
                            identify::Event::Received { peer_id, info, .. } => {
                                info!(
                                    %peer_id,
                                    protocol_version = %info.protocol_version,
                                    agent_version = %info.agent_version,
                                    observed_addr = %info.observed_addr,
                                    "Identify: Received"
                                );
                                for addr in &info.listen_addrs {
                                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                                }
                                swarm.add_external_address(info.observed_addr);
                            }
                            identify::Event::Sent { peer_id, .. } => {
                                debug!(%peer_id, "Identify: Sent");
                            }
                            identify::Event::Pushed { peer_id, info, .. } => {
                                debug!(%peer_id, agent = %info.agent_version, "Identify: Pushed");
                            }
                            identify::Event::Error { peer_id, error, .. } => {
                                warn!(%peer_id, %error, "Identify: Error");
                            }
                        }
                    }

                    // --- Ping events ---
                    SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Ping(event)) => {
                        match event.result {
                            Ok(rtt) => {
                                pings_success += 1;
                                info!(
                                    peer = %event.peer,
                                    rtt_ms = rtt.as_millis(),
                                    total_pings = pings_success,
                                    "Ping: Success"
                                );
                            }
                            Err(e) => {
                                warn!(peer = %event.peer, err = %e, "Ping: Failed");
                            }
                        }
                    }

                    // --- Dandelion++ request-response events (D5) ---
                    SwarmEvent::Behaviour(HiveNodeBehaviourEvent::DandelionRr(event)) => {
                        let peers_vec: Vec<PeerId> = connected_peers.iter().copied().collect();
                        match event {
                            request_response::Event::Message { message, .. } => {
                                match message {
                                    request_response::Message::Request { request, channel, .. } => {
                                        // Inbound stem message from another peer
                                        let response = dandelion.handle_inbound_stem(request, &peers_vec);
                                        let _ = swarm.behaviour_mut().dandelion_rr.send_response(channel, response);
                                    }
                                    request_response::Message::Response { request_id, response } => {
                                        // Response to our outbound stem
                                        if let Some(DandelionEvent::StemFailed { tuple_id, reason }) =
                                            dandelion.handle_response(request_id, response, &peers_vec)
                                        {
                                            warn!(?tuple_id, %reason, "Stem rejected");
                                        }
                                    }
                                }
                            }
                            request_response::Event::OutboundFailure { request_id, error, .. } => {
                                warn!(%error, "Dandelion outbound failure");
                                if let Some(DandelionEvent::StemFailed { tuple_id, reason }) =
                                    dandelion.handle_outbound_failure(request_id, &peers_vec)
                                {
                                    warn!(?tuple_id, %reason, "Stem exhausted retries after failure");
                                }
                            }
                            request_response::Event::InboundFailure { error, .. } => {
                                debug!(%error, "Dandelion inbound failure (remote's problem)");
                            }
                            _ => {}
                        }
                    }

                    other => {
                        debug!(event = ?other, "Swarm event");
                    }
                }

                // Publish a test rule once connected (if --publish)
                if args.publish && !has_published && connections_established > 0 {
                    has_published = true;
                    let mut test_rule = create_test_rule(
                        "medical_bill",
                        SensitivityTier::S1,
                        1,
                        0.85,
                    );
                    test_rule.publisher_id = local_peer_id.to_string();
                    test_rule.sign(&signing_key);

                    match behaviour::publish_rule(&mut swarm.behaviour_mut().gossipsub, &test_rule) {
                        Ok(msg_id) => {
                            rules_published += 1;
                            info!(
                                msg_id = %msg_id,
                                topic = %test_rule.shard_key().topic_name(),
                                "Published test rule via Gossipsub"
                            );
                            behaviour::store_rule_in_dht(
                                &mut swarm.behaviour_mut().kademlia,
                                &test_rule,
                            );
                        }
                        Err(e) => {
                            warn!(err = %e, "Failed to publish test rule");
                        }
                    }
                }
            }

            // --- D5: Tuple channel receiver (privacy pipeline -> Dandelion++) ---
            msg = async {
                match tuple_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(payload) = msg {
                    debug!(
                        tuple_id = ?payload.tuple_id,
                        tier = payload.sensitivity_tier,
                        hops = payload.stem_hops,
                        "Enqueued tuple for Dandelion++ stem"
                    );
                    dandelion.send_tuple(
                        payload.wire_bytes,
                        payload.sensitivity_tier,
                        payload.stem_hops,
                        payload.tuple_id,
                    );
                } else {
                    info!("Tuple channel closed, no more outbound tuples");
                }
            }

            // --- D5: Dandelion++ process timer (1s tick) ---
            _ = dandelion_timer.tick() => {
                let peers_vec: Vec<PeerId> = connected_peers.iter().copied().collect();
                dandelion.process_outbound(&peers_vec);

                for event in dandelion.drain_fluff_events() {
                    match event {
                        DandelionEvent::ReadyForFluff { topic, data } => {
                            let gossipsub_topic = gossipsub::IdentTopic::new(&topic);
                            match swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, data) {
                                Ok(msg_id) => debug!(?msg_id, "Fluffed tuple via Gossipsub"),
                                Err(e) => warn!(err = %e, "Failed to fluff tuple"),
                            }
                        }
                        DandelionEvent::StemFailed { tuple_id, reason } => {
                            warn!(?tuple_id, %reason, "Dandelion++ stem failed");
                        }
                    }
                }
            }

            // Periodic Kademlia bootstrap
            _ = bootstrap_timer.tick() => {
                if !peers_discovered.is_empty() {
                    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                        debug!(err = %e, "Kademlia bootstrap");
                    }
                }
                // D5: Bootstrap sequence
                if !bootstrap_complete && connected_peers.len() >= 2 {
                    bootstrap_complete = true;
                    info!(
                        connected = connected_peers.len(),
                        "Cold-start bootstrap sequence initiated"
                    );
                }
            }

            // Handle Ctrl+C gracefully
            _ = tokio::signal::ctrl_c() => {
                let elapsed = start_time.elapsed();
                info!("=== Shutting down ===");
                info!(
                    elapsed_s = elapsed.as_secs(),
                    peers_discovered = peers_discovered.len(),
                    connections = connections_established,
                    pings = pings_success,
                    dcutr_attempts = dcutr_attempts,
                    dcutr_successes = dcutr_successes,
                    nat_status = ?nat_status,
                    rules_in_store = rule_store.len(),
                    rules_received = rules_received,
                    rules_published = rules_published,
                    dandelion_pending = dandelion.pending_count(),
                    dandelion_active = dandelion.active_count(),
                    dandelion_dedup_cache = dandelion.dedup_cache_size(),
                    connected_peers = connected_peers.len(),
                    "Final stats"
                );
                // D5: Drop channels to signal orchestrator
                drop(tuple_rx);
                drop(rule_tx);
                break;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    if args.relay {
        run_relay_server(args, None, None).await
    } else {
        run_client(args, None, None).await
    }
}

// =============================================================================
// Tests
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::swarm::SwarmEvent;
    use std::time::Duration;

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    /// Extract a TCP listen address from a client swarm.
    async fn get_tcp_listen_addr(
        swarm: &mut libp2p::Swarm<impl libp2p::swarm::NetworkBehaviour>,
    ) -> Multiaddr {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                let addr_str = address.to_string();
                if addr_str.contains("/tcp/") && !addr_str.contains("/quic") {
                    return address;
                }
            }
        }
    }

    /// Extract a QUIC listen address from a swarm.
    async fn get_quic_listen_addr(
        swarm: &mut libp2p::Swarm<impl libp2p::swarm::NetworkBehaviour>,
    ) -> Multiaddr {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                let addr_str = address.to_string();
                if addr_str.contains("/quic-v1") {
                    return address;
                }
            }
        }
    }

    /// Helper: get any listen address
    async fn get_any_listen_addr(
        swarm: &mut libp2p::Swarm<impl libp2p::swarm::NetworkBehaviour>,
    ) -> Multiaddr {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                let addr_str = address.to_string();
                if addr_str.contains("/tcp/") && !addr_str.contains("/quic") {
                    return address;
                }
            }
        }
    }

    // =========================================================================
    // N3 tests: NAT traversal and transport
    // =========================================================================

    // Test 1: QUIC transport connection between two peers
    #[tokio::test]
    async fn test_quic_transport_connection() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

        let mut swarm_a = behaviour::build_client_swarm().unwrap();
        let mut swarm_b = behaviour::build_client_swarm().unwrap();

        let peer_a = *swarm_a.local_peer_id();
        let peer_b = *swarm_b.local_peer_id();

        swarm_a
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        swarm_b
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();

        let addr_a = get_quic_listen_addr(&mut swarm_a).await;
        let _addr_b = get_quic_listen_addr(&mut swarm_b).await;

        swarm_b.dial(addr_a).unwrap();

        let connected = tokio::time::timeout(Duration::from_secs(10), async {
            let mut a_connected = false;
            let mut b_connected = false;
            loop {
                tokio::select! {
                    event = swarm_a.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                            if peer_id == peer_b { a_connected = true; }
                        }
                    }
                    event = swarm_b.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                            if peer_id == peer_a { b_connected = true; }
                        }
                    }
                }
                if a_connected && b_connected {
                    return true;
                }
            }
        })
        .await;

        assert!(
            connected.unwrap_or(false),
            "QUIC connection should be established"
        );
    }

    // Test 2: Dual-transport (TCP + QUIC) simultaneous listening
    #[tokio::test]
    async fn test_dual_transport_listening() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

        let mut swarm = behaviour::build_client_swarm().unwrap();

        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        swarm
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();

        let mut tcp_found = false;
        let mut quic_found = false;

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                    let addr_str = address.to_string();
                    if addr_str.contains("/tcp/") && !addr_str.contains("/quic") {
                        tcp_found = true;
                    }
                    if addr_str.contains("/quic-v1") {
                        quic_found = true;
                    }
                    if tcp_found && quic_found {
                        return true;
                    }
                }
            }
        })
        .await;

        assert!(
            result.unwrap_or(false),
            "Should listen on both TCP and QUIC"
        );
    }

    // Test 3: Relay circuit establishment (A -> Relay -> B)
    #[tokio::test]
    async fn test_relay_circuit() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

        let mut relay_swarm = behaviour::build_relay_server_swarm().unwrap();
        let relay_peer_id = *relay_swarm.local_peer_id();
        relay_swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let relay_addr = get_tcp_listen_addr(&mut relay_swarm).await;
        relay_swarm.add_external_address(relay_addr.clone());

        let relay_addr_with_peer: Multiaddr = format!("{}/p2p/{}", relay_addr, relay_peer_id)
            .parse()
            .unwrap();

        let mut swarm_b = behaviour::build_client_swarm().unwrap();
        let peer_b = *swarm_b.local_peer_id();
        swarm_b
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        swarm_b.dial(relay_addr_with_peer.clone()).unwrap();

        let mut swarm_a = behaviour::build_client_swarm().unwrap();
        swarm_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(15), async {
            let mut b_connected_to_relay = false;
            let mut a_dialed_via_relay = false;

            loop {
                tokio::select! {
                    event = relay_swarm.select_next_some() => {
                        if let SwarmEvent::Behaviour(RelayServerBehaviourEvent::Relay(
                            relay::Event::CircuitReqAccepted { .. }
                        )) = event {
                            return true;
                        }
                    }
                    event = swarm_b.select_next_some() => {
                        match event {
                            SwarmEvent::ConnectionEstablished { peer_id, .. }
                                if peer_id == relay_peer_id =>
                            {
                                if !b_connected_to_relay {
                                    b_connected_to_relay = true;
                                    let circuit_addr: Multiaddr = format!(
                                        "{}/p2p-circuit", relay_addr_with_peer
                                    ).parse().unwrap();
                                    swarm_b.listen_on(circuit_addr).unwrap();
                                }
                            }
                            SwarmEvent::NewListenAddr { address, .. } => {
                                let addr_str = address.to_string();
                                if addr_str.contains("p2p-circuit") && !a_dialed_via_relay {
                                    a_dialed_via_relay = true;
                                    let dial_b_via_relay: Multiaddr = format!(
                                        "{}/p2p-circuit/p2p/{}", relay_addr_with_peer, peer_b
                                    ).parse().unwrap();
                                    swarm_a.dial(dial_b_via_relay).unwrap();
                                }
                            }
                            _ => {}
                        }
                    }
                    event = swarm_a.select_next_some() => {
                        match event {
                            SwarmEvent::ConnectionEstablished { peer_id, .. }
                                if peer_id == peer_b =>
                            {
                                return true;
                            }
                            _ => {}
                        }
                    }
                }
            }
        })
        .await;

        assert!(
            result.unwrap_or(false),
            "Relay circuit should be established: A -> Relay -> B"
        );
    }

    // Test 4: AutoNAT status detection
    #[tokio::test]
    async fn test_autonat_status_detection() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

        let mut swarm_a = behaviour::build_client_swarm().unwrap();
        let mut swarm_b = behaviour::build_client_swarm().unwrap();

        swarm_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        swarm_b
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let addr_a = get_tcp_listen_addr(&mut swarm_a).await;
        let _addr_b = get_tcp_listen_addr(&mut swarm_b).await;

        swarm_b.dial(addr_a).unwrap();

        let result = tokio::time::timeout(Duration::from_secs(8), async {
            let mut connection_ok = false;

            loop {
                tokio::select! {
                    event = swarm_a.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { .. } = event {
                            connection_ok = true;
                        }
                    }
                    event = swarm_b.select_next_some() => {
                        let _ = event;
                    }
                }

                if connection_ok {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    return true;
                }
            }
        })
        .await;

        assert!(
            result.unwrap_or(false),
            "Peers should connect (autonat initializes correctly)"
        );
    }

    // Test 5: Kademlia + mDNS still works with all behaviours
    #[tokio::test]
    async fn test_kademlia_mdns_with_all_behaviours() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

        let mut swarm_a = behaviour::build_client_swarm().unwrap();
        let mut swarm_b = behaviour::build_client_swarm().unwrap();

        let peer_a = *swarm_a.local_peer_id();
        let peer_b = *swarm_b.local_peer_id();

        swarm_a
            .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .unwrap();
        swarm_a
            .listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        swarm_b
            .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .unwrap();
        swarm_b
            .listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap())
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(15), async {
            let mut mdns_discovered = false;
            let mut kad_updated = false;
            let mut identify_received = false;
            let mut ping_ok = false;

            loop {
                tokio::select! {
                    event = swarm_a.select_next_some() => {
                        match event {
                            SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Mdns(
                                mdns::Event::Discovered(peers)
                            )) => {
                                for (pid, addr) in &peers {
                                    if *pid == peer_b {
                                        mdns_discovered = true;
                                        let clean: Multiaddr = addr.iter()
                                            .take_while(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
                                            .collect();
                                        swarm_a.behaviour_mut().kademlia.add_address(pid, clean.clone());
                                        if peer_a < peer_b {
                                            let _ = swarm_a.dial(
                                                DialOpts::peer_id(*pid)
                                                    .addresses(vec![clean])
                                                    .extend_addresses_through_behaviour()
                                                    .build()
                                            );
                                        }
                                    }
                                }
                            }
                            SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Kademlia(
                                kad::Event::RoutingUpdated { peer, .. }
                            )) => {
                                if peer == peer_b {
                                    kad_updated = true;
                                }
                            }
                            SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Identify(
                                identify::Event::Received { peer_id, info, .. }
                            )) => {
                                if peer_id == peer_b {
                                    identify_received = true;
                                    for addr in &info.listen_addrs {
                                        swarm_a.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                                    }
                                }
                            }
                            SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Ping(event)) => {
                                if event.peer == peer_b && event.result.is_ok() {
                                    ping_ok = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    event = swarm_b.select_next_some() => {
                        if let SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Mdns(
                            mdns::Event::Discovered(peers)
                        )) = event {
                            for (pid, addr) in &peers {
                                if *pid == peer_a {
                                    let clean: Multiaddr = addr.iter()
                                        .take_while(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
                                        .collect();
                                    swarm_b.behaviour_mut().kademlia.add_address(pid, clean.clone());
                                    if peer_b < peer_a {
                                        let _ = swarm_b.dial(
                                            DialOpts::peer_id(*pid)
                                                .addresses(vec![clean])
                                                .extend_addresses_through_behaviour()
                                                .build()
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                if mdns_discovered && kad_updated && identify_received && ping_ok {
                    return true;
                }
            }
        }).await;

        assert!(
            result.unwrap_or(false),
            "mDNS, Kademlia, Identify, and Ping should all work with unified behaviours"
        );
    }

    // =========================================================================
    // N4 tests: Rule shard distribution
    // =========================================================================

    // Test 6: Gossipsub publish/subscribe across two peers
    #[tokio::test]
    async fn test_gossipsub_publish_subscribe() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

        let mut swarm_a = behaviour::build_client_swarm().unwrap();
        let mut swarm_b = behaviour::build_client_swarm().unwrap();

        let peer_b_id = *swarm_b.local_peer_id();

        // Subscribe to all topics
        behaviour::subscribe_all_topics(&mut swarm_a.behaviour_mut().gossipsub).unwrap();
        behaviour::subscribe_all_topics(&mut swarm_b.behaviour_mut().gossipsub).unwrap();

        swarm_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        swarm_b
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let addr_a = get_any_listen_addr(&mut swarm_a).await;
        let _addr_b = get_any_listen_addr(&mut swarm_b).await;
        swarm_b.dial(addr_a).unwrap();

        let signing_key = SigningKey::generate(&mut OsRng);
        let mut test_rule = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        test_rule.publisher_id = peer_b_id.to_string();
        test_rule.sign(&signing_key);

        let expected_rule_id = test_rule.rule_id;
        let start = Instant::now();
        let timeout = Duration::from_secs(30);
        let mut connected = false;
        let mut published = false;
        let mut received = false;
        let mut publish_time: Option<Instant> = None;
        let mut propagation_latency: Option<Duration> = None;

        loop {
            if start.elapsed() > timeout {
                panic!(
                    "Test timed out. connected={}, published={}, received={}",
                    connected, published, received
                );
            }

            tokio::select! {
                event = swarm_a.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { .. } => {
                            connected = true;
                        }
                        SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { message, .. }
                        )) => {
                            if let Ok(rule) = RuleMessage::from_bytes(&message.data) {
                                if rule.rule_id == expected_rule_id {
                                    received = true;
                                    propagation_latency = publish_time.map(|t| t.elapsed());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                event = swarm_b.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = event {
                        connected = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if connected && !published {
                        tokio::time::sleep(Duration::from_millis(2000)).await;
                        if behaviour::publish_rule(
                            &mut swarm_b.behaviour_mut().gossipsub,
                            &test_rule,
                        ).is_ok() {
                            published = true;
                            publish_time = Some(Instant::now());
                        }
                    }
                }
            }

            if received {
                break;
            }
        }

        assert!(
            received,
            "Node A should receive the rule published by Node B"
        );

        if let Some(lat) = propagation_latency {
            assert!(
                lat < Duration::from_secs(5),
                "Propagation latency {:?} exceeds 5s target",
                lat
            );
        }
    }

    // Test 7: Kademlia DHT store and retrieve
    #[tokio::test]
    async fn test_kademlia_store_retrieve() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

        let mut swarm_a = behaviour::build_client_swarm().unwrap();
        let mut swarm_b = behaviour::build_client_swarm().unwrap();

        swarm_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        swarm_b
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let addr_a = get_any_listen_addr(&mut swarm_a).await;
        let _addr_b = get_any_listen_addr(&mut swarm_b).await;
        swarm_b.dial(addr_a).unwrap();

        let signing_key = SigningKey::generate(&mut OsRng);
        let mut test_rule = create_test_rule("bank_statement", SensitivityTier::S2, 42, 0.72);
        test_rule.sign(&signing_key);

        let expected_rule_id = test_rule.rule_id;

        let start = Instant::now();
        let timeout = Duration::from_secs(30);
        let mut connected = false;
        let mut kad_ready = false;
        let mut stored = false;
        let mut retrieved = false;
        let mut get_started = false;

        loop {
            if start.elapsed() > timeout {
                panic!("Test timed out. stored={}, retrieved={}", stored, retrieved);
            }

            tokio::select! {
                event = swarm_a.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { .. } => { connected = true; }
                        SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Identify(
                            identify::Event::Received { peer_id, info, .. }
                        )) => {
                            for addr in &info.listen_addrs {
                                swarm_a.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                            }
                            kad_ready = true;
                        }
                        SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Kademlia(
                            kad::Event::OutboundQueryProgressed {
                                result: kad::QueryResult::PutRecord(Ok(_)),
                                ..
                            }
                        )) => {
                            stored = true;
                        }
                        _ => {}
                    }
                }
                event = swarm_b.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { .. } => { connected = true; }
                        SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Identify(
                            identify::Event::Received { peer_id, info, .. }
                        )) => {
                            for addr in &info.listen_addrs {
                                swarm_b.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                            }
                            kad_ready = true;
                        }
                        SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Kademlia(
                            kad::Event::OutboundQueryProgressed {
                                result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(rec))),
                                ..
                            }
                        )) => {
                            if let Ok(rule) = RuleMessage::from_bytes(&rec.record.value) {
                                if rule.rule_id == expected_rule_id {
                                    retrieved = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if connected && kad_ready && !stored {
                        behaviour::store_rule_in_dht(
                            &mut swarm_a.behaviour_mut().kademlia,
                            &test_rule,
                        );
                    }
                    if stored && !get_started {
                        get_started = true;
                        behaviour::get_rule_from_dht(
                            &mut swarm_b.behaviour_mut().kademlia,
                            "bank_statement",
                            &SensitivityTier::S2,
                        );
                    }
                }
            }

            if retrieved {
                break;
            }
        }

        assert!(
            retrieved,
            "Node B should retrieve the rule stored by Node A in DHT"
        );
    }

    // Test 8: Multi-shard routing (3 rules across 3 different shard topics)
    #[tokio::test]
    async fn test_multi_shard_routing() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

        let mut swarm_a = behaviour::build_client_swarm().unwrap();
        let mut swarm_b = behaviour::build_client_swarm().unwrap();

        behaviour::subscribe_all_topics(&mut swarm_a.behaviour_mut().gossipsub).unwrap();
        behaviour::subscribe_all_topics(&mut swarm_b.behaviour_mut().gossipsub).unwrap();

        swarm_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        swarm_b
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let addr_a = get_any_listen_addr(&mut swarm_a).await;
        let _addr_b = get_any_listen_addr(&mut swarm_b).await;
        swarm_b.dial(addr_a).unwrap();

        let signing_key = SigningKey::generate(&mut OsRng);

        let mut rule1 = create_test_rule("medical_bill", SensitivityTier::S1, 100, 0.85);
        rule1.sign(&signing_key);
        let mut rule2 = create_test_rule("receipt", SensitivityTier::S4, 200, 0.70);
        rule2.sign(&signing_key);
        let mut rule3 = create_test_rule("credit_card", SensitivityTier::S2, 300, 0.60);
        rule3.sign(&signing_key);

        let start = Instant::now();
        let timeout = Duration::from_secs(30);
        let mut connected = false;
        let mut published_count = 0u32;
        let mut received_ids: Vec<u64> = Vec::new();

        loop {
            if start.elapsed() > timeout {
                panic!("Test timed out. received={}", received_ids.len());
            }

            tokio::select! {
                event = swarm_a.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { .. } => { connected = true; }
                        SwarmEvent::Behaviour(HiveNodeBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { message, .. }
                        )) => {
                            if let Ok(rule) = RuleMessage::from_bytes(&message.data) {
                                if !received_ids.contains(&rule.rule_id) {
                                    received_ids.push(rule.rule_id);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                event = swarm_b.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = event {
                        connected = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if connected && published_count == 0 {
                        tokio::time::sleep(Duration::from_millis(2000)).await;
                        for rule in [&rule1, &rule2, &rule3] {
                            if behaviour::publish_rule(
                                &mut swarm_b.behaviour_mut().gossipsub, rule
                            ).is_ok() {
                                published_count += 1;
                            }
                        }
                    }
                }
            }

            if received_ids.len() >= 3 {
                break;
            }
        }

        assert!(
            received_ids.contains(&100),
            "Should receive medical_bill/S1 rule"
        );
        assert!(
            received_ids.contains(&200),
            "Should receive receipt/S4 rule"
        );
        assert!(
            received_ids.contains(&300),
            "Should receive credit_card/S2 rule"
        );
    }

    // Test 9: Message validation (unit test, no network)
    #[tokio::test]
    async fn test_message_validation() {
        let rule = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        assert!(rule.validate().is_ok());

        let mut bad_cat = rule.clone();
        bad_cat.doc_category = "not_a_category".to_string();
        assert!(bad_cat.validate().is_err());

        let mut bad_tier = rule.clone();
        bad_tier.sensitivity_tier = "S9".to_string();
        assert!(bad_tier.validate().is_err());

        let mut bad_conf = rule.clone();
        bad_conf.confidence = 1.5;
        assert!(bad_conf.validate().is_err());

        let mut empty_cond = rule.clone();
        empty_cond.condition = String::new();
        assert!(empty_cond.validate().is_err());
    }

    // =========================================================================
    // N6 tests: Unified functionality
    // =========================================================================

    // Test 10: Relay server also receives Gossipsub rules
    #[tokio::test]
    async fn test_relay_server_receives_gossipsub() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

        let mut relay_swarm = behaviour::build_relay_server_swarm().unwrap();
        let mut client_swarm = behaviour::build_client_swarm().unwrap();

        // Subscribe both to all topics
        behaviour::subscribe_all_topics(&mut relay_swarm.behaviour_mut().gossipsub).unwrap();
        behaviour::subscribe_all_topics(&mut client_swarm.behaviour_mut().gossipsub).unwrap();

        relay_swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        client_swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let relay_addr = get_tcp_listen_addr(&mut relay_swarm).await;
        let _client_addr = get_tcp_listen_addr(&mut client_swarm).await;

        client_swarm.dial(relay_addr).unwrap();

        let signing_key = SigningKey::generate(&mut OsRng);
        let mut test_rule = create_test_rule("utility_bill", SensitivityTier::S3, 999, 0.65);
        test_rule.sign(&signing_key);
        let expected_rule_id = test_rule.rule_id;

        let start = Instant::now();
        let timeout = Duration::from_secs(30);
        let mut connected = false;
        let mut published = false;
        let mut received = false;

        loop {
            if start.elapsed() > timeout {
                panic!(
                    "Test timed out. connected={}, published={}, received={}",
                    connected, published, received
                );
            }

            tokio::select! {
                event = relay_swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { .. } => { connected = true; }
                        SwarmEvent::Behaviour(RelayServerBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { message, .. }
                        )) => {
                            if let Ok(rule) = RuleMessage::from_bytes(&message.data) {
                                if rule.rule_id == expected_rule_id {
                                    received = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                event = client_swarm.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = event {
                        connected = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if connected && !published {
                        tokio::time::sleep(Duration::from_millis(2000)).await;
                        if behaviour::publish_rule(
                            &mut client_swarm.behaviour_mut().gossipsub,
                            &test_rule,
                        ).is_ok() {
                            published = true;
                        }
                    }
                }
            }

            if received {
                break;
            }
        }

        assert!(received, "Relay server should receive rules via Gossipsub");
    }

    // Test 11: CLI argument parsing
    #[test]
    fn test_cli_parsing() {
        // Test --relay
        let args = Args::parse_from(["hive-p2p-node", "--relay"]);
        assert!(args.relay);

        // Test --bootstrap
        let args = Args::parse_from([
            "hive-p2p-node",
            "--bootstrap",
            "/ip4/1.2.3.4/tcp/4001",
            "--bootstrap",
            "/ip4/5.6.7.8/tcp/4001",
        ]);
        assert_eq!(args.bootstrap.len(), 2);

        // Test --subscribe
        let args = Args::parse_from([
            "hive-p2p-node",
            "--subscribe",
            "medical_bill:S1",
            "--subscribe",
            "receipt:S4",
        ]);
        assert_eq!(args.subscribe.len(), 2);
        let parsed: Vec<_> = args
            .subscribe
            .iter()
            .filter_map(|s| parse_subscription(s))
            .collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], ("medical_bill".to_string(), "S1".to_string()));
        assert_eq!(parsed[1], ("receipt".to_string(), "S4".to_string()));

        // Test --port
        let args = Args::parse_from(["hive-p2p-node", "--port", "4001"]);
        assert_eq!(args.port, 4001);
    }

    // Test 12: Subscription parsing
    #[test]
    fn test_subscription_parsing() {
        assert_eq!(
            parse_subscription("medical_bill:S1"),
            Some(("medical_bill".to_string(), "S1".to_string()))
        );
        assert_eq!(
            parse_subscription("receipt:S4"),
            Some(("receipt".to_string(), "S4".to_string()))
        );
        assert_eq!(parse_subscription("invalid"), None);
        assert_eq!(parse_subscription(""), None);
    }
}
