//! Unified network behaviours for the HIVE P2P node.
//!
//! Merges NAT traversal and rule shard distribution into two
//! composed behaviours:
//!
//! 1. `RelayServerBehaviour` -- for public relay nodes that relay traffic
//!    for NATted peers AND participate in Gossipsub rule distribution.
//!
//! 2. `HiveNodeBehaviour` -- for regular client nodes with relay client,
//!    DCUtR hole-punching, AND Gossipsub rule distribution.
//!
//! Both behaviours include: mDNS, Kademlia, Identify, Ping, Gossipsub, AutoNAT.
//! The relay server adds relay::Behaviour; the client adds relay::client + DCUtR.

use crate::dandelion::{DandelionCodec, DANDELION_PROTOCOL};
use crate::rule::RuleMessage;
use crate::shard;

use libp2p::{
    autonat, dcutr, gossipsub, identify, kad,
    kad::store::MemoryStore,
    mdns, noise, ping, relay,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
    tcp, yamux, SwarmBuilder,
};
use std::collections::HashMap;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Protocol version -- unified node
// ---------------------------------------------------------------------------

/// Protocol version string used in Identify handshake.
pub const PROTOCOL_VERSION: &str = "/hive/node/0.3.0";

// ---------------------------------------------------------------------------
// Relay server behaviour (relay + gossipsub)
// ---------------------------------------------------------------------------

/// Composed network behaviour for relay SERVER mode.
/// Relay servers relay traffic for NATted peers AND participate in
/// Gossipsub rule distribution.
#[derive(NetworkBehaviour)]
pub struct RelayServerBehaviour {
    /// Relay server -- accepts and relays circuit connections
    pub relay: relay::Behaviour,
    /// Gossipsub -- rule shard pub/sub distribution
    pub gossipsub: gossipsub::Behaviour,
    /// mDNS for LAN peer discovery
    pub mdns: mdns::tokio::Behaviour,
    /// Kademlia DHT for distributed peer discovery + rule storage
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// Identify protocol for peer metadata exchange
    pub identify: identify::Behaviour,
    /// Ping protocol for basic connectivity verification
    pub ping: ping::Behaviour,
    /// AutoNAT for NAT status detection
    pub autonat: autonat::Behaviour,
    /// Dandelion++ request-response transport for stem relay.
    /// Routing logic (stem decisions, dedup cache, fluff transitions) lives in
    /// a separate `DandelionBehaviour` instance owned by the event loop.
    pub dandelion_rr: request_response::Behaviour<DandelionCodec>,
}

// ---------------------------------------------------------------------------
// Client node behaviour (relay client + gossipsub)
// ---------------------------------------------------------------------------

/// Composed network behaviour for regular CLIENT mode.
/// Clients use relay::client for NAT traversal, DCUtR for hole-punching,
/// AND Gossipsub for rule shard distribution.
#[derive(NetworkBehaviour)]
pub struct HiveNodeBehaviour {
    /// Relay client -- enables connecting through relay servers
    pub relay_client: relay::client::Behaviour,
    /// DCUtR -- Direct Connection Upgrade through Relay (hole-punching)
    pub dcutr: dcutr::Behaviour,
    /// Gossipsub -- rule shard pub/sub distribution
    pub gossipsub: gossipsub::Behaviour,
    /// mDNS for LAN peer discovery
    pub mdns: mdns::tokio::Behaviour,
    /// Kademlia DHT for distributed peer discovery + rule storage
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// Identify protocol for peer metadata exchange
    pub identify: identify::Behaviour,
    /// Ping protocol for basic connectivity verification
    pub ping: ping::Behaviour,
    /// AutoNAT for NAT status detection
    pub autonat: autonat::Behaviour,
    /// Dandelion++ request-response transport for stem relay.
    /// Routing logic (stem decisions, dedup cache, fluff transitions) lives in
    /// a separate `DandelionBehaviour` instance owned by the event loop.
    pub dandelion_rr: request_response::Behaviour<DandelionCodec>,
}

// ---------------------------------------------------------------------------
// Gossipsub configuration
// ---------------------------------------------------------------------------

/// Build Gossipsub v1.1 config.
pub fn build_gossipsub_config() -> gossipsub::Config {
    gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .mesh_n(6) // D = 6
        .mesh_n_low(4) // D_low = 4
        .mesh_n_high(12) // D_high = 12
        .gossip_lazy(6) // D_lazy = 6
        .history_length(5)
        .history_gossip(3)
        .flood_publish(true)
        .max_transmit_size(1024)
        .message_id_fn(|msg: &gossipsub::Message| {
            // message_id = BLAKE3(data)[0..20]
            let hash = blake3::hash(&msg.data);
            let bytes = hash.as_bytes();
            gossipsub::MessageId::from(&bytes[..20])
        })
        .build()
        .expect("valid gossipsub config")
}

// ---------------------------------------------------------------------------
// Peer scoring (wire P3/P4 constants into Gossipsub)
// ---------------------------------------------------------------------------

// Re-export scoring constants from rule_ingest for cross-module visibility.
// These are defined canonically in rule_ingest.rs.
pub use crate::rule_ingest::{P3_RATE_PENALTY_THRESHOLD, P4_INVALID_MESSAGE_WEIGHT};

/// Build Gossipsub v1.1 peer scoring parameters.
///
/// Configures:
/// - P4 (invalid message deliveries) with weight from `P4_INVALID_MESSAGE_WEIGHT`
/// - P3 (mesh message deliveries) with threshold from `P3_RATE_PENALTY_THRESHOLD`
/// - Topic-specific params for "hive/rules/v1/meta" and "hive/tuples/v1"
/// - Conservative thresholds to graylist and suppress malicious peers
pub fn build_peer_score_params() -> (gossipsub::PeerScoreParams, gossipsub::PeerScoreThresholds) {
    // Topic-specific scoring for both HIVE topics
    let topic_params = gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        // P1: time in mesh (reward)
        time_in_mesh_weight: 0.5,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 3600.0,
        // P2: first message deliveries (reward)
        first_message_deliveries_weight: 1.0,
        first_message_deliveries_decay: 0.5,
        first_message_deliveries_cap: 100.0,
        // P3: mesh message deliveries (penalty for under-delivery)
        mesh_message_deliveries_weight: -1.0,
        mesh_message_deliveries_decay: 0.5,
        mesh_message_deliveries_cap: 100.0,
        mesh_message_deliveries_threshold: P3_RATE_PENALTY_THRESHOLD as f64,
        mesh_message_deliveries_window: Duration::from_millis(10),
        mesh_message_deliveries_activation: Duration::from_secs(30),
        // P3b: sticky mesh failure penalty
        mesh_failure_penalty_weight: -1.0,
        mesh_failure_penalty_decay: 0.5,
        // P4: invalid message deliveries (penalty)
        invalid_message_deliveries_weight: P4_INVALID_MESSAGE_WEIGHT,
        invalid_message_deliveries_decay: 0.3,
    };

    // Apply the same topic scoring to both HIVE topics
    let mut topics = HashMap::new();
    let meta_topic = gossipsub::IdentTopic::new("hive/rules/v1/meta");
    topics.insert(meta_topic.hash(), topic_params.clone());
    let tuple_topic = gossipsub::IdentTopic::new("hive/tuples/v1");
    topics.insert(tuple_topic.hash(), topic_params);

    let params = gossipsub::PeerScoreParams {
        topics,
        topic_score_cap: 3600.0,
        app_specific_weight: 10.0,
        ip_colocation_factor_weight: -5.0,
        ip_colocation_factor_threshold: 10.0,
        behaviour_penalty_weight: -10.0,
        behaviour_penalty_threshold: 0.0,
        behaviour_penalty_decay: 0.2,
        decay_interval: Duration::from_secs(1),
        decay_to_zero: 0.1,
        retain_score: Duration::from_secs(3600),
        slow_peer_weight: -0.2,
        slow_peer_threshold: 0.0,
        slow_peer_decay: 0.2,
        ..Default::default()
    };

    // Thresholds: aggressive enough to suppress malicious peers.
    // P4_INVALID_MESSAGE_WEIGHT = -100.0, so a single invalid message
    // produces a topic score of -100.0.  Two invalids => -100 * 4 = -400.
    // graylist_threshold at -300 means 2 invalid messages gray-lists the peer.
    let thresholds = gossipsub::PeerScoreThresholds {
        gossip_threshold: -100.0,
        publish_threshold: -200.0,
        graylist_threshold: -300.0,
        accept_px_threshold: 10.0,
        opportunistic_graft_threshold: 5.0,
    };

    (params, thresholds)
}

// ---------------------------------------------------------------------------
// Dandelion++ request-response builder
// ---------------------------------------------------------------------------

/// Build a `request_response::Behaviour<DandelionCodec>` for Dandelion++ stem
/// relay transport.  This is the network-level transport only; the routing
/// logic lives in `DandelionBehaviour` (dandelion.rs), owned by the event loop.
pub fn build_dandelion_rr() -> request_response::Behaviour<DandelionCodec> {
    request_response::Behaviour::with_codec(
        DandelionCodec,
        [(DANDELION_PROTOCOL.to_string(), ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(10)),
    )
}

// ---------------------------------------------------------------------------
// Swarm builders
// ---------------------------------------------------------------------------

/// Build a relay server swarm. Used when `--relay` flag is passed.
/// Includes: relay server, Gossipsub, mDNS, Kademlia, Identify, Ping, AutoNAT.
/// Transport: TCP + QUIC.
pub fn build_relay_server_swarm(
) -> Result<libp2p::Swarm<RelayServerBehaviour>, Box<dyn std::error::Error>> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();

            // Relay server
            let relay = relay::Behaviour::new(peer_id, relay::Config::default());

            // Gossipsub
            let gossipsub_config = build_gossipsub_config();
            let mut gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| format!("gossipsub init error: {e}"))?;

            // Subscribe to Dandelion++ / tuple topics
            let tuple_topic = gossipsub::IdentTopic::new("hive/tuples/v1");
            gossipsub.subscribe(&tuple_topic)?;
            let meta_topic = gossipsub::IdentTopic::new("hive/rules/v1/meta");
            gossipsub.subscribe(&meta_topic)?;

            // Wire peer scoring
            let (score_params, score_thresholds) = build_peer_score_params();
            gossipsub
                .with_peer_score(score_params, score_thresholds)
                .map_err(|e| format!("peer score init error: {e}"))?;

            // mDNS
            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;

            // Kademlia
            let mut kademlia = kad::Behaviour::new(peer_id, MemoryStore::new(peer_id));
            kademlia.set_mode(Some(kad::Mode::Server));

            // Identify
            let identify = identify::Behaviour::new(
                identify::Config::new(PROTOCOL_VERSION.to_string(), key.public())
                    .with_push_listen_addr_updates(true),
            );

            // Ping
            let ping =
                ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(15)));

            // AutoNAT
            let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());

            // Dandelion++ request-response transport
            let dandelion_rr = build_dandelion_rr();

            Ok(RelayServerBehaviour {
                relay,
                gossipsub,
                mdns,
                kademlia,
                identify,
                ping,
                autonat,
                dandelion_rr,
            })
        })
        .map_err(|e| format!("Behaviour init error: {e}"))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    Ok(swarm)
}

/// Build a client node swarm (default mode).
/// Includes: relay client, DCUtR, Gossipsub, mDNS, Kademlia, Identify, Ping, AutoNAT.
/// Transport: TCP + QUIC + relay.
pub fn build_client_swarm() -> Result<libp2p::Swarm<HiveNodeBehaviour>, Box<dyn std::error::Error>>
{
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            let peer_id = key.public().to_peer_id();

            // DCUtR (hole-punching)
            let dcutr = dcutr::Behaviour::new(peer_id);

            // Gossipsub
            let gossipsub_config = build_gossipsub_config();
            let mut gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| format!("gossipsub init error: {e}"))?;

            // Subscribe to Dandelion++ / tuple topics
            let tuple_topic = gossipsub::IdentTopic::new("hive/tuples/v1");
            gossipsub.subscribe(&tuple_topic)?;
            let meta_topic = gossipsub::IdentTopic::new("hive/rules/v1/meta");
            gossipsub.subscribe(&meta_topic)?;

            // Wire peer scoring
            let (score_params, score_thresholds) = build_peer_score_params();
            gossipsub
                .with_peer_score(score_params, score_thresholds)
                .map_err(|e| format!("peer score init error: {e}"))?;

            // mDNS
            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;

            // Kademlia
            let mut kademlia = kad::Behaviour::new(peer_id, MemoryStore::new(peer_id));
            kademlia.set_mode(Some(kad::Mode::Server));

            // Identify
            let identify = identify::Behaviour::new(
                identify::Config::new(PROTOCOL_VERSION.to_string(), key.public())
                    .with_push_listen_addr_updates(true),
            );

            // Ping
            let ping =
                ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(15)));

            // AutoNAT
            let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());

            // Dandelion++ request-response transport
            let dandelion_rr = build_dandelion_rr();

            Ok(HiveNodeBehaviour {
                relay_client,
                dcutr,
                gossipsub,
                mdns,
                kademlia,
                identify,
                ping,
                autonat,
                dandelion_rr,
            })
        })
        .map_err(|e| format!("Behaviour init error: {e}"))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    Ok(swarm)
}

// ---------------------------------------------------------------------------
// Gossipsub helpers
// ---------------------------------------------------------------------------

/// Subscribe to all 40 shard topics. Privacy-preserving default.
pub fn subscribe_all_topics(
    gossipsub: &mut gossipsub::Behaviour,
) -> Result<(), Box<dyn std::error::Error>> {
    for topic in shard::all_shard_topics() {
        gossipsub.subscribe(&topic)?;
    }
    Ok(())
}

/// Subscribe to specific shard topics by category/tier pairs.
pub fn subscribe_topics(
    gossipsub: &mut gossipsub::Behaviour,
    subscriptions: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    for (cat, tier_str) in subscriptions {
        if let Some(tier) = crate::rule::SensitivityTier::from_str(tier_str) {
            let key = crate::rule::ShardKey::new(cat, tier);
            let topic = shard::shard_topic(&key);
            gossipsub.subscribe(&topic)?;
        }
    }
    Ok(())
}

/// Publish a rule to its appropriate Gossipsub shard topic.
pub fn publish_rule(
    gossipsub: &mut gossipsub::Behaviour,
    rule: &RuleMessage,
) -> Result<gossipsub::MessageId, gossipsub::PublishError> {
    let shard_key = rule.shard_key();
    let topic = shard::shard_topic(&shard_key);
    let data = rule.to_bytes();
    gossipsub.publish(topic, data)
}

/// Store a rule in the Kademlia DHT for pull-based retrieval.
pub fn store_rule_in_dht(
    kademlia: &mut kad::Behaviour<MemoryStore>,
    rule: &RuleMessage,
) -> kad::QueryId {
    let shard_key = rule.shard_key();
    let key_bytes = shard_key.dht_key();
    let record_key = kad::RecordKey::new(&key_bytes);
    let value = rule.to_bytes();

    let record = kad::Record {
        key: record_key,
        value,
        publisher: None,
        expires: None,
    };

    kademlia
        .put_record(record, kad::Quorum::One)
        .expect("DHT put should start")
}

/// Retrieve a rule from the Kademlia DHT by its shard key.
pub fn get_rule_from_dht(
    kademlia: &mut kad::Behaviour<MemoryStore>,
    doc_category: &str,
    tier: &crate::rule::SensitivityTier,
) -> kad::QueryId {
    let shard_key = crate::rule::ShardKey::new(doc_category, tier.clone());
    let key_bytes = shard_key.dht_key();
    let record_key = kad::RecordKey::new(&key_bytes);
    kademlia.get_record(record_key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Composed behaviour compilation tests ───────────────

    // NOTE: Tests that call `build_relay_server_swarm()` or
    // `build_client_swarm()` MUST be `#[tokio::test]`. Both constructors
    // build an `mdns::tokio::Behaviour`, which on Linux registers a netlink
    // socket via `tokio::io::unix::AsyncFd::new` and panics with "there is
    // no reactor running" outside a Tokio 1.x runtime context. Discovered
    // when CI moved to Linux runners; previously passed on Darwin where
    // mdns uses kqueue and does not require netlink.

    /// Verify that RelayServerBehaviour compiles with the dandelion_rr field
    /// and its auto-generated event enum has the DandelionRr variant.
    #[tokio::test]
    async fn relay_server_behaviour_has_dandelion_rr_event_variant() {
        // Build a relay server swarm -- this exercises the full struct
        // construction including the dandelion_rr field.
        let swarm = build_relay_server_swarm().unwrap();
        let _peer_id = *swarm.local_peer_id();

        // Prove the auto-generated event enum has the expected variant
        // by constructing a dummy DandelionRr event.  If the variant
        // name were different, this would fail at compile time.
        fn _assert_variant_exists(evt: RelayServerBehaviourEvent) -> bool {
            matches!(evt, RelayServerBehaviourEvent::DandelionRr(_))
        }
    }

    /// Verify that HiveNodeBehaviour compiles with the dandelion_rr field
    /// and its auto-generated event enum has the DandelionRr variant.
    #[tokio::test]
    async fn hive_node_behaviour_has_dandelion_rr_event_variant() {
        let swarm = build_client_swarm().unwrap();
        let _peer_id = *swarm.local_peer_id();

        fn _assert_variant_exists(evt: HiveNodeBehaviourEvent) -> bool {
            matches!(evt, HiveNodeBehaviourEvent::DandelionRr(_))
        }
    }

    /// Verify the build_dandelion_rr helper produces a valid behaviour.
    #[test]
    fn build_dandelion_rr_produces_valid_behaviour() {
        let _rr = build_dandelion_rr();
        // If this compiles and runs, the constructor is correct.
    }

    /// Verify the dandelion_rr field is accessible on the relay server behaviour.
    #[tokio::test]
    async fn relay_server_dandelion_rr_field_accessible() {
        let swarm = build_relay_server_swarm().unwrap();
        // Access the dandelion_rr field through the behaviour to prove it exists.
        let _rr = &swarm.behaviour().dandelion_rr;
    }

    /// Verify the dandelion_rr field is accessible on the client behaviour.
    #[tokio::test]
    async fn hive_node_dandelion_rr_field_accessible() {
        let swarm = build_client_swarm().unwrap();
        let _rr = &swarm.behaviour().dandelion_rr;
    }

    /// Verify that gossipsub topics "hive/tuples/v1" and "hive/rules/v1/meta"
    /// are subscribed during swarm construction (client).
    #[tokio::test]
    async fn client_swarm_subscribes_to_tuple_and_meta_topics() {
        let swarm = build_client_swarm().unwrap();
        let gossipsub = &swarm.behaviour().gossipsub;
        let topics: Vec<String> = gossipsub.topics().map(|t| t.to_string()).collect();
        assert!(
            topics.iter().any(|t| t.contains("hive/tuples/v1")),
            "Client should be subscribed to hive/tuples/v1, got: {:?}",
            topics
        );
        assert!(
            topics.iter().any(|t| t.contains("hive/rules/v1/meta")),
            "Client should be subscribed to hive/rules/v1/meta, got: {:?}",
            topics
        );
    }

    /// Verify that gossipsub topics "hive/tuples/v1" and "hive/rules/v1/meta"
    /// are subscribed during swarm construction (relay server).
    #[tokio::test]
    async fn relay_server_subscribes_to_tuple_and_meta_topics() {
        let swarm = build_relay_server_swarm().unwrap();
        let gossipsub = &swarm.behaviour().gossipsub;
        let topics: Vec<String> = gossipsub.topics().map(|t| t.to_string()).collect();
        assert!(
            topics.iter().any(|t| t.contains("hive/tuples/v1")),
            "Relay should be subscribed to hive/tuples/v1, got: {:?}",
            topics
        );
        assert!(
            topics.iter().any(|t| t.contains("hive/rules/v1/meta")),
            "Relay should be subscribed to hive/rules/v1/meta, got: {:?}",
            topics
        );
    }

    // ── Strict validation mode tests ───────────────────────────

    /// Verify that build_gossipsub_config() uses Strict validation mode
    /// (not Permissive).
    #[test]
    fn gossipsub_config_uses_strict_validation() {
        let config = build_gossipsub_config();
        // Strict mode means messages are held pending until explicitly
        // validated via report_message_validation_result().
        assert!(
            matches!(config.validation_mode(), gossipsub::ValidationMode::Strict),
            "Gossipsub config must use Strict validation mode"
        );
    }

    // ── Peer scoring configuration tests ───────────────────────

    /// Verify build_peer_score_params() returns valid params that pass
    /// libp2p's internal validation.
    #[test]
    fn peer_score_params_are_valid() {
        let (params, thresholds) = build_peer_score_params();
        params.validate().expect("PeerScoreParams must be valid");
        thresholds
            .validate()
            .expect("PeerScoreThresholds must be valid");
    }

    /// Verify that P4 invalid message weight matches the canonical constant.
    #[test]
    fn peer_score_p4_weight_matches_adr015() {
        let (params, _) = build_peer_score_params();
        let meta_topic = gossipsub::IdentTopic::new("hive/rules/v1/meta");
        let meta_params = params
            .topics
            .get(&meta_topic.hash())
            .expect("hive/rules/v1/meta topic must have score params");
        assert_eq!(
            meta_params.invalid_message_deliveries_weight,
            crate::rule_ingest::P4_INVALID_MESSAGE_WEIGHT,
            "P4 weight must equal P4_INVALID_MESSAGE_WEIGHT from rule_ingest"
        );
    }

    /// Verify that P3 mesh message delivery threshold matches the canonical constant.
    #[test]
    fn peer_score_p3_threshold_matches_adr015() {
        let (params, _) = build_peer_score_params();
        let tuple_topic = gossipsub::IdentTopic::new("hive/tuples/v1");
        let tuple_params = params
            .topics
            .get(&tuple_topic.hash())
            .expect("hive/tuples/v1 topic must have score params");
        assert_eq!(
            tuple_params.mesh_message_deliveries_threshold,
            crate::rule_ingest::P3_RATE_PENALTY_THRESHOLD as f64,
            "P3 threshold must equal P3_RATE_PENALTY_THRESHOLD from rule_ingest"
        );
    }

    /// Verify both HIVE topics have scoring params configured.
    #[test]
    fn peer_score_covers_both_topics() {
        let (params, _) = build_peer_score_params();
        let meta_topic = gossipsub::IdentTopic::new("hive/rules/v1/meta");
        let tuple_topic = gossipsub::IdentTopic::new("hive/tuples/v1");
        assert!(
            params.topics.contains_key(&meta_topic.hash()),
            "PeerScoreParams must include hive/rules/v1/meta topic"
        );
        assert!(
            params.topics.contains_key(&tuple_topic.hash()),
            "PeerScoreParams must include hive/tuples/v1 topic"
        );
    }

    /// Verify thresholds are negative and correctly ordered.
    #[test]
    fn peer_score_thresholds_correctly_ordered() {
        let (_, thresholds) = build_peer_score_params();
        assert!(
            thresholds.gossip_threshold < 0.0,
            "gossip_threshold must be negative"
        );
        assert!(
            thresholds.publish_threshold < 0.0,
            "publish_threshold must be negative"
        );
        assert!(
            thresholds.graylist_threshold < 0.0,
            "graylist_threshold must be negative"
        );
        assert!(
            thresholds.graylist_threshold <= thresholds.publish_threshold,
            "graylist_threshold must be <= publish_threshold"
        );
        assert!(
            thresholds.publish_threshold <= thresholds.gossip_threshold,
            "publish_threshold must be <= gossip_threshold"
        );
    }

    /// Verify that peer scoring is active on the relay server swarm.
    #[tokio::test]
    async fn relay_server_has_peer_scoring_active() {
        let swarm = build_relay_server_swarm().unwrap();
        // peer_score() returns None when scoring is disabled,
        // Some(score) when active. For a peer that doesn't exist,
        // it returns Some(0.0) when scoring is active.
        let fake_peer = libp2p::PeerId::random();
        // With scoring active, querying an unknown peer returns Some(0.0)
        // because the scoring system is initialized even if no peers are connected.
        let score = swarm.behaviour().gossipsub.peer_score(&fake_peer);
        assert!(
            score.is_some(),
            "Peer scoring must be active on relay server (expected Some, got None)"
        );
    }

    /// Verify that peer scoring is active on the client swarm.
    #[tokio::test]
    async fn client_has_peer_scoring_active() {
        let swarm = build_client_swarm().unwrap();
        let fake_peer = libp2p::PeerId::random();
        let score = swarm.behaviour().gossipsub.peer_score(&fake_peer);
        assert!(
            score.is_some(),
            "Peer scoring must be active on client node (expected Some, got None)"
        );
    }
}
