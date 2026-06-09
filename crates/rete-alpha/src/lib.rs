//! HIVE Rete-II Alpha Network
//!
//! Minimal alpha-only Rete engine for validating WME insertion throughput.
//! Provides the alpha network plus a JTMS for justification tracking and
//! belief revision.
//!
//! Architecture:
//! - Dictionary-encoded u16 fields for WMEs
//! - FxHashMap-based field indexes in the alpha network
//! - Conjunction bitmask checking for production firing
//! - AlphaOutput trait as a beta-network extension point
//! - JTMS for justification-based truth maintenance

pub mod alpha_network;
pub mod dictionary;
pub mod engine;
pub mod generalization;
pub mod insight_gen;
pub mod jtms;
pub mod lifecycle;
pub mod pipeline;
pub mod production;
pub mod serialization;
pub mod tuple_adapter;
pub mod wme;
pub mod wme_factory;

// Process orchestrator modules
pub mod doc_queue;
pub mod extraction_manager;
pub mod orchestrator;

// Pre-seeded rule loading
pub mod rule_loader;
pub mod seed_rules;

// Terminal UI
pub mod tui;

// Onboarding and config
pub mod hive_config;
pub mod onboarding;

// Privacy pipeline
pub mod privacy;

// Privacy pipeline <-> P2P bridge
pub mod bridge;

// Diagnostic export and invite codes
pub mod diagnostics;
pub mod invite;

// Standardized WHAT/WHY/DO error formatting
pub mod error_format;

// Watch folder for automatic document processing
pub mod watch_folder;
