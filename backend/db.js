const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const dbPath = path.join(__dirname, 'aegis.db');
const db = new DatabaseSync(dbPath);

// Enable WAL mode and foreign keys
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS source_registry (
      source_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      access_method TEXT NOT NULL,
      poll_cadence TEXT NOT NULL,
      confidence_ceiling TEXT NOT NULL,
      license_type TEXT NOT NULL,
      status TEXT NOT NULL,
      last_polled_at TEXT,
      obs_count INTEGER DEFAULT 0,
      ent_count INTEGER DEFAULT 0,
      metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS raw_records (
      record_id TEXT PRIMARY KEY,
      source_id TEXT NOT NULL,
      retrieved_at TEXT NOT NULL,
      payload_url TEXT,
      raw_content TEXT NOT NULL,
      hash TEXT NOT NULL,
      FOREIGN KEY (source_id) REFERENCES source_registry(source_id)
    );

    CREATE TABLE IF NOT EXISTS entities (
      entity_id TEXT PRIMARY KEY,
      master_key_type TEXT NOT NULL,
      master_key_val TEXT NOT NULL,
      canonical_name TEXT NOT NULL,
      legal_form TEXT,
      sector TEXT NOT NULL,
      country TEXT NOT NULL,
      city TEXT,
      lat REAL,
      lon REAL,
      employees_est INTEGER,
      revenue_eur_m REAL,
      nis2_status TEXT,
      is_sanctioned INTEGER DEFAULT 0,
      is_suppressed INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS entity_identifiers (
      entity_id TEXT NOT NULL,
      identifier_type TEXT NOT NULL,
      identifier_val TEXT NOT NULL,
      PRIMARY KEY (entity_id, identifier_type, identifier_val),
      FOREIGN KEY (entity_id) REFERENCES entities(entity_id)
    );

    CREATE TABLE IF NOT EXISTS entity_domains (
      domain TEXT PRIMARY KEY,
      entity_id TEXT NOT NULL,
      is_primary INTEGER DEFAULT 0,
      confidence_grade TEXT NOT NULL,
      FOREIGN KEY (entity_id) REFERENCES entities(entity_id)
    );

    CREATE TABLE IF NOT EXISTS entity_relationships (
      relationship_id TEXT PRIMARY KEY,
      parent_entity_id TEXT NOT NULL,
      child_entity_id TEXT NOT NULL,
      relationship_type TEXT NOT NULL,
      ownership_pct REAL,
      source_citation TEXT,
      FOREIGN KEY (parent_entity_id) REFERENCES entities(entity_id),
      FOREIGN KEY (child_entity_id) REFERENCES entities(entity_id)
    );

    CREATE TABLE IF NOT EXISTS signals (
      signal_id TEXT PRIMARY KEY,
      source_id TEXT NOT NULL,
      record_id TEXT,
      signal_type TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      severity INTEGER DEFAULT 50,
      confidence_grade TEXT NOT NULL,
      detected_at TEXT NOT NULL,
      raw_metadata TEXT,
      FOREIGN KEY (source_id) REFERENCES source_registry(source_id)
    );

    CREATE TABLE IF NOT EXISTS entity_signals (
      entity_id TEXT NOT NULL,
      signal_id TEXT NOT NULL,
      attribution_method TEXT NOT NULL,
      confidence_grade TEXT NOT NULL,
      attributed_at TEXT NOT NULL,
      PRIMARY KEY (entity_id, signal_id),
      FOREIGN KEY (entity_id) REFERENCES entities(entity_id),
      FOREIGN KEY (signal_id) REFERENCES signals(signal_id)
    );

    CREATE TABLE IF NOT EXISTS entity_scores (
      score_id TEXT PRIMARY KEY,
      entity_id TEXT NOT NULL,
      computed_at TEXT NOT NULL,
      external_pressure_score INTEGER NOT NULL,
      internal_weakness_score INTEGER NOT NULL,
      composite_exposure_score INTEGER NOT NULL,
      readiness_score INTEGER NOT NULL,
      axis_scores TEXT NOT NULL,
      confidence_summary TEXT NOT NULL,
      citations TEXT NOT NULL,
      FOREIGN KEY (entity_id) REFERENCES entities(entity_id)
    );

    CREATE TABLE IF NOT EXISTS review_queue (
      review_id TEXT PRIMARY KEY,
      signal_id TEXT,
      proposed_entity_id TEXT,
      proposed_grade TEXT NOT NULL,
      claim_text TEXT NOT NULL,
      llm_raw_output TEXT,
      status TEXT NOT NULL DEFAULT 'PENDING',
      reviewed_by TEXT,
      reviewed_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sanctions_suppression (
      list_type TEXT NOT NULL, -- SANCTIONS or SUPPRESSION
      entity_name TEXT NOT NULL,
      identifier_val TEXT,
      reason TEXT NOT NULL,
      added_at TEXT NOT NULL,
      PRIMARY KEY (list_type, entity_name)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      log_id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      entity_id TEXT,
      details TEXT NOT NULL,
      timestamp TEXT NOT NULL
    );
  `);
  console.log('[DB] Schema initialized successfully.');
}

initSchema();

module.exports = db;
