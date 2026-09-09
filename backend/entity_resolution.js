const db = require('./db');

class EntityResolutionEngine {
  // Confidence Ceiling Rules
  static getConfidenceCeiling(sourceId, attributionMethod) {
    const srcRow = db.prepare("SELECT confidence_ceiling FROM source_registry WHERE source_id = ?").get(sourceId);
    const sourceCeiling = srcRow ? srcRow.confidence_ceiling : 'C';

    if (attributionMethod === 'LLM_EXTRACTION_UNVERIFIED') {
      return 'D'; // LLM extractions start at D until analyst confirmed
    }
    if (attributionMethod === 'MODELLED_INFERRED') {
      return 'D';
    }
    if (attributionMethod === 'SINGLE_NEWS_SOURCE') {
      return 'C';
    }
    if (attributionMethod === 'PASSIVE_CORROBORATED_2PLUS') {
      return sourceCeiling === 'A' ? 'A' : 'B';
    }
    return sourceCeiling;
  }

  // Resolve entity by domain or registry key
  static resolveEntity(queryStr) {
    // 1. Try LEI
    if (queryStr.startsWith('LEI:')) {
      return db.prepare("SELECT * FROM entities WHERE entity_id = ?").get(queryStr);
    }
    // 2. Try Domain
    const domainRow = db.prepare("SELECT entity_id FROM entity_domains WHERE domain = ?").get(queryStr.toLowerCase());
    if (domainRow) {
      return db.prepare("SELECT * FROM entities WHERE entity_id = ?").get(domainRow.entity_id);
    }
    // 3. Try Registry Key (CRN/HRB/KvK)
    const identRow = db.prepare("SELECT entity_id FROM entity_identifiers WHERE identifier_val = ?").get(queryStr);
    if (identRow) {
      return db.prepare("SELECT * FROM entities WHERE entity_id = ?").get(identRow.entity_id);
    }
    // 4. Try Canonical Name Fuzzy/Exact Match
    return db.prepare("SELECT * FROM entities WHERE UPPER(canonical_name) LIKE UPPER(?)").get(`%${queryStr}%`);
  }

  // Queue LLM extraction for human analyst review
  static queueLLMExtraction(claimText, proposedEntityId, rawLlmOutput) {
    const reviewId = `rev_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const stmt = db.prepare(`
      INSERT INTO review_queue (review_id, proposed_entity_id, proposed_grade, claim_text, llm_raw_output, status, created_at)
      VALUES (?, ?, 'D', ?, ?, 'PENDING', ?)
    `);
    stmt.run(reviewId, proposedEntityId, claimText, rawLlmOutput, new Date().toISOString());
    console.log(`[REVIEW QUEUE] Queued Grade D LLM extraction review item: ${reviewId}`);
    return reviewId;
  }

  // Analyst review confirmation (upgrades Grade D to underlying source ceiling)
  static approveReviewItem(reviewId, analystId) {
    const item = db.prepare("SELECT * FROM review_queue WHERE review_id = ?").get(reviewId);
    if (!item) return null;

    db.prepare(`
      UPDATE review_queue 
      SET status = 'APPROVED', reviewed_by = ?, reviewed_at = ?
      WHERE review_id = ?
    `).run(analystId, new Date().toISOString(), reviewId);

    // Upgrade confidence grade in attributed signal
    if (item.signal_id) {
      db.prepare(`
        UPDATE entity_signals 
        SET confidence_grade = 'B'
        WHERE entity_id = ? AND signal_id = ?
      `).run(item.proposed_entity_id, item.signal_id);
    }

    db.prepare(`
      INSERT INTO audit_logs (event_type, entity_id, details, timestamp)
      VALUES ('ANALYST_REVIEW_APPROVED', ?, ?, ?)
    `).run(item.proposed_entity_id, JSON.stringify({ review_id: reviewId, analyst: analystId }), new Date().toISOString());

    return { success: true, review_id: reviewId };
  }
}

module.exports = EntityResolutionEngine;
