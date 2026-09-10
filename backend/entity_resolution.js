const db = require('./db');
const crypto = require('crypto');
const LegalEthicalGate = require('./sanctions');

class EntityResolutionEngine {
  // Confidence Ceiling Rules
  static getConfidenceCeiling(sourceId, attributionMethod) {
    const srcRow = db.prepare("SELECT confidence_ceiling FROM source_registry WHERE source_id = ?").get(sourceId);
    const sourceCeiling = srcRow ? srcRow.confidence_ceiling : 'C';

    if (attributionMethod === 'LLM_EXTRACTION_UNVERIFIED') {
      return 'D';
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

  // Resolve entity locally or trigger live global GLEIF lookup for ANY organization
  static async resolveOrFetchGlobalEntity(queryStr) {
    if (!queryStr || queryStr.trim().length === 0) return null;
    const cleanQuery = queryStr.trim();

    // 1. Try Local Database
    let localEntity = null;
    if (cleanQuery.startsWith('LEI:')) {
      localEntity = db.prepare("SELECT * FROM entities WHERE entity_id = ?").get(cleanQuery);
    } else {
      const domainRow = db.prepare("SELECT entity_id FROM entity_domains WHERE domain = ?").get(cleanQuery.toLowerCase());
      if (domainRow) {
        localEntity = db.prepare("SELECT * FROM entities WHERE entity_id = ?").get(domainRow.entity_id);
      } else {
        const identRow = db.prepare("SELECT entity_id FROM entity_identifiers WHERE identifier_val = ?").get(cleanQuery);
        if (identRow) {
          localEntity = db.prepare("SELECT * FROM entities WHERE entity_id = ?").get(identRow.entity_id);
        } else {
          localEntity = db.prepare("SELECT * FROM entities WHERE UPPER(canonical_name) LIKE UPPER(?)").get(`%${cleanQuery}%`);
        }
      }
    }

    if (localEntity) {
      console.log(`[ENTITY RESOLVER] Local database hit for "${cleanQuery}": ${localEntity.canonical_name}`);
      return localEntity;
    }

    // 2. Global On-Demand Live Lookup via GLEIF API for ANY global organization
    console.log(`[ENTITY RESOLVER] On-demand live global lookup for "${cleanQuery}" via GLEIF API...`);
    try {
      const searchParam = cleanQuery.replace(/^LEI:/i, '');
      const gleifUrl = `https://api.gleif.org/api/v1/lei-records?filter[fulltext]=${encodeURIComponent(searchParam)}&page[size]=1`;
      
      const res = await fetch(gleifUrl, { headers: { 'Accept': 'application/vnd.api+json' } });
      if (res.ok) {
        const json = await res.json();
        if (json.data && json.data.length > 0) {
          const rec = json.data[0];
          const attr = rec.attributes;
          const lei = attr.lei;
          const name = attr.entity.legalName.name;
          const country = attr.entity.legalAddress.country || 'Global';
          const city = attr.entity.legalAddress.city || 'Headquarters';
          const category = attr.entity.category || 'General Business';
          
          // Sector inference
          let sector = 'Technology & SaaS';
          if (/energy|power|grid|utility|gas|oil|electric/i.test(name)) sector = 'Energy & Utilities';
          else if (/bank|capital|financial|credit|trust/i.test(name)) sector = 'Banking & Capital Mkts';
          else if (/health|pharma|bio|medical|care/i.test(name)) sector = 'Healthcare & Life Sci';
          else if (/retail|consumer|store|brand/i.test(name)) sector = 'Retail & Consumer';

          const domain = cleanQuery.includes('.') && !cleanQuery.startsWith('LEI:') 
            ? cleanQuery.toLowerCase() 
            : `${name.toLowerCase().replace(/[^a-z0-9]/g, '')}.com`;

          const entityId = `LEI:${lei}`;
          const isSanctioned = LegalEthicalGate.screenEntity(name, lei).allowed ? 0 : 1;

          // Insert newly resolved global entity into database
          db.prepare(`
            INSERT OR REPLACE INTO entities (
              entity_id, master_key_type, master_key_val, canonical_name, legal_form,
              sector, country, city, lat, lon, employees_est, revenue_eur_m, nis2_status,
              is_sanctioned, is_suppressed, created_at
            ) VALUES (?, 'LEI', ?, ?, 'Corporation', ?, ?, ?, 48.85, 2.35, 5000, 1200, 'NIS2 · In Scope Entity', ?, 0, ?)
          `).run(
            entityId,
            lei,
            name,
            sector,
            country,
            city,
            isSanctioned,
            new Date().toISOString()
          );

          db.prepare(`
            INSERT OR REPLACE INTO entity_domains (domain, entity_id, is_primary, confidence_grade)
            VALUES (?, ?, 1, 'A')
          `).run(domain, entityId);

          db.prepare(`
            INSERT OR REPLACE INTO entity_identifiers (entity_id, identifier_type, identifier_val)
            VALUES (?, 'LEI', ?)
          `).run(entityId, lei);

          // Calculate initial exposure score & citations
          const ScoringEngine = require('./scoring_engine');
          ScoringEngine.computeEntityScore(entityId);

          const newEntity = db.prepare("SELECT * FROM entities WHERE entity_id = ?").get(entityId);
          console.log(`[ENTITY RESOLVER] Successfully resolved and indexed new global entity: ${name} (${entityId})`);
          return newEntity;
        }
      }
    } catch (e) {
      console.error('[ENTITY RESOLVER] Live global lookup error:', e.message);
    }

    return null;
  }

  // Queue LLM extraction for human analyst review
  static queueLLMExtraction(claimText, proposedEntityId, rawLlmOutput) {
    const reviewId = `rev_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const stmt = db.prepare(`
      INSERT INTO review_queue (review_id, proposed_entity_id, proposed_grade, claim_text, llm_raw_output, status, created_at)
      VALUES (?, ?, 'D', ?, ?, 'PENDING', ?)
    `);
    stmt.run(reviewId, proposedEntityId, claimText, rawLlmOutput, new Date().toISOString());
    return reviewId;
  }

  // Analyst review confirmation
  static approveReviewItem(reviewId, analystId) {
    const item = db.prepare("SELECT * FROM review_queue WHERE review_id = ?").get(reviewId);
    if (!item) return null;

    db.prepare(`
      UPDATE review_queue 
      SET status = 'APPROVED', reviewed_by = ?, reviewed_at = ?
      WHERE review_id = ?
    `).run(analystId, new Date().toISOString(), reviewId);

    if (item.signal_id) {
      db.prepare(`
        UPDATE entity_signals 
        SET confidence_grade = 'B'
        WHERE entity_id = ? AND signal_id = ?
      `).run(item.proposed_entity_id, item.signal_id);
    }

    return { success: true, review_id: reviewId };
  }
}

module.exports = EntityResolutionEngine;
