const db = require('./db');

// Seed default Sanctions & Suppression rules
function seedSanctionsAndSuppression() {
  const checkStmt = db.prepare("SELECT COUNT(*) as cnt FROM sanctions_suppression");
  const count = checkStmt.get().cnt;
  if (count === 0) {
    const insertStmt = db.prepare(`
      INSERT INTO sanctions_suppression (list_type, entity_name, identifier_val, reason, added_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    // Sanctions entries (OFAC / BIS / EU-UK)
    const sanctions = [
      ['SANCTIONS', 'ROSNEFT OIL COMPANY', '213800K9F2S39U3R3940', 'EU / UK / US Consolidated Sanctions List', new Date().toISOString()],
      ['SANCTIONS', 'GAZPROM NEFT PJSC', '2138006N8P3M9O011122', 'OFAC / BIS / EU Consolidated Sanctions List', new Date().toISOString()],
      ['SANCTIONS', 'CRIMEA ENERGY ENTERPRISE', 'UK:00998877', 'UK Sanctions Act 2018', new Date().toISOString()],
    ];

    // Suppression entries (do-not-contact / existing clients)
    const suppression = [
      ['SUPPRESSION', 'CONFIDENTIAL CLIENT ALPHA', 'LEI:SUPPRESS001', 'Active Retainer Client — Do Not Quote Commercial Brief', new Date().toISOString()],
      ['SUPPRESSION', 'DO NOT CONTACT UTILITY A', 'LEI:SUPPRESS002', 'Explicit Opt-out Request', new Date().toISOString()],
    ];

    for (const row of [...sanctions, ...suppression]) {
      insertStmt.run(...row);
    }
    console.log('[SANCTIONS] Initialized sanctions & suppression list.');
  }
}

seedSanctionsAndSuppression();

// Legal & Ethical Gate Engine
class LegalEthicalGate {
  static screenEntity(entityName, lei = null) {
    const stmt = db.prepare(`
      SELECT * FROM sanctions_suppression 
      WHERE UPPER(entity_name) = UPPER(?) OR (identifier_val IS NOT NULL AND identifier_val = ?)
    `);
    const match = stmt.get(entityName, lei || '');
    if (match) {
      this.logAudit('SANCTIONS_OR_SUPPRESSION_BLOCKED', lei, {
        entity_name: entityName,
        list_type: match.list_type,
        reason: match.reason
      });
      return {
        allowed: false,
        list_type: match.list_type,
        reason: match.reason
      };
    }
    return { allowed: true };
  }

  static enforceDisclosureGate(entityId, exposureType, actionType) {
    // State-machine rule: Commercial/BRIEF actions require prior logged disclosure
    if (actionType === 'COMMERCIAL_BRIEF') {
      const checkDisclosure = db.prepare(`
        SELECT COUNT(*) as cnt FROM audit_logs 
        WHERE event_type = 'DISCLOSURE_SENT' AND entity_id = ?
      `);
      const res = checkDisclosure.get(entityId);
      if (res.cnt === 0) {
        this.logAudit('COMMERCIAL_ACTION_BLOCKED', entityId, {
          reason: 'Disclosure to security contact required prior to commercial brief.',
          exposure_type: exposureType
        });
        return {
          allowed: false,
          reason: 'GATE BLOCKED: Exposure must route through disclosure to security contact first.'
        };
      }
    }
    return { allowed: true };
  }

  static sanitizeRoleContact(contactName, roleTitle) {
    // Rule: No dossiers on named individuals. Role-level contacts only.
    return {
      role: roleTitle || 'Group CISO / Head of Security',
      individual_names_redacted: true
    };
  }

  static sanitizeDarkWebMetadata(payload) {
    // Rule: Counts, kinds, dates, domains ONLY. Never credential values or dump contents.
    return {
      domain: payload.domain,
      infostealer_session_count: payload.session_count || 0,
      log_kinds: payload.log_kinds || ['COOKIES', 'CREDENTIAL_HASH'],
      first_seen: payload.first_seen,
      last_seen: payload.last_seen,
      raw_credentials_scrubbed: true
    };
  }

  static logAudit(eventType, entityId, details) {
    const stmt = db.prepare(`
      INSERT INTO audit_logs (event_type, entity_id, details, timestamp)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(eventType, entityId || 'SYSTEM', JSON.stringify(details), new Date().toISOString());
  }
}

module.exports = LegalEthicalGate;
