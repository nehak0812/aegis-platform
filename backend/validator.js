const LegalEthicalGate = require('./sanctions');

class DataValidator {
  // 1. Validate LEI & Registry Identifiers
  static validateEntityIdentifier(leiOrRegId, idType = 'LEI') {
    if (!leiOrRegId || typeof leiOrRegId !== 'string') {
      return { valid: false, reason: 'Identifier is missing or empty' };
    }
    const cleanId = leiOrRegId.trim().toUpperCase();

    if (idType === 'LEI') {
      // LEI standard format: 20 alphanumeric characters
      const leiRegex = /^[0-9A-Z]{20}$/;
      if (!leiRegex.test(cleanId) && !cleanId.startsWith('LEI:')) {
        return { valid: false, reason: 'Invalid LEI format (must be 20 alphanumeric chars)' };
      }
    }
    return { valid: true, identifier: cleanId };
  }

  // 2. Validate Domain Syntax & Attribution
  static validateDomain(domain) {
    if (!domain || typeof domain !== 'string') {
      return { valid: false, reason: 'Domain is missing or empty' };
    }
    const cleanDomain = domain.trim().toLowerCase();
    const domainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}$/;
    if (!domainRegex.test(cleanDomain)) {
      return { valid: false, reason: 'Invalid domain syntax' };
    }
    return { valid: true, domain: cleanDomain };
  }

  // 3. Validate Citation Completeness & Source Lineage
  static validateCitations(citations) {
    if (!Array.isArray(citations) || citations.length === 0) {
      return { valid: false, reason: 'Record must carry at least 1 verified source citation' };
    }
    for (const c of citations) {
      if (!c.name || !c.url || !c.retrieved_at || !c.confidence) {
        return { valid: false, reason: 'Incomplete citation object (must contain name, url, retrieved_at, confidence)' };
      }
      if (!['A', 'B', 'C', 'D'].includes(c.confidence)) {
        return { valid: false, reason: `Invalid confidence grade '${c.confidence}' (must be A, B, C, or D)` };
      }
    }
    return { valid: true };
  }

  // 4. Enforce Confidence Ceilings based on Source Type
  static enforceConfidenceCeiling(sourceId, proposedGrade) {
    const ceilings = {
      GLEIF: 'A',
      COMPANIES_HOUSE: 'A',
      SEC_EDGAR: 'A',
      CISA_KEV: 'A',
      FIRST_EPSS: 'A',
      NATIONAL_CERTS: 'A',
      SANCTIONS_LISTS: 'A',
      AI_RISK_REPO: 'A',
      CYBER_ESSENTIALS: 'A',
      PASSIVE_DNS_CRT: 'B',
      RANSOMWARE_LIVE: 'B',
      DARKWEB_META: 'B',
      OPEN_SUPPLY: 'B',
      CHATTER_NEWS: 'C',
      LLM_EXTRACTION: 'D'
    };

    const maxGrade = ceilings[sourceId] || 'C';
    const gradeRanks = { A: 4, B: 3, C: 2, D: 1 };

    if (gradeRanks[proposedGrade] > gradeRanks[maxGrade]) {
      return maxGrade; // Cap at allowed ceiling
    }
    return proposedGrade;
  }

  // 5. Full Entity Pre-Publish Authenticity Check
  static validateEntityForPublish(entityData) {
    // Sanctions gate check
    const gate = LegalEthicalGate.screenEntity(entityData.canonical_name, entityData.master_key_val);
    if (!gate.allowed) {
      return { allowed: false, reason: `Sanctions/Suppression Blocked: ${gate.reason}` };
    }

    // Identifier check
    const idCheck = this.validateEntityIdentifier(entityData.master_key_val, entityData.master_key_type || 'LEI');
    if (!idCheck.valid) {
      return { allowed: false, reason: idCheck.reason };
    }

    // Domain check
    if (entityData.primary_domain) {
      const domainCheck = this.validateDomain(entityData.primary_domain);
      if (!domainCheck.valid) {
        return { allowed: false, reason: domainCheck.reason };
      }
    }

    // Citations check
    if (entityData.citations) {
      const citCheck = this.validateCitations(entityData.citations);
      if (!citCheck.valid) {
        return { allowed: false, reason: citCheck.reason };
      }
    }

    return { allowed: true };
  }
}

module.exports = DataValidator;
