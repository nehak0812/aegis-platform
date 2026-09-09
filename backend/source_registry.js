const db = require('./db');

const SOURCE_CATALOG = [
  {
    source_id: 'GLEIF',
    name: 'GLEIF LEI + Level 2 Relationships',
    access_method: 'Open API / Bulk JSON',
    poll_cadence: 'Daily',
    confidence_ceiling: 'A',
    license_type: 'CC0',
    status: 'ONLINE',
    obs_count: 24500,
    ent_count: 2000,
    metadata: JSON.stringify({ chapters: ['OBSERVE', 'CONNECT', 'LOOKUP'] })
  },
  {
    source_id: 'COMPANIES_HOUSE',
    name: 'Companies House · SEC EDGAR · National Registers',
    access_method: 'Open API / EDGAR Bulk',
    poll_cadence: 'Daily',
    confidence_ceiling: 'A',
    license_type: 'OGL / Public Domain',
    status: 'ONLINE',
    obs_count: 18200,
    ent_count: 1500,
    metadata: JSON.stringify({ chapters: ['OBSERVE', 'LOOKUP', 'CLOCK'] })
  },
  {
    source_id: 'CISA_KEV',
    name: 'CISA KEV · FIRST EPSS · NVD',
    access_method: 'Open JSON / API',
    poll_cadence: 'Daily',
    confidence_ceiling: 'A',
    license_type: 'Public Domain',
    status: 'ONLINE',
    obs_count: 1420,
    ent_count: 380,
    metadata: JSON.stringify({ chapters: ['OBSERVE', 'DECIDE', 'LOOKUP'] })
  },
  {
    source_id: 'NATIONAL_CERTS',
    name: 'National CERTs (CISA, NCSC, BSI, ANSSI, ENISA)',
    access_method: 'RSS / HTML',
    poll_cadence: 'Hourly',
    confidence_ceiling: 'A',
    license_type: 'Public Records',
    status: 'ONLINE',
    obs_count: 480,
    ent_count: 140,
    metadata: JSON.stringify({ chapters: ['OBSERVE', 'ORIENT', 'DECIDE'] })
  },
  {
    source_id: 'RANSOMWARE_LIVE',
    name: 'ransomware.live · Leak-Site Index',
    access_method: 'Open API',
    poll_cadence: 'Hourly',
    confidence_ceiling: 'B',
    license_type: 'Metadata Only',
    status: 'ONLINE',
    obs_count: 890,
    ent_count: 210,
    metadata: JSON.stringify({ chapters: ['OBSERVE', 'LOOKUP'] })
  },
  {
    source_id: 'REGULATORY_REGISTERS',
    name: 'Regulatory Registers (NIS2, DORA, ICO, DPC, CNIL)',
    access_method: 'HTML / PDF Scrape',
    poll_cadence: 'Daily',
    confidence_ceiling: 'A',
    license_type: 'Public Records',
    status: 'ONLINE',
    obs_count: 310,
    ent_count: 95,
    metadata: JSON.stringify({ chapters: ['CLOCK', 'DECIDE'] })
  },
  {
    source_id: 'PASSIVE_DNS_CRT',
    name: 'crt.sh · Passive DNS · DMARC/SPF',
    access_method: 'Open Lookups',
    poll_cadence: 'Daily',
    confidence_ceiling: 'B',
    license_type: 'Public CT Logs',
    status: 'ONLINE',
    obs_count: 12400,
    ent_count: 1200,
    metadata: JSON.stringify({ chapters: ['OBSERVE', 'LOOKUP'] })
  },
  {
    source_id: 'PROCUREMENT',
    name: 'Public Procurement (TED, Contracts Finder, SAM.gov)',
    access_method: 'Open API',
    poll_cadence: 'Daily',
    confidence_ceiling: 'A',
    license_type: 'Public Data',
    status: 'ONLINE',
    obs_count: 5400,
    ent_count: 650,
    metadata: JSON.stringify({ chapters: ['DECIDE', 'CONNECT'] })
  },
  {
    source_id: 'DARKWEB_META',
    name: 'Hudson Rock Cavalier · IntelX Metadata',
    access_method: 'Free API / Rate Limited',
    poll_cadence: 'Daily',
    confidence_ceiling: 'B',
    license_type: 'Metadata Only',
    status: 'DEGRADED',
    obs_count: 1890,
    ent_count: 420,
    metadata: JSON.stringify({ chapters: ['DECIDE', 'LOOKUP'] })
  },
  {
    source_id: 'CHATTER_NEWS',
    name: 'GDELT · Google News RSS · Mastodon',
    access_method: 'Open RSS / API',
    poll_cadence: 'Hourly',
    confidence_ceiling: 'C',
    license_type: 'Open APIs',
    status: 'ONLINE',
    obs_count: 9800,
    ent_count: 1100,
    metadata: JSON.stringify({ chapters: ['OBSERVE', 'ORIENT'] })
  },
  {
    source_id: 'AI_RISK_REPO',
    name: 'MIT AI Risk Repo · AI Incident Database',
    access_method: 'Open API',
    poll_cadence: 'Weekly',
    confidence_ceiling: 'A',
    license_type: 'CC BY 4.0',
    status: 'ONLINE',
    obs_count: 320,
    ent_count: 85,
    metadata: JSON.stringify({ chapters: ['ORIENT', 'DECIDE'] })
  },
  {
    source_id: 'OPEN_SUPPLY',
    name: 'OpenOwnership / PSC / Wikidata',
    access_method: 'Bulk Downloads',
    poll_cadence: 'Weekly',
    confidence_ceiling: 'B',
    license_type: 'Open Data',
    status: 'ONLINE',
    obs_count: 7600,
    ent_count: 980,
    metadata: JSON.stringify({ chapters: ['CONNECT', 'LOOKUP'] })
  },
  {
    source_id: 'CYBER_ESSENTIALS',
    name: 'Cyber Essentials · ISO 27001 Registers',
    access_method: 'Public Lookups',
    poll_cadence: 'Weekly',
    confidence_ceiling: 'A',
    license_type: 'Public Registers',
    status: 'ONLINE',
    obs_count: 4300,
    ent_count: 720,
    metadata: JSON.stringify({ chapters: ['LOOKUP', 'DECIDE'] })
  },
  {
    source_id: 'SANCTIONS_LISTS',
    name: 'OFAC · BIS · EU / UK Consolidated Sanctions',
    access_method: 'Open API',
    poll_cadence: 'Daily',
    confidence_ceiling: 'A',
    license_type: 'Public Domain',
    status: 'ONLINE',
    obs_count: 14500,
    ent_count: 14500,
    metadata: JSON.stringify({ chapters: ['TRUST', 'ACT'] })
  },
  {
    source_id: 'SHODAN_CENSYS',
    name: 'Shodan / Censys / Shadowserver Aggregate',
    access_method: 'API Keys',
    poll_cadence: 'Daily',
    confidence_ceiling: 'B',
    license_type: 'Free Tier',
    status: 'NEEDS KEY',
    obs_count: 0,
    ent_count: 0,
    metadata: JSON.stringify({ chapters: ['OBSERVE', 'LOOKUP'] })
  }
];

function seedSourceRegistry() {
  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO source_registry (
      source_id, name, access_method, poll_cadence, confidence_ceiling,
      license_type, status, last_polled_at, obs_count, ent_count, metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const src of SOURCE_CATALOG) {
    insertStmt.run(
      src.source_id,
      src.name,
      src.access_method,
      src.poll_cadence,
      src.confidence_ceiling,
      src.license_type,
      src.status,
      new Date().toISOString(),
      src.obs_count,
      src.ent_count,
      src.metadata
    );
  }
  console.log('[SOURCE REGISTRY] Initialized 15 catalog sources.');
}

seedSourceRegistry();

module.exports = { SOURCE_CATALOG, seedSourceRegistry };
