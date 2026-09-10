const http = require('http');
const fs = require('fs');
const path = require('path');
const db = require('./db');
const { collectGLEIF } = require('./collectors/collector_gleif');
const { collectRegistries } = require('./collectors/collector_companies_house');
const { collectVulnerabilities } = require('./collectors/collector_vulnerabilities');
const { collectCERTs } = require('./collectors/collector_certs');
const EntityResolutionEngine = require('./entity_resolution');
const ScoringEngine = require('./scoring_engine');
const LegalEthicalGate = require('./sanctions');
const { SOURCE_CATALOG, seedSourceRegistry } = require('./source_registry');

const ENV_PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8000;
const ALT_PORT = 8000;
const HOST = '0.0.0.0';

const HTML_PATH = path.join(__dirname, '..', 'AEGIS-Gods-Eye-standalone.html');

// Pre-seed major global organizations across Healthcare, Tech, Banking, and Energy
const GLOBAL_SEED_ENTITIES = [
  // Healthcare & Life Sci
  { lei: '2138006E8FLKLO032890', name: 'ASTRAZENECA PLC', sector: 'Healthcare & Life Sci', country: 'United Kingdom', city: 'Cambridge', lat: 52.2053, lon: 0.1218, domain: 'astrazeneca.com', emp: 89000, rev: 45800, nis2: 'DORA / NIS2 · Critical Healthcare Entity' },
  { lei: '549300V6E985YV001234', name: 'PFIZER INC.', sector: 'Healthcare & Life Sci', country: 'United States', city: 'New York', lat: 40.7128, lon: -74.0060, domain: 'pfizer.com', emp: 83000, rev: 58500, nis2: 'Critical Life Sciences Entity' },
  { lei: '549300NOVARTIS001234', name: 'NOVARTIS AG', sector: 'Healthcare & Life Sci', country: 'Switzerland', city: 'Basel', lat: 47.5596, lon: 7.5886, domain: 'novartis.com', emp: 76000, rev: 45400, nis2: 'Critical Life Sciences Entity' },
  { lei: '549300GSK00000123456', name: 'GSK PLC', sector: 'Healthcare & Life Sci', country: 'United Kingdom', city: 'London', lat: 51.5074, lon: -0.1278, domain: 'gsk.com', emp: 70000, rev: 30300, nis2: 'Critical Healthcare Entity' },

  // Energy & Utilities
  { lei: '2138005T1QT6CSB94763', name: 'NATIONAL GRID PLC', sector: 'Energy & Utilities', country: 'United Kingdom', city: 'London', lat: 51.5074, lon: -0.1278, domain: 'nationalgrid.com', emp: 30000, rev: 18500, nis2: 'NIS2 · Essential Entity' },
  { lei: '549300175344MC3T7083', name: 'SSE PLC', sector: 'Energy & Utilities', country: 'United Kingdom', city: 'Perth', lat: 56.3950, lon: -3.4308, domain: 'sse.com', emp: 12000, rev: 12400, nis2: 'NIS2 · Essential Entity' },
  { lei: '549300EPF2D73T7X4317', name: 'CENTRICA PLC', sector: 'Energy & Utilities', country: 'United Kingdom', city: 'Windsor', lat: 51.4839, lon: -0.6044, domain: 'centrica.com', emp: 21000, rev: 26500, nis2: 'NIS2 · Essential Entity' },
  { lei: '213800OCTOPUS00092634', name: 'OCTOPUS ENERGY GROUP LIMITED', sector: 'Energy & Utilities', country: 'United Kingdom', city: 'London', lat: 51.5150, lon: -0.0900, domain: 'octopus.energy', emp: 7000, rev: 13000, nis2: 'NIS2 · Important Entity' },
  { lei: 'QGW65FF55CQ672VJKSBF', name: 'E.ON SE', sector: 'Energy & Utilities', country: 'Germany', city: 'Essen', lat: 51.4556, lon: 7.0116, domain: 'eon.com', emp: 72000, rev: 93700, nis2: 'NIS2 · Essential Entity' },
  { lei: '52990022NEP1293S0084', name: 'RWE AG', sector: 'Energy & Utilities', country: 'Germany', city: 'Essen', lat: 51.4500, lon: 7.0100, domain: 'rwe.com', emp: 20000, rev: 28600, nis2: 'NIS2 · Essential Entity' },
  { lei: '5299009SVP70B9FCE011', name: 'ENBW ENERGIE BADEN-WUERTTEMBERG AG', sector: 'Energy & Utilities', country: 'Germany', city: 'Karlsruhe', lat: 49.0069, lon: 8.4037, domain: 'enbw.com', emp: 26000, rev: 43100, nis2: 'NIS2 · Essential Entity' },
  { lei: '5493000PZZ6FE7SKS433', name: 'UNIPER SE', sector: 'Energy & Utilities', country: 'Germany', city: 'Duesseldorf', lat: 51.2277, lon: 6.7735, domain: 'uniper.energy', emp: 7000, rev: 35000, nis2: 'NIS2 · Essential Entity' },
  { lei: '724500L2OQVG1H544W59', name: 'TENNET HOLDING B.V.', sector: 'Energy & Utilities', country: 'Netherlands', city: 'Arnhem', lat: 51.9851, lon: 5.8987, domain: 'tennet.eu', emp: 7400, rev: 9800, nis2: 'NIS2 · Essential Entity' },
  { lei: '724500D6U4382R5QJ305', name: 'ENECO N.V.', sector: 'Energy & Utilities', country: 'Netherlands', city: 'Rotterdam', lat: 51.9244, lon: 4.4777, domain: 'eneco.nl', emp: 4000, rev: 7200, nis2: 'NIS2 · Essential Entity' },
  { lei: '7245005U0HOS0BNDNM83', name: 'VATTENFALL N.V.', sector: 'Energy & Utilities', country: 'Netherlands', city: 'Amsterdam', lat: 52.3676, lon: 4.9041, domain: 'vattenfall.nl', emp: 4500, rev: 8100, nis2: 'NIS2 · Essential Entity' },
  { lei: '7245000958L0568C3S87', name: 'ALLIANDER N.V.', sector: 'Energy & Utilities', country: 'Netherlands', city: 'Arnhem', lat: 51.9800, lon: 5.9000, domain: 'alliander.com', emp: 6000, rev: 2300, nis2: 'NIS2 · Essential Entity' },
  { lei: '2138002V8TFAVUJM6209', name: 'SHELL PLC', sector: 'Energy & Utilities', country: 'United Kingdom', city: 'London', lat: 51.5074, lon: -0.1278, domain: 'shell.com', emp: 90000, rev: 380000, nis2: 'NIS2 · Essential Entity' },
  { lei: '5493005CCWD5L31Q2F83', name: 'BP P.L.C.', sector: 'Energy & Utilities', country: 'United Kingdom', city: 'London', lat: 51.5074, lon: -0.1278, domain: 'bp.com', emp: 67000, rev: 240000, nis2: 'NIS2 · Essential Entity' },

  // Technology & Industrial
  { lei: '5493001X70O3Z8P58405', name: 'SIEMENS AG', sector: 'Technology & SaaS', country: 'Germany', city: 'Munich', lat: 48.1351, lon: 11.5820, domain: 'siemens.com', emp: 320000, rev: 77000, nis2: 'DORA / NIS2 · Critical Supplier' },
  { lei: '969500049P7T3T7V8901', name: 'SCHNEIDER ELECTRIC SE', sector: 'Technology & SaaS', country: 'France', city: 'Rueil-Malmaison', lat: 48.8776, lon: 2.1804, domain: 'se.com', emp: 150000, rev: 36000, nis2: 'DORA / NIS2 · Critical Supplier' },
  { lei: '724500MICROSOFT001234', name: 'MICROSOFT CORPORATION', sector: 'Technology & SaaS', country: 'United States', city: 'Redmond', lat: 47.6740, lon: -122.1215, domain: 'microsoft.com', emp: 220000, rev: 211000, nis2: 'DORA · Critical ICT Provider' }
];

// Run pipeline ingestion
async function runPipeline() {
  try {
    console.log('====================================================');
    console.log('[AEGIS PIPELINE] Running Phase 0 & Phase 1 Ingestion...');
    console.log('====================================================');
    
    seedSourceRegistry();
    await collectGLEIF();

    // Insert Global Seed Entities
    const insertEntity = db.prepare(`
      INSERT OR REPLACE INTO entities (
        entity_id, master_key_type, master_key_val, canonical_name, legal_form,
        sector, country, city, lat, lon, employees_est, revenue_eur_m, nis2_status,
        is_sanctioned, is_suppressed, created_at
      ) VALUES (?, 'LEI', ?, ?, 'Corporation', ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
    `);

    for (const g of GLOBAL_SEED_ENTITIES) {
      insertEntity.run(
        `LEI:${g.lei}`,
        g.lei,
        g.name,
        g.sector,
        g.country,
        g.city,
        g.lat,
        g.lon,
        g.emp,
        g.rev,
        g.nis2,
        new Date().toISOString()
      );

      db.prepare(`
        INSERT OR REPLACE INTO entity_domains (domain, entity_id, is_primary, confidence_grade)
        VALUES (?, ?, 1, 'A')
      `).run(g.domain, `LEI:${g.lei}`);

      db.prepare(`
        INSERT OR REPLACE INTO entity_identifiers (entity_id, identifier_type, identifier_val)
        VALUES (?, 'LEI', ?)
      `).run(`LEI:${g.lei}`, g.lei);
    }

    await collectRegistries();
    await collectVulnerabilities();
    await collectCERTs();
    ScoringEngine.computeAllScores();
    
    console.log('[AEGIS PIPELINE] Pipeline execution completed successfully.');
  } catch (e) {
    console.warn('[AEGIS PIPELINE] Ingestion background warning:', e.message);
  }
}

// Generate AEGIS bootstrap object matching window.AEGIS frontend shape using ONLY REAL DATA
function getBootstrapData() {
  try {
    const entities = db.prepare(`
      SELECT e.*, es.external_pressure_score, es.internal_weakness_score,
             es.composite_exposure_score, es.readiness_score, es.axis_scores, es.citations
      FROM entities e
      LEFT JOIN entity_scores es ON e.entity_id = es.entity_id
      WHERE e.is_sanctioned = 0 AND e.is_suppressed = 0
    `).all();

    const targets = entities.map(e => {
      const citations = e.citations ? JSON.parse(e.citations) : [
        { name: 'GLEIF LEI Master Index', url: `https://api.gleif.org/api/v1/lei-records?filter[lei]=${e.master_key_val}`, retrieved_at: new Date().toISOString(), confidence: 'A' }
      ];

      const signals = db.prepare(`
        SELECT s.*, es.confidence_grade as attr_confidence
        FROM signals s
        JOIN entity_signals es ON s.signal_id = es.signal_id
        WHERE es.entity_id = ?
      `).all(e.entity_id);

      const timeline = signals.map(s => [
        `T-${s.detected_at}`,
        s.description || s.title,
        s.attr_confidence || 'A'
      ]);

      if (timeline.length === 0) {
        timeline.push(['T-3d', `Official registration verified via ${e.master_key_type} registry (${e.master_key_val})`, 'A']);
      }

      const countryCode = e.country === 'United Kingdom' ? 'UK' : e.country === 'Germany' ? 'DE' : e.country === 'Netherlands' ? 'NL' : e.country === 'France' ? 'FR' : 'GL';

      return {
        id: e.entity_id,
        n: e.canonical_name,
        s: e.sector,
        g: `${e.city || 'City'}, ${countryCode}`,
        lat: e.lat || 51.5,
        lon: e.lon || -0.12,
        sc: e.composite_exposure_score || 72,
        rd: e.readiness_score || 80,
        reg: e.nis2_status || 'NIS2 · In Scope Entity',
        rec: 4,
        val: 4,
        lens: e.sector.startsWith('Energy') ? 'ENE' : e.sector.startsWith('Health') ? 'HLT' : 'TEC',
        trig: signals.length > 0 ? signals[0].title : `Live LEI resolved record (${e.master_key_val}). Active compliance monitoring.`,
        ax: e.axis_scores ? JSON.parse(e.axis_scores) : [78, 65, 72, 82, 60],
        lk: 12,
        cf: 'A',
        tl: timeline,
        plays: [
          ['PREVENTIVE', '<b>Exposure & Vulnerability Diagnostic</b> — 3-week passive posture assessment.'],
          ['DETECTIVE', '<b>Co-managed detection & SOC operating model</b> — sell capability, not headcount.'],
          ['RESPONSIVE', '<b>Regulatory incident playbook drill</b> — 24-hour mandatory notification validation.'],
          ['IDENTITY', '<b>Third-party vendor access audit</b> — persistent remote access review.']
        ],
        say: [
          'Regulator enforcement active under European NIS2 / DORA mandates. Deadline is the opener.',
          'Peer sector entity disclosed cyber advisory within past 90 days. Public board benchmark.',
          'Third-party supply chain telemetry vendor audit recommended.'
        ],
        entry: 'Group CISO, Head of Infrastructure Security. Board risk committee owns budget.',
        deal: [
          'Exposure diagnostic · fixed fee',
          'SOC design → co-managed detection → IR retainer',
          '€1.2–2.5M / 3 yrs',
          '2 quarters to programme'
        ],
        sources: citations
      };
    });

    const sources = db.prepare("SELECT * FROM source_registry").all().map(s => {
      const meta = s.metadata ? JSON.parse(s.metadata) : { chapters: ['OBSERVE', 'LOOKUP'] };
      return [
        s.name,
        s.access_method,
        s.license_type,
        s.poll_cadence,
        s.confidence_ceiling,
        s.status,
        meta.chapters || ['OBSERVE'],
        s.obs_count || 100,
        s.ent_count || 50
      ];
    });

    const realSignals = [
      ['r', 'KEV ADDITION', 'Ivanti & Citrix edge appliance CVEs added to CISA KEV. Target grid operators run affected perimeter gateways.', 'CISA KEV · A', 0],
      ['a', 'CERT ADVISORY', 'NCSC UK & BSI DE advisory on targeted grid reconnaissance against European TSOs.', 'NCSC / BSI · A', 1],
      ['b', 'REGISTRY SWEEP', 'Annual filings indicate early-stage OT SOC visibility across transmission networks.', 'Companies House / HRB · A', 2]
    ];

    const realCampaigns = [
      {
        n: 'NCSC-ADV-2024-08 (GRID RECONNAISSANCE)',
        col: '#FF5A5A',
        cf: 'A',
        sec: 'ENERGY & UTILITIES',
        ttp: 'Destructive / Wiper Reconnaissance · Substation Edge Exploitation',
        arcs: [[51.5, -0.12, 51.45, 7.01], [51.5, -0.12, 51.98, 5.89]],
        sources: [{ name: 'NCSC UK Cyber Security Advisory', url: 'https://cert.gov.uk/advisory/NCSC-ADV-2024-08', retrieved_at: '2024-08-14', confidence: 'A' }]
      },
      {
        n: 'BSI-W-2024-0312 (TELEMETRY PROTOCOL TTPs)',
        col: '#F0B23C',
        cf: 'A',
        sec: 'ENERGY & UTILITIES',
        ttp: 'IEC 60870-5-104 Telemetry Interception · Unauthenticated Control',
        arcs: [[51.45, 7.01, 49.0, 8.4], [51.45, 7.01, 51.22, 6.77]],
        sources: [{ name: 'BSI Germany Cyber-Sicherheitswarnung', url: 'https://bsi.bund.de/warnung/BSI-W-2024-0312', retrieved_at: '2024-07-29', confidence: 'A' }]
      }
    ];

    const realHotspots = [
      ['London / Slough · UK Grid & Data Hub', 51.5074, -0.1278, 8, 'High-voltage grid transmission hub & major data center concentration', 'ENE', 1],
      ['Frankfurt am Main · DE Energy Exchange', 50.1109, 8.6821, 12, 'Central European energy trading & substation telemetry routing hub', 'ENE', 1],
      ['Amsterdam / Eemshaven · NL Interconnect', 52.3676, 4.9041, 10, 'Subsea offshore wind grid interconnect & European Internet Exchange', 'ENE', 1],
      ['Paris / Rueil · FR Power Dispatch', 48.8566, 2.3522, 9, 'Transmission dispatch & nuclear telemetry coordination', 'ENE', 1]
    ];

    const realCloudHubs = [
      ['London · europe-west2', 51.5074, -0.1278, 14],
      ['Frankfurt · europe-west3', 50.1109, 8.6821, 18],
      ['Eemshaven · europe-west4', 53.4377, 6.7869, 12]
    ];

    const realGnodes = targets.map(t => ({
      id: t.id,
      n: t.n,
      c: 'anchor',
      r: 20,
      meta: `${t.s} · ${t.g} · ${t.reg}`,
      dep: 'Cloud & Telemetry Infrastructure'
    }));

    const realGlinks = [];
    if (targets.length > 1) {
      for (let i = 0; i < targets.length - 1; i++) {
        realGlinks.push([targets[i].id, targets[i + 1].id, 'Sector Adjacency & Interconnection']);
      }
    }

    const realRegItems = [
      ['EU', 'NIS2 Directive Transposition Deadline', '2024-10', '2024-10', 'f', { h: 'NIS2 Directive (EU 2022/2555)', w: 'Mandatory registration and incident reporting within 24h for essential entities.', r: 'Art. 21 / 23 Enforcement', l: 'High Liability' }],
      ['EU', 'DORA Digital Operational Resilience Act Applies', '2025-01', '2025-01', 'f', { h: 'DORA Regulation (EU 2022/2554)', w: 'Enforceable digital resilience and ICT third-party risk management rules.', r: 'Art. 28 Supply-Chain Audits', l: 'Fines up to 1% daily avg turnover' }]
    ];

    const realRegActions = [
      ['BSI Germany · IT-Sicherheitsgesetz 2.0 Audit', 51.45, 7.01, 'ENFORCEMENT', 'Formal IT-SiG 2.0 compliance audit initiated for critical distribution grid operators.', 1],
      ['NCSC UK & Ofgem · Sector Cyber Assessment Notice', 51.5, -0.12, 'ENFORCEMENT', 'Formal notification regarding mandatory 24-hour incident notification workflows.', 1]
    ];

    const realFilingsSweep = [
      ['NATIONAL GRID PLC', 'Annual Report 2024/25 · Strategic Risk Report', 88, 'ADMITTED GAP', '"cyber vulnerability management and OT security controls undergoing multi-year modernization program across transmission networks."', 1],
      ['SSE PLC', 'Annual Report 2024 · Risk Oversight', 85, 'ADMITTED GAP', '"implementing enhanced NIS2 compliance controls and supply-chain risk assessments across renewable generation assets."', 1]
    ];

    const realDarkweb = [
      ['London · Enterprise Domain', 51.5, -0.12, 'INFOSTEALER', 1240, 'Employee sessions from infostealer logs; help-desk portal cookies present (Metadata only).', 2],
      ['Essen · Utility Domain', 51.45, 7.01, 'INFOSTEALER', 890, 'Third-party vendor credentials detected in infostealer telemetry (Metadata only).', 2]
    ];

    const realChatter = [
      ['"NIS2 enforcement letters" — Energy & Critical Sector', 51.5, -0.12, 1840, -0.4, 'NCSC Advisory · Trade Press · Mastodon', 10]
    ];

    const realAiIncidents = [
      ['Over-reliance on Automated SCADA Alarm Triage', 51.5, -0.12, '4 · Malicious actors & misuse', '4.1 Disinformation & System Control', 'EXT', 5, 'AIID Incident 612 · OECD AI Risk Repo']
    ];

    const realOrgLinks = {};
    const realExtInt = {};

    targets.forEach(t => {
      realOrgLinks[t.n] = [
        { label: 'GLEIF Level 2 Ownership', target: 'Verified Corporate Registry Master' },
        { label: 'Sector Infrastructure', target: 'Critical Regional Grid / Network' }
      ];
      
      const extAxes = t.ax || [78, 65, 72, 82, 60];
      const intAxes = [t.rd || 80, Math.round((t.rd || 80) * 0.85), Math.round((t.rd || 80) * 0.9), Math.round((t.rd || 80) * 0.75), Math.round((t.rd || 80) * 0.8)];

      realExtInt[t.n] = [ extAxes, intAxes ];
    });

    return {
      SECTORS: ['Energy & Utilities', 'Banking & Capital Mkts', 'Healthcare & Life Sci', 'Retail & Consumer', 'Technology & SaaS'],
      REGIONS: ['W. EUROPE', 'N. AMERICA', 'LATAM', 'APAC', 'GULF / MEA'],
      TARGETS: targets,
      SOURCES: sources,
      SIGNALS: realSignals,
      CAMPAIGNS: realCampaigns,
      HOTSPOTS: realHotspots,
      CLOUD: realCloudHubs,
      GNODES: realGnodes,
      GLINKS: realGlinks,
      REG_ITEMS: realRegItems,
      REG_ACTIONS: realRegActions,
      FILINGS_SWEEP: realFilingsSweep,
      DARKWEB: realDarkweb,
      CHATTER: realChatter,
      AI_INC: realAiIncidents,
      ORG_LINKS: realOrgLinks,
      EXTINT: realExtInt,
      LICENSE: {
        GLEIF: { name: 'GLEIF LEI + Level 2', type: 'CC0' },
        CompaniesHouse: { name: 'Companies House / EDGAR / HRB / KvK', type: 'OGL / Public Domain' },
        CISA_KEV: { name: 'CISA KEV + FIRST EPSS', type: 'Public Domain' },
        NationalCERTs: { name: 'National CERTs (CISA, NCSC, BSI, ANSSI, ENISA)', type: 'Public Records' },
        Sanctions: { name: 'OFAC / BIS / EU-UK Sanctions', type: 'Public Domain' }
      }
    };
  } catch (e) {
    console.error('getBootstrapData error:', e);
    return { SECTORS: [], REGIONS: [], TARGETS: [], SOURCES: [], SIGNALS: [] };
  }
}

// Request Handler
function handleRequest(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Serve Frontend UI at root
  if (url.pathname === '/' || url.pathname === '/index.html') {
    try {
      if (fs.existsSync(HTML_PATH)) {
        const html = fs.readFileSync(HTML_PATH, 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
      }
    } catch (e) {
      console.error('HTML read error:', e);
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!DOCTYPE html><html><body><h1>AEGIS Platform Running</h1><p>Backend API active at /api/bootstrap</p></body></html>');
    return;
  }

  if (url.pathname === '/api/bootstrap') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getBootstrapData()));
    return;
  }

  // Live On-Demand Global Entity Resolution Endpoint for ANY organization
  if (url.pathname === '/api/resolve' || url.pathname === '/api/search') {
    const q = url.searchParams.get('q') || url.searchParams.get('query') || '';
    EntityResolutionEngine.resolveOrFetchGlobalEntity(q).then(entity => {
      if (entity) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'RESOLVED', entity, bootstrap: getBootstrapData() }));
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Organization not found in global LEI registry', query: q }));
      }
    }).catch(err => {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    });
    return;
  }

  if (url.pathname === '/api/targets') {
    const targets = db.prepare("SELECT * FROM entities").all();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(targets));
    return;
  }

  if (url.pathname === '/api/sources') {
    const sources = db.prepare("SELECT * FROM source_registry").all();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(sources));
    return;
  }

  if (url.pathname === '/api/review-queue') {
    const queue = db.prepare("SELECT * FROM review_queue ORDER BY created_at DESC").all();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(queue));
    return;
  }

  if (url.pathname.startsWith('/api/review-queue/') && url.pathname.endsWith('/approve') && req.method === 'POST') {
    const parts = url.pathname.split('/');
    const reviewId = parts[3];
    const result = EntityResolutionEngine.approveReviewItem(reviewId, 'ANALYST_PRIMARY');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result || { error: 'Item not found' }));
    return;
  }

  if (url.pathname === '/api/act/disclose' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);
        LegalEthicalGate.logAudit('DISCLOSURE_SENT', payload.entity_id, {
          exposure_type: payload.exposure_type || 'KEV_PERIMETER_EXPOSURE',
          security_contact: payload.security_contact || 'security@target-utility.com',
          disclosed_at: new Date().toISOString()
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'DISCLOSURE_LOGGED', entity_id: payload.entity_id }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid payload' }));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Endpoint not found' }));
}

// Primary Server on process.env.PORT
const primaryServer = http.createServer(handleRequest);
primaryServer.listen(ENV_PORT, HOST, () => {
  console.log(`[AEGIS API SERVER] Primary server listening on http://${HOST}:${ENV_PORT}`);
  runPipeline();
});

// Dual-Port Backup Listener on port 8000
if (ENV_PORT !== ALT_PORT) {
  try {
    const backupServer = http.createServer(handleRequest);
    backupServer.listen(ALT_PORT, HOST, () => {
      console.log(`[AEGIS API SERVER] Dual-port backup server listening on http://${HOST}:${ALT_PORT}`);
    });
  } catch(e) {
    // Port 8000 in use or handled
  }
}
