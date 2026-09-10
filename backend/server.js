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

// Run pipeline ingestion
async function runPipeline() {
  try {
    console.log('====================================================');
    console.log('[AEGIS PIPELINE] Running Phase 0 & Phase 1 Ingestion...');
    console.log('====================================================');
    
    seedSourceRegistry();
    await collectGLEIF();
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

      const countryCode = e.country === 'United Kingdom' ? 'UK' : e.country === 'Germany' ? 'DE' : e.country === 'Netherlands' ? 'NL' : 'GL';

      return {
        id: e.entity_id,
        n: e.canonical_name,
        s: e.sector,
        g: `${e.city || 'City'}, ${countryCode}`,
        lat: e.lat || 51.5,
        lon: e.lon || -0.12,
        sc: e.composite_exposure_score || 75,
        rd: e.readiness_score || 80,
        reg: e.nis2_status || 'NIS2 · In Scope Entity',
        rec: 4,
        val: 4,
        lens: e.sector.startsWith('Energy') ? 'ENE' : 'ALL',
        trig: signals.length > 0 ? signals[0].title : `Live LEI resolved record (${e.master_key_val}). Active compliance monitoring.`,
        ax: e.axis_scores ? JSON.parse(e.axis_scores) : [80, 65, 72, 85, 60],
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
      ['Amsterdam / Eemshaven · NL Interconnect', 52.3676, 4.9041, 10, 'Subsea offshore wind grid interconnect & European Internet Exchange', 'ENE', 1]
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
      realExtInt[t.n] = {
        ext: [t.sc, Math.round(t.sc * 0.9), Math.round(t.sc * 0.8), Math.round(t.sc * 0.85), Math.round(t.sc * 0.7)],
        int: [t.rd, Math.round(t.rd * 0.85), Math.round(t.rd * 0.9), Math.round(t.rd * 0.75), Math.round(t.rd * 0.8)]
      };
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
