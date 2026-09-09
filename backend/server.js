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

// Generate AEGIS bootstrap object matching window.AEGIS frontend shape
function getBootstrapData() {
  try {
    const entities = db.prepare(`
      SELECT e.*, es.external_pressure_score, es.internal_weakness_score,
             es.composite_exposure_score, es.readiness_score, es.axis_scores, es.citations
      FROM entities e
      LEFT JOIN entity_scores es ON e.entity_id = es.entity_id
      WHERE e.sector = 'Energy & Utilities' AND e.is_sanctioned = 0 AND e.is_suppressed = 0
    `).all();

    const targets = entities.map(e => {
      const citations = e.citations ? JSON.parse(e.citations) : [
        { name: 'GLEIF LEI Master', url: `https://api.gleif.org/api/v1/lei-records?filter[lei]=${e.master_key_val}`, retrieved_at: new Date().toISOString(), confidence: 'A' }
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

      const countryCode = e.country === 'United Kingdom' ? 'UK' : e.country === 'Germany' ? 'DE' : e.country === 'Netherlands' ? 'NL' : 'EU';

      return {
        id: e.entity_id,
        n: e.canonical_name,
        s: e.sector,
        g: `${e.city || 'City'}, ${countryCode}`,
        lat: e.lat,
        lon: e.lon,
        sc: e.composite_exposure_score || 75,
        rd: e.readiness_score || 80,
        reg: e.nis2_status || 'NIS2 · Essential Entity',
        rec: 4,
        val: 4,
        lens: 'ENE',
        trig: signals.length > 0 ? signals[0].title : `Live LEI resolved record (${e.master_key_val}). Active NIS2 compliance monitoring.`,
        ax: e.axis_scores ? JSON.parse(e.axis_scores) : [80, 65, 72, 85, 60],
        lk: 12,
        cf: 'A',
        tl: timeline,
        plays: [
          ['PREVENTIVE', '<b>OT exposure diagnostic</b> — 3-week passive assessment benchmarked against European TSOs.'],
          ['DETECTIVE', '<b>Co-managed detection & OT SOC architecture</b> — sell the operating model.'],
          ['RESPONSIVE', '<b>NIS2 incident reporting drill</b> — 24-hour mandatory notification workflow validation.'],
          ['IDENTITY', '<b>Vendor privileged access audit</b> — persistent OT remote access review.']
        ],
        say: [
          'Regulator enforcement active under NIS2 mandate. Reporting deadline is the opener.',
          `Peer European utility disclosed cyber advisory within past 90 days. Public board benchmark.`,
          'Third-party supply chain telemetry vendor audit recommended.'
        ],
        entry: 'Group CISO, Head of OT Security. Board risk committee owns budget under NIS2 management liability.',
        deal: [
          'OT exposure diagnostic · fixed fee',
          'OT SOC design → co-managed detection → IR retainer',
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

    return {
      SECTORS: ['Energy & Utilities', 'Banking & Capital Mkts', 'Healthcare & Life Sci', 'Retail & Consumer', 'Technology & SaaS'],
      REGIONS: ['W. EUROPE', 'N. AMERICA', 'LATAM', 'APAC', 'GULF / MEA'],
      TARGETS: targets,
      SOURCES: sources,
      SIGNALS: [
        ['r', 'KEV ADDITION', 'Ivanti & Citrix edge appliance CVEs added to CISA KEV. Target grid operators run affected perimeter gateways.', 'CISA KEV · A', 0],
        ['a', 'CERT ADVISORY', 'NCSC UK & BSI DE advisory on targeted grid reconnaissance against European TSOs.', 'NCSC / BSI · A', 1],
        ['b', 'REGISTRY SWEEP', 'Annual filings indicate early-stage OT SOC visibility across transmission networks.', 'Companies House / HRB · A', 2]
      ]
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

  if (url.pathname === '/api/targets') {
    const targets = db.prepare("SELECT * FROM entities WHERE sector = 'Energy & Utilities'").all();
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

// Create Primary Server on process.env.PORT
const primaryServer = http.createServer(handleRequest);
primaryServer.listen(ENV_PORT, HOST, () => {
  console.log(`[AEGIS API SERVER] Primary server listening on http://${HOST}:${ENV_PORT}`);
  runPipeline();
});

// Create Backup Dual-Port Listener on port 8000 if process.env.PORT is different
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
