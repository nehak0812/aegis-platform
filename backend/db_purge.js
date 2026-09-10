const db = require('./db');

function purgeSyntheticData() {
  console.log('[DB PURGE] Purging legacy database records...');

  db.exec('DELETE FROM entity_scores;');
  db.exec('DELETE FROM entity_signals;');
  db.exec('DELETE FROM entity_relationships;');
  db.exec('DELETE FROM entity_domains;');
  db.exec('DELETE FROM entity_identifiers;');
  db.exec('DELETE FROM signals;');
  db.exec('DELETE FROM review_queue;');
  db.exec('DELETE FROM raw_records;');
  db.exec('DELETE FROM entities;');
  
  console.log('[DB PURGE] Purge complete. All tables reset to 100% clean state.');
}

if (require.main === module) {
  purgeSyntheticData();
}

module.exports = purgeSyntheticData;
