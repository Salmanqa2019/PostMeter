/**
 * Persistent store for PostMeter: collections + env.
 * Uses SQLite when available (local), else falls back to JSON file.
 */
const path = require('path');
const fs = require('fs');

const DB_FILE = path.join(__dirname, 'postmeter.db');
const FALLBACK_FILE = path.join(__dirname, 'postmeter-data.json');

let db = null;
let useFile = false;

function init() {
  if (db !== null) return;
  try {
    const Database = require('better-sqlite3');
    db = new Database(DB_FILE);
    db.exec(`
      CREATE TABLE IF NOT EXISTS store (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
    const row = db.prepare("SELECT value FROM store WHERE key = 'collections'").get();
    if (!row) {
      db.prepare("INSERT INTO store (key, value) VALUES ('collections', ?)").run(JSON.stringify([]));
    }
  } catch (e) {
    useFile = true;
    db = null;
  }
}

function getCollectionsPath() {
  return path.join(__dirname, 'hoppscotch-team-collections.json');
}

function readCollectionsFromFile(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(raw);
      return Array.isArray(data) ? data : (data && data.collections ? data.collections : []);
    }
  } catch (_) {}
  return [];
}

function getCollections() {
  init();
  if (db) {
    try {
      const row = db.prepare("SELECT value FROM store WHERE key = 'collections'").get();
      if (row && row.value) {
        const data = JSON.parse(row.value);
        return Array.isArray(data) ? data : [];
      }
    } catch (e) {
      return [];
    }
    return [];
  }
  return readCollectionsFromFile(FALLBACK_FILE);
}

function saveCollections(data) {
  const arr = Array.isArray(data) ? data : [];
  init();
  if (db) {
    try {
      const stmt = db.prepare("INSERT OR REPLACE INTO store (key, value) VALUES ('collections', ?)");
      stmt.run(JSON.stringify(arr));
      return true;
    } catch (e) {
      return false;
    }
  }
  try {
    fs.writeFileSync(FALLBACK_FILE, JSON.stringify(arr, null, 2), 'utf8');
    return true;
  } catch (e) {
    return false;
  }
}

function useDatabase() {
  init();
  return db !== null;
}

module.exports = {
  getCollections,
  saveCollections,
  getCollectionsPath,
  readCollectionsFromFile,
  useDatabase,
  FALLBACK_FILE,
};
