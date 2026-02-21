/**
 * Persistent store for PostMeter: users, workspaces, members, collections per workspace.
 * Uses SQLite when available, else falls back to JSON file for collections only.
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
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS workspaces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS workspace_members (
        workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role TEXT NOT NULL DEFAULT 'member',
        created_at TEXT DEFAULT (datetime('now')),
        PRIMARY KEY (workspace_id, user_id)
      );
      CREATE INDEX IF NOT EXISTS idx_workspace_members_user ON workspace_members(user_id);
      CREATE INDEX IF NOT EXISTS idx_workspaces_owner ON workspaces(owner_id);
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

function getStoreKey(workspaceId) {
  return workspaceId != null ? `collections_${workspaceId}` : 'collections';
}

/** Get collections (no workspace = legacy key 'collections') */
function getCollections(workspaceId) {
  init();
  if (db) {
    try {
      const key = getStoreKey(workspaceId);
      const row = db.prepare("SELECT value FROM store WHERE key = ?").get(key);
      if (row && row.value) {
        const data = JSON.parse(row.value);
        return Array.isArray(data) ? data : [];
      }
      return [];
    } catch (e) {
      return [];
    }
  }
  return readCollectionsFromFile(FALLBACK_FILE);
}

/** Save collections for a workspace (or legacy key if no workspaceId) */
function saveCollections(data, workspaceId) {
  const arr = Array.isArray(data) ? data : [];
  init();
  if (db) {
    try {
      const key = getStoreKey(workspaceId);
      const stmt = db.prepare("INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)");
      stmt.run(key, JSON.stringify(arr));
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

// ---------- Users ----------
function createUser(email, passwordHash, name) {
  init();
  if (!db) return null;
  try {
    const r = db.prepare(
      "INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)"
    ).run(email.trim().toLowerCase(), passwordHash, (name || '').trim() || null);
    return r.lastInsertRowid;
  } catch (e) {
    return null;
  }
}

function getUserByEmail(email) {
  init();
  if (!db) return null;
  return db.prepare(
    "SELECT id, email, password_hash, name, created_at FROM users WHERE email = ?"
  ).get((email || '').trim().toLowerCase());
}

function getUserById(id) {
  init();
  if (!db) return null;
  const row = db.prepare(
    "SELECT id, email, name, created_at FROM users WHERE id = ?"
  ).get(id);
  if (!row) return null;
  return { id: row.id, email: row.email, name: row.name, created_at: row.created_at };
}

// ---------- Workspaces ----------
function createWorkspace(name, ownerId) {
  init();
  if (!db) return null;
  try {
    const r = db.prepare(
      "INSERT INTO workspaces (name, owner_id) VALUES (?, ?)"
    ).run((name || 'Workspace').trim(), ownerId);
    return r.lastInsertRowid;
  } catch (e) {
    return null;
  }
}

function getWorkspaceById(id) {
  init();
  if (!db) return null;
  return db.prepare(
    "SELECT id, name, owner_id, created_at FROM workspaces WHERE id = ?"
  ).get(id);
}

function getWorkspacesForUser(userId) {
  init();
  if (!db) return [];
  const rows = db.prepare(`
    SELECT w.id, w.name, w.owner_id, w.created_at,
           CASE WHEN w.owner_id = ? THEN 'owner' ELSE wm.role END AS role
    FROM workspaces w
    LEFT JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
    WHERE w.owner_id = ? OR wm.user_id = ?
    ORDER BY w.created_at DESC
  `).all(userId, userId, userId, userId);
  return rows;
}

function updateWorkspace(id, name) {
  init();
  if (!db) return false;
  try {
    db.prepare("UPDATE workspaces SET name = ? WHERE id = ?").run((name || '').trim(), id);
    return true;
  } catch (e) {
    return false;
  }
}

function deleteWorkspace(id) {
  init();
  if (!db) return false;
  try {
    const key = getStoreKey(id);
    db.prepare("DELETE FROM store WHERE key = ?").run(key);
    db.prepare("DELETE FROM workspace_members WHERE workspace_id = ?").run(id);
    db.prepare("DELETE FROM workspaces WHERE id = ?").run(id);
    return true;
  } catch (e) {
    return false;
  }
}

// ---------- Workspace members (share) ----------
function addWorkspaceMember(workspaceId, userId, role) {
  init();
  if (!db) return false;
  try {
    db.prepare(
      "INSERT OR REPLACE INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)"
    ).run(workspaceId, userId, role || 'member');
    return true;
  } catch (e) {
    return false;
  }
}

function removeWorkspaceMember(workspaceId, userId) {
  init();
  if (!db) return false;
  try {
    db.prepare("DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?").run(workspaceId, userId);
    return true;
  } catch (e) {
    return false;
  }
}

function getWorkspaceMembers(workspaceId) {
  init();
  if (!db) return [];
  const w = getWorkspaceById(workspaceId);
  if (!w) return [];
  const owner = getUserById(w.owner_id);
  if (!owner) return [];
  const list = [{ id: owner.id, email: owner.email, name: owner.name, role: 'owner' }];
  const members = db.prepare(
    "SELECT user_id, role FROM workspace_members WHERE workspace_id = ?"
  ).all(workspaceId);
  const seen = new Set([owner.id]);
  for (const m of members) {
    if (seen.has(m.user_id)) continue;
    seen.add(m.user_id);
    const u = getUserById(m.user_id);
    if (u) list.push({ id: u.id, email: u.email, name: u.name, role: m.role || 'member' });
  }
  return list;
}

/** Check if user has access to workspace (owner or member) */
function userHasWorkspaceAccess(userId, workspaceId) {
  init();
  if (!db) return false;
  const w = getWorkspaceById(workspaceId);
  if (!w) return false;
  if (w.owner_id === userId) return true;
  const m = db.prepare("SELECT 1 FROM workspace_members WHERE workspace_id = ? AND user_id = ?").get(workspaceId, userId);
  return !!m;
}

module.exports = {
  getCollections,
  saveCollections,
  getCollectionsPath,
  readCollectionsFromFile,
  useDatabase,
  FALLBACK_FILE,
  createUser,
  getUserByEmail,
  getUserById,
  createWorkspace,
  getWorkspaceById,
  getWorkspacesForUser,
  updateWorkspace,
  deleteWorkspace,
  addWorkspaceMember,
  removeWorkspaceMember,
  getWorkspaceMembers,
  userHasWorkspaceAccess,
};
