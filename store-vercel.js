/**
 * File-based store for Vercel serverless (no SQLite).
 * Uses /tmp for auth and collections; data may be ephemeral between cold starts.
 */
const fs = require('fs');
const path = require('path');

const AUTH_FILE = '/tmp/postmeter-auth.json';
const COLLECTIONS_DIR = '/tmp/postmeter-collections';

function ensureDir(p) {
  try {
    if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
  } catch (_) {}
}

function readAuth() {
  try {
    if (fs.existsSync(AUTH_FILE)) {
      const raw = fs.readFileSync(AUTH_FILE, 'utf8');
      const d = JSON.parse(raw);
      return {
        users: Array.isArray(d.users) ? d.users : [],
        workspaces: Array.isArray(d.workspaces) ? d.workspaces : [],
        workspace_members: Array.isArray(d.workspace_members) ? d.workspace_members : [],
        nextUserId: typeof d.nextUserId === 'number' ? d.nextUserId : 1,
        nextWorkspaceId: typeof d.nextWorkspaceId === 'number' ? d.nextWorkspaceId : 1,
      };
    }
  } catch (_) {}
  return { users: [], workspaces: [], workspace_members: [], nextUserId: 1, nextWorkspaceId: 1 };
}

function writeAuth(data) {
  try {
    fs.writeFileSync(AUTH_FILE, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (_) {
    return false;
  }
}

function getCollectionsPath() {
  return path.join(COLLECTIONS_DIR, 'legacy.json');
}

function getStoreKey(workspaceId) {
  return workspaceId != null ? `collections_${workspaceId}` : 'collections';
}

function getCollectionsFilePath(workspaceId) {
  ensureDir(COLLECTIONS_DIR);
  const name = workspaceId != null ? `collections_${workspaceId}.json` : 'collections.json';
  return path.join(COLLECTIONS_DIR, name);
}

function getCollections(workspaceId) {
  try {
    const fp = getCollectionsFilePath(workspaceId);
    if (fs.existsSync(fp)) {
      const raw = fs.readFileSync(fp, 'utf8');
      const data = JSON.parse(raw);
      return Array.isArray(data) ? data : (data && data.collections ? data.collections : []);
    }
  } catch (_) {}
  return [];
}

function saveCollections(data, workspaceId) {
  const arr = Array.isArray(data) ? data : [];
  try {
    const fp = getCollectionsFilePath(workspaceId);
    ensureDir(COLLECTIONS_DIR);
    fs.writeFileSync(fp, JSON.stringify(arr, null, 2), 'utf8');
    return true;
  } catch (_) {
    return false;
  }
}

function useDatabase() {
  return true;
}

// ---------- Users ----------
function createUser(email, passwordHash, name) {
  const data = readAuth();
  const emailLower = (email || '').trim().toLowerCase();
  if (data.users.some((u) => (u.email || '').toLowerCase() === emailLower)) return null;
  const id = data.nextUserId++;
  data.users.push({
    id,
    email: emailLower,
    password_hash: passwordHash,
    name: (name || '').trim() || null,
    created_at: new Date().toISOString(),
  });
  return writeAuth(data) ? id : null;
}

function getUserByEmail(email) {
  const data = readAuth();
  const emailLower = (email || '').trim().toLowerCase();
  return data.users.find((u) => (u.email || '').toLowerCase() === emailLower) || null;
}

function getUserById(id) {
  const data = readAuth();
  const u = data.users.find((x) => x.id === id);
  if (!u) return null;
  return { id: u.id, email: u.email, name: u.name, created_at: u.created_at };
}

// ---------- Workspaces ----------
function createWorkspace(name, ownerId) {
  const data = readAuth();
  const id = data.nextWorkspaceId++;
  data.workspaces.push({
    id,
    name: (name || 'Workspace').trim(),
    owner_id: ownerId,
    created_at: new Date().toISOString(),
  });
  return writeAuth(data) ? id : null;
}

function getWorkspaceById(id) {
  const data = readAuth();
  return data.workspaces.find((w) => w.id === id) || null;
}

function getWorkspacesForUser(userId) {
  const data = readAuth();
  const list = [];
  for (const w of data.workspaces) {
    if (w.owner_id === userId) {
      list.push({ ...w, role: 'owner' });
      continue;
    }
    const m = data.workspace_members.find((m) => m.workspace_id === w.id && m.user_id === userId);
    if (m) list.push({ ...w, role: m.role || 'member' });
  }
  return list.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
}

function updateWorkspace(id, name) {
  const data = readAuth();
  const w = data.workspaces.find((x) => x.id === id);
  if (!w) return false;
  w.name = (name || 'Workspace').trim();
  return writeAuth(data);
}

function deleteWorkspace(id) {
  const data = readAuth();
  data.workspaces = data.workspaces.filter((w) => w.id !== id);
  data.workspace_members = data.workspace_members.filter((m) => m.workspace_id !== id);
  try {
    const fp = getCollectionsFilePath(id);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  } catch (_) {}
  return writeAuth(data);
}

function addWorkspaceMember(workspaceId, userId, role) {
  const data = readAuth();
  const idx = data.workspace_members.findIndex((m) => m.workspace_id === workspaceId && m.user_id === userId);
  const row = { workspace_id: workspaceId, user_id: userId, role: role || 'member', created_at: new Date().toISOString() };
  if (idx >= 0) data.workspace_members[idx] = row;
  else data.workspace_members.push(row);
  return writeAuth(data);
}

function removeWorkspaceMember(workspaceId, userId) {
  const data = readAuth();
  data.workspace_members = data.workspace_members.filter((m) => !(m.workspace_id === workspaceId && m.user_id === userId));
  return writeAuth(data);
}

function getWorkspaceMembers(workspaceId) {
  const data = readAuth();
  const w = data.workspaces.find((x) => x.id === workspaceId);
  if (!w) return [];
  const owner = data.users.find((u) => u.id === w.owner_id);
  const list = owner ? [{ id: owner.id, email: owner.email, name: owner.name, role: 'owner' }] : [];
  const seen = new Set(list.map((x) => x.id));
  for (const m of data.workspace_members) {
    if (m.workspace_id !== workspaceId || seen.has(m.user_id)) continue;
    const u = data.users.find((x) => x.id === m.user_id);
    if (u) {
      seen.add(u.id);
      list.push({ id: u.id, email: u.email, name: u.name, role: m.role || 'member' });
    }
  }
  return list;
}

function userHasWorkspaceAccess(userId, workspaceId) {
  const data = readAuth();
  const w = data.workspaces.find((x) => x.id === workspaceId);
  if (!w) return false;
  if (w.owner_id === userId) return true;
  return data.workspace_members.some((m) => m.workspace_id === workspaceId && m.user_id === userId);
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

module.exports = {
  getCollections,
  saveCollections,
  getCollectionsPath,
  readCollectionsFromFile,
  useDatabase,
  FALLBACK_FILE: getCollectionsFilePath(null),
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
