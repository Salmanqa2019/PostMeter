const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3847;
const IS_VERCEL = process.env.VERCEL === '1';
const JWT_SECRET = process.env.JWT_SECRET || 'postmeter-dev-secret-change-in-production';
const MAX_CONCURRENCY = Math.min(500, Math.max(1, parseInt(process.env.MAX_CONCURRENCY, 10) || 200));

// Shared HTTP/HTTPS agents for scalable load testing (reuse connections, limit sockets)
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: Math.min(100, MAX_CONCURRENCY) });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: Math.min(100, MAX_CONCURRENCY) });

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const COLLECTIONS_PATH = IS_VERCEL
  ? '/tmp/hoppscotch-team-collections.json'
  : path.join(__dirname, 'hoppscotch-team-collections.json');
const COLLECTIONS_PATH_ALT = path.join(process.cwd(), 'hoppscotch-team-collections.json');

let store = null;
function getStore() {
  if (!IS_VERCEL && !store) {
    try { store = require('./db'); } catch (_) {}
  }
  return store;
}

function getCollectionsPath() {
  if (IS_VERCEL) {
    if (!fs.existsSync(COLLECTIONS_PATH)) {
      try { fs.writeFileSync(COLLECTIONS_PATH, JSON.stringify({ collections: [] }), 'utf8'); } catch (_) {}
    }
    return COLLECTIONS_PATH;
  }
  if (fs.existsSync(COLLECTIONS_PATH)) return COLLECTIONS_PATH;
  if (fs.existsSync(COLLECTIONS_PATH_ALT)) return COLLECTIONS_PATH_ALT;
  return COLLECTIONS_PATH;
}

function readCollections(workspaceId) {
  const s = getStore();
  if (s && s.useDatabase && s.useDatabase()) {
    if (workspaceId != null && workspaceId !== '') {
      const data = s.getCollections(workspaceId);
      return Array.isArray(data) ? data : [];
    }
    let data = s.getCollections(null);
    if (Array.isArray(data) && data.length > 0) return data;
    const filePath = getCollectionsPath();
    if (fs.existsSync(filePath)) {
      try {
        const raw = fs.readFileSync(filePath, 'utf8');
        const parsed = JSON.parse(raw);
        const arr = Array.isArray(parsed) ? parsed : (parsed && parsed.collections ? parsed.collections : []);
        if (arr.length) { s.saveCollections(arr, null); return arr; }
      } catch (_) {}
    }
    return data || [];
  }
  if (workspaceId != null && workspaceId !== '') return [];
  const filePath = getCollectionsPath();
  if (IS_VERCEL && !fs.existsSync(COLLECTIONS_PATH)) {
    try { fs.writeFileSync(COLLECTIONS_PATH, JSON.stringify([]), 'utf8'); } catch (_) {}
  }
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(raw);
      return Array.isArray(data) ? data : (data && data.collections ? data.collections : []);
    }
  } catch (_) {}
  return [];
}

function writeCollections(data, workspaceId) {
  const arr = Array.isArray(data) ? data : [];
  const s = getStore();
  if (s && s.useDatabase && s.useDatabase()) {
    if (s.saveCollections(arr, workspaceId)) return true;
  }
  if (workspaceId != null) return false;
  const filePath = getCollectionsPath();
  try {
    fs.writeFileSync(fs.existsSync(filePath) ? filePath : COLLECTIONS_PATH, JSON.stringify(arr, null, 2), 'utf8');
    return true;
  } catch (_) { return false; }
}

// ----- Auth & workspace helpers -----
app.use((req, res, next) => {
  const auth = req.headers.authorization;
  if (auth && typeof auth === 'string' && auth.startsWith('Bearer ')) {
    try {
      const payload = jwt.verify(auth.slice(7), JWT_SECRET);
      const store = getStore();
      if (store && store.getUserById) req.user = store.getUserById(payload.userId);
    } catch (_) {}
  }
  next();
});

function assertWorkspaceAccess(req, res) {
  const wid = req.query.workspaceId ?? req.body?.workspaceId;
  if (wid == null || wid === '') return undefined;
  if (!req.user) {
    res.status(401).json({ error: 'Login required' });
    return false;
  }
  const store = getStore();
  if (!store || !store.userHasWorkspaceAccess) {
    res.status(501).json({ error: 'Workspaces not available' });
    return false;
  }
  const id = parseInt(wid, 10);
  if (isNaN(id) || !store.userHasWorkspaceAccess(req.user.id, id)) {
    res.status(403).json({ error: 'No access to this workspace' });
    return false;
  }
  return id;
}

// Convert Postman Collection v2.x to Hoppscotch-style array of collections
function postmanToHoppscotch(postmanJson) {
  const collections = [];
  const id = () => 'id-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9);

  // Returns { url, queryParams } when url is object (so caller can set req.params); else returns url string.
  function parseUrl(url) {
    if (typeof url === 'string') return { url: url.replace(/\{\{baseUrl\}\}/g, '<<baseUrl>>'), queryParams: null };
    if (!url) return { url: '<<baseUrl>>/', queryParams: null };
    const raw = url.raw || url;
    if (typeof raw === 'string') {
      const qIdx = raw.indexOf('?');
      const base = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
      let queryParams = null;
      if (qIdx >= 0 && raw.slice(qIdx + 1)) {
        queryParams = raw.slice(qIdx + 1).split('&').map(pair => {
          const eq = pair.indexOf('=');
          const k = eq >= 0 ? decodeURIComponent(pair.slice(0, eq).replace(/\+/g, ' ')) : decodeURIComponent(pair.replace(/\+/g, ' '));
          const v = eq >= 0 ? decodeURIComponent((pair.slice(eq + 1) || '').replace(/\+/g, ' ')) : '';
          return { key: k, value: v, disabled: false };
        }).filter(q => q.key != null);
        if (!queryParams.length) queryParams = null;
      }
      return { url: base.replace(/\{\{baseUrl\}\}/g, '<<baseUrl>>'), queryParams };
    }
    const protocol = (url.protocol || 'https').replace(':', '');
    const host = (url.host || []).join('.') || '{{baseUrl}}';
    const path = (url.path || []).filter(Boolean).join('/');
    let out = `${protocol}://${host}/${path}`.replace(/\/+/g, '/').replace(/\{\{baseUrl\}\}/g, '<<baseUrl>>');
    const queryParams = (url.query || []).filter(qq => qq.key).map(qq => ({
      key: qq.key,
      value: qq.value != null ? qq.value : '',
      disabled: qq.disabled === true,
      description: qq.description || '',
    }));
    return { url: out, queryParams: queryParams.length ? queryParams : null };
  }

  function rawLanguageToContentType(lang) {
    const m = { json: 'application/json', xml: 'application/xml', html: 'text/html', text: 'text/plain' };
    return m[(lang || '').toLowerCase()] || 'text/plain';
  }

  function convertRequest(pmReq) {
    if (!pmReq) return null;
    const method = (pmReq.method || 'GET').toUpperCase();
    const parsed = parseUrl(pmReq.url);
    const endpoint = parsed.url;
    const params = (parsed.queryParams || []).map(q => ({ key: q.key, value: q.value || '', active: !q.disabled, description: q.description || '' }));
    const headers = (pmReq.header || []).map(h => ({ key: h.key || '', value: h.value || '', active: !(h.disabled === true) }));
    let body = null;
    const b = pmReq.body;
    if (b && (b.raw != null || b.mode === 'raw')) {
      const rawBody = typeof b.raw === 'string' ? b.raw : (b.raw ? JSON.stringify(b.raw) : '');
      const contentType = rawLanguageToContentType(b.options?.raw?.language);
      body = { body: rawBody, contentType };
    } else if (b && b.mode === 'urlencoded' && Array.isArray(b.urlencoded)) {
      const encoded = b.urlencoded
        .filter(p => p.key != null)
        .map(p => encodeURIComponent(p.key) + '=' + encodeURIComponent(p.value != null ? p.value : ''))
        .join('&');
      body = { body: encoded, contentType: 'application/x-www-form-urlencoded' };
    } else if (b && b.mode === 'formdata' && Array.isArray(b.formdata)) {
      const parts = b.formdata.filter(p => p.key != null && p.type !== 'file');
      const encoded = parts.map(p => encodeURIComponent(p.key) + '=' + encodeURIComponent((p.value != null ? p.value : ''))).join('&');
      body = { body: encoded, contentType: 'application/x-www-form-urlencoded' };
    }
    const auth = pmReq.auth || {};
    let token = '';
    if (auth.type === 'bearer' && Array.isArray(auth.bearer)) {
      token = (auth.bearer.find(x => x.key === 'token') || {}).value || '';
    } else if (auth.type === 'basic' && Array.isArray(auth.basic)) {
      const user = (auth.basic.find(x => x.key === 'username') || {}).value || '';
      const pass = (auth.basic.find(x => x.key === 'password') || {}).value || '';
      if (user || pass) {
        const val = Buffer.from(user + ':' + pass, 'utf8').toString('base64');
        headers.push({ key: 'Authorization', value: 'Basic ' + val, active: true });
      }
    } else if (auth.type === 'apikey' && auth.apikey) {
      const apikey = auth.apikey;
      const addTo = (apikey.addTo || 'header').toLowerCase();
      const key = apikey.key || 'apikey';
      const value = apikey.value || '';
      if (addTo === 'header') headers.push({ key, value, active: true });
      else if (addTo === 'query') params.push({ key, value, active: true });
    }
    return {
      v: '17',
      id: id(),
      name: pmReq.name || method + ' Request',
      method,
      endpoint,
      params,
      headers,
      body: body || { body: null, contentType: null },
      auth: { token, authType: token ? 'bearer' : 'inherit', authActive: true },
      requestVariables: [],
      responses: {},
      testScript: '',
      description: pmReq.description || null,
      preRequestScript: '',
    };
  }

  function processItem(pmItem, parentFolder, colName, colPath) {
    if (!pmItem) return;
    if (pmItem.request) {
      const req = convertRequest(pmItem.request);
      if (req) {
        req.name = pmItem.name || req.name;
        (parentFolder ? parentFolder.requests : (parentFolder = { name: colName, folders: [], requests: [] }).requests).push(req);
      }
      return;
    }
    if (Array.isArray(pmItem.item) && pmItem.item.length) {
      const folder = { v: 11, id: id(), name: pmItem.name || 'Folder', folders: [], requests: [] };
      (parentFolder ? parentFolder.folders : (collections.push({ v: 11, id: id(), name: colName || pmItem.name, folders: [folder], requests: [] }), collections[collections.length - 1].folders)).push(folder);
      pmItem.item.forEach(child => processItem(child, folder, colName, colPath + ' > ' + (folder.name || '')));
    }
  }

  if (postmanJson.item && Array.isArray(postmanJson.item)) {
    const colName = (postmanJson.info && postmanJson.info.name) || 'Imported from Postman';
    const col = { v: 11, id: id(), name: colName, folders: [], requests: [] };
    postmanJson.item.forEach(pmItem => processItem(pmItem, col, colName, colName));
    if (col.requests.length || col.folders.length) collections.push(col);
  }
  return collections;
}

function collectFromFolder(folder, colName, colPath, colIndex, folderIndex, list) {
  const folderName = folder.name || 'Folder';
  const folderPath = `${colPath} > ${folderName}`;
  (folder.requests || []).forEach(req => {
    list.push({
      id: req.id,
      path: folderPath,
      collectionName: colName,
      folderName: folderName,
      collectionIndex: colIndex,
      folderIndex,
      request: req,
    });
  });
  (folder.folders || []).forEach((sub, fi) => collectFromFolder(sub, colName, folderPath, colIndex, fi, list));
}

// Flatten collections to list of { path, collectionName, folderIndex, request, collectionIndex }
function flattenRequests(collections) {
  const list = [];
  if (!Array.isArray(collections)) return list;

  collections.forEach((col, colIndex) => {
    const colName = col.name || 'Collection';
    const colPath = colName;

    (col.requests || []).forEach(req => {
      list.push({
        id: req.id,
        path: colPath,
        collectionName: colName,
        folderName: null,
        collectionIndex: colIndex,
        folderIndex: null,
        request: req,
      });
    });

    (col.folders || []).forEach((folder, fi) => collectFromFolder(folder, colName, colPath, colIndex, fi, list));
  });
  return list;
}

function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function substituteVariables(str, vars) {
  if (str == null || typeof str !== 'string') return str;
  let out = str;
  Object.entries(vars || {}).forEach(([k, v]) => {
    if (k == null) return;
    out = out.replace(new RegExp('<<' + escapeRegex(k) + '>>', 'gi'), String(v ?? ''));
  });
  return out;
}

function resolveUrl(endpoint, baseUrl, requestVariables = []) {
  let url = (endpoint || '').replace(/<<baseUrl>>/g, (baseUrl || '').trim());
  (requestVariables || []).filter(v => v && v.active).forEach(v => {
    const key = v.key;
    if (key) url = url.replace(new RegExp(`<<${escapeRegex(key)}>>`, 'gi'), (v.value || '').trim());
  });
  return url;
}

function buildRequestOptions(req, baseUrl, globalVariables = {}, perRequestVars = {}) {
  const endpoint = req.endpoint || '';
  const mergedVars = { ...globalVariables, ...perRequestVars };
  const vars = [
    ...(req.requestVariables || []),
    ...Object.entries(mergedVars).map(([k, v]) => ({ key: k, value: String(v), active: true })),
  ];
  let url = resolveUrl(endpoint, baseUrl, vars);
  let params = (req.params || []).filter(p => p.active && p.key).reduce((acc, p) => { acc[p.key] = p.value; return acc; }, {});
  let headers = (req.headers || []).filter(h => h.key && h.active !== false).reduce((acc, h) => { acc[h.key] = h.value; return acc; }, {});
  url = substituteVariables(url, perRequestVars);
  Object.keys(params).forEach((k) => { params[k] = substituteVariables(params[k], perRequestVars); });
  Object.keys(headers).forEach((k) => { headers[k] = substituteVariables(headers[k], perRequestVars); });

  let data = null;
  if (req.body && req.body.body != null) {
    try {
      data = typeof req.body.body === 'string' ? req.body.body : JSON.stringify(req.body.body);
    } catch (_) {
      data = req.body.body;
    }
    data = substituteVariables(data, perRequestVars);
    const contentType = (req.body && req.body.contentType) || 'application/json';
    if (contentType && !headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = contentType;
    }
  }
  const auth = req.auth || {};
  const useInherit = auth.authType === 'inherit';
  const token = (perRequestVars.token || perRequestVars.bearerToken) || (useInherit ? (globalVariables.bearerToken || auth.token) : (auth.token || globalVariables.bearerToken));
  if (auth.authType === 'bearer' || useInherit) {
    if (token) headers['Authorization'] = `Bearer ${token}`;
  } else if (auth.authType === 'apikey' && auth.apikeyKey) {
    const key = auth.apikeyKey.trim();
    const value = substituteVariables((auth.apikeyValue || '').trim(), perRequestVars) || (auth.apikeyValue || '').trim();
    const addTo = (auth.apikeyAddTo || 'header').toLowerCase();
    if (addTo === 'header' && value) headers[key] = value;
    else if (addTo === 'query' && value) params[key] = value;
  } else if (auth.authType === 'basic' && (auth.basicUser != null || auth.basicPass != null)) {
    const user = substituteVariables((auth.basicUser || '').trim(), perRequestVars) || (auth.basicUser || '').trim();
    const pass = substituteVariables((auth.basicPass || '').trim(), perRequestVars) || (auth.basicPass || '').trim();
    const val = Buffer.from(user + ':' + pass, 'utf8').toString('base64');
    headers['Authorization'] = 'Basic ' + val;
  }
  return { url, params, headers, data, method: (req.method || 'GET').toUpperCase() };
}

async function runSingleRequest(axiosConfig) {
  const start = Date.now();
  let statusCode = 0;
  let success = false;
  let errorMessage = '';
  if (!axiosConfig || typeof axiosConfig !== 'object') {
    return { duration: 0, statusCode: 0, success: false, error: 'Invalid request config' };
  }
  let bodyPreview = '';
  let responseHeaders = {};
  try {
    const res = await axios({
      ...axiosConfig,
      timeout: 30000,
      validateStatus: () => true,
      httpAgent,
      httpsAgent,
      responseType: 'text',
    });
    statusCode = res.status;
    success = res.status >= 200 && res.status < 300;
    if (res.data != null) {
      const raw = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
      bodyPreview = raw.length > 2000 ? raw.slice(0, 2000) + '\n...[truncated]' : raw;
    }
    if (res.headers && typeof res.headers === 'object') {
      responseHeaders = { ...res.headers };
    }
  } catch (err) {
    errorMessage = (err && (err.code || err.message)) || String(err);
  }
  const duration = Date.now() - start;
  return { duration, statusCode, success, error: errorMessage || null, bodyPreview, responseHeaders };
}

async function sendOneRequest(axiosConfig) {
  const start = Date.now();
  try {
    const res = await axios({
      ...axiosConfig,
      timeout: 60000,
      validateStatus: () => true,
      responseType: 'text',
      httpAgent,
      httpsAgent,
    });
    const duration = Date.now() - start;
    let data = res.data;
    const contentType = (res.headers && (res.headers['content-type'] || res.headers['Content-Type'])) || '';
    if (typeof data === 'object' && contentType.includes('json')) data = JSON.stringify(data);
    return {
      duration,
      statusCode: res.status,
      success: res.status >= 200 && res.status < 300,
      headers: res.headers,
      data: typeof data === 'string' ? data : JSON.stringify(data),
      error: null,
    };
  } catch (err) {
    return {
      duration: Date.now() - start,
      statusCode: 0,
      success: false,
      headers: {},
      data: null,
      error: err.code || err.message || String(err),
    };
  }
}

function runWithConcurrency(tasks, concurrency, delayBetweenMs = 0, rampUpMs = 0, taskTimeoutMs = 20000, onResult = null) {
  return new Promise((resolve) => {
    const results = [];
    let index = 0;
    let running = 0;
    const startTime = Date.now();
    const timeoutMs = Math.min(120000, Math.max(5000, taskTimeoutMs));
    function getCurrentMax() {
      if (rampUpMs <= 0) return concurrency;
      const elapsed = Date.now() - startTime;
      if (elapsed >= rampUpMs) return concurrency;
      return Math.min(concurrency, Math.max(1, Math.floor(1 + (concurrency - 1) * (elapsed / rampUpMs))));
    }

    function runTaskWithTimeout(task, i) {
      const timeoutPromise = new Promise((_, rej) => setTimeout(() => rej(new Error('Timeout')), timeoutMs));
      return Promise.race([task(), timeoutPromise]);
    }

    function runNext() {
      if (index >= tasks.length) {
        if (running === 0) {
          for (let j = 0; j < tasks.length; j++) {
            if (results[j] === undefined) results[j] = { duration: 0, statusCode: 0, success: false, error: 'No result' };
          }
          resolve(results);
        }
        return;
      }
      const maxNow = getCurrentMax();
      if (running >= maxNow) return;
      const i = index++;
      const task = tasks[i];
      if (typeof task !== 'function') {
        results[i] = { duration: 0, statusCode: 0, success: false, error: 'Invalid task' };
        runNext();
        return;
      }
      running++;
      function done() {
        running--;
        runNext();
      }
      runTaskWithTimeout(task, i)
        .then((r) => {
          try {
            results[i] = (r && typeof r === 'object') ? r : { duration: 0, statusCode: 0, success: false, error: 'Invalid result' };
          } catch (_) {
            results[i] = { duration: 0, statusCode: 0, success: false, error: 'Result assign failed' };
          }
          if (onResult && results[i]) onResult(results[i], i);
          if (delayBetweenMs > 0) return new Promise((res) => setTimeout(res, delayBetweenMs));
        })
        .catch((e) => {
          try {
            results[i] = { duration: 0, statusCode: 0, success: false, error: (e && e.message) ? e.message : String(e) };
          } catch (_) {
            results[i] = { duration: 0, statusCode: 0, success: false, error: 'Error' };
          }
          if (onResult && results[i]) onResult(results[i], i);
          if (delayBetweenMs > 0) return new Promise((res) => setTimeout(res, delayBetweenMs));
        })
        .finally(() => { done(); });
      runNext();
    }

    const initialSlots = rampUpMs > 0 ? 1 : Math.min(concurrency, tasks.length);
    for (let c = 0; c < initialSlots; c++) runNext();
  });
}

function runWithDuration(toRun, getOptsForItem, durationMs, concurrency, delayBetweenMs, rampUpMs = 0, onResult = null) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const results = [];
    let running = 0;
    let index = 0;
    let taskIndex = 0;
    function getCurrentMax() {
      if (rampUpMs <= 0) return concurrency;
      const elapsed = Date.now() - startTime;
      if (elapsed >= rampUpMs) return concurrency;
      return Math.min(concurrency, Math.max(1, Math.floor(1 + (concurrency - 1) * (elapsed / rampUpMs))));
    }

    function runOne() {
      if (Date.now() - startTime >= durationMs) {
        running--;
        if (running === 0) resolve(results);
        return;
      }
      const item = toRun[index % toRun.length];
      index++;
      const currentTaskIndex = taskIndex++;
      const opts = getOptsForItem(item, currentTaskIndex);
      runSingleRequest(opts)
        .then((r) => {
          const row = { ...r, name: item.request?.name, path: item.path, id: item.id };
          results.push(row);
          if (onResult) onResult(row, results.length - 1);
          if (delayBetweenMs > 0) return new Promise((res) => setTimeout(res, delayBetweenMs));
        })
        .catch((e) => {
          const row = { duration: 0, statusCode: 0, success: false, error: e.message, name: item.request?.name, path: item.path, id: item.id };
          results.push(row);
          if (onResult) onResult(row, results.length - 1);
          if (delayBetweenMs > 0) return new Promise((res) => setTimeout(res, delayBetweenMs));
        })
        .then(() => {
          running--;
          runNext();
        });
      running++;
    }

    function runNext() {
      const maxNow = getCurrentMax();
      while (running < maxNow && Date.now() - startTime < durationMs) runOne();
      if (running === 0) resolve(results);
    }

    runNext();
  });
}

function computeStats(results) {
  const arr = results || [];
  const safe = arr.filter(r => r && typeof r === 'object');
  const missingCount = arr.length - safe.length;
  const durations = safe.map(r => r.duration).filter(n => typeof n === 'number');
  const sorted = [...durations].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  const n = sorted.length;
  const success = safe.filter(r => r.success).length;
  const failed = safe.filter(r => !r.success);
  const failCount = failed.length + missingCount;
  const totalRequests = arr.length;
  const p50 = sorted[Math.floor(n * 0.5)] ?? 0;
  const p95 = sorted[Math.floor(n * 0.95)] ?? 0;
  const p99 = sorted[Math.floor(n * 0.99)] ?? 0;
  const min = sorted[0] ?? 0;
  const max = sorted[n - 1] ?? 0;
  const avg = n ? sum / n : 0;
  const errors = failed.map(f => f.error).filter(Boolean);
  if (missingCount > 0) errors.push(...Array(missingCount).fill('No response (timeout/hang)'));
  const errorCounts = {};
  errors.forEach(e => { errorCounts[e] = (errorCounts[e] || 0) + 1; });
  const statusCodeCounts = {};
  safe.forEach(r => {
    const code = r.statusCode != null ? r.statusCode : 0;
    statusCodeCounts[code] = (statusCodeCounts[code] || 0) + 1;
  });
  return {
    totalRequests,
    successCount: success,
    failCount,
    successRate: totalRequests ? ((success / totalRequests) * 100).toFixed(2) + '%' : '0%',
    duration: { min, max, avg: Math.round(avg), p50, p95, p99 },
    errors: errorCounts,
    rawDurations: durations,
    statusCodeCounts,
  };
}

// ----- Auth -----
app.post('/api/auth/register', (req, res) => {
  try {
    const store = getStore();
    if (!store || !store.createUser) return res.status(501).json({ error: 'Registration not available' });
    const { email, password, name } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const emailStr = String(email).trim().toLowerCase();
    if (!emailStr) return res.status(400).json({ error: 'Invalid email' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (store.getUserByEmail(emailStr)) return res.status(409).json({ error: 'Email already registered' });
    const hash = bcrypt.hashSync(String(password), 10);
    const userId = store.createUser(emailStr, hash, name);
    if (!userId) return res.status(500).json({ error: 'Registration failed' });
    const user = store.getUserById(userId);
    const defaultWorkspaceId = store.createWorkspace('My Workspace', userId);
    if (defaultWorkspaceId) store.addWorkspaceMember(defaultWorkspaceId, userId, 'owner');
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ user: { id: user.id, email: user.email, name: user.name }, token });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Registration failed' });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const store = getStore();
    if (!store || !store.getUserByEmail) return res.status(501).json({ error: 'Login not available' });
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const row = store.getUserByEmail(String(email).trim().toLowerCase());
    if (!row || !bcrypt.compareSync(String(password), row.password_hash)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const user = store.getUserById(row.id);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ user: { id: user.id, email: user.email, name: user.name }, token });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Login failed' });
  }
});

app.get('/api/auth/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  res.json(req.user);
});

// ----- Workspaces -----
app.get('/api/workspaces', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const store = getStore();
  if (!store || !store.getWorkspacesForUser) return res.status(501).json({ error: 'Workspaces not available' });
  try {
    const list = store.getWorkspacesForUser(req.user.id);
    res.json({ workspaces: list });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/workspaces', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const store = getStore();
  if (!store || !store.createWorkspace) return res.status(501).json({ error: 'Workspaces not available' });
  const name = (req.body && req.body.name) || 'New Workspace';
  try {
    const id = store.createWorkspace(name, req.user.id);
    if (!id) return res.status(500).json({ error: 'Failed to create workspace' });
    store.addWorkspaceMember(id, req.user.id, 'owner');
    const workspace = store.getWorkspaceById(id);
    res.status(201).json(workspace);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/workspaces/:id', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const store = getStore();
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid workspace id' });
  if (!store.userHasWorkspaceAccess(req.user.id, id)) return res.status(403).json({ error: 'No access' });
  const w = store.getWorkspaceById(id);
  if (!w) return res.status(404).json({ error: 'Workspace not found' });
  res.json(w);
});

app.patch('/api/workspaces/:id', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const store = getStore();
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid workspace id' });
  const w = store.getWorkspaceById(id);
  if (!w || w.owner_id !== req.user.id) return res.status(403).json({ error: 'Only owner can update' });
  const name = req.body && req.body.name;
  if (name != null) store.updateWorkspace(id, name);
  res.json(store.getWorkspaceById(id));
});

app.delete('/api/workspaces/:id', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const store = getStore();
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid workspace id' });
  const w = store.getWorkspaceById(id);
  if (!w || w.owner_id !== req.user.id) return res.status(403).json({ error: 'Only owner can delete' });
  store.deleteWorkspace(id);
  res.json({ ok: true });
});

app.get('/api/workspaces/:id/members', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const store = getStore();
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid workspace id' });
  if (!store.userHasWorkspaceAccess(req.user.id, id)) return res.status(403).json({ error: 'No access' });
  const members = store.getWorkspaceMembers(id);
  res.json({ members });
});

app.post('/api/workspaces/:id/members', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const store = getStore();
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid workspace id' });
  const w = store.getWorkspaceById(id);
  if (!w || w.owner_id !== req.user.id) return res.status(403).json({ error: 'Only owner can invite' });
  const email = (req.body && req.body.email) || '';
  const emailStr = String(email).trim().toLowerCase();
  if (!emailStr) return res.status(400).json({ error: 'Email required' });
  const memberUser = store.getUserByEmail(emailStr);
  if (!memberUser) return res.status(404).json({ error: 'User not found. They must register first.' });
  if (memberUser.id === req.user.id) return res.status(400).json({ error: 'You are already the owner' });
  store.addWorkspaceMember(id, memberUser.id, 'member');
  res.json({ ok: true, member: { id: memberUser.id, email: memberUser.email, name: memberUser.name, role: 'member' } });
});

app.delete('/api/workspaces/:id/members/:userId', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  const store = getStore();
  const wid = parseInt(req.params.id, 10);
  const uid = parseInt(req.params.userId, 10);
  if (isNaN(wid) || isNaN(uid)) return res.status(400).json({ error: 'Invalid id' });
  const w = store.getWorkspaceById(wid);
  if (!w || w.owner_id !== req.user.id) return res.status(403).json({ error: 'Only owner can remove members' });
  if (uid === w.owner_id) return res.status(400).json({ error: 'Cannot remove owner' });
  store.removeWorkspaceMember(wid, uid);
  res.json({ ok: true });
});

// GET collections structure (from DB or file)
app.get('/api/collections', (req, res) => {
  try {
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    const data = readCollections(workspaceId);
    const flat = flattenRequests(data);
    let env = { baseUrl: '', bearerToken: '' };
    try {
      const extract = (vars) => {
        const arr = Array.isArray(vars) ? vars : (vars && vars.variables ? vars.variables : []);
        if (Array.isArray(arr)) arr.forEach(v => {
          if (v && v.key) {
            const k = (v.key || '').toLowerCase();
            if (k === 'baseurl') env.baseUrl = v.value || '';
            if (k === 'token' || k === 'bearertoken' || k === 'auth') env.bearerToken = v.value || '';
          }
        });
      };
      if (Array.isArray(data) && data[0]) {
        const first = data[0];
        if (first.environment) extract(first.environment);
        else if (first.env) extract(first.env);
      } else if (data && typeof data === 'object') {
        if (data.environment) extract(data.environment);
        else if (data.env) extract(data.env);
        else if (data.variables) extract(data.variables);
      }
    } catch (_) {}
    res.json({ collections: data, flat, env });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to load collections' });
  }
});

function normalizeCollectionName(s) {
  return (s || '').trim().replace(/\s+/g, ' ');
}

// Resolve baseUrl and token: collection-level overrides, then global (for Inherit)
function resolveForRequest(item, globalBaseUrl, globalToken, collectionVariables) {
  const name = normalizeCollectionName(item.collectionName || '');
  let coll = {};
  if (collectionVariables && typeof collectionVariables === 'object' && name) {
    coll = collectionVariables[item.collectionName] || collectionVariables[name] || {};
    if (!(coll.baseUrl != null && String(coll.baseUrl).trim() !== '')) {
      const key = Object.keys(collectionVariables).find((k) => normalizeCollectionName(k) === name);
      if (key) coll = collectionVariables[key] || {};
    }
  }
  const baseUrl = (coll.baseUrl != null && String(coll.baseUrl).trim() !== '') ? String(coll.baseUrl).trim() : (globalBaseUrl || '').trim();
  const token = (coll.token != null && String(coll.token).trim() !== '') ? coll.token : (globalToken || '');
  return { baseUrl, token };
}

// POST send single request (payload, headers, auth from JSON)
app.post('/api/send', async (req, res) => {
  try {
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    const { requestId, baseUrl, bearerToken, collectionVariables } = req.body;
    if (!requestId) return res.status(400).json({ error: 'requestId required' });
    const data = readCollections(workspaceId);
    if (!Array.isArray(data) || data.length === 0) return res.status(400).json({ error: 'No collections loaded' });
    const flat = flattenRequests(data);
    const item = flat.find(r => r.id === requestId);
    if (!item) return res.status(404).json({ error: 'Request not found' });
    const { baseUrl: resolvedBase, token } = resolveForRequest(item, baseUrl, bearerToken, collectionVariables);
    const gv = { bearerToken: token };
    const opts = buildRequestOptions(item.request, resolvedBase, gv);
    const result = await sendOneRequest(opts);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Send failed' });
  }
});

// POST run test (single / multiple / regression)
app.post('/api/run', async (req, res) => {
  try {
    console.log('[PostMeter] Run test requested');
    const {
      type,
      requestIds,
      baseUrl,
      iterations = 1,
      concurrency = 1,
      durationSeconds = 0,
      delayBetweenRequestsMs = 0,
      rampUpSeconds = 0,
      workers = 1,
      sla = {},
      globalVariables = {},
      bearerToken,
      collectionVariables: cv,
      userData = [],
      stream: streamMode = false,
    } = req.body;
    const collectionVariables = cv && typeof cv === 'object' ? cv : {};
    const gv = { ...globalVariables };
    if (bearerToken) gv.bearerToken = bearerToken;
    const users = Array.isArray(userData) ? userData.filter((u) => u && typeof u === 'object') : [];
    const durationMs = Math.max(0, parseInt(durationSeconds, 10) || 0) * 1000;
    const delayMs = Math.max(0, parseInt(delayBetweenRequestsMs, 10) || 0);
    const rampUpMs = Math.max(0, parseInt(rampUpSeconds, 10) || 0) * 1000;
    const workersNum = Math.min(8, Math.max(1, parseInt(workers, 10) || 1));
    const taskTimeoutMs = 35000;
    const minSuccessRate = Math.min(100, Math.max(0, parseFloat(sla.minSuccessRate) || 0));
    const maxP95Ms = Math.max(0, parseInt(sla.maxP95Ms, 10) || 0);
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    const data = readCollections(workspaceId);
    if (!Array.isArray(data)) return res.status(400).json({ error: 'No collections loaded. Import JSON or add requests.' });
    const flat = flattenRequests(data);

    let toRun = [];
    if (type === 'regression' || type === 'all') {
      toRun = flat;
    } else if (type === 'multiple' && Array.isArray(requestIds) && requestIds.length) {
      const set = new Set(requestIds);
      toRun = flat.filter(r => set.has(r.id));
    } else if ((type === 'single' || type === 'one') && requestIds && requestIds.length) {
      const id = requestIds[0];
      toRun = flat.filter(r => r.id === id);
    }

    if (!toRun.length) {
      return res.status(400).json({ error: 'No requests selected' });
    }

    const base = (baseUrl || '').trim();
    // Allow run when baseUrl is set globally OR at collection level (per request)
    const needsBaseUrl = toRun.some((item) => (item.request?.endpoint || '').includes('<<baseUrl>>'));
    if (needsBaseUrl) {
      const missing = toRun.find((item) => {
        if (!(item.request?.endpoint || '').includes('<<baseUrl>>')) return false;
        const { baseUrl: resolvedBase } = resolveForRequest(item, base, gv.bearerToken, collectionVariables);
        return !(resolvedBase && resolvedBase.trim());
      });
      if (missing) {
        const cn = missing.collectionName || 'this request\'s collection';
        return res.status(400).json({ error: 'baseUrl is required. Set it in Environment: either in Global (default) or under Per collection override for "' + cn + '".' });
      }
    }

    const startTime = Date.now();
    const concurrencyNum = Math.min(MAX_CONCURRENCY, Math.max(1, parseInt(concurrency, 10) || 1));
    const concurrencyPerWorker = Math.max(1, Math.floor(concurrencyNum / workersNum));

    if (streamMode) {
      res.setHeader('Content-Type', 'application/x-ndjson');
      res.setHeader('Cache-Control', 'no-cache');
      if (res.flushHeaders) res.flushHeaders();
    }
    let streamIndex = 0;
    const streamOnResult = streamMode ? (r) => {
      try { res.write(JSON.stringify({ type: 'result', result: r, index: ++streamIndex }) + '\n'); } catch (e) {}
    } : null;

    let results;
    let taskIndex = 0;
    const getPerRequestVars = () => (users.length ? users[taskIndex++ % users.length] : {});

    if (durationMs > 0) {
      const getOpts = (item, index) => {
        const perRequest = users.length ? users[index % users.length] : {};
        const { baseUrl: resolvedBase, token } = resolveForRequest(item, base, gv.bearerToken, collectionVariables);
        const reqGv = { ...gv, bearerToken: token };
        const opts = buildRequestOptions(item.request, resolvedBase, reqGv, perRequest);
        return opts;
      };
      if (workersNum <= 1) {
        results = await runWithDuration(toRun, getOpts, durationMs, concurrencyNum, delayMs, rampUpMs, streamOnResult);
      } else {
        const workerPromises = [];
        for (let w = 0; w < workersNum; w++) {
          workerPromises.push(runWithDuration(toRun, getOpts, durationMs, concurrencyPerWorker, delayMs, rampUpMs, streamOnResult));
        }
        const workerResults = await Promise.all(workerPromises);
        results = workerResults.flat();
      }
    } else {
      const allTasks = [];
      for (let i = 0; i < iterations; i++) {
        for (const item of toRun) {
          if (!item || !item.request) continue;
          const perRequest = getPerRequestVars();
          const { baseUrl: resolvedBase, token } = resolveForRequest(item, base, gv.bearerToken, collectionVariables);
          const reqGv = { ...gv, bearerToken: token };
          let opts;
          try {
            opts = buildRequestOptions(item.request, resolvedBase, reqGv, perRequest);
          } catch (buildErr) {
            allTasks.push(() => Promise.resolve({ duration: 0, statusCode: 0, success: false, error: (buildErr && buildErr.message) || 'Build failed', name: item.request && item.request.name, path: item.path, id: item.id }));
            continue;
          }
          const name = item.request.name;
          const path = item.path;
          const id = item.id;
          allTasks.push(() => runSingleRequest(opts).then(r => ({ ...r, name, path, id })));
        }
      }
      if (allTasks.length === 0) {
        return res.status(400).json({ error: 'No valid requests to run. Check selection and request config.' });
      }
      console.log('[PostMeter] Running', allTasks.length, 'requests, concurrency', concurrencyNum);
      if (workersNum <= 1) {
        results = await runWithConcurrency(allTasks, concurrencyNum, delayMs, rampUpMs, taskTimeoutMs, streamOnResult);
      } else {
        const chunkSize = Math.ceil(allTasks.length / workersNum);
        const chunks = [];
        for (let w = 0; w < workersNum; w++) {
          chunks.push(allTasks.slice(w * chunkSize, w * chunkSize + chunkSize));
        }
        const workerResults = await Promise.all(chunks.map(chunk => chunk.length ? runWithConcurrency(chunk, concurrencyPerWorker, delayMs, rampUpMs, taskTimeoutMs, streamOnResult) : Promise.resolve([])));
        results = workerResults.flat();
      }
    }

    const totalTime = Date.now() - startTime;

    const byRequest = {};
    results.forEach(r => {
      const key = r.id || r.name || 'unknown';
      if (!byRequest[key]) byRequest[key] = [];
      byRequest[key].push(r);
    });

    const report = {
      type,
      totalTime,
      concurrency: concurrencyNum,
      iterations,
      requestCount: toRun.length,
      totalCalls: results.length,
      startTime: new Date(startTime).toISOString(),
      allResultsInOrder: results.map(r => (r && typeof r === 'object' ? { duration: r.duration, success: r.success, statusCode: r.statusCode, name: r.name } : { duration: 0, success: false, statusCode: 0, name: '?' })),
      byRequest: {},
      summary: null,
    };

    for (const [reqId, reqResults] of Object.entries(byRequest)) {
      const validResults = (reqResults || []).filter(Boolean);
      report.byRequest[reqId] = {
        name: validResults[0]?.name,
        path: validResults[0]?.path,
        stats: computeStats(validResults),
        results: validResults.map(r => ({ duration: r.duration, statusCode: r.statusCode, success: r.success, error: r.error, bodyPreview: r.bodyPreview || '', responseHeaders: r.responseHeaders || {} })),
      };
    }

    const allStats = computeStats(results);
    report.summary = allStats;
    report.summary.throughputPerSec = totalTime > 0 ? (results.length / (totalTime / 1000)).toFixed(2) : 0;

    report.durationSeconds = durationMs > 0 ? durationMs / 1000 : null;
    report.delayBetweenRequestsMs = delayMs > 0 ? delayMs : null;
    report.rampUpSeconds = rampUpMs > 0 ? rampUpMs / 1000 : null;
    report.workers = workersNum;
    report.sla = { minSuccessRate: minSuccessRate || null, maxP95Ms: maxP95Ms || null };
    if (minSuccessRate > 0 || maxP95Ms > 0) {
      const actualRate = results.length ? (results.filter((r) => r && r.success).length / results.length) * 100 : 0;
      const p95 = (allStats.duration && allStats.duration.p95) != null ? allStats.duration.p95 : 0;
      const passRate = minSuccessRate <= 0 || actualRate >= minSuccessRate;
      const passP95 = maxP95Ms <= 0 || p95 <= maxP95Ms;
      report.sla.actualSuccessRate = Math.round(actualRate * 100) / 100;
      report.sla.actualP95Ms = p95;
      report.sla.pass = passRate && passP95;
    }

    console.log('[PostMeter] Run finished:', results.length, 'results');
    if (streamMode) {
      try { res.write(JSON.stringify({ type: 'report', report }) + '\n'); } catch (e) {}
      res.end();
      return;
    }
    res.json(report);
  } catch (err) {
    console.error('[PostMeter] Run error:', err && err.message);
    if (!res.headersSent) res.status(500).json({ error: (err && err.message) || 'Run failed' });
  }
});

// Import: upload collection JSON (Hoppscotch array OR Postman v2.1 single object)
app.post('/api/collections/upload', (req, res) => {
  let body = req.body;
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid JSON' });
  }
  try {
    let collections = [];
    if (Array.isArray(body)) {
      collections = body;
    } else if (body.item && Array.isArray(body.item)) {
      collections = postmanToHoppscotch(body);
      if (!collections.length) return res.status(400).json({ error: 'Postman collection had no requests' });
    } else {
      return res.status(400).json({ error: 'Use Hoppscotch (array) or Postman (object with item[]) JSON' });
    }
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    writeCollections(collections, workspaceId);
    const flat = flattenRequests(collections);
    res.json({ ok: true, flat, collections });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Export: get current collection as JSON (like Postman/Hoppscotch export)
app.get('/api/collections/export', (req, res) => {
  try {
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    const data = readCollections(workspaceId);
    if (!Array.isArray(data) || data.length === 0) return res.status(404).json({ error: 'No collection to export' });
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="collection.json"');
    res.send(JSON.stringify(data, null, 2));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Helper: find request by id in nested collections; returns { colIndex, folderIndex (null = root), requestIndex, request }
function findRequestLocation(data, requestId) {
  if (!Array.isArray(data)) return null;
  for (let ci = 0; ci < data.length; ci++) {
    const col = data[ci];
    const rootReqs = col.requests || [];
    const idx = rootReqs.findIndex(r => r.id === requestId);
    if (idx >= 0) return { colIndex: ci, folderIndex: null, requestIndex: idx, request: rootReqs[idx] };
    for (let fi = 0; fi < (col.folders || []).length; fi++) {
      const reqs = (col.folders[fi].requests || []);
      const i = reqs.findIndex(r => r.id === requestId);
      if (i >= 0) return { colIndex: ci, folderIndex: fi, requestIndex: i, request: reqs[i] };
    }
  }
  return null;
}

// Add new collection
app.post('/api/collections', (req, res) => {
  try {
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    let data = readCollections(workspaceId);
    if (!Array.isArray(data)) data = [];
    const name = (req.body && req.body.name) || 'New Collection';
    const newCol = {
      v: 11,
      id: 'col-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9),
      name,
      folders: [],
      requests: [],
    };
    data.push(newCol);
    writeCollections(data, workspaceId);
    const flat = flattenRequests(data);
    res.json({ ok: true, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update collection (e.g. rename)
app.patch('/api/collections/:index', (req, res) => {
  try {
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    let data = readCollections(workspaceId);
    if (!Array.isArray(data)) data = [];
    const index = parseInt(req.params.index, 10);
    if (isNaN(index) || index < 0 || index >= data.length) return res.status(400).json({ error: 'Invalid collection index' });
    const col = data[index];
    if (req.body && req.body.name != null) col.name = String(req.body.name).trim() || col.name || 'Collection';
    writeCollections(data, workspaceId);
    const flat = flattenRequests(data);
    res.json({ ok: true, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete collection by index
app.delete('/api/collections/:index', (req, res) => {
  try {
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    let data = readCollections(workspaceId);
    if (!Array.isArray(data)) data = [];
    const index = parseInt(req.params.index, 10);
    if (isNaN(index) || index < 0 || index >= data.length) return res.status(400).json({ error: 'Invalid collection index' });
    data.splice(index, 1);
    writeCollections(data, workspaceId);
    const flat = flattenRequests(data);
    res.json({ ok: true, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete request by id
app.delete('/api/collections/request/:requestId', (req, res) => {
  try {
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    const requestId = req.params.requestId;
    if (!requestId) return res.status(400).json({ error: 'requestId required' });
    const data = readCollections(workspaceId);
    if (!Array.isArray(data)) return res.status(404).json({ error: 'No collections' });
    const loc = findRequestLocation(data, requestId);
    if (!loc) return res.status(404).json({ error: 'Request not found' });
    const col = data[loc.colIndex];
    const reqList = loc.folderIndex != null ? (col.folders[loc.folderIndex].requests || []) : (col.requests || []);
    reqList.splice(loc.requestIndex, 1);
    writeCollections(data, workspaceId);
    const flat = flattenRequests(data);
    res.json({ ok: true, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update request (Save)
app.put('/api/collections/request/:requestId', (req, res) => {
  try {
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    const requestId = req.params.requestId;
    const updates = req.body && req.body.request ? req.body.request : req.body;
    if (!requestId) return res.status(400).json({ error: 'requestId required' });
    const data = readCollections(workspaceId);
    if (!Array.isArray(data)) return res.status(404).json({ error: 'No collections' });
    const loc = findRequestLocation(data, requestId);
    if (!loc) return res.status(404).json({ error: 'Request not found' });
    const reqObj = loc.request;
    if (updates.name != null) reqObj.name = updates.name;
    if (updates.method != null) reqObj.method = (updates.method + '').toUpperCase();
    if (updates.endpoint != null) reqObj.endpoint = updates.endpoint;
    if (updates.params != null) reqObj.params = Array.isArray(updates.params) ? updates.params : [];
    if (updates.headers != null) reqObj.headers = Array.isArray(updates.headers) ? updates.headers : [];
    if (updates.body != null) reqObj.body = updates.body;
    if (updates.auth != null) reqObj.auth = updates.auth;
    writeCollections(data, workspaceId);
    const flat = flattenRequests(data);
    res.json({ ok: true, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Duplicate request (same folder)
app.post('/api/collections/request/duplicate', (req, res) => {
  try {
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    const requestId = req.body && req.body.requestId;
    if (!requestId) return res.status(400).json({ error: 'requestId required' });
    const data = readCollections(workspaceId);
    if (!Array.isArray(data)) return res.status(404).json({ error: 'No collections' });
    const loc = findRequestLocation(data, requestId);
    if (!loc) return res.status(404).json({ error: 'Request not found' });
    const col = data[loc.colIndex];
    const reqList = loc.folderIndex != null ? (col.folders[loc.folderIndex].requests || []) : (col.requests || []);
    const oldReq = loc.request;
    const newId = 'req-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9);
    const newReq = JSON.parse(JSON.stringify(oldReq));
    newReq.id = newId;
    newReq.name = (oldReq.name || 'Request') + ' (copy)';
    reqList.splice(loc.requestIndex + 1, 0, newReq);
    writeCollections(data, workspaceId);
    const flat = flattenRequests(data);
    res.json({ ok: true, id: newId, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add new API request to collection
app.post('/api/collections/request', (req, res) => {
  try {
    const workspaceId = assertWorkspaceAccess(req, res);
    if (workspaceId === false) return;
    let data = readCollections(workspaceId);
    if (!Array.isArray(data)) data = [];

    const { collectionIndex = 0, folderIndex, request: newReq } = req.body;
    if (!newReq || !newReq.name) {
      return res.status(400).json({ error: 'request.name required' });
    }

    const col = data[collectionIndex] || (data[0]);
    if (!col) {
      const first = {
        v: 11,
        id: 'col-' + Date.now(),
        name: 'My Collection',
        folders: [],
        requests: [],
      };
      data.push(first);
      data[0] = first;
    }
    const target = data[collectionIndex || 0];
    const reqList = folderIndex != null && target.folders && target.folders[folderIndex]
      ? target.folders[folderIndex].requests
      : (target.requests = target.requests || []);

    const id = 'req-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9);
    const reqObj = {
      v: '17',
      auth: newReq.auth || { token: '', authType: 'inherit', authActive: true },
      body: newReq.body || { body: null, contentType: null },
      name: newReq.name,
      method: (newReq.method || 'GET').toUpperCase(),
      params: newReq.params || [],
      headers: newReq.headers || [],
      endpoint: newReq.endpoint || '<<baseUrl>>/',
      responses: {},
      testScript: '',
      description: newReq.description || null,
      preRequestScript: '',
      requestVariables: newReq.requestVariables || [],
      id,
    };
    reqList.push(reqObj);
    writeCollections(data, workspaceId);
    const flat = flattenRequests(data);
    res.json({ ok: true, id, flat, collections: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (!IS_VERCEL) {
  app.listen(PORT, () => {
    console.log(`API Load/Stress Tester running at http://localhost:${PORT}`);
  });
}

module.exports = app;
