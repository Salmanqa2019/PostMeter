const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3847;
const IS_VERCEL = process.env.VERCEL === '1';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const COLLECTIONS_PATH = IS_VERCEL
  ? '/tmp/hoppscotch-team-collections.json'
  : path.join(__dirname, 'hoppscotch-team-collections.json');
const COLLECTIONS_PATH_ALT = path.join(process.cwd(), 'hoppscotch-team-collections.json');

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

function resolveUrl(endpoint, baseUrl, requestVariables = []) {
  let url = (endpoint || '').replace(/<<baseUrl>>/g, (baseUrl || '').trim());
  (requestVariables || []).filter(v => v && v.active).forEach(v => {
    const key = v.key;
    if (key) url = url.replace(new RegExp(`<<${key}>>`, 'g'), (v.value || '').trim());
  });
  return url;
}

function buildRequestOptions(req, baseUrl, globalVariables = {}) {
  const endpoint = req.endpoint || '';
  const vars = [...(req.requestVariables || []), ...Object.entries(globalVariables).map(([k, v]) => ({ key: k, value: String(v), active: true }))];
  let url = resolveUrl(endpoint, baseUrl, vars);
  const params = (req.params || []).filter(p => p.active && p.key).reduce((acc, p) => { acc[p.key] = p.value; return acc; }, {});
  const headers = (req.headers || []).filter(h => h.key && h.active !== false).reduce((acc, h) => { acc[h.key] = h.value; return acc; }, {});
  let data = null;
  if (req.body && req.body.body != null) {
    try {
      data = typeof req.body.body === 'string' ? req.body.body : JSON.stringify(req.body.body);
    } catch (_) {
      data = req.body.body;
    }
    const contentType = (req.body && req.body.contentType) || 'application/json';
    if (contentType && !headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = contentType;
    }
  }
  const auth = req.auth || {};
  const useInherit = auth.authType === 'inherit';
  const token = useInherit
    ? (globalVariables.bearerToken || auth.token)
    : (auth.token || globalVariables.bearerToken);
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  } else if (auth.authActive && auth.authType === 'bearer' && auth.token) {
    headers['Authorization'] = `Bearer ${auth.token}`;
  }
  return { url, params, headers, data, method: (req.method || 'GET').toUpperCase() };
}

async function runSingleRequest(axiosConfig) {
  const start = Date.now();
  let statusCode = 0;
  let success = false;
  let errorMessage = '';
  try {
    const res = await axios({
      ...axiosConfig,
      timeout: 30000,
      validateStatus: () => true,
    });
    statusCode = res.status;
    success = res.status >= 200 && res.status < 300;
  } catch (err) {
    errorMessage = err.code || err.message || String(err);
  }
  const duration = Date.now() - start;
  return { duration, statusCode, success, error: errorMessage || null };
}

async function sendOneRequest(axiosConfig) {
  const start = Date.now();
  try {
    const res = await axios({
      ...axiosConfig,
      timeout: 60000,
      validateStatus: () => true,
      responseType: 'text',
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

function runWithConcurrency(tasks, concurrency) {
  return new Promise((resolve) => {
    const results = [];
    let index = 0;

    function runNext() {
      if (index >= tasks.length) {
        if (results.length === tasks.length) resolve(results);
        return;
      }
      const i = index++;
      const task = tasks[i];
      task()
        .then((r) => { results[i] = r; runNext(); })
        .catch((e) => { results[i] = { duration: 0, statusCode: 0, success: false, error: e.message }; runNext(); });
    }

    for (let c = 0; c < Math.min(concurrency, tasks.length); c++) runNext();
  });
}

function computeStats(results) {
  const safe = (results || []).filter(r => r && typeof r === 'object');
  const durations = safe.map(r => r.duration).filter(n => typeof n === 'number');
  const sorted = [...durations].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  const n = sorted.length;
  const success = safe.filter(r => r.success).length;
  const failed = safe.filter(r => !r.success);
  const p50 = sorted[Math.floor(n * 0.5)] ?? 0;
  const p95 = sorted[Math.floor(n * 0.95)] ?? 0;
  const p99 = sorted[Math.floor(n * 0.99)] ?? 0;
  const min = sorted[0] ?? 0;
  const max = sorted[n - 1] ?? 0;
  const avg = n ? sum / n : 0;
  const errors = failed.map(f => f.error).filter(Boolean);
  const errorCounts = {};
  errors.forEach(e => { errorCounts[e] = (errorCounts[e] || 0) + 1; });
  const statusCodeCounts = {};
  safe.forEach(r => {
    const code = r.statusCode != null ? r.statusCode : 0;
    statusCodeCounts[code] = (statusCodeCounts[code] || 0) + 1;
  });
  return {
    totalRequests: safe.length,
    successCount: success,
    failCount: failed.length,
    successRate: safe.length ? (success / safe.length * 100).toFixed(2) + '%' : '0%',
    duration: { min, max, avg: Math.round(avg), p50, p95, p99 },
    errors: errorCounts,
    rawDurations: durations,
    statusCodeCounts,
  };
}

// GET collections structure (from file or from body later)
app.get('/api/collections', (req, res) => {
  try {
    let data = [];
    const filePath = getCollectionsPath();
    try {
      if (fs.existsSync(filePath)) {
        const raw = fs.readFileSync(filePath, 'utf8');
        data = JSON.parse(raw);
        if (!Array.isArray(data)) data = [];
      }
    } catch (err) {
      console.error('Read collections error:', err.message);
    }
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
    const { requestId, baseUrl, bearerToken, collectionVariables } = req.body;
    if (!requestId) return res.status(400).json({ error: 'requestId required' });
    const filePath = getCollectionsPath();
    let raw;
    try {
      if (!fs.existsSync(filePath)) return res.status(400).json({ error: 'Collections file not found' });
      raw = fs.readFileSync(filePath, 'utf8');
    } catch (_) {
      return res.status(400).json({ error: 'Collections file not found' });
    }
    const data = JSON.parse(raw);
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
    const { type, requestIds, baseUrl, iterations = 1, concurrency = 1, globalVariables = {}, bearerToken, collectionVariables: cv } = req.body;
    const collectionVariables = cv && typeof cv === 'object' ? cv : {};
    const gv = { ...globalVariables };
    if (bearerToken) gv.bearerToken = bearerToken;
    const filePath = getCollectionsPath();
    let raw;
    try {
      if (!fs.existsSync(filePath)) return res.status(400).json({ error: 'Collections file not found. Add hoppscotch-team-collections.json or Import JSON.' });
      raw = fs.readFileSync(filePath, 'utf8');
    } catch (_) {
      return res.status(400).json({ error: 'Collections file not found' });
    }
    const data = JSON.parse(raw);
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
    const allTasks = [];
    for (let i = 0; i < iterations; i++) {
      for (const item of toRun) {
        const { baseUrl: resolvedBase, token } = resolveForRequest(item, base, gv.bearerToken, collectionVariables);
        const reqGv = { ...gv, bearerToken: token };
        const opts = buildRequestOptions(item.request, resolvedBase, reqGv);
        allTasks.push(() => runSingleRequest(opts).then(r => ({ ...r, name: item.request.name, path: item.path, id: item.id })));
      }
    }

    const concurrencyNum = Math.max(1, parseInt(concurrency, 10) || 1);
    const results = await runWithConcurrency(allTasks, concurrencyNum);
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
        results: validResults.map(r => ({ duration: r.duration, statusCode: r.statusCode, success: r.success, error: r.error })),
      };
    }

    const allStats = computeStats(results);
    report.summary = allStats;
    report.summary.throughputPerSec = totalTime > 0 ? (results.length / (totalTime / 1000)).toFixed(2) : 0;

    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Run failed' });
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
    const filePath = getCollectionsPath();
    fs.writeFileSync(fs.existsSync(filePath) ? filePath : COLLECTIONS_PATH, JSON.stringify(collections, null, 2), 'utf8');
    const flat = flattenRequests(collections);
    res.json({ ok: true, flat, collections });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Export: get current collection as JSON (like Postman/Hoppscotch export)
app.get('/api/collections/export', (req, res) => {
  try {
    const filePath = getCollectionsPath();
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'No collection to export' });
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="collection.json"');
    res.send(JSON.stringify(Array.isArray(data) ? data : [data], null, 2));
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
    let data = [];
    const filePath = getCollectionsPath();
    try {
      if (fs.existsSync(filePath)) data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (!Array.isArray(data)) data = [];
    } catch (_) {
      data = [];
    }
    const name = (req.body && req.body.name) || 'New Collection';
    const newCol = {
      v: 11,
      id: 'col-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9),
      name,
      folders: [],
      requests: [],
    };
    data.push(newCol);
    fs.writeFileSync(fs.existsSync(filePath) ? filePath : COLLECTIONS_PATH, JSON.stringify(data, null, 2), 'utf8');
    const flat = flattenRequests(data);
    res.json({ ok: true, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete collection by index
app.delete('/api/collections/:index', (req, res) => {
  try {
    const filePath = getCollectionsPath();
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'No collections file' });
    let data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (!Array.isArray(data)) data = [];
    const index = parseInt(req.params.index, 10);
    if (isNaN(index) || index < 0 || index >= data.length) return res.status(400).json({ error: 'Invalid collection index' });
    data.splice(index, 1);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    const flat = flattenRequests(data);
    res.json({ ok: true, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete request by id
app.delete('/api/collections/request/:requestId', (req, res) => {
  try {
    const requestId = req.params.requestId;
    if (!requestId) return res.status(400).json({ error: 'requestId required' });
    const filePath = getCollectionsPath();
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'No collections file' });
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const loc = findRequestLocation(data, requestId);
    if (!loc) return res.status(404).json({ error: 'Request not found' });
    const col = data[loc.colIndex];
    const reqList = loc.folderIndex != null ? (col.folders[loc.folderIndex].requests || []) : (col.requests || []);
    reqList.splice(loc.requestIndex, 1);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    const flat = flattenRequests(data);
    res.json({ ok: true, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update request (Save)
app.put('/api/collections/request/:requestId', (req, res) => {
  try {
    const requestId = req.params.requestId;
    const updates = req.body && req.body.request ? req.body.request : req.body;
    if (!requestId) return res.status(400).json({ error: 'requestId required' });
    const filePath = getCollectionsPath();
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'No collections file' });
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
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
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    const flat = flattenRequests(data);
    res.json({ ok: true, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Duplicate request (same folder)
app.post('/api/collections/request/duplicate', (req, res) => {
  try {
    const requestId = req.body && req.body.requestId;
    if (!requestId) return res.status(400).json({ error: 'requestId required' });
    const filePath = getCollectionsPath();
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'No collections file' });
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
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
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    const flat = flattenRequests(data);
    res.json({ ok: true, id: newId, collections: data, flat });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add new API request to collection
app.post('/api/collections/request', (req, res) => {
  try {
    let data = [];
    const filePath = getCollectionsPath();
    try {
      if (fs.existsSync(filePath)) data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (!Array.isArray(data)) data = [];
    } catch (_) {
      data = [];
    }
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
    const savePath = fs.existsSync(getCollectionsPath()) ? getCollectionsPath() : COLLECTIONS_PATH;
    fs.writeFileSync(savePath, JSON.stringify(data, null, 2), 'utf8');
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
