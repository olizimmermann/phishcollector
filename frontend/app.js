'use strict';

// ═══════════════════════════════════════════════════════════════
//  PhishCollector SPA — vanilla JS, hash routing, no dependencies
// ═══════════════════════════════════════════════════════════════

// ── State ───────────────────────────────────────────────────────
const S = {
  view:           'dashboard',
  pollingId:      null,
  detail:         null,
  detailReqs:     [],
  detailSpider:   [],
  detailPlugins:  [],
  activeTab:      'fingerprint',
  currentDetailId: null,   // track which collection is shown so tab is preserved
  stats:          { total: 0, completed: 0, running: 0, failed: 0 },
};


// ── API helper ──────────────────────────────────────────────────
async function api(method, path, body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(`/api/v1${path}`, opts);
  if (!r.ok) {
    let msg = r.statusText;
    try {
      const data = await r.json();
      if (Array.isArray(data.detail)) {
        // FastAPI validation errors: [{msg: "...", loc: [...]}]
        msg = data.detail.map(e => e.msg.replace(/^Value error, /, '')).join(' · ');
      } else if (data.detail) {
        msg = String(data.detail);
      }
    } catch { /* leave msg as statusText */ }
    throw new Error(msg);
  }
  if (r.status === 204) return null;
  return r.json();
}


// ── Toasts ──────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const c = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast t-${type === 'success' ? 'ok' : type === 'error' ? 'err' : 'info'}`;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}


// ── URL copy helper (NEVER render phishing URLs as clickable links) ──
function copyUrl(el) {
  const url = el.dataset.url;
  navigator.clipboard.writeText(url).then(
    () => toast('URL copied to clipboard', 'success'),
    () => toast('Copy failed — check browser permissions', 'error'),
  );
}

/**
 * Render a phishing URL as unclickable text + copy button.
 * This prevents any accidental navigation to the malicious site.
 */
function urlCell(url, extraStyle = '') {
  if (!url) return '<span style="color:var(--dim)">—</span>';
  return `<span class="url-display" style="${esc(extraStyle)}">${esc(url)}</span>` +
         `<button class="btn-copy" data-url="${esc(url)}" onclick="copyUrl(this)" title="Copy URL">⧉</button>`;
}


// ── Clock & health ──────────────────────────────────────────────
function tickClock() {
  const el = document.getElementById('sys-clock');
  if (el) el.textContent = new Date().toISOString().slice(11, 19) + 'Z';
}

async function checkHealth() {
  const dot   = document.getElementById('api-dot');
  const label = document.getElementById('api-label');
  try {
    await fetch('/api/v1/collections?limit=1');
    if (dot)   { dot.className = 'dot online'; }
    if (label) { label.textContent = 'API ONLINE'; }
  } catch {
    if (dot)   { dot.className = 'dot offline'; }
    if (label) { label.textContent = 'API OFFLINE'; }
  }
}


// ── Router ──────────────────────────────────────────────────────
function route() {
  const hash = location.hash.slice(1) || 'dashboard';
  const [view, param] = hash.split('/');
  stopPolling();
  S.view = view;

  document.querySelectorAll('.nav-link').forEach(a => {
    a.classList.toggle('active', a.dataset.view === view);
  });

  const c = document.getElementById('content');
  c.innerHTML = `<div class="loader">LOADING</div>`;

  switch (view) {
    case 'collections': renderCollections(); break;
    case 'detail':      renderDetail(param); break;
    case 'search':      renderSearch();      break;
    default:            renderDashboard();
  }
}


// ═══════════════════════════════════════════════════════════════
//  VIEWS
// ═══════════════════════════════════════════════════════════════

// ── Dashboard ───────────────────────────────────────────────────
async function renderDashboard() {
  const [collections] = await Promise.all([
    api('GET', '/collections?limit=500').catch(() => []),
  ]);

  S.stats = {
    total:     collections.length,
    completed: collections.filter(c => c.status === 'completed').length,
    running:   collections.filter(c => c.status === 'running').length,
    failed:    collections.filter(c => c.status === 'failed').length,
  };

  const recent = collections.slice(0, 12);

  document.getElementById('content').innerHTML = `
    <div class="fade-in">
      <div class="stats-row">
        ${statCard('TOTAL COLLECTED', S.stats.total,     '',                        'all time',      'stat-total')}
        ${statCard('COMPLETED',       S.stats.completed, 'g',                       'fully analyzed','stat-completed')}
        ${statCard('RUNNING',         S.stats.running,   'a',                       'in progress',   'stat-running')}
        ${statCard('FAILED',          S.stats.failed,    S.stats.failed ? 'r' : '', 'errors',        'stat-failed')}
      </div>

      <div class="card">
        <div class="card-hdr">
          <span class="card-title">// INITIATE SCAN</span>
        </div>
        <div class="card-body">
          <div class="scan-form">
            <div class="input-row">
              <span class="input-pfx">TARGET ▸</span>
              <input id="scan-url" class="cyber-input" type="url"
                placeholder="https://suspicious-site.example.com"
                autocomplete="off" spellcheck="false">
            </div>
            <div class="form-opts">
              <label class="toggle">
                <input type="checkbox" id="opt-wordlist">
                <span class="toggle-lbl">ENABLE WORDLIST FUZZING</span>
              </label>
            </div>
            <div class="form-actions">
              <button class="btn btn-g" id="btn-scan" onclick="submitScan()">
                [ INITIATE SCAN ]
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-hdr">
          <span class="card-title">// RECENT COLLECTIONS</span>
          <div style="display:flex;gap:.5rem;align-items:center">
            <button class="btn btn-sm btn-c" onclick="downloadBulkExport('json')">↓ JSON</button>
            <button class="btn btn-sm btn-c" onclick="downloadBulkExport('csv')">↓ CSV</button>
            <a href="#collections" class="btn btn-sm btn-c">VIEW ALL →</a>
          </div>
        </div>
        <div class="card-body" style="padding:0">
          ${collectionTable(recent)}
        </div>
      </div>
    </div>
  `;

  document.getElementById('scan-url')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') submitScan();
  });

  if (S.stats.running > 0) startPolling(_pollDashboard, 5000);
}


// ── Collections ─────────────────────────────────────────────────
async function renderCollections() {
  const list = await api('GET', '/collections?limit=500').catch(() => []);

  document.getElementById('content').innerHTML = `
    <div class="fade-in">
      <div class="card">
        <div class="card-hdr">
          <span class="card-title">// COLLECTION INDEX [ ${list.length} ]</span>
          <div style="display:flex;gap:.5rem;align-items:center">
            <button class="btn btn-sm btn-c" onclick="downloadBulkExport('json')">↓ JSON</button>
            <button class="btn btn-sm btn-c" onclick="downloadBulkExport('csv')">↓ CSV</button>
            <button class="btn btn-sm btn-g" onclick="location.hash='#dashboard'">+ NEW SCAN</button>
          </div>
        </div>
        <div class="card-body" style="padding:0">
          ${collectionTable(list)}
        </div>
      </div>
    </div>
  `;

  if (list.some(c => c.status === 'running' || c.status === 'pending')) {
    startPolling(renderCollections, 5000);
  }
}


// ── Detail ──────────────────────────────────────────────────────
async function renderDetail(id) {
  if (!id) { location.hash = '#collections'; return; }

  let detail, reqs, spider, plugins;
  try {
    [detail, reqs, spider, plugins] = await Promise.all([
      api('GET', `/collections/${id}`),
      api('GET', `/collections/${id}/requests`),
      api('GET', `/collections/${id}/spider`),
      api('GET', `/collections/${id}/plugins`).catch(() => []),
    ]);
  } catch (e) {
    document.getElementById('content').innerHTML =
      `<div class="empty">Error: ${esc(e.message)}</div>`;
    return;
  }

  S.detail       = detail;
  S.detailReqs   = reqs    || [];
  S.detailSpider = spider  || [];
  S.detailPlugins = plugins || [];
  // Only reset tab when navigating to a different collection
  if (S.currentDetailId !== id) {
    S.activeTab = 'fingerprint';
    S.currentDetailId = id;
  }

  const fp     = detail.fingerprint || {};
  const threat = calcThreat(fp.phishing_indicators, S.detailPlugins);

  document.getElementById('content').innerHTML = `
    <div class="fade-in">
      <button class="back-btn" onclick="history.back()">BACK</button>

      <!-- ── Summary bar ── -->
      <div class="card">
        <div class="card-hdr">
          <span class="card-title" style="color:var(--cyan);word-break:break-all">${esc(detail.url)}</span>
          <div style="display:flex;gap:.5rem;align-items:center;flex-shrink:0">
            <span id="detail-status-badge">${badge(detail.status)}</span>
            <button class="btn btn-sm btn-c" onclick="doRescan('${esc(id)}')">[ RESCAN ]</button>
            <button class="btn btn-sm btn-c" onclick="downloadExport('${esc(id)}','json')">↓ JSON</button>
            <button class="btn btn-sm btn-c" onclick="downloadExport('${esc(id)}','csv')">↓ CSV</button>
            <button class="btn btn-sm btn-r" onclick="doDelete('${esc(id)}')">[ DELETE ]</button>
          </div>
        </div>
        <div class="card-body">
          <div class="kv" style="grid-template-columns:110px 1fr;font-size:11px">
            <span class="kk">Job ID</span>
            <span class="kv-val mono">${detail.id}</span>
            <span class="kk">Submitted</span>
            <span class="kv-val">${fmtTs(detail.submitted_at)}</span>
            <span class="kk">Completed</span>
            <span class="kv-val">${detail.completed_at ? fmtTs(detail.completed_at) : '—'}</span>
            <span class="kk">User-Agent</span>
            <span class="kv-val mono" style="font-size:10px">${esc(detail.user_agent || '—')}</span>
            ${detail.parent_id ? `<span class="kk">Rescanned From</span>
            <span class="kv-val"><button class="btn btn-sm btn-c"
              onclick="location.hash='#detail/${detail.parent_id}'"
              style="font-size:9px">${detail.parent_id.slice(0,8)}…</button></span>` : ''}
            ${detail.error ? `<span class="kk" style="color:var(--red)">Error</span>
            <span class="kv-val" style="color:var(--red)">${esc(detail.error)}</span>` : ''}
          </div>

          <!-- Tags -->
          <div class="annotations-row">
            <div class="ann-label">TAGS</div>
            <div id="tag-editor" class="tag-editor">
              ${_tagsHtml(id, detail.tags || [])}
            </div>
          </div>

          <!-- Notes -->
          <div class="annotations-row" style="align-items:flex-start">
            <div class="ann-label">
              NOTES
              <span id="notes-saved" style="color:var(--green);font-size:9px;display:block;font-weight:normal"></span>
            </div>
            <textarea id="notes-area" class="notes-area" data-id="${esc(id)}"
              placeholder="analyst notes, IOCs, observations…"
              onblur="doSaveNotes(this)">${esc(detail.notes || '')}</textarea>
          </div>
        </div>
      </div>

      <!-- ── Screenshot + threat ── -->
      <div class="detail-grid">
        <div class="screenshot-frame">
          <div class="screenshot-lbl">SCREENSHOT</div>
          <img src="/api/v1/collections/${esc(id)}/screenshot"
               alt="page screenshot"
               onclick="window.open(this.src,'_blank')"
               onerror="this.parentElement.innerHTML='<div class=\\'no-screenshot\\'>No screenshot available</div>'">
        </div>
        <div style="display:flex;flex-direction:column;gap:1rem">
          <div class="threat-box">
            <div class="threat-lbl">// THREAT ASSESSMENT</div>
            <div class="threat-lvl lvl-${threat.level}">${threat.level}</div>
            <div class="threat-bar">
              ${Array.from({length:10},(_,i) =>
                `<div class="t-seg ${i < threat.bars ? 'fill-'+threat.level : ''}"></div>`
              ).join('')}
            </div>
            <div class="threat-ct">${threat.count} indicator${threat.count !== 1 ? 's' : ''} matched</div>
            <div id="plugin-badges-wrap" style="margin-top:.75rem;display:flex;flex-wrap:wrap;gap:.35rem">
              ${S.detailPlugins.map(p => pluginBadge(p)).join('')}
            </div>
          </div>

          <div class="card" style="margin-bottom:0;flex:1">
            <div class="card-hdr"><span class="card-title">// QUICK FACTS</span></div>
            <div class="card-body">
              <div class="kv">
                <span class="kk">IP</span>       <span class="kv-val">${esc(fp.ip_address || '—')}</span>
                <span class="kk">ASN</span>       <span class="kv-val">${esc(fp.asn || '—')}</span>
                <span class="kk">Org</span>       <span class="kv-val">${esc(fp.org || '—')}</span>
                <span class="kk">Country</span>   <span class="kv-val">${esc(fp.country || '—')}${fp.city ? ' / ' + esc(fp.city) : ''}</span>
                <span class="kk">HTTP</span>      <span class="kv-val" style="color:${httpColor(fp.status_code)}">${fp.status_code || '—'}</span>
                <span class="kk">Title</span>     <span class="kv-val">${esc(fp.title || '—')}</span>
                <span class="kk">Favicon</span>   <span class="kv-val" style="color:var(--purple)">${esc(fp.favicon_hash_mmh3 || '—')}</span>
                <span class="kk">TLS Valid</span> <span class="kv-val ${fp.ssl_valid === false ? 'cert-bad' : 'cert-ok'}">${fp.ssl_valid == null ? '—' : fp.ssl_valid ? 'YES' : 'NO'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- ── Tabbed detail ── -->
      <div class="card">
        <div class="card-hdr" style="padding:0">
          <div class="tabs" style="border-bottom:none;margin:0;padding:0 .5rem;flex:1">
            ${['fingerprint','indicators','plugins','network','spider'].map(t =>
              `<button class="tab ${S.activeTab===t?'active':''}" data-tab="${t}"
                onclick="switchTab('${t}')">${t.toUpperCase()}</button>`
            ).join('')}
            <span style="margin-left:auto;padding:.5rem .75rem;font-size:9px;color:var(--dim)">
              ${detail.spider_count} URLs &nbsp;·&nbsp;
              ${detail.asset_count} assets &nbsp;·&nbsp;
              ${detail.request_count} reqs
            </span>
          </div>
        </div>
        <div class="card-body">
          <div id="pane-fingerprint" class="tab-panel ${S.activeTab==='fingerprint'?'active':''}">
            ${paneFingerprint(fp)}
          </div>
          <div id="pane-indicators" class="tab-panel ${S.activeTab==='indicators'?'active':''}">
            ${paneIndicators(fp.phishing_indicators)}
          </div>
          <div id="pane-plugins" class="tab-panel ${S.activeTab==='plugins'?'active':''}">
            ${panePlugins(S.detailPlugins)}
          </div>
          <div id="pane-network" class="tab-panel ${S.activeTab==='network'?'active':''}">
            ${paneNetwork(S.detailReqs)}
          </div>
          <div id="pane-spider" class="tab-panel ${S.activeTab==='spider'?'active':''}">
            ${paneSpider(S.detailSpider)}
          </div>
        </div>
      </div>
    </div>
  `;

  if (detail.status === 'running' || detail.status === 'pending') {
    startPolling(() => _pollDetail(id), 4000);
  } else if (_hasUnknownPlugin(S.detailPlugins)) {
    // Job is done but a plugin result is still pending (e.g. VT analysis in queue)
    startPolling(() => _pollPlugins(id), 30000);
  }
}

function switchTab(t) {
  S.activeTab = t;
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === t));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `pane-${t}`));
}


// ── Search ──────────────────────────────────────────────────────
function renderSearch() {
  document.getElementById('content').innerHTML = `
    <div class="fade-in">
      <div class="card">
        <div class="card-hdr">
          <span class="card-title">// FINGERPRINT SEARCH</span>
        </div>
        <div class="card-body">
          <div class="search-grid">
            <div class="field-grp">
              <label class="field-lbl">Favicon Hash (mmh3)</label>
              <input class="cyber-input" id="s-fav" placeholder="-1234567890" autocomplete="off">
            </div>
            <div class="field-grp">
              <label class="field-lbl">IP Address</label>
              <input class="cyber-input" id="s-ip" placeholder="185.220.101.x" autocomplete="off">
            </div>
            <div class="field-grp">
              <label class="field-lbl">Technology</label>
              <input class="cyber-input" id="s-tech" placeholder="WordPress" autocomplete="off">
            </div>
            <div class="field-grp">
              <label class="field-lbl">Country Code</label>
              <input class="cyber-input" id="s-country" placeholder="RU" autocomplete="off">
            </div>
            <div class="field-grp">
              <label class="field-lbl">Page Title (partial)</label>
              <input class="cyber-input" id="s-title" placeholder="Sign in to" autocomplete="off">
            </div>
          </div>
          <div class="form-actions">
            <button class="btn btn-g" onclick="doSearch()">[ SEARCH ]</button>
          </div>
        </div>
      </div>
      <div id="search-results"></div>
    </div>
  `;
  document.querySelectorAll('.cyber-input').forEach(i =>
    i.addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); })
  );
}


// ═══════════════════════════════════════════════════════════════
//  TAB PANELS
// ═══════════════════════════════════════════════════════════════

function paneFingerprint(fp) {
  if (!fp || !Object.keys(fp).length)
    return `<div class="empty">No fingerprint data — collection may still be running.</div>`;

  const tls    = fp.ssl_cert        || {};
  const whois  = fp.whois           || {};
  const forms  = fp.forms           || [];
  const techs  = fp.technologies    || [];
  const ext    = fp.external_domains || [];
  const ck     = fp.cookies         || [];
  const chain  = fp.redirect_chain  || [];

  return `
    <div class="two-col">
      <!-- LEFT -->
      <div>
        <div class="panel-sec">
          <div class="panel-sec-title">NETWORK</div>
          <div class="kv" style="grid-template-columns:110px 1fr">
            <span class="kk">Final URL</span>
            <span class="kv-val url-cell" style="font-size:11px">
              ${urlCell(fp.final_url)}
            </span>
            <span class="kk">Page SHA256</span>
            <span class="kv-val mono">${fp.page_sha256 ? fp.page_sha256.slice(0,32)+'…' : '—'}</span>
            <span class="kk">Fav SHA256</span>
            <span class="kv-val mono">${fp.favicon_sha256 ? fp.favicon_sha256.slice(0,32)+'…' : '—'}</span>
          </div>
        </div>

        ${chain.length > 1 ? `
        <div class="panel-sec">
          <div class="panel-sec-title">REDIRECT CHAIN (${chain.length})</div>
          <div class="redir-chain">
            ${chain.map(u => `<div class="redir-step">${urlCell(u)}</div>`).join('')}
          </div>
        </div>` : ''}

        <div class="panel-sec">
          <div class="panel-sec-title">TLS CERTIFICATE</div>
          ${tls.error
            ? `<div style="color:var(--red);font-size:11px">${esc(tls.error)}</div>`
            : `<div class="kv" style="grid-template-columns:90px 1fr">
                <span class="kk">Issuer</span>
                <span class="kv-val" style="font-size:10px">${esc(tls.issuer||'—')}</span>
                <span class="kk">Subject</span>
                <span class="kv-val" style="font-size:10px">${esc(tls.subject||'—')}</span>
                <span class="kk">Not before</span>
                <span class="kv-val">${tls.not_before ? fmtTs(tls.not_before) : '—'}</span>
                <span class="kk">Expires</span>
                <span class="kv-val ${tls.expired ? 'cert-bad' : 'cert-ok'}">
                  ${tls.not_after ? fmtTs(tls.not_after) : '—'}
                  ${tls.expired ? ' [EXPIRED]' : tls.days_remaining != null ? ` [${tls.days_remaining}d]` : ''}
                </span>
                ${tls.sans?.length ? `
                <span class="kk">SANs</span>
                <span class="kv-val" style="font-size:10px">
                  ${tls.sans.slice(0,6).map(esc).join(', ')}${tls.sans.length>6?' +more':''}
                </span>` : ''}
              </div>`
          }
        </div>

        <div class="panel-sec">
          <div class="panel-sec-title">WHOIS</div>
          ${whois.error
            ? `<div style="color:var(--dim);font-size:11px">${esc(whois.error)}</div>`
            : `<div class="kv" style="grid-template-columns:90px 1fr">
                <span class="kk">Registrar</span>
                <span class="kv-val">${esc(whois.registrar||'—')}</span>
                <span class="kk">Created</span>
                <span class="kv-val">${esc(String(whois.creation_date||'—').split('T')[0])}</span>
                <span class="kk">Expires</span>
                <span class="kv-val">${esc(String(whois.expiration_date||'—').split('T')[0])}</span>
              </div>`
          }
        </div>
      </div>

      <!-- RIGHT -->
      <div>
        ${techs.length ? `
        <div class="panel-sec">
          <div class="panel-sec-title">TECHNOLOGIES (${techs.length})</div>
          <div class="tags">
            ${techs.map(t => `<span class="tag">${esc(t)}</span>`).join('')}
          </div>
        </div>` : ''}

        ${forms.length ? `
        <div class="panel-sec">
          <div class="panel-sec-title">FORMS (${forms.length})</div>
          ${forms.map(f => `
            <div class="form-card">
              <div class="form-card-hdr">
                <span><span class="f-method">${esc(f.method)}</span><span class="f-action">${esc(f.action||'/')}</span></span>
                ${f.credential_form ? '<span class="cred-badge">CREDENTIAL FORM</span>' : ''}
              </div>
              <div class="form-fields">
                ${(f.fields||[]).map(field => `
                  <div class="form-field">
                    <span class="ff-type ${field.type==='password'?'pw':field.hidden?'hid':''}">[${esc(field.type)}]</span>
                    <span class="ff-name">${esc(field.name||'unnamed')}</span>
                    ${field.placeholder ? `<span class="ff-ph">"${esc(field.placeholder)}"</span>` : ''}
                  </div>
                `).join('')}
              </div>
            </div>
          `).join('')}
        </div>` : ''}

        ${ext.length ? `
        <div class="panel-sec">
          <div class="panel-sec-title">EXTERNAL DOMAINS (${ext.length})</div>
          <div class="domains">${ext.map(d => `<span class="domain-pill">${esc(d)}</span>`).join('')}</div>
        </div>` : ''}

        ${ck.length ? `
        <div class="panel-sec">
          <div class="panel-sec-title">COOKIES (${ck.length})</div>
          ${ck.slice(0,15).map(c => `
            <div class="cookie-row">
              <span class="ck-name">${esc(c.name||'')}</span>
              <span class="ck-eq">=</span>
              <span class="ck-val">${esc((c.value||'').slice(0,50))}${(c.value||'').length>50?'…':''}</span>
            </div>
          `).join('')}
          ${ck.length>15?`<div style="font-size:10px;color:var(--dim);padding:.3rem 0">+${ck.length-15} more</div>`:''}
        </div>` : ''}
      </div>
    </div>
  `;
}

function paneIndicators(indicators) {
  if (!indicators || !Object.keys(indicators).length)
    return `<div class="empty">// NO INDICATORS DETECTED — this site appears clean</div>`;

  return Object.entries(indicators).map(([cat, matches]) => `
    <div class="ind-cat">
      <div class="ind-cat-title">${esc(cat.replace(/_/g,' ').toUpperCase())}
        <span style="color:var(--dim);font-weight:normal">(${matches.length})</span>
      </div>
      ${matches.map(m => `<div class="ind-match">${esc(m)}</div>`).join('')}
    </div>
  `).join('');
}

function panePlugins(plugins) {
  if (!plugins || !plugins.length)
    return `<div class="empty">No threat-intelligence plugins are enabled.<br>
      Set <span class="mono">PHISH_URLHAUS_ENABLED=true</span> or
      <span class="mono">PHISH_VIRUSTOTAL_API_KEY=…</span> in your .env to activate them.</div>`;

  return plugins.map(p => {
    const cls = { malicious:'r', suspicious:'a', clean:'g', unknown:'', error:'' }[p.status] || '';
    const score = p.score != null ? `${Math.round(p.score * 100)}%` : '—';
    return `
      <div class="plugin-card">
        <div class="plugin-hdr">
          <span class="plugin-name">${esc(p.plugin_name.toUpperCase())}</span>
          <span class="plugin-status s-${cls}">${esc(p.status.toUpperCase())}</span>
          <span class="plugin-score">score: ${score}</span>
          <span class="plugin-ts">${p.queried_at ? fmtTs(p.queried_at) : ''}</span>
        </div>
        ${p.result ? `
        <pre class="plugin-raw">${esc(JSON.stringify(p.result, null, 2))}</pre>` : ''}
      </div>
    `;
  }).join('');
}

function paneNetwork(reqs) {
  if (!reqs.length) return `<div class="empty">No network requests logged.</div>`;

  const shown = reqs.slice(0, 300);
  return `
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th>METHOD</th><th>URL</th><th>STATUS</th><th>TYPE</th><th>BODY SHA256</th></tr>
        </thead>
        <tbody>
          ${shown.map(r => `
            <tr>
              <td style="color:var(--green);font-size:10px">${esc(r.method)}</td>
              <td class="td-url">${urlCell(r.url)}</td>
              <td style="font-size:11px;color:${httpColor(r.status)}">${r.status||'—'}</td>
              <td style="font-size:10px;color:var(--dim)">${esc(r.resource_type||'—')}</td>
              <td style="font-size:10px;color:var(--dim)">${r.response_body_sha256 ? r.response_body_sha256.slice(0,16)+'…' : '—'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
      ${reqs.length > 300 ? `<div class="empty" style="padding:.6rem">Showing 300 of ${reqs.length} requests</div>` : ''}
    </div>
  `;
}

function paneSpider(spider) {
  if (!spider.length) return `<div class="empty">No spider results — either still running or spidering was minimal.</div>`;

  return `
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th>URL</th><th>STATUS</th><th>FOUND VIA</th><th>TITLE</th><th>SIZE</th></tr>
        </thead>
        <tbody>
          ${spider.map(s => `
            <tr>
              <td style="max-width:360px">
                ${urlCell(s.url, 'font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:340px;display:inline-block;vertical-align:middle')}
              </td>
              <td style="font-size:11px;color:${httpColor(s.status_code)}">${s.status_code||'—'}</td>
              <td><span class="tag" style="font-size:9px">${esc(s.found_via||'—')}</span></td>
              <td style="font-size:11px;color:var(--bright);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s.title||'—')}</td>
              <td style="font-size:10px;color:var(--dim);white-space:nowrap">${s.size_bytes != null ? fmtBytes(s.size_bytes) : '—'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}


// ═══════════════════════════════════════════════════════════════
//  ACTIONS
// ═══════════════════════════════════════════════════════════════

async function submitScan() {
  const input = document.getElementById('scan-url');
  const url   = input?.value.trim();
  if (!url) { toast('Enter a target URL', 'error'); return; }

  const btn = document.getElementById('btn-scan');
  if (btn) { btn.disabled = true; btn.textContent = '[ INITIATING… ]'; }

  try {
    const res = await api('POST', '/collections', {
      url,
      use_wordlist: document.getElementById('opt-wordlist')?.checked || false,
    });
    toast(`Scan queued: ${res.id.slice(0,8)}…`, 'success');
    if (input) input.value = '';
    location.hash = `#detail/${res.id}`;
  } catch (e) {
    toast(`Error: ${e.message}`, 'error');
    if (btn) { btn.disabled = false; btn.textContent = '[ INITIATE SCAN ]'; }
  }
}

async function doDelete(id) {
  if (!confirm(`Delete collection ${id.slice(0,8)}…?\n\nThis removes all stored artifacts.`)) return;
  try {
    await api('DELETE', `/collections/${id}`);
    toast('Collection deleted', 'success');
    if (location.hash.includes(id)) location.hash = '#collections';
    else route();
  } catch (e) {
    toast(`Delete failed: ${e.message}`, 'error');
  }
}

async function doRescan(id) {
  try {
    const res = await api('POST', `/collections/${id}/rescan`);
    toast(`Rescan queued: ${res.id.slice(0,8)}…`, 'success');
    location.hash = `#detail/${res.id}`;
  } catch (e) {
    toast(`Rescan failed: ${e.message}`, 'error');
  }
}

function downloadExport(id, format) {
  // Trigger a direct browser download — no JS navigation to the phishing URL
  const a = document.createElement('a');
  a.href = `/api/v1/collections/${id}/export?format=${format}`;
  a.download = `collection_${id.slice(0,8)}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function downloadBulkExport(format) {
  try {
    const list = await api('GET', '/collections?limit=500');
    if (!list.length) { toast('No collections to export', 'info'); return; }

    if (format === 'json') {
      const blob = new Blob([JSON.stringify(list, null, 2)], { type: 'application/json' });
      _triggerDownload(blob, `phishcollector_export.json`);
    } else {
      const headers = Object.keys(list[0]).join(',');
      const rows = list.map(r => Object.values(r).map(v =>
        JSON.stringify(v ?? '')).join(',')
      ).join('\n');
      const blob = new Blob([headers + '\n' + rows], { type: 'text/csv' });
      _triggerDownload(blob, `phishcollector_export.csv`);
    }
  } catch (e) {
    toast(`Export failed: ${e.message}`, 'error');
  }
}

function _triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function doSearch() {
  const p = new URLSearchParams();
  const g = id => document.getElementById(id)?.value.trim();
  if (g('s-fav'))     p.set('favicon_hash', g('s-fav'));
  if (g('s-ip'))      p.set('ip',           g('s-ip'));
  if (g('s-tech'))    p.set('technology',   g('s-tech'));
  if (g('s-country')) p.set('country',      g('s-country'));
  if (g('s-title'))   p.set('title',        g('s-title'));

  const res = document.getElementById('search-results');
  res.innerHTML = `<div class="loader">SEARCHING</div>`;

  try {
    const rows = await api('GET', `/search?${p}&limit=200`);
    if (!rows.length) { res.innerHTML = `<div class="empty">No results matched your query.</div>`; return; }

    res.innerHTML = `
      <div class="card">
        <div class="card-hdr">
          <span class="card-title">// RESULTS [ ${rows.length} ]</span>
        </div>
        <div class="card-body" style="padding:0">
          <div class="tbl-wrap">
            <table>
              <thead><tr>
                <th>COLLECTION</th><th>IP</th><th>COUNTRY</th><th>TITLE</th>
                <th>TECHNOLOGIES</th><th>FAVICON mmh3</th>
              </tr></thead>
              <tbody>
                ${rows.map(r => `
                  <tr>
                    <td>
                      <button class="btn btn-sm btn-c"
                        onclick="location.hash='#detail/${r.collection_id}'"
                        style="font-size:9px">${r.collection_id.slice(0,8)}…</button>
                    </td>
                    <td style="font-size:11px">${esc(r.ip_address||'—')}</td>
                    <td style="font-size:11px">${esc(r.country||'—')}</td>
                    <td style="font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.title||'—')}</td>
                    <td><div class="tags">${(r.technologies||[]).map(t=>`<span class="tag" style="font-size:9px">${esc(t)}</span>`).join('')}</div></td>
                    <td style="font-size:11px;color:var(--purple)">${esc(r.favicon_hash_mmh3||'—')}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  } catch (e) {
    res.innerHTML = `<div class="empty">Search error: ${esc(e.message)}</div>`;
  }
}


// ═══════════════════════════════════════════════════════════════
//  COMPONENTS
// ═══════════════════════════════════════════════════════════════

function statCard(label, value, cls, sub, id = '') {
  return `
    <div class="stat-card">
      <div class="stat-label">${label}</div>
      <div class="stat-val ${cls}" ${id ? `id="${id}"` : ''}>${value}</div>
      <div class="stat-sub">${sub}</div>
    </div>
  `;
}

function badge(status) {
  const cls = { completed:'b-completed', running:'b-running', failed:'b-failed', pending:'b-pending' }[status] || 'b-pending';
  return `<span class="badge ${cls}">${status}</span>`;
}

function pluginBadge(p) {
  const cls = { malicious:'b-failed', suspicious:'b-running', clean:'b-completed', unknown:'b-pending', error:'b-pending' }[p.status] || 'b-pending';
  return `<span class="badge ${cls}" title="${esc(p.plugin_name)}: ${esc(p.status)}">${esc(p.plugin_name.toUpperCase())}: ${esc(p.status.toUpperCase())}</span>`;
}

function collectionTable(list) {
  if (!list.length)
    return `<div class="empty">No collections yet. Submit a URL above to begin.</div>`;

  return `
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>ID</th><th>URL</th><th>STATUS</th><th>SUBMITTED</th><th>ACTIONS</th></tr></thead>
        <tbody>
          ${list.map(c => `
            <tr>
              <td class="td-id">${c.id.slice(0,8)}…</td>
              <td class="td-url" title="${esc(c.url)}">
                ${urlCell(c.url)}
                ${(c.tags||[]).length ? `<div class="row-tags">${(c.tags).map(t=>`<span class="tag tag-sm">${esc(t)}</span>`).join('')}</div>` : ''}
              </td>
              <td>${badge(c.status)}</td>
              <td class="td-time">${timeAgo(c.submitted_at)}</td>
              <td>
                <div class="td-acts">
                  <button class="btn btn-sm btn-c" onclick="location.hash='#detail/${c.id}'">VIEW</button>
                  <button class="btn btn-sm btn-r" onclick="doDelete('${c.id}')">DEL</button>
                </div>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}


// ═══════════════════════════════════════════════════════════════
//  POLLING  (lightweight — no full page re-render while running)
// ═══════════════════════════════════════════════════════════════

function startPolling(fn, ms) {
  stopPolling();
  S.pollingId = setInterval(fn, ms);
}
function stopPolling() {
  if (S.pollingId) clearInterval(S.pollingId);
  S.pollingId = null;
}

/**
 * Light-weight detail poller.
 * Only updates the status badge in place.  When the job finishes, stops
 * polling and does ONE final full re-render to show the completed data.
 */
async function _pollDetail(id) {
  try {
    const d = await api('GET', `/collections/${id}`);
    // Update badge in place — no full re-render
    const wrap = document.getElementById('detail-status-badge');
    if (wrap) wrap.innerHTML = badge(d.status);

    if (d.status !== 'running' && d.status !== 'pending') {
      stopPolling();
      renderDetail(id);   // one final full render with all completed data
    }
  } catch { /* transient errors — just wait for next tick */ }
}

/** True when any plugin result is still pending / unknown. */
function _hasUnknownPlugin(plugins) {
  return (plugins || []).some(p => p.status === 'unknown');
}

/**
 * Plugin poller — triggers a server-side re-query then updates only the
 * plugins pane and threat badges in-place.  Stops once all results resolve.
 */
async function _pollPlugins(id) {
  try {
    await api('POST', `/collections/${id}/plugins/refresh`);
    // Give the background task a moment to complete
    await new Promise(r => setTimeout(r, 3000));
    const plugins = await api('GET', `/collections/${id}/plugins`);
    S.detailPlugins = plugins || [];

    // Update plugins tab pane
    const pane = document.getElementById('pane-plugins');
    if (pane) pane.innerHTML = panePlugins(S.detailPlugins);

    // Update plugin badges in threat box
    const wrap = document.getElementById('plugin-badges-wrap');
    if (wrap) wrap.innerHTML = S.detailPlugins.map(p => pluginBadge(p)).join('');

    // Stop once no more unknowns
    if (!_hasUnknownPlugin(S.detailPlugins)) stopPolling();
  } catch { /* ignore transient errors */ }
}

/**
 * Light-weight dashboard poller.
 * Updates the four stat numbers in place without wiping the scan form or
 * the recent-collections table while the user might be typing.
 */
async function _pollDashboard() {
  try {
    const list = await api('GET', '/collections?limit=500');
    const stats = {
      total:     list.length,
      completed: list.filter(c => c.status === 'completed').length,
      running:   list.filter(c => c.status === 'running').length,
      failed:    list.filter(c => c.status === 'failed').length,
    };
    ['total', 'completed', 'running', 'failed'].forEach(k => {
      const el = document.getElementById(`stat-${k}`);
      if (el) el.textContent = stats[k];
    });
    if (stats.running === 0) {
      stopPolling();
      renderDashboard();   // one final render to refresh the recent table
    }
  } catch { /* ignore */ }
}


// ═══════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════

function calcThreat(indicators, plugins = []) {
  // Count phishing indicators
  const indCount = indicators
    ? Object.values(indicators).flat().length
    : 0;

  // Boost score if a TI plugin says malicious
  const pluginMalicious = plugins.some(p => p.status === 'malicious');
  const pluginSuspicious = plugins.some(p => p.status === 'suspicious');

  const count = indCount + (pluginMalicious ? 3 : 0) + (pluginSuspicious ? 1 : 0);

  if (count === 0 && !pluginMalicious && !pluginSuspicious)
    return { level:'CLEAN', bars:1, count: indCount };
  if (pluginMalicious || count > 5)
    return { level:'HIGH',   bars:10, count: indCount };
  if (count <= 2)
    return { level:'LOW',    bars:3,  count: indCount };
  return       { level:'MEDIUM', bars:6,  count: indCount };
}

function httpColor(code) {
  if (!code)       return 'var(--dim)';
  if (code < 300)  return 'var(--green)';
  if (code < 400)  return 'var(--cyan)';
  if (code < 500)  return 'var(--amber)';
  return 'var(--red)';
}

function timeAgo(ts) {
  if (!ts) return '—';
  const s = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

function fmtTs(ts) {
  if (!ts) return '—';
  return new Date(ts).toISOString().replace('T',' ').slice(0,19) + 'Z';
}

function fmtBytes(n) {
  if (n < 1024)    return `${n}B`;
  if (n < 1048576) return `${(n/1024).toFixed(1)}KB`;
  return `${(n/1048576).toFixed(1)}MB`;
}

function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}


// ═══════════════════════════════════════════════════════════════
//  TAGS & NOTES
// ═══════════════════════════════════════════════════════════════

/** Render the tag chips + inline add-input into a container element. */
function _tagsHtml(id, tags) {
  const chips = (tags || []).map(t =>
    `<span class="tag-chip">${esc(t)
    }<button class="tag-rm" data-id="${esc(id)}" data-tag="${esc(t)}"
       onclick="doRemoveTag(this)" title="Remove tag">×</button></span>`
  ).join('');
  return chips +
    `<input class="tag-input" data-id="${esc(id)}"
       placeholder="${(tags||[]).length ? 'add tag…' : 'add tag and press Enter…'}"
       onkeydown="if(event.key==='Enter'&&this.value.trim())doAddTag(this)">`;
}

async function doAddTag(input) {
  const id  = input.dataset.id;
  const tag = input.value.trim();
  if (!tag) return;
  const current = S.detail?.tags || [];
  if (current.includes(tag)) { input.value = ''; return; }
  try {
    const res = await api('PATCH', `/collections/${id}`, { tags: [...current, tag] });
    if (S.detail) S.detail.tags = res.tags;
    input.value = '';
    _refreshTags(id);
  } catch (e) { toast(e.message, 'error'); }
}

async function doRemoveTag(btn) {
  const id  = btn.dataset.id;
  const tag = btn.dataset.tag;
  const current = (S.detail?.tags || []).filter(t => t !== tag);
  try {
    const res = await api('PATCH', `/collections/${id}`, { tags: current });
    if (S.detail) S.detail.tags = res.tags;
    _refreshTags(id);
  } catch (e) { toast(e.message, 'error'); }
}

function _refreshTags(id) {
  const el = document.getElementById('tag-editor');
  if (el) el.innerHTML = _tagsHtml(id, S.detail?.tags || []);
}

async function doSaveNotes(el) {
  const id    = el.dataset.id;
  const notes = el.value || null;
  try {
    await api('PATCH', `/collections/${id}`, { notes });
    if (S.detail) S.detail.notes = notes;
    const ind = document.getElementById('notes-saved');
    if (ind) { ind.textContent = '✓ saved'; setTimeout(() => { ind.textContent = ''; }, 2500); }
  } catch (e) { toast(e.message, 'error'); }
}


// ═══════════════════════════════════════════════════════════════
//  BOOT
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  tickClock();
  setInterval(tickClock, 1000);

  checkHealth();
  setInterval(checkHealth, 30_000);

  window.addEventListener('hashchange', route);
  route();
});
