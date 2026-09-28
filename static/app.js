const SAMPLE_EVENTS = [
  'CEF:0|Fortinet|FortiGate|7.4.2|traffic-1001|Blocked outbound DNS|8|src=10.12.4.21 dst=203.0.113.77 spt=53122 dpt=53 proto=UDP act=deny rt=2026-09-29T04:12:41Z ruleName="Egress DNS Control" duser=alex.morgan',
  'LEEF:2.0|Palo Alto Networks|PAN-OS|11.1|THREAT|cat=THREAT\tsrc=10.12.8.44\tdst=198.51.100.29\tspt=49810\tdpt=443\tproto=tcp\taction=allow\tsev=3\tdevTime=2026-09-29T04:14:02Z\tusrName=svc-build\truleName=Outbound Web',
  '<134>1 2026-09-29T04:16:13Z edge-fw-03 CiscoASA - - - action=drop src=10.12.2.19 dst=192.0.2.81 spt=60123 dpt=22 proto=tcp msg="SSH policy violation"',
  '{"@timestamp":"2026-09-29T04:17:50Z","observer":{"vendor":"NetShield","product":"Branch NGFW","name":"branch-fw-02","ip":"10.0.0.254"},"source":{"ip":"10.0.2.17","port":54012},"destination":{"ip":"198.51.100.22","port":443},"network":{"protocol":"tcp","application":"tls"},"event":{"action":"allow","severity":"low","code":"TRAFFIC_ACCEPT","reason":"Matched outbound web policy"},"user":{"name":"jules.park"},"rule":{"name":"Standard web access"}}',
  'ORBIT-GW [notice] sensor=west-2 payload_signature=7f8b1a event="new firmware state observed"'
];

const $ = (selector) => document.querySelector(selector);
const state = { events: [], total: 0, offset: 0, limit: 40, selected: null, detailTab: 'normalized' };

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

function prettyTime(value) {
  if (!value) return { time: '—', date: '' };
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return { time: value, date: '' };
  return { time: date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }), date: date.toLocaleDateString([], { month: 'short', day: '2-digit' }) };
}

function sourceTitle(event) {
  const source = event.source || {};
  return [source.vendor, source.product].filter(Boolean).join(' ') || source.device_name || (source.format === 'raw' ? 'Unidentified source' : source.format || 'Unknown source');
}

function formatName(format) {
  return ({ 'syslog/cef': 'Syslog · CEF', 'syslog/leef': 'Syslog · LEEF', cef: 'CEF', leef: 'LEEF', json: 'JSON', syslog: 'Syslog', raw: 'Raw fallback' })[format] || format || 'Unknown';
}

function shortFormat(format) {
  return ({ 'syslog/cef': 'S', 'syslog/leef': 'S', cef: 'C', leef: 'L', json: '{}', syslog: 'S', raw: '↳' })[format] || '≋';
}

function statusLabel(status) {
  return ({ normalized: 'Normalized', partial: 'Partial', unparsed: 'Unparsed' })[status] || status || 'Unknown';
}

function actionClass(action) {
  const value = (action || '').toLowerCase();
  return ['deny', 'denied', 'drop', 'dropped', 'block', 'blocked', 'reject', 'rejected'].includes(value) ? 'action-deny' : ['allow', 'allowed', 'accept', 'permit', 'permitted', 'pass'].includes(value) ? 'action-allow' : 'action-other';
}

function buildFlow(event) {
  const src = event.source_endpoint || {};
  const dst = event.destination_endpoint || {};
  if (!src.ip && !dst.ip) return '<span class="flow-cell">No endpoint fields</span>';
  const left = `${escapeHtml(src.ip || src.hostname || '—')}${src.port ? `<span class="port">:${escapeHtml(src.port)}</span>` : ''}`;
  const right = `${escapeHtml(dst.ip || dst.hostname || '—')}${dst.port ? `<span class="port">:${escapeHtml(dst.port)}</span>` : ''}`;
  return `<span class="flow-cell"><span>${left}</span><span class="arrow">→</span><span>${right}</span></span>`;
}

function renderRows(append = false) {
  const body = $('#events-body');
  const rows = state.events.map((event) => {
    const when = prettyTime(event.event?.created || event.event?.ingested);
    const source = sourceTitle(event);
    const action = event.event?.action;
    const status = event.normalization?.status || 'unparsed';
    return `<tr class="event-row" data-id="${escapeHtml(event.event_id)}">
      <td><div class="event-time">${escapeHtml(when.time)}</div><div class="event-date">${escapeHtml(when.date)}</div></td>
      <td><div class="source-cell"><span class="source-mini">${escapeHtml(shortFormat(event.source?.format))}</span><span class="source-label"><strong title="${escapeHtml(source)}">${escapeHtml(source)}</strong><small>${escapeHtml(formatName(event.source?.format))}</small></span></div></td>
      <td>${buildFlow(event)}</td>
      <td>${action ? `<span class="action-pill ${actionClass(action)}">${escapeHtml(action)}</span>` : '<span class="source-label"><small>—</small></span>'}</td>
      <td><span class="status-pill status-${escapeHtml(status)}">${escapeHtml(statusLabel(status))}</span></td>
      <td class="row-chevron">›</td>
    </tr>`;
  }).join('');
  if (!state.events.length) {
    const queryActive = $('#search-input').value || $('#status-filter').value || $('#format-filter').value;
    body.innerHTML = `<tr class="empty-row"><td colspan="6"><div class="empty-state"><span class="empty-icon">⌁</span><strong>${queryActive ? 'No matching events' : 'No events yet'}</strong><span>${queryActive ? 'Try adjusting your search or filters.' : 'Load the demo bundle above or paste logs to see normalized events here.'}</span></div></td></tr>`;
  } else if (append) {
    body.insertAdjacentHTML('beforeend', rows);
  } else {
    body.innerHTML = rows;
  }
  body.querySelectorAll('.event-row').forEach((row) => row.addEventListener('click', () => selectEvent(row.dataset.id)));
  $('#result-count').textContent = `${state.total.toLocaleString()} event${state.total === 1 ? '' : 's'}`;
  $('#table-summary').textContent = state.total ? `Showing ${Math.min(state.events.length, state.total)} of ${state.total} event${state.total === 1 ? '' : 's'}` : 'Waiting for incoming events';
  $('#load-more').hidden = state.events.length >= state.total || state.total === 0;
}

function renderDetail() {
  const event = state.selected;
  if (!event) return;
  $('#event-detail').hidden = false;
  $('#detail-title').textContent = `${event.event?.action || 'Network event'}${event.event?.code ? ` · ${event.event.code}` : ''}`;
  $('#detail-subtitle').textContent = event.event_id;
  $('#detail-meta').innerHTML = `<span class="meta-chip"><strong>Source:</strong> ${escapeHtml(sourceTitle(event))}</span><span class="meta-chip"><strong>Format:</strong> ${escapeHtml(formatName(event.source?.format))}</span><span class="meta-chip"><strong>Status:</strong> ${escapeHtml(statusLabel(event.normalization?.status))}</span><span class="meta-chip"><strong>Raw SHA-256:</strong> ${escapeHtml((event.raw?.sha256 || '').slice(0, 16))}…</span>`;
  const normalized = event;
  const shown = state.detailTab === 'raw' ? event.raw?.text || '' : normalized;
  $('#detail-json').textContent = state.detailTab === 'raw' ? shown : JSON.stringify(shown, null, 2);
  document.querySelectorAll('.detail-tab').forEach((button) => button.classList.toggle('active', button.dataset.tab === state.detailTab));
}

async function selectEvent(id) {
  let event = state.events.find((item) => item.event_id === id);
  if (!event) return;
  try {
    const response = await fetch(`/api/events/${encodeURIComponent(id)}`);
    if (response.ok) event = await response.json();
  } catch (_) { /* Keep the event row's cached copy available in offline mode. */ }
  state.selected = event;
  state.detailTab = 'normalized';
  renderDetail();
  $('#event-detail').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function loadStats() {
  const response = await fetch('/api/stats');
  if (!response.ok) throw new Error('Could not read pipeline statistics');
  const stats = await response.json();
  const normalized = stats.by_status?.normalized || 0;
  $('#stat-total').textContent = stats.total.toLocaleString();
  $('#stat-normalized').innerHTML = `${normalized.toLocaleString()}<span class="stat-unit"> events</span>`;
  $('#stat-formats').textContent = Object.keys(stats.by_format || {}).length || '5';
  $('#nav-count').textContent = stats.total > 999 ? '999+' : stats.total;
  $('#normalized-share').textContent = stats.total ? `${Math.round(normalized * 100 / stats.total)}%` : '—';
  $('#format-summary').innerHTML = `<span class="stat-sub">${Object.entries(stats.by_format || {}).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([format, count]) => `${escapeHtml(formatName(format))} ${count}`).join(' · ') || '5 adapters available'}</span><span class="format-dots"><i></i><i></i><i></i></span>`;
}

function queryString(offset = 0) {
  const params = new URLSearchParams({ limit: String(state.limit), offset: String(offset) });
  const q = $('#search-input').value.trim();
  const status = $('#status-filter').value;
  const format = $('#format-filter').value;
  if (q) params.set('q', q);
  if (status) params.set('status', status);
  if (format) params.set('format', format);
  return params.toString();
}

async function loadEvents(append = false) {
  const offset = append ? state.offset : 0;
  const response = await fetch(`/api/events?${queryString(offset)}`);
  if (!response.ok) throw new Error('Could not load event stream');
  const data = await response.json();
  state.total = data.total;
  state.offset = offset + data.events.length;
  state.events = append ? [...state.events, ...data.events] : data.events;
  renderRows(append);
}

async function refresh() {
  try {
    await Promise.all([loadStats(), loadEvents(false)]);
  } catch (error) {
    console.error(error);
  }
}

function updateLineCount() {
  const count = $('#event-input').value.split(/\r?\n/).filter((line) => line.trim()).length;
  $('#line-count').textContent = `${count} event${count === 1 ? '' : 's'} ready`;
}

async function ingest() {
  const raws = $('#event-input').value.split(/\r?\n/).filter((line) => line.trim());
  const result = $('#ingest-result');
  const button = $('#ingest-button');
  if (!raws.length) {
    result.hidden = false;
    result.className = 'ingest-result error';
    result.textContent = 'Paste at least one non-empty event line first.';
    return;
  }
  button.disabled = true;
  button.querySelector('span:first-child').textContent = 'Processing…';
  result.hidden = true;
  try {
    const response = await fetch('/api/ingest', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ events: raws }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Ingestion failed');
    const normalized = data.events.filter((event) => event.normalization.status === 'normalized').length;
    result.hidden = false;
    result.className = 'ingest-result success';
    result.textContent = `Accepted ${data.accepted} event${data.accepted === 1 ? '' : 's'} · ${normalized} normalized · all raw payloads retained with SHA-256 lineage.`;
    $('#event-input').value = '';
    updateLineCount();
    await refresh();
  } catch (error) {
    result.hidden = false;
    result.className = 'ingest-result error';
    result.textContent = error.message;
  } finally {
    button.disabled = false;
    button.querySelector('span:first-child').textContent = 'Normalize events';
  }
}

function initFormatFilter() {
  const select = $('#format-filter');
  ['cef', 'leef', 'syslog', 'syslog/cef', 'syslog/leef', 'json', 'raw'].forEach((format) => {
    const option = document.createElement('option');
    option.value = format;
    option.textContent = formatName(format);
    select.append(option);
  });
}

$('#event-input').addEventListener('input', updateLineCount);
$('#load-samples').addEventListener('click', () => {
  $('#event-input').value = SAMPLE_EVENTS.join('\n');
  updateLineCount();
  $('#event-input').focus();
});
$('#clear-input').addEventListener('click', () => {
  $('#event-input').value = '';
  updateLineCount();
  $('#ingest-result').hidden = true;
});
$('#ingest-button').addEventListener('click', ingest);
$('#refresh-button').addEventListener('click', refresh);
$('#status-filter').addEventListener('change', () => loadEvents(false).catch(console.error));
$('#format-filter').addEventListener('change', () => loadEvents(false).catch(console.error));
$('#load-more').addEventListener('click', () => loadEvents(true).catch(console.error));
$('#close-detail').addEventListener('click', () => { $('#event-detail').hidden = true; state.selected = null; });
document.querySelectorAll('.detail-tab').forEach((button) => button.addEventListener('click', () => { state.detailTab = button.dataset.tab; renderDetail(); }));
$('#download-raw').addEventListener('click', () => {
  if (!state.selected) return;
  const anchor = document.createElement('a');
  anchor.href = `/api/events/${encodeURIComponent(state.selected.event_id)}/raw`;
  anchor.download = `${state.selected.event_id}.log`;
  anchor.click();
});
let searchTimer;
$('#search-input').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadEvents(false).catch(console.error), 180);
});

initFormatFilter();
updateLineCount();
refresh();
window.setInterval(refresh, 15000);
