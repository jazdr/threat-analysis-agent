/* ThreatIntel-Agent Web UI Frontend */

const $ = id => document.getElementById(id);
const HISTORY_KEY = 'threat_intel_history';
const MAX_HISTORY = 50;
const HISTORY_ROWS_LIMIT = 200;
let queryHistory = [];
let currentHistoryId = null;
let currentResultRows = [];
let currentResultColumns = [];
let currentFilteredRows = [];
let currentTotalRowCount = 0;
let currentSort = { column: null, direction: 'asc' };
let currentQuestion = '';
let currentSql = '';
let availableTables = [];
let mentionActive = false;
let mentionStart = -1;
let mentionIndex = 0;

function escapeHtml(text) {
  if (text == null) return '';
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

function normalizeAnalysis(text) {
  return String(text || '')
    .replace(/\r\n/g, '\n')
    .replace(/\*\*/g, '')
    .trim();
}

function getHistoryStoragePayload() {
  return queryHistory.slice(0, MAX_HISTORY).map(item => ({
    ...item,
    rows: Array.isArray(item.rows) ? item.rows.slice(0, HISTORY_ROWS_LIMIT) : [],
  }));
}

function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    queryHistory = Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    console.warn('Failed to load query history', e);
    queryHistory = [];
  }
  renderHistory();
}

function saveHistory() {
  queryHistory = queryHistory.slice(0, MAX_HISTORY);
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(getHistoryStoragePayload()));
  } catch (e) {
    console.warn('History persistence skipped. Keeping in-memory history only.', e);
  }
  renderHistory();
}

function clearHistory() {
  queryHistory = [];
  currentHistoryId = null;
  try { localStorage.removeItem(HISTORY_KEY); } catch {}
  renderHistory();
}

function formatRelativeTime(ts) {
  if (!ts) return '방금 전';
  const diff = Math.max(0, Date.now() - Number(ts));
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return '방금 전';
  if (minutes < 60) return `${minutes}분 전`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}시간 전`;
  return `${Math.floor(hours / 24)}일 전`;
}

function formatTimestampSeconds(ts) {
  if (!ts) return '-';
  return new Date(Number(ts) * 1000).toLocaleString();
}

function setClearHistoryState() {
  const btn = $('clearHistoryBtn');
  if (!btn) return;
  const empty = queryHistory.length === 0;
  btn.disabled = empty;
  btn.classList.toggle('opacity-30', empty);
  btn.classList.toggle('cursor-not-allowed', empty);
}

function renderHistory() {
  const c = $('historyList');
  if (!c) return;
  c.textContent = '';
  setClearHistoryState();

  if (queryHistory.length === 0) {
    const e = document.createElement('div');
    e.className = 'text-[11px] text-slate-400 text-center py-6 leading-5';
    e.textContent = '아직 조회 기록이 없습니다. 질문을 실행하면 이곳에 기록됩니다.';
    c.appendChild(e);
    return;
  }

  queryHistory.forEach((item, idx) => {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = [
      'w-full text-left group px-2.5 py-2 rounded-lg cursor-pointer transition-colors mb-1 border',
      item.id === currentHistoryId
        ? 'bg-blue-50 border-blue-100 shadow-sm'
        : 'bg-white/50 hover:bg-slate-100 border-transparent'
    ].join(' ');
    row.onclick = () => restoreHistoryItem(idx);

    const title = document.createElement('div');
    title.className = 'text-[11px] font-semibold text-slate-700 leading-snug line-clamp-2';
    title.textContent = item.question || 'Untitled query';
    row.appendChild(title);

    const sql = document.createElement('div');
    sql.className = 'mt-1 text-[10px] text-slate-400 font-mono leading-tight line-clamp-1';
    sql.textContent = item.sql || 'SQL 없음';
    row.appendChild(sql);

    const meta = document.createElement('div');
    meta.className = 'mt-1.5 flex items-center gap-1.5 text-[10px] text-slate-400';
    const rows = document.createElement('span');
    rows.className = 'px-1.5 py-0.5 rounded bg-slate-100 text-slate-500 font-mono';
    rows.textContent = `${Number(item.rowCount || 0).toLocaleString()} rows`;
    const time = document.createElement('span');
    time.textContent = `${item.elapsed || '-'}s · ${formatRelativeTime(item.timestamp)}`;
    meta.appendChild(rows);
    meta.appendChild(time);
    row.appendChild(meta);

    c.appendChild(row);
  });
}

function addHistoryItem({ question, sql, rows, columns, analysis, elapsed, trace, verification, emptyResultCheck }) {
  const cleanAnalysis = normalizeAnalysis(analysis);
  const item = {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    question,
    sql,
    rows: Array.isArray(rows) ? rows.slice(0, HISTORY_ROWS_LIMIT) : [],
    columns: Array.isArray(columns) ? columns : [],
    rowCount: Array.isArray(rows) ? rows.length : 0,
    analysis: cleanAnalysis,
    trace: Array.isArray(trace) ? trace : [],
    verification: verification || null,
    emptyResultCheck: emptyResultCheck || null,
    elapsed,
    timestamp: Date.now(),
  };
  queryHistory = queryHistory.filter(prev => !(prev.question === question && prev.sql === sql));
  queryHistory.unshift(item);
  currentHistoryId = item.id;
  saveHistory();
}

function restoreHistoryItem(idx) {
  const item = queryHistory[idx];
  if (!item) return;
  currentHistoryId = item.id;
  $('welcome').classList.add('hidden');
  renderQuestion(item.question);
  renderSql(item.sql);
  renderTrace(item.trace || []);
  renderTrustPanel(item);
  renderResults(item.rows || [], item.columns || [], item.rowCount);
  renderAnalysis(item.analysis, item.sql, item.elapsed, item.question, item.rowCount);
  $('statusText').textContent = 'Restored';
  renderHistory();
}

async function init() {
  await loadDatabases();
  loadHistory();
}

function setQuestion(text) {
  const input = $('questionInput');
  input.value = text;
  input.focus();
  ask();
}

async function loadDatabases() {
  try {
    const res = await fetch('/api/databases');
    const data = await res.json();
    renderDbTree(data.databases || []);
  } catch (e) {
    console.error(e);
    const el = $('dbExplorer');
    el.textContent = '';
    const err = document.createElement('div');
    err.className = 'text-xs text-red-500 p-2';
    err.textContent = 'DB 로드 실패';
    el.appendChild(err);
  }
}

function metricCard(label, value, tone = 'slate') {
  const card = document.createElement('div');
  const tones = {
    green: 'border-emerald-100 bg-emerald-50 text-emerald-700',
    red: 'border-red-100 bg-red-50 text-red-700',
    blue: 'border-blue-100 bg-blue-50 text-blue-700',
    amber: 'border-amber-100 bg-amber-50 text-amber-700',
    slate: 'border-slate-200 bg-slate-50 text-slate-700',
  };
  card.className = `rounded-lg border px-3 py-2 ${tones[tone] || tones.slate}`;
  const l = document.createElement('div');
  l.className = 'text-[10px] uppercase tracking-wider opacity-70 font-bold';
  l.textContent = label;
  const v = document.createElement('div');
  v.className = 'mt-1 text-base font-bold font-mono';
  v.textContent = value;
  card.appendChild(l);
  card.appendChild(v);
  return card;
}

function toggleDashboard() {
  const section = $('dashboardSection');
  if (!section) return;
  const opening = section.classList.contains('hidden');
  section.classList.toggle('hidden', !opening);
  if (opening) loadDashboard();
}

function refreshDashboardIfOpen() {
  const section = $('dashboardSection');
  if (section && !section.classList.contains('hidden')) loadDashboard();
}

async function loadDashboard() {
  const summary = $('dashboardSummary');
  const tables = $('dashboardDbTables');
  const recent = $('dashboardRecent');
  if (!summary || !tables || !recent) return;
  summary.textContent = '';
  tables.textContent = '';
  recent.textContent = '';
  summary.appendChild(metricCard('Loading', '...', 'blue'));

  try {
    const res = await fetch('/api/dashboard');
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    renderDashboard(data);
  } catch (e) {
    summary.textContent = '';
    summary.appendChild(metricCard('Dashboard Error', 'ERR', 'red'));
    const err = document.createElement('div');
    err.className = 'text-sm text-red-600';
    err.textContent = String(e);
    recent.appendChild(err);
  }
}

function renderDashboard(data) {
  const db = data.database || {};
  const metrics = data.metrics || {};
  const limits = data.limits || {};
  const summary = $('dashboardSummary');
  summary.textContent = '';
  summary.appendChild(metricCard('DB', db.connected ? 'UP' : 'DOWN', db.connected ? 'green' : 'red'));
  summary.appendChild(metricCard('Events', Number(metrics.total_events || 0).toLocaleString(), 'blue'));
  summary.appendChild(metricCard('Success', Number(metrics.successes || 0).toLocaleString(), 'green'));
  summary.appendChild(metricCard('Failures', Number(metrics.failures || 0).toLocaleString(), metrics.failures ? 'red' : 'slate'));
  summary.appendChild(metricCard('Avg ms', Number(metrics.avg_elapsed_ms || 0).toLocaleString(), 'amber'));

  const badge = $('dashboardDbBadge');
  badge.textContent = db.connected ? 'CONNECTED' : 'DISCONNECTED';
  badge.className = 'text-[10px] font-bold rounded px-2 py-0.5 border ' + (
    db.connected ? 'bg-emerald-50 text-emerald-700 border-emerald-100' : 'bg-red-50 text-red-700 border-red-100'
  );

  const tableBox = $('dashboardDbTables');
  tableBox.textContent = '';
  const meta = document.createElement('div');
  meta.className = 'text-[11px] text-slate-500 mb-2 font-mono';
  meta.textContent = `${db.name || '-'} @ ${db.host || '-'}`;
  tableBox.appendChild(meta);
  if (db.error) {
    const err = document.createElement('div');
    err.className = 'text-[12px] text-red-600 leading-5';
    err.textContent = db.error;
    tableBox.appendChild(err);
  }
  (db.tables || []).forEach(table => {
    const row = document.createElement('div');
    row.className = 'flex items-center justify-between border-b border-slate-100 py-1.5 last:border-b-0';
    const name = document.createElement('span');
    name.className = 'text-[12px] font-mono text-slate-700';
    name.textContent = table.name;
    const count = document.createElement('span');
    count.className = 'text-[11px] font-mono text-slate-400';
    count.textContent = Number(table.row_count || 0).toLocaleString() + ' rows';
    row.appendChild(name);
    row.appendChild(count);
    tableBox.appendChild(row);
  });

  $('dashboardLimits').textContent = `limit ${limits.max_result_rows || '-'} · timeout ${limits.query_timeout_ms || '-'}ms`;

  const recent = $('dashboardRecent');
  recent.textContent = '';
  const events = metrics.recent_events || [];
  if (!events.length) {
    const empty = document.createElement('div');
    empty.className = 'text-[12px] text-slate-400 text-center py-6';
    empty.textContent = '아직 기록된 조회가 없습니다.';
    recent.appendChild(empty);
  }
  events.slice(0, 12).forEach(event => {
    const row = document.createElement('div');
    row.className = 'border-b border-slate-100 py-2 last:border-b-0';
    const top = document.createElement('div');
    top.className = 'flex items-center justify-between gap-2';
    const title = document.createElement('div');
    title.className = 'text-[12px] font-semibold text-slate-700 truncate';
    title.textContent = event.question || event.sql || event.type || 'event';
    const badge = document.createElement('span');
    badge.className = 'text-[10px] font-bold rounded px-1.5 py-0.5 border ' + (
      event.status === 'success' ? 'bg-emerald-50 text-emerald-700 border-emerald-100' : 'bg-red-50 text-red-700 border-red-100'
    );
    badge.textContent = event.status || '-';
    top.appendChild(title);
    top.appendChild(badge);
    const detail = document.createElement('div');
    detail.className = 'mt-1 text-[10px] text-slate-400 font-mono truncate';
    detail.textContent = `${event.type || '-'} · ${event.sql_source || 'manual'} · ${Number(event.row_count || 0).toLocaleString()} rows · ${event.elapsed_ms || '-'}ms · ${formatTimestampSeconds(event.ts)}`;
    row.appendChild(top);
    row.appendChild(detail);
    recent.appendChild(row);
  });
}

function renderDbTree(databases) {
  const container = $('dbExplorer');
  container.textContent = '';
  const dbCount = $('dbCount');
  if (dbCount) dbCount.textContent = String(databases.length);
  availableTables = [...new Set(databases.flatMap(db => db.tables || []))].sort();

  databases.forEach((db) => {
    const name = db.name || 'unknown';
    const tables = db.tables || [];
    const dbWrap = document.createElement('div');
    dbWrap.className = 'mb-1';

    const header = document.createElement('div');
    header.className = 'flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-gray-100 cursor-pointer select-none';
    header.innerHTML = '<svg class="w-3.5 h-3.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg><svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg><span class="text-xs font-medium text-gray-700">' + escapeHtml(name) + '</span>';
    dbWrap.appendChild(header);

    const countLabel = document.createElement('div');
    countLabel.className = 'text-[10px] text-gray-400 px-2 py-0.5';
    countLabel.textContent = tables.length + ' tables';
    dbWrap.appendChild(countLabel);

    tables.forEach(t => {
      const tRow = document.createElement('button');
      tRow.type = 'button';
      tRow.className = 'w-full flex items-center gap-2 px-2 py-1 rounded hover:bg-gray-100 text-left';
      tRow.onclick = () => setQuestion(`${t} 테이블의 주요 보안 인사이트를 요약해줘`);
      tRow.innerHTML = '<svg class="w-3.5 h-3.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg><span class="text-[11px] text-gray-600">' + escapeHtml(t) + '</span>';
      dbWrap.appendChild(tRow);
    });
    container.appendChild(dbWrap);
  });
}

function getMentionState(input) {
  const cursor = input.selectionStart ?? input.value.length;
  const before = input.value.slice(0, cursor);
  const at = before.lastIndexOf('@');
  if (at < 0) return null;
  const token = before.slice(at + 1);
  if (/\s/.test(token)) return null;
  return { at, token, cursor };
}

function handleQuestionInput(event) {
  const input = event.target;
  const state = getMentionState(input);
  if (!state) {
    hideTableMentionMenu();
    return;
  }
  mentionStart = state.at;
  mentionIndex = 0;
  const query = state.token.toLowerCase();
  const matches = availableTables
    .filter(table => table.toLowerCase().includes(query))
    .slice(0, 8);
  renderTableMentionMenu(matches);
}

function handleQuestionKeydown(event) {
  if (event.isComposing || event.keyCode === 229) return;
  if (mentionActive && ['ArrowDown', 'ArrowUp', 'Enter', 'Escape', 'Tab'].includes(event.key)) {
    const items = [...$('tableMentionMenu').querySelectorAll('button[data-table]')];
    if (event.key === 'Escape') {
      hideTableMentionMenu();
      event.preventDefault();
      return;
    }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      const delta = event.key === 'ArrowDown' ? 1 : -1;
      mentionIndex = (mentionIndex + delta + items.length) % Math.max(items.length, 1);
      highlightMentionItem();
      event.preventDefault();
      return;
    }
    if ((event.key === 'Enter' || event.key === 'Tab') && items[mentionIndex]) {
      insertMentionTable(items[mentionIndex].dataset.table);
      event.preventDefault();
      return;
    }
  }
  if (event.key === 'Enter') ask();
}

function renderTableMentionMenu(tables) {
  const menu = $('tableMentionMenu');
  if (!menu) return;
  menu.textContent = '';
  if (!tables.length) {
    const empty = document.createElement('div');
    empty.className = 'px-2 py-2 text-[11px] text-slate-400';
    empty.textContent = '일치하는 테이블이 없습니다';
    menu.appendChild(empty);
  } else {
    tables.forEach((table, idx) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.dataset.table = table;
      btn.className = 'mention-item w-full text-left px-2 py-1.5 rounded-md text-[12px] font-mono text-slate-700 hover:bg-blue-50 hover:text-blue-700';
      btn.textContent = table;
      btn.onclick = () => insertMentionTable(table);
      menu.appendChild(btn);
      if (idx === 0) btn.classList.add('bg-blue-50', 'text-blue-700');
    });
  }
  mentionActive = true;
  menu.classList.remove('hidden');
}

function highlightMentionItem() {
  const items = [...$('tableMentionMenu').querySelectorAll('button[data-table]')];
  items.forEach((item, idx) => {
    item.classList.toggle('bg-blue-50', idx === mentionIndex);
    item.classList.toggle('text-blue-700', idx === mentionIndex);
  });
}

function insertMentionTable(table) {
  const input = $('questionInput');
  const cursor = input.selectionStart ?? input.value.length;
  const before = input.value.slice(0, mentionStart);
  const after = input.value.slice(cursor);
  const insertion = table + ' ';
  input.value = before + insertion + after;
  const nextCursor = before.length + insertion.length;
  input.setSelectionRange(nextCursor, nextCursor);
  input.focus();
  hideTableMentionMenu();
}

function hideTableMentionMenu() {
  const menu = $('tableMentionMenu');
  if (menu) menu.classList.add('hidden');
  mentionActive = false;
  mentionStart = -1;
  mentionIndex = 0;
}

async function readStreamEvents(response, onEvent) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split('\n\n');
    buffer = chunks.pop() || '';
    for (const chunk of chunks) {
      const line = chunk.split('\n').find(l => l.startsWith('data: '));
      if (!line) continue;
      onEvent(JSON.parse(line.slice(6)));
    }
  }
  if (buffer.trim().startsWith('data: ')) {
    onEvent(JSON.parse(buffer.trim().slice(6)));
  }
}

function handleStreamEvent(event, context) {
  if (event.type === 'step') {
    const displayEvent = {
      step: event.step,
      status: event.status,
      reason: event.reason || event.message,
      error: event.error,
      row_count: event.row_count,
      sql: event.sql,
      sql_preview: event.sql_preview,
      detail: event.detail,
      tables: event.tables,
      columns: event.columns,
      source: event.source,
      fallback_reason: event.fallback_reason,
      attempt: event.attempt,
      message: event.message,
    };
    if (event.status !== 'started') context.trace.push(displayEvent);
    else context.trace.push(displayEvent);
    renderTrace(context.trace);
    $('statusText').textContent = event.message || traceLabel(event.step);
    if (event.step === 'analyze_results' && event.status === 'started') renderAnalysisLoading(event.message || '분석 리포트 작성 중');
    if (event.sql) renderSql(event.sql);
    return;
  }

  if (event.type === 'error') {
    const data = event.result || {};
    showError(data.error || '요청 처리 중 오류가 발생했습니다.');
    $('statusText').textContent = 'Error';
    return;
  }

  if (event.type === 'final') {
    const data = event.result || {};
    const elapsed = ((Date.now() - context.start) / 1000).toFixed(1);
    if (data.error) {
      showError(data.error);
    } else {
      $('welcome').classList.add('hidden');
      const cleanAnalysis = normalizeAnalysis(data.analysis);
      renderSql(data.sql);
      renderTrace(data.trace || context.trace);
      renderTrustPanel(data);
      renderAnalysis(cleanAnalysis, data.sql, elapsed, context.question, Array.isArray(data.rows) ? data.rows.length : 0);
      renderResults(data.rows, data.columns);
      addHistoryItem({
        question: context.question,
        sql: data.sql,
        rows: data.rows,
        columns: data.columns,
        analysis: cleanAnalysis,
        elapsed,
        trace: data.trace || context.trace,
        verification: data.verification,
        emptyResultCheck: data.empty_result_check,
      });
      $('statusText').textContent = 'Done ' + elapsed + 's';
      refreshDashboardIfOpen();
    }
  }
}

async function ask() {
  const input = $('questionInput');
  const question = input.value.trim();
  if (!question) return;

  hideTableMentionMenu();
  input.value = '';
  showLoading(true);
  hideResults();
  $('welcome').classList.add('hidden');

  const context = { question, start: Date.now(), trace: [] };
  renderQuestion(question);
  $('statusText').textContent = 'SQL 생성 중...';
  renderTrace([{ step: 'generate_sql', status: 'started', reason: 'SQL 생성 중' }]);

  try {
    const res = await fetch('/api/query/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
    });

    if (!res.ok || !res.body) {
      throw new Error('stream endpoint failed: ' + res.status);
    }

    await readStreamEvents(res, event => handleStreamEvent(event, context));
  } catch (e) {
    showError('요청 실패: ' + String(e));
    $('statusText').textContent = 'Error';
  } finally {
    showLoading(false);
  }
}

function toggleSqlConsole() {
  const body = $('sqlConsoleBody');
  const label = $('sqlConsoleToggle');
  const opening = body.classList.contains('hidden');
  body.classList.toggle('hidden', !opening);
  label.textContent = opening ? '닫기' : '열기';
  if (opening) $('sqlConsoleInput').focus();
}

async function executeRawSql() {
  const input = $('sqlConsoleInput');
  const sql = input.value.trim();
  if (!sql) return;

  showLoading(true);
  hideResults();
  $('welcome').classList.add('hidden');
  renderQuestion('직접 SQL 실행');
  renderSql(sql);
  $('statusText').textContent = 'SQL 실행 중...';

  try {
    const res = await fetch('/api/sql/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sql }),
    });
    const data = await res.json();
    if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);
    renderTrace([{ step: 'execute_sql', status: 'ok', reason: '직접 입력한 SQL을 안전 검증 후 실행했습니다.', row_count: data.row_count }]);
    renderResults(data.rows || [], data.columns || [], data.row_count);
    $('analysisContent').textContent = '';
    const msg = document.createElement('div');
    msg.className = 'text-sm text-slate-500 text-center py-10';
    msg.textContent = '직접 실행한 SQL 결과입니다. 분석 리포트는 자연어 질문 실행 시 생성됩니다.';
    $('analysisContent').appendChild(msg);
    $('statusText').textContent = `SQL Done · ${Number(data.row_count || 0).toLocaleString()} rows`;
    refreshDashboardIfOpen();
  } catch (e) {
    showError(String(e).replace(/^Error:\s*/, ''));
    $('statusText').textContent = 'SQL Error';
  } finally {
    showLoading(false);
  }
}

function showError(msg) {
  const content = $('analysisContent');
  content.textContent = '';

  const wrap = document.createElement('div');
  wrap.className = 'flex items-start gap-3';

  const icon = document.createElement('div');
  icon.className = 'w-5 h-5 rounded-full bg-red-100 flex items-center justify-center shrink-0 mt-0.5';
  icon.innerHTML = '<svg class="w-3 h-3 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>';
  wrap.appendChild(icon);

  const body = document.createElement('div');
  const title = document.createElement('div');
  title.className = 'text-[11px] font-semibold text-red-700 uppercase tracking-wider mb-1';
  title.textContent = 'Error';
  body.appendChild(title);

  const desc = document.createElement('div');
  desc.className = 'text-sm text-red-600 leading-relaxed';
  desc.textContent = msg;
  body.appendChild(desc);

  wrap.appendChild(body);
  content.appendChild(wrap);
}

function renderQuestion(question) {
  const section = $('questionSection');
  const text = $('queryQuestion');
  if (!section || !text) return;
  text.textContent = question || '';
  currentQuestion = question || '';
  section.classList.toggle('hidden', !question);
}

function formatSqlForDisplay(sql) {
  if (!sql) return '';
  let formatted = String(sql).trim().replace(/\s+/g, ' ');
  formatted = formatted
    .replace(/\s+(FROM)\s+/i, '\n$1 ')
    .replace(/\s+(WHERE)\s+/i, '\n$1 ')
    .replace(/\s+(GROUP\s+BY)\s+/i, '\n$1 ')
    .replace(/\s+(ORDER\s+BY)\s+/i, '\n$1 ')
    .replace(/\s+(HAVING)\s+/i, '\n$1 ')
    .replace(/\s+(LIMIT)\s+/i, '\n$1 ')
    .replace(/\s+(WITH)\s+/i, '\n$1 ')
    .replace(/\s+(JOIN|LEFT\s+JOIN|RIGHT\s+JOIN|INNER\s+JOIN|FULL\s+JOIN)\s+/ig, '\n$1 ')
    .replace(/\s+(AND|OR)\s+/ig, '\n  $1 ');
  if (!formatted.endsWith(';')) formatted += ';';
  return formatted;
}

function escapeSqlHtml(text) {
  if (text == null) return '';
  return String(text).replace(/[&<>]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[m]));
}

function highlightSql(sql) {
  const escaped = escapeSqlHtml(formatSqlForDisplay(sql));
  return escaped
    .replace(/('[^']*')/g, '<span class="sql-string">$1</span>')
    .replace(/\b(SELECT|FROM|WHERE|GROUP BY|ORDER BY|HAVING|LIMIT|WITH|JOIN|LEFT JOIN|RIGHT JOIN|INNER JOIN|FULL JOIN|ON|AND|OR|AS|DISTINCT|COUNT|AVG|ROUND|MIN|MAX|SUM|ROW_NUMBER|OVER|PARTITION BY)\b/g, match => {
      const cls = /^(COUNT|AVG|ROUND|MIN|MAX|SUM|ROW_NUMBER)$/i.test(match) ? 'sql-function' : 'sql-keyword';
      return `<span class="${cls}">${match}</span>`;
    })
    .replace(/\b(\d+(?:\.\d+)?)\b/g, '<span class="sql-number">$1</span>');
}

function renderSql(sql) {
  if (!sql) return;
  currentSql = sql;
  $('welcome').classList.add('hidden');
  $('sqlSection').classList.remove('hidden');
  const code = $('sqlCode');
  code.innerHTML = highlightSql(sql);
}

function extractTables(sql) {
  const matches = String(sql || '').matchAll(/\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_.]*)/gi);
  return [...new Set([...matches].map(m => m[1].replace(/^public\./, '')))];
}

function renderTrustPanel(data) {
  const section = $('trustSection');
  if (!section || !data) return;
  const verification = data.verification || {};
  const emptyCheck = data.emptyResultCheck || data.empty_result_check || {};
  const valid = verification.valid === true;
  const corrected = Array.isArray(data.trace) && data.trace.some(step => step.status === 'corrected');
  const badge = $('trustBadge');
  badge.textContent = corrected ? 'CORRECTED' : valid ? 'VERIFIED' : 'NEEDS REVIEW';
  badge.className = 'text-[10px] font-bold rounded px-2 py-0.5 border ' + (
    corrected
      ? 'bg-amber-50 text-amber-700 border-amber-100'
      : valid
        ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
        : 'bg-slate-50 text-slate-600 border-slate-200'
  );
  $('trustTables').textContent = extractTables(data.sql).join(', ') || '확인된 테이블 없음';
  $('trustReason').textContent = verification.reason || '검증 메타데이터가 없습니다.';
  $('trustFallback').textContent = emptyCheck.reason
    ? `${emptyCheck.retried ? 'Fallback 재조회 수행' : 'Fallback 없음'} · ${emptyCheck.reason}`
    : '결과 보정 정보가 없습니다.';
  section.classList.remove('hidden');
}

function formatCellValue(value) {
  if (value === null || value === undefined) return null;
  return String(value);
}

function traceLabel(step) {
  const labels = {
    generate_sql: 'SQL 생성',
    verify_sql: '의도 검증',
    execute_sql: 'SQL 실행',
    execution_error: '실행 오류',
    regenerate_sql: 'SQL 재생성',
    empty_result_check: '빈 결과 검증',
    analyze_results: '답변 생성',
  };
  return labels[step] || step || 'step';
}

function traceStatusText(status) {
  const labels = {
    ok: 'OK',
    passed: 'PASSED',
    corrected: 'CORRECTED',
    retrying: 'RETRYING',
    retried: 'RETRIED',
    failed: 'FAILED',
    fallback_failed: 'FAILED',
    not_retried: 'CHECKED',
    skipped: 'SKIPPED',
    needs_review: 'REVIEW',
    started: 'RUNNING',
  };
  return labels[status] || String(status || 'OK').toUpperCase();
}

function traceMetaItems(item) {
  const meta = [];
  if (item.source) meta.push(`source: ${item.source}`);
  if (item.attempt) meta.push(`attempt ${item.attempt}`);
  if (Array.isArray(item.tables) && item.tables.length) meta.push(`tables: ${item.tables.slice(0, 4).join(', ')}`);
  if (item.row_count !== undefined) meta.push(`${Number(item.row_count || 0).toLocaleString()} rows`);
  if (Array.isArray(item.columns) && item.columns.length) meta.push(`${item.columns.length} columns`);
  if (item.fallback_reason) meta.push(`fallback: ${item.fallback_reason}`);
  return meta;
}

function renderTrace(trace) {
  const section = $('traceSection');
  const list = $('traceList');
  if (!section || !list) return;
  list.textContent = '';
  if (!Array.isArray(trace) || trace.length === 0) {
    section.classList.add('hidden');
    return;
  }

  section.classList.remove('hidden');
  trace.forEach((item, idx) => {
    const card = document.createElement('div');
    const status = item.status || 'ok';
    const tone = status.includes('fail') || status.includes('error')
      ? 'border-red-100 bg-red-50 text-red-700'
      : status.includes('correct') || status.includes('retry')
        ? 'border-amber-100 bg-amber-50 text-amber-700'
        : 'border-slate-200 bg-slate-50 text-slate-700';
    card.className = `rounded-lg border px-3 py-2 ${tone}`;

    const header = document.createElement('div');
    header.className = 'flex items-center justify-between gap-2';

    const title = document.createElement('div');
    title.className = 'text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 min-w-0';
    title.textContent = `${idx + 1}. ${traceLabel(item.step)}`;
    header.appendChild(title);

    const statusBadge = document.createElement('span');
    statusBadge.className = 'shrink-0 rounded border border-current/15 bg-white/70 px-1.5 py-0.5 text-[9px] font-bold';
    statusBadge.textContent = traceStatusText(status);
    header.appendChild(statusBadge);
    card.appendChild(header);

    const desc = document.createElement('div');
    desc.className = 'mt-1 text-[11px] leading-4 text-slate-500';
    desc.textContent = item.detail || item.reason || item.error || `${status}${item.row_count !== undefined ? ` · ${item.row_count} rows` : ''}`;
    card.appendChild(desc);

    const metaItems = traceMetaItems(item);
    if (metaItems.length) {
      const meta = document.createElement('div');
      meta.className = 'mt-2 flex flex-wrap gap-1';
      metaItems.forEach(value => {
        const chip = document.createElement('span');
        chip.className = 'rounded border border-current/10 bg-white/60 px-1.5 py-0.5 text-[10px] leading-4 text-slate-500';
        chip.textContent = value;
        meta.appendChild(chip);
      });
      card.appendChild(meta);
    }

    const sqlPreview = item.sql_preview || item.sql;
    if (sqlPreview && item.step !== 'execute_sql') {
      const code = document.createElement('pre');
      code.className = 'mt-2 max-h-20 overflow-auto rounded border border-slate-200 bg-white/70 px-2 py-1.5 text-[10px] leading-4 text-slate-600';
      code.textContent = formatSqlForDisplay(sqlPreview);
      card.appendChild(code);
    }

    if (item.error) {
      const error = document.createElement('div');
      error.className = 'mt-2 rounded border border-red-100 bg-white/70 px-2 py-1.5 text-[10px] leading-4 text-red-600';
      error.textContent = item.error;
      card.appendChild(error);
    }
    list.appendChild(card);
  });
}

function renderResults(rows, columns, totalRowCount) {
  if (!rows || !columns) return;
  $('resultSection').classList.remove('hidden');
  currentResultRows = Array.isArray(rows) ? rows : [];
  currentResultColumns = Array.isArray(columns) ? columns : [];
  currentTotalRowCount = Number(totalRowCount ?? currentResultRows.length ?? 0);
  currentSort = { column: null, direction: 'asc' };
  const filter = $('resultFilter');
  if (filter) filter.value = '';
  const detail = $('rowDetail');
  if (detail) detail.classList.add('hidden');

  renderResultTable(currentResultRows);
}

function compareCellValues(a, b) {
  const aNum = Number(a);
  const bNum = Number(b);
  if (a !== null && b !== null && !Number.isNaN(aNum) && !Number.isNaN(bNum)) return aNum - bNum;
  return String(a ?? '').localeCompare(String(b ?? ''), 'ko');
}

function getVisibleResultRows() {
  const term = (($('resultFilter') && $('resultFilter').value) || '').trim().toLowerCase();
  let rows = currentResultRows;
  if (term) {
    rows = rows.filter(row => currentResultColumns.some(col => String(row[col] ?? '').toLowerCase().includes(term)));
  }
  if (currentSort.column) {
    rows = [...rows].sort((a, b) => {
      const cmp = compareCellValues(a[currentSort.column], b[currentSort.column]);
      return currentSort.direction === 'asc' ? cmp : -cmp;
    });
  }
  currentFilteredRows = rows;
  return rows;
}

function renderResultTable() {
  const rows = getVisibleResultRows();
  const columns = currentResultColumns;

  const head = $('resultHead');
  head.textContent = '';
  columns.forEach(c => {
    const th = document.createElement('th');
    th.className = 'px-3 py-2 whitespace-nowrap border-b border-gray-200 text-[11px] font-semibold text-slate-600 bg-slate-50 cursor-pointer select-none hover:text-blue-700';
    th.title = '정렬';
    const marker = currentSort.column === c ? (currentSort.direction === 'asc' ? ' ↑' : ' ↓') : '';
    th.textContent = c + marker;
    th.onclick = () => setResultSort(c);
    head.appendChild(th);
  });

  const body = $('resultBody');
  body.textContent = '';
  rows.slice(0, 200).forEach((row, idx) => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-blue-50 cursor-pointer';
    tr.onclick = () => showRowDetail(row, idx);
    columns.forEach(c => {
      const td = document.createElement('td');
      td.className = 'px-3 py-2 border-b border-gray-100 text-[12px] align-top min-w-[140px] max-w-[320px] whitespace-normal break-words';
      td.style.overflowWrap = 'anywhere';
      td.style.wordBreak = 'break-word';
      const val = formatCellValue(row[c]);
      if (val === null) {
        const span = document.createElement('span');
        span.className = 'text-gray-300 italic';
        span.textContent = 'NULL';
        td.appendChild(span);
      } else {
        td.textContent = val;
        td.title = val;
      }
      tr.appendChild(td);
    });
    body.appendChild(tr);
  });

  const visible = rows.length;
  const total = currentTotalRowCount || currentResultRows.length;
  const filtered = visible !== currentResultRows.length ? ` · ${visible.toLocaleString()} matched` : '';
  $('rowCount').textContent = total.toLocaleString() + ' rows' + filtered + (visible > 200 ? ' (showing first 200)' : '');
}

function setResultSort(column) {
  if (currentSort.column === column) {
    currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
  } else {
    currentSort = { column, direction: 'asc' };
  }
  renderResultTable();
}

function applyResultFilter() {
  renderResultTable();
}

function showRowDetail(row, idx) {
  const detail = $('rowDetail');
  if (!detail) return;
  detail.textContent = '';
  detail.classList.remove('hidden');

  const header = document.createElement('div');
  header.className = 'flex items-center justify-between mb-2';
  const title = document.createElement('div');
  title.className = 'text-[10px] font-bold text-slate-500 uppercase tracking-wider';
  title.textContent = `Row Detail #${idx + 1}`;
  const copy = document.createElement('button');
  copy.className = 'text-[10px] text-blue-600 hover:text-blue-700 font-medium';
  copy.textContent = 'JSON 복사';
  copy.onclick = () => navigator.clipboard.writeText(JSON.stringify(row, null, 2));
  header.appendChild(title);
  header.appendChild(copy);
  detail.appendChild(header);

  const grid = document.createElement('div');
  grid.className = 'grid grid-cols-1 md:grid-cols-2 gap-2';
  currentResultColumns.forEach(col => {
    const item = document.createElement('div');
    item.className = 'rounded border border-slate-200 bg-white px-2 py-1.5';
    const label = document.createElement('div');
    label.className = 'text-[10px] font-mono text-slate-400 mb-0.5';
    label.textContent = col;
    const value = document.createElement('div');
    value.className = 'text-[12px] text-slate-700 break-words';
    value.textContent = formatCellValue(row[col]) ?? 'NULL';
    item.appendChild(label);
    item.appendChild(value);
    grid.appendChild(item);
  });
  detail.appendChild(grid);
}

function csvCell(value) {
  const text = value == null ? '' : String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function exportResultsCsv() {
  const rows = currentFilteredRows.length ? currentFilteredRows : getVisibleResultRows();
  if (!rows.length || !currentResultColumns.length) return;
  const lines = [
    currentResultColumns.map(csvCell).join(','),
    ...rows.map(row => currentResultColumns.map(col => csvCell(row[col])).join(',')),
  ];
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `threat-intel-results-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function _parseMdBlock(container, text) {
  const lines = String(text || '').split('\n');
  let currentUl = null;
  let currentOl = null;
  const flushList = () => {
    if (currentUl) { container.appendChild(currentUl); currentUl = null; }
    if (currentOl) { container.appendChild(currentOl); currentOl = null; }
  };

  lines.forEach(line => {
    const trimmed = line.trim();
    if (!trimmed) { flushList(); return; }

    const headingMatch = trimmed.match(/^#{1,4}\s+(.*)$/) || trimmed.match(/^(요약|핵심 인사이트|주의 신호|우선 대응|권장 조치|후속 조회|추가 확인)\s*:?$/);
    if (headingMatch) {
      flushList();
      const h = document.createElement('div');
      h.className = 'mt-4 first:mt-0 mb-2 text-[11px] font-bold text-slate-500 uppercase tracking-wider';
      h.textContent = headingMatch[1] || headingMatch[0].replace(/:$/, '');
      container.appendChild(h);
      return;
    }

    const bulletMatch = trimmed.match(/^[-•‣◦]\s+(.*)$/);
    if (bulletMatch) {
      if (!currentUl) { currentUl = document.createElement('ul'); currentUl.className = 'list-disc pl-5 mb-3 space-y-1.5'; }
      const li = document.createElement('li');
      li.className = 'text-[13px] text-slate-700 leading-6';
      _mdInline(li, bulletMatch[1]);
      currentUl.appendChild(li);
      return;
    }

    const numMatch = trimmed.match(/^\d+\.\s+(.*)$/);
    if (numMatch) {
      if (!currentOl) { currentOl = document.createElement('ol'); currentOl.className = 'list-decimal pl-5 mb-3 space-y-1.5'; }
      const li = document.createElement('li');
      li.className = 'text-[13px] text-slate-700 leading-6';
      _mdInline(li, numMatch[1]);
      currentOl.appendChild(li);
      return;
    }

    flushList();
    const p = document.createElement('p');
    p.className = 'mb-2 text-[13px] text-slate-700 leading-6';
    _mdInline(p, trimmed);
    container.appendChild(p);
  });
  flushList();
}

function _mdInline(el, text) {
  const cleanText = String(text || '').replace(/\*\*/g, '');
  const pattern = /(`([^`]+)`|\b(CVE-\d{4}-\d{4,})\b|\b(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?%?)\b)/g;
  let lastIndex = 0;
  let m;
  while ((m = pattern.exec(cleanText)) !== null) {
    if (m.index > lastIndex) el.appendChild(document.createTextNode(cleanText.slice(lastIndex, m.index)));
    if (m[2]) {
      const code = document.createElement('code');
      code.className = 'px-1 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[12px]';
      code.textContent = m[2];
      el.appendChild(code);
    } else if (m[3]) {
      const strong = document.createElement('strong');
      strong.className = 'font-semibold text-blue-700';
      strong.textContent = m[3];
      el.appendChild(strong);
    } else {
      const strong = document.createElement('strong');
      strong.className = 'font-semibold text-slate-900';
      strong.textContent = m[4];
      el.appendChild(strong);
    }
    lastIndex = pattern.lastIndex;
  }
  if (lastIndex < cleanText.length) el.appendChild(document.createTextNode(cleanText.slice(lastIndex)));
}

function detectSeverity(analysis) {
  const lower = String(analysis || '').toLowerCase();
  if (/critical|severe|high|심각|높음|위험|긴급|랜섬웨어|악용/.test(lower)) return 'critical';
  if (/medium|moderate|중간|보통|주의/.test(lower)) return 'warning';
  if (/low|minor|낮음|약함/.test(lower)) return 'low';
  return 'info';
}

function createSeverityBadge(severity) {
  const badge = document.createElement('span');
  const base = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-bold border';
  const dot = document.createElement('span');
  dot.className = 'w-1.5 h-1.5 rounded-full';
  if (severity === 'critical') {
    badge.className = `${base} bg-red-50 text-red-700 border-red-100`;
    badge.appendChild(dot); dot.classList.add('bg-red-500'); badge.append(' HIGH RISK');
  } else if (severity === 'warning') {
    badge.className = `${base} bg-amber-50 text-amber-700 border-amber-100`;
    badge.appendChild(dot); dot.classList.add('bg-amber-500'); badge.append(' MEDIUM RISK');
  } else if (severity === 'low') {
    badge.className = `${base} bg-emerald-50 text-emerald-700 border-emerald-100`;
    badge.appendChild(dot); dot.classList.add('bg-emerald-500'); badge.append(' LOW RISK');
  } else {
    badge.className = `${base} bg-blue-50 text-blue-700 border-blue-100`;
    badge.appendChild(dot); dot.classList.add('bg-blue-500'); badge.append(' INFO');
  }
  return badge;
}

function extractMetricCards(analysis, rowCount) {
  const cards = [];
  if (Number(rowCount) > 0) cards.push({ label: '조회 결과', value: Number(rowCount).toLocaleString(), tone: 'blue' });
  const cveCount = (analysis.match(/CVE-\d{4}-\d{4,}/g) || []).length;
  if (cveCount) cards.push({ label: '언급 CVE', value: String(cveCount), tone: 'slate' });
  if (/랜섬웨어|ransomware/i.test(analysis)) cards.push({ label: '랜섬웨어 악용', value: '확인 필요', tone: 'red' });
  if (/RCE|원격 코드|remote code/i.test(analysis)) cards.push({ label: 'RCE 신호', value: '주의', tone: 'amber' });
  return cards.slice(0, 4);
}

function renderMetricCards(content, cards) {
  if (!cards.length) return;
  const grid = document.createElement('div');
  grid.className = 'grid grid-cols-2 md:grid-cols-4 gap-2 mb-4';
  cards.forEach(card => {
    const box = document.createElement('div');
    const tone = card.tone === 'red' ? 'border-red-100 bg-red-50 text-red-700' : card.tone === 'amber' ? 'border-amber-100 bg-amber-50 text-amber-700' : 'border-slate-200 bg-slate-50 text-slate-700';
    box.className = `rounded-lg border px-3 py-2 ${tone}`;
    const label = document.createElement('div');
    label.className = 'text-[10px] uppercase tracking-wider opacity-70 font-bold';
    label.textContent = card.label;
    const value = document.createElement('div');
    value.className = 'mt-1 text-sm font-bold';
    value.textContent = card.value;
    box.appendChild(label);
    box.appendChild(value);
    grid.appendChild(box);
  });
  content.appendChild(grid);
}

function buildFallbackSections(analysis) {
  const sentences = analysis.split(/(?<=[.!?。]|다\.)\s+/).map(s => s.trim()).filter(Boolean);
  if (sentences.length <= 1) return analysis;
  const summary = sentences.slice(0, 2).join(' ');
  const details = sentences.slice(2, 6);
  return ['요약', summary, '', '핵심 인사이트', ...details.map(s => `- ${s}`)].join('\n');
}

function renderAnalysisLoading(message = '분석 리포트 작성 중') {
  const content = $('analysisContent');
  if (!content) return;
  content.textContent = '';
  const wrap = document.createElement('div');
  wrap.className = 'rounded-xl border border-blue-100 bg-blue-50/70 p-5 flex items-center gap-3';
  const spinner = document.createElement('div');
  spinner.className = 'w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin shrink-0';
  const text = document.createElement('div');
  const title = document.createElement('div');
  title.className = 'text-sm font-semibold text-blue-700';
  title.textContent = message;
  const desc = document.createElement('div');
  desc.className = 'text-[12px] text-blue-500 mt-0.5';
  desc.textContent = '조회 결과를 기반으로 보안 인사이트와 우선 대응 항목을 생성하고 있습니다.';
  text.appendChild(title);
  text.appendChild(desc);
  wrap.appendChild(spinner);
  wrap.appendChild(text);
  content.appendChild(wrap);
}

function renderAnalysis(analysis, sql, elapsed, question, rowCount) {
  if (!analysis) return;
  const cleanAnalysis = normalizeAnalysis(analysis);
  const content = $('analysisContent');
  content.textContent = '';
  $('reportMeta').textContent = (question ? question.substring(0,45) + (question.length>45?'...':'') : '') + ' | ' + elapsed + 's';

  const top = document.createElement('div');
  top.className = 'flex flex-wrap items-center justify-between gap-2 mb-4';
  top.appendChild(createSeverityBadge(detectSeverity(cleanAnalysis)));
  const meta = document.createElement('div');
  meta.className = 'text-[10px] text-slate-400 font-mono';
  meta.textContent = `SQL ${sql ? sql.length : 0} chars · Elapsed ${elapsed}s`;
  top.appendChild(meta);
  content.appendChild(top);

  renderMetricCards(content, extractMetricCards(cleanAnalysis, rowCount));

  const report = document.createElement('div');
  report.className = 'bg-white border border-slate-200 rounded-xl p-4';
  _parseMdBlock(report, /요약|핵심 인사이트|우선 대응|권장 조치|후속 조회/.test(cleanAnalysis) ? cleanAnalysis : buildFallbackSections(cleanAnalysis));
  content.appendChild(report);
}

function hideResults() {
  $('questionSection').classList.add('hidden');
  $('sqlSection').classList.add('hidden');
  $('traceSection').classList.add('hidden');
  $('trustSection').classList.add('hidden');
  $('resultSection').classList.add('hidden');
  const detail = $('rowDetail');
  if (detail) detail.classList.add('hidden');
  const content = $('analysisContent');
  content.textContent = '';

  const empty = document.createElement('div');
  empty.className = 'text-sm text-slate-400 text-center py-10';
  empty.innerHTML = '<svg class="w-8 h-8 mx-auto mb-3 text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg><div>분석 의견이 여기에 표시됩니다</div><div class="text-[11px] text-slate-300 mt-1">natural language query will produce an intelligence report</div>';
  content.appendChild(empty);
}

function showLoading(show) {
  const el = $('loading');
  const btn = $('sendBtn');
  if (show) {
    el.classList.remove('hidden');
    btn.disabled = true;
    btn.classList.add('opacity-50');
  } else {
    el.classList.add('hidden');
    btn.disabled = false;
    btn.classList.remove('opacity-50');
  }
}

function copySql() {
  const sql = $('sqlCode').textContent;
  if (!sql) return;
  navigator.clipboard.writeText(sql).then(() => {
    const btn = document.querySelector('#sqlSection button');
    const orig = btn.textContent;
    btn.textContent = '복사됨';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

async function trainCurrentSql() {
  if (!currentQuestion || !currentSql) return;
  try {
    const res = await fetch('/api/training/sql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: currentQuestion, sql: currentSql }),
    });
    const data = await res.json();
    $('statusText').textContent = data.trained ? 'Vanna trained' : 'Training failed';
    if (!data.trained) showError(data.error || data.message || 'Vanna 학습 실패');
  } catch (e) {
    showError('Vanna 학습 요청 실패: ' + String(e));
  }
}

init();
