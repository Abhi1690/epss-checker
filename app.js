(function () {
  'use strict';

  // ---------- Configuration ----------
  var API_BASE = 'https://api.first.org/data/v1/epss';
  var BATCH_SIZE = 100;          // API max rows per page
  var MAX_BULK = 2000;           // max unique CVEs per bulk run
  var MAX_FILE_BYTES = 1024 * 1024;
  var MAX_TEXT_CHARS = 40000;
  var REQUEST_TIMEOUT_MS = 20000;
  var BATCH_DELAY_MS = 300;
  var MAX_RETRIES = 3;
  var EPSS_MIN_DATE = '2021-04-14'; // first published EPSS scores

  var CVE_RE = /^CVE-(\d{4})-(\d{4,7})$/;
  var DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
  var NUM_RE = /^\d+(\.\d+)?(e-?\d+)?$/i;

  // ---------- Validation helpers ----------
  function currentYear() { return new Date().getUTCFullYear(); }

  function todayISO() { return new Date().toISOString().slice(0, 10); }

  // Returns the canonical upper-case CVE ID or null.
  function normalizeCve(raw) {
    if (typeof raw !== 'string') return null;
    var s = raw.trim().toUpperCase();
    if (s.length < 13 || s.length > 20) return null;
    var m = CVE_RE.exec(s);
    if (!m) return null;
    var year = parseInt(m[1], 10);
    if (year < 1999 || year > currentYear() + 1) return null;
    return s;
  }

  // Returns '' (no date), a valid YYYY-MM-DD string, or null (invalid).
  function validateDate(raw) {
    if (typeof raw !== 'string' || raw === '') return '';
    if (raw.length !== 10) return null;
    var m = DATE_RE.exec(raw);
    if (!m) return null;
    var d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
    if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== raw) return null;
    if (raw < EPSS_MIN_DATE || raw > todayISO()) return null;
    return raw;
  }

  function parseProbability(v) {
    if (typeof v !== 'string' && typeof v !== 'number') return null;
    var s = String(v).trim();
    if (s.length > 32 || !NUM_RE.test(s)) return null;
    var n = Number(s);
    if (!isFinite(n) || n < 0 || n > 1) return null;
    return n;
  }

  // Split free text into tokens; classify into valid (deduped) and invalid.
  function parseCveList(text) {
    var tokens = String(text).split(/[\s,;|"']+/);
    var seen = Object.create(null);
    var valid = [];
    var invalid = [];
    for (var i = 0; i < tokens.length; i++) {
      var t = tokens[i];
      if (!t) continue;
      var c = normalizeCve(t);
      if (c) {
        if (!seen[c]) { seen[c] = true; valid.push(c); }
      } else if (!/^cve$/i.test(t)) { // ignore a CSV "cve" header
        invalid.push(t.length > 30 ? t.slice(0, 30) + '…' : t);
      }
    }
    return { valid: valid, invalid: invalid };
  }

  // ---------- API ----------
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function buildUrl(cves, date) {
    var u = new URL(API_BASE);
    u.searchParams.set('cve', cves.join(','));
    u.searchParams.set('limit', String(BATCH_SIZE));
    if (date) u.searchParams.set('date', date);
    return u.toString();
  }

  async function fetchJson(url) {
    for (var attempt = 0; ; attempt++) {
      var ctrl = new AbortController();
      var timer = setTimeout(function () { ctrl.abort(); }, REQUEST_TIMEOUT_MS);
      var res;
      try {
        res = await fetch(url, {
          method: 'GET',
          mode: 'cors',
          credentials: 'omit',
          cache: 'no-store',
          redirect: 'error',
          referrerPolicy: 'no-referrer',
          headers: { 'Accept': 'application/json' },
          signal: ctrl.signal
        });
      } catch (e) {
        clearTimeout(timer);
        if (attempt < MAX_RETRIES) { await sleep(1000 * Math.pow(2, attempt)); continue; }
        throw new Error(e && e.name === 'AbortError' ? 'Request timed out.' : 'Network error contacting api.first.org.');
      }
      clearTimeout(timer);
      if ((res.status === 429 || res.status >= 500) && attempt < MAX_RETRIES) {
        await sleep(1500 * Math.pow(2, attempt));
        continue;
      }
      if (!res.ok) throw new Error('API returned HTTP ' + res.status + '.');
      var ct = res.headers.get('content-type') || '';
      if (ct.indexOf('json') === -1) throw new Error('Unexpected response type from API.');
      var text = await res.text();
      if (text.length > 5 * 1024 * 1024) throw new Error('API response too large.');
      try { return JSON.parse(text); } catch (e2) { throw new Error('Malformed JSON from API.'); }
    }
  }

  // Validates the envelope and every row; only rows for requested CVEs are kept.
  function sanitizeResponse(json, requested) {
    if (!json || typeof json !== 'object' || Array.isArray(json)) throw new Error('Unexpected API response.');
    if (json.status !== 'OK' || Number(json['status-code']) !== 200) throw new Error('API reported an error.');
    if (!Array.isArray(json.data)) throw new Error('Unexpected API response (no data).');
    var want = Object.create(null);
    requested.forEach(function (c) { want[c] = true; });
    var out = Object.create(null);
    json.data.forEach(function (row) {
      if (!row || typeof row !== 'object') return;
      var cve = normalizeCve(typeof row.cve === 'string' ? row.cve : '');
      if (!cve || !want[cve]) return;
      var epss = parseProbability(row.epss);
      var pct = parseProbability(row.percentile);
      var date = typeof row.date === 'string' && DATE_RE.test(row.date) ? row.date : '';
      if (epss === null || pct === null) return;
      out[cve] = { cve: cve, epss: epss, percentile: pct, date: date, status: 'OK' };
    });
    return out;
  }

  async function lookup(cves, date) {
    var json = await fetchJson(buildUrl(cves, date));
    return sanitizeResponse(json, cves);
  }

  // ---------- DOM helpers (text only, never innerHTML) ----------
  function $(id) { return document.getElementById(id); }

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }

  function setMsg(node, text, kind) {
    node.textContent = text || '';
    node.className = 'msg' + (kind ? ' ' + kind : '');
  }

  function fmtPct(n) { return (n * 100).toFixed(3) + '%'; }

  function riskClass(epss) {
    if (epss >= 0.5) return 'risk-critical';
    if (epss >= 0.1) return 'risk-high';
    if (epss >= 0.01) return 'risk-medium';
    return 'risk-low';
  }

  function nvdLink(cve) {
    // cve has already passed normalizeCve(), so it is safe to place in a URL path.
    var a = el('a', {
      href: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(cve),
      target: '_blank',
      rel: 'noopener noreferrer'
    }, cve);
    return a;
  }

  // ---------- Single lookup ----------
  function initSingle() {
    var form = $('single-form');
    var input = $('single-cve');
    var dateIn = $('single-date');
    var btn = $('single-btn');
    var msg = $('single-msg');
    var box = $('single-result');
    dateIn.min = EPSS_MIN_DATE;
    dateIn.max = todayISO();

    form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      box.hidden = true;
      box.replaceChildren();
      var cve = normalizeCve(input.value);
      if (!cve) {
        input.setAttribute('aria-invalid', 'true');
        setMsg(msg, 'Invalid CVE ID. Expected format CVE-YYYY-NNNN (4–7 digits).', 'error');
        return;
      }
      input.removeAttribute('aria-invalid');
      input.value = cve;
      var date = validateDate(dateIn.value);
      if (date === null) {
        setMsg(msg, 'Invalid date. Use a date between ' + EPSS_MIN_DATE + ' and today.', 'error');
        return;
      }
      btn.disabled = true;
      setMsg(msg, 'Looking up ' + cve + '…');
      try {
        var res = await lookup([cve], date);
        var r = res[cve];
        if (!r) {
          setMsg(msg, 'No EPSS score found for ' + cve + (date ? ' on ' + date : '') + '.', 'warn');
          return;
        }
        setMsg(msg, '');
        var title = el('h3');
        title.appendChild(nvdLink(r.cve));
        var grid = el('dl', { 'class': 'kv' });
        [['EPSS score', r.epss.toFixed(5) + ' (' + fmtPct(r.epss) + ')'],
         ['Percentile', r.percentile.toFixed(5) + ' (' + fmtPct(r.percentile) + ')'],
         ['Score date', r.date || '—']].forEach(function (p) {
          grid.appendChild(el('dt', null, p[0]));
          grid.appendChild(el('dd', null, p[1]));
        });
        var bar = el('div', { 'class': 'bar' });
        var fill = el('div', { 'class': 'bar-fill ' + riskClass(r.epss) });
        fill.style.width = Math.max(0.5, r.epss * 100).toFixed(2) + '%';
        bar.appendChild(fill);
        box.append(title, grid, bar);
        box.hidden = false;
      } catch (e) {
        setMsg(msg, e.message || 'Lookup failed.', 'error');
      } finally {
        btn.disabled = false;
      }
    });
  }

  // ---------- Bulk lookup ----------
  var bulkRows = [];
  var bulkMeta = { date: '' };
  var sortState = { key: null, dir: 1 };

  function renderTable() {
    var table = $('bulk-table');
    var tbody = table.tBodies[0];
    var frag = document.createDocumentFragment();
    bulkRows.forEach(function (r) {
      var tr = el('tr');
      var td = el('td');
      td.appendChild(nvdLink(r.cve));
      tr.appendChild(td);
      var tdE = el('td', { 'class': 'num' }, r.epss === null ? '—' : r.epss.toFixed(5));
      if (r.epss !== null) tdE.classList.add(riskClass(r.epss) + '-text');
      tr.appendChild(tdE);
      tr.appendChild(el('td', { 'class': 'num' }, r.percentile === null ? '—' : fmtPct(r.percentile)));
      tr.appendChild(el('td', null, r.date || '—'));
      tr.appendChild(el('td', null, r.status));
      frag.appendChild(tr);
    });
    tbody.replaceChildren(frag);
    table.hidden = bulkRows.length === 0;
  }

  function sortBy(key) {
    sortState.dir = sortState.key === key ? -sortState.dir : (key === 'epss' || key === 'percentile' ? -1 : 1);
    sortState.key = key;
    var d = sortState.dir;
    bulkRows.sort(function (a, b) {
      var x = a[key], y = b[key];
      if (x === null || x === '') return 1;
      if (y === null || y === '') return -1;
      return (x < y ? -1 : x > y ? 1 : 0) * d;
    });
    renderTable();
  }

  function initBulk() {
    var form = $('bulk-form');
    var ta = $('bulk-cves');
    var fileIn = $('bulk-file');
    var dateIn = $('bulk-date');
    var btn = $('bulk-btn');
    var dl = $('bulk-download');
    var clear = $('bulk-clear');
    var msg = $('bulk-msg');
    var prog = $('bulk-progress');
    $('bulk-max').textContent = String(MAX_BULK);
    dateIn.min = EPSS_MIN_DATE;
    dateIn.max = todayISO();

    fileIn.addEventListener('change', function () {
      var f = fileIn.files && fileIn.files[0];
      if (!f) return;
      if (f.size > MAX_FILE_BYTES) {
        setMsg(msg, 'File too large (max 1 MB).', 'error');
        fileIn.value = '';
        return;
      }
      if (!/\.(txt|csv)$/i.test(f.name)) {
        setMsg(msg, 'Only .txt or .csv files are accepted.', 'error');
        fileIn.value = '';
        return;
      }
      var reader = new FileReader();
      reader.onload = function () {
        var text = String(reader.result || '');
        // Only extract CVE-looking tokens from files; ignore everything else.
        var found = text.match(/CVE-\d{4}-\d{4,7}/gi) || [];
        var parsed = parseCveList(found.join('\n'));
        ta.value = parsed.valid.join('\n').slice(0, MAX_TEXT_CHARS);
        setMsg(msg, 'Loaded ' + parsed.valid.length + ' unique CVE ID(s) from file.', parsed.valid.length ? '' : 'warn');
        fileIn.value = '';
      };
      reader.onerror = function () { setMsg(msg, 'Could not read file.', 'error'); };
      reader.readAsText(f);
    });

    clear.addEventListener('click', function () {
      ta.value = '';
      dateIn.value = '';
      bulkRows = [];
      renderTable();
      dl.disabled = true;
      prog.hidden = true;
      setMsg(msg, '');
    });

    document.querySelectorAll('#bulk-table th button[data-sort]').forEach(function (b) {
      b.addEventListener('click', function () {
        var k = b.getAttribute('data-sort');
        if (['cve', 'epss', 'percentile', 'date', 'status'].indexOf(k) !== -1) sortBy(k);
      });
    });

    dl.addEventListener('click', function () {
      if (!bulkRows.length) return;
      try {
        var blob = buildXlsx(bulkRows, bulkMeta);
        var name = 'epss-' + (bulkMeta.date || todayISO()) + '.xlsx';
        var url = URL.createObjectURL(blob);
        var a = el('a', { href: url, download: name });
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
      } catch (e) {
        setMsg(msg, 'Could not create Excel file.', 'error');
      }
    });

    form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      if (ta.value.length > MAX_TEXT_CHARS) {
        setMsg(msg, 'Input too long (max ' + MAX_TEXT_CHARS + ' characters).', 'error');
        return;
      }
      var parsed = parseCveList(ta.value);
      if (parsed.invalid.length) {
        var shown = parsed.invalid.slice(0, 10).join(', ');
        setMsg(msg, parsed.invalid.length + ' invalid entr' + (parsed.invalid.length === 1 ? 'y' : 'ies') +
          ' — fix or remove them: ' + shown + (parsed.invalid.length > 10 ? ', …' : ''), 'error');
        ta.setAttribute('aria-invalid', 'true');
        return;
      }
      ta.removeAttribute('aria-invalid');
      if (!parsed.valid.length) { setMsg(msg, 'Enter at least one CVE ID.', 'error'); return; }
      if (parsed.valid.length > MAX_BULK) {
        setMsg(msg, 'Too many CVEs (' + parsed.valid.length + '). Max is ' + MAX_BULK + ' per run.', 'error');
        return;
      }
      var date = validateDate(dateIn.value);
      if (date === null) {
        setMsg(msg, 'Invalid date. Use a date between ' + EPSS_MIN_DATE + ' and today.', 'error');
        return;
      }

      btn.disabled = true; dl.disabled = true; clear.disabled = true;
      bulkRows = []; renderTable();
      var list = parsed.valid;
      var batches = Math.ceil(list.length / BATCH_SIZE);
      prog.max = batches; prog.value = 0; prog.hidden = false;
      var results = Object.create(null);
      var failed = Object.create(null);
      for (var i = 0; i < batches; i++) {
        var chunk = list.slice(i * BATCH_SIZE, (i + 1) * BATCH_SIZE);
        setMsg(msg, 'Fetching batch ' + (i + 1) + ' of ' + batches + '…');
        try {
          var res = await lookup(chunk, date);
          Object.keys(res).forEach(function (k) { results[k] = res[k]; });
        } catch (e) {
          chunk.forEach(function (c) { failed[c] = e.message || 'Error'; });
        }
        prog.value = i + 1;
        if (i < batches - 1) await sleep(BATCH_DELAY_MS);
      }

      var found = 0, missing = 0, errors = 0;
      bulkRows = list.map(function (c) {
        if (results[c]) { found++; return results[c]; }
        if (failed[c]) { errors++; return { cve: c, epss: null, percentile: null, date: '', status: 'Error: ' + failed[c] }; }
        missing++;
        return { cve: c, epss: null, percentile: null, date: '', status: 'Not found' };
      });
      bulkMeta = { date: date };
      sortState = { key: null, dir: 1 };
      renderTable();
      setMsg(msg, 'Done: ' + found + ' found, ' + missing + ' not found' + (errors ? ', ' + errors + ' errored' : '') + '.',
        errors ? 'warn' : '');
      btn.disabled = false; clear.disabled = false; dl.disabled = bulkRows.length === 0;
    });
  }

  // ---------- Minimal XLSX writer (no dependencies) ----------
  var CRC_TABLE = (function () {
    var t = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();

  function crc32(bytes) {
    var c = 0xFFFFFFFF;
    for (var i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  // Uncompressed ("stored") ZIP archive.
  function zip(files) {
    var enc = new TextEncoder();
    var parts = [], central = [], offset = 0;
    var now = new Date();
    var dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1);
    var dosDate = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
    files.forEach(function (f) {
      var name = enc.encode(f.name);
      var data = enc.encode(f.data);
      var crc = crc32(data);
      var lh = new DataView(new ArrayBuffer(30));
      lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true);
      lh.setUint16(8, 0, true); lh.setUint16(10, dosTime, true); lh.setUint16(12, dosDate, true);
      lh.setUint32(14, crc, true); lh.setUint32(18, data.length, true); lh.setUint32(22, data.length, true);
      lh.setUint16(26, name.length, true); lh.setUint16(28, 0, true);
      parts.push(new Uint8Array(lh.buffer), name, data);
      var ch = new DataView(new ArrayBuffer(46));
      ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true);
      ch.setUint16(8, 0x0800, true); ch.setUint16(10, 0, true); ch.setUint16(12, dosTime, true);
      ch.setUint16(14, dosDate, true); ch.setUint32(16, crc, true); ch.setUint32(20, data.length, true);
      ch.setUint32(24, data.length, true); ch.setUint16(28, name.length, true);
      ch.setUint32(42, offset, true);
      central.push(new Uint8Array(ch.buffer), name);
      offset += 30 + name.length + data.length;
    });
    var cdSize = central.reduce(function (s, p) { return s + p.length; }, 0);
    var end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true);
    end.setUint16(8, files.length, true); end.setUint16(10, files.length, true);
    end.setUint32(12, cdSize, true); end.setUint32(16, offset, true);
    return new Blob(parts.concat(central, [new Uint8Array(end.buffer)]),
      { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  }

  function xmlEsc(s) {
    return String(s)
      .replace(/[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]/g, '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
  }

  function colName(i) { return String.fromCharCode(65 + i); }

  // Strings are written as inline strings (never formulas), so CSV/formula injection is not possible.
  function strCell(ref, v, style) {
    return '<c r="' + ref + '" t="inlineStr"' + (style ? ' s="' + style + '"' : '') +
      '><is><t xml:space="preserve">' + xmlEsc(v) + '</t></is></c>';
  }
  function numCell(ref, v, style) {
    if (typeof v !== 'number' || !isFinite(v)) return '';
    return '<c r="' + ref + '"' + (style ? ' s="' + style + '"' : '') + '><v>' + v + '</v></c>';
  }

  function buildXlsx(rows, meta) {
    var headers = ['CVE', 'EPSS', 'Percentile', 'EPSS Date', 'Status'];
    var x = [];
    x.push('<row r="1">' + headers.map(function (h, i) { return strCell(colName(i) + '1', h, 1); }).join('') + '</row>');
    rows.forEach(function (r, idx) {
      var n = idx + 2;
      x.push('<row r="' + n + '">' +
        strCell('A' + n, r.cve) +
        (r.epss === null ? '' : numCell('B' + n, r.epss, 2)) +
        (r.percentile === null ? '' : numCell('C' + n, r.percentile, 3)) +
        (r.date ? strCell('D' + n, r.date) : '') +
        strCell('E' + n, r.status) + '</row>');
    });
    var last = rows.length + 1;
    var sheet = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
      '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>' +
      '<cols><col min="1" max="1" width="20" customWidth="1"/><col min="2" max="3" width="13" customWidth="1"/>' +
      '<col min="4" max="4" width="13" customWidth="1"/><col min="5" max="5" width="40" customWidth="1"/></cols>' +
      '<sheetData>' + x.join('') + '</sheetData>' +
      '<autoFilter ref="A1:E' + last + '"/></worksheet>';

    var info = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cols><col min="1" max="2" width="28" customWidth="1"/></cols><sheetData>' +
      [['Source', 'https://api.first.org/data/v1/epss'],
       ['Generated (UTC)', new Date().toISOString()],
       ['Requested score date', meta.date || 'latest'],
       ['Total CVEs', String(rows.length)]].map(function (p, i) {
        var n = i + 1;
        return '<row r="' + n + '">' + strCell('A' + n, p[0], 1) + strCell('B' + n, p[1]) + '</row>';
      }).join('') + '</sheetData></worksheet>';

    var styles = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
      '<numFmts count="2"><numFmt numFmtId="164" formatCode="0.00000"/><numFmt numFmtId="165" formatCode="0.000%"/></numFmts>' +
      '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>' +
      '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>' +
      '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
      '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
      '<cellXfs count="4"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
      '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>' +
      '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>' +
      '<xf numFmtId="165" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs>' +
      '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>';

    var workbook = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' +
      '<sheets><sheet name="EPSS" sheetId="1" r:id="rId1"/><sheet name="Info" sheetId="2" r:id="rId2"/></sheets>' +
      '<definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">EPSS!$A$1:$E$' + last + '</definedName></definedNames>' +
      '</workbook>';

    var wbRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
      '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>' +
      '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>' +
      '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' +
      '</Relationships>';

    var rootRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
      '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
      '</Relationships>';

    var ctypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
      '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
      '<Default Extension="xml" ContentType="application/xml"/>' +
      '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
      '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' +
      '<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' +
      '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
      '</Types>';

    return zip([
      { name: '[Content_Types].xml', data: ctypes },
      { name: '_rels/.rels', data: rootRels },
      { name: 'xl/workbook.xml', data: workbook },
      { name: 'xl/_rels/workbook.xml.rels', data: wbRels },
      { name: 'xl/styles.xml', data: styles },
      { name: 'xl/worksheets/sheet1.xml', data: sheet },
      { name: 'xl/worksheets/sheet2.xml', data: info }
    ]);
  }

  // ---------- Boot ----------
  // Refuse to run inside a frame (clickjacking defence; GitHub Pages cannot send X-Frame-Options).
  if (window.top !== window.self) {
    document.addEventListener('DOMContentLoaded', function () {
      document.body.replaceChildren(el('p', null, 'This page cannot be displayed inside a frame.'));
    });
    return;
  }

  document.addEventListener('DOMContentLoaded', function () {
    initSingle();
    initBulk();
  });
})();
