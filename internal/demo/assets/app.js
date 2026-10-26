// Verdict public demo — the prism hero, the scan form, and the signal
// readout. Served as a file rather than inline so the demo's CSP can keep
// script-src to 'self' + Cloudflare (Turnstile) with no 'unsafe-inline'.
//
// Everything rendered from a scan goes through textContent / createElement,
// never innerHTML: findings carry text scraped from arbitrary third-party
// pages (titles, header values), so they're treated as hostile.
(function () {
  'use strict';

  var SVGNS = 'http://www.w3.org/2000/svg';
  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  // Order is shared by the prism beams (top to bottom), the legend, and the
  // result panels (left to right), so a colour means the same thing everywhere.
  var MODULES = [
    { id: 'security', name: 'Security', cls: 'sig-sec' },
    { id: 'seo', name: 'SEO', cls: 'sig-seo' },
    { id: 'geo', name: 'GEO', cls: 'sig-geo' }
  ];

  function h(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function s(tag, attrs) {
    var n = document.createElementNS(SVGNS, tag);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  }

  // ---------------------------------------------------------------- prism --

  function sinePath(from, to, wl, amp, phase) {
    var d = '';
    for (var x = from; x <= to + 0.001; x += 3) {
      var y = amp * Math.sin((x / wl) * 2 * Math.PI + phase);
      d += (d ? 'L' : 'M') + x.toFixed(1) + ',' + y.toFixed(2);
    }
    return d;
  }

  // Each beam is drawn in its own rotated frame: a clipped window [0, len]
  // over a braided sine that is one wavelength longer, translated by exactly
  // one wavelength per cycle — a seamless loop animated on transform only.
  function drawBeam(root, defs, b, i) {
    var clipId = 'beam-clip-' + i;
    var cp = s('clipPath', { id: clipId, clipPathUnits: 'userSpaceOnUse' });
    cp.appendChild(s('rect', { x: 0, y: -b.amp * 3, width: b.len, height: b.amp * 6 }));
    defs.appendChild(cp);

    var g = s('g', { transform: 'translate(' + b.x + ' ' + b.y + ') rotate(' + b.angle + ')', 'class': 'beam ' + b.cls });
    var clip = s('g', { 'clip-path': 'url(#' + clipId + ')', filter: 'url(#glow)' });
    var flow = s('g', { 'class': 'flow' });
    flow.style.setProperty('--wl', b.wl + 'px');
    flow.style.setProperty('--dur', (b.wl / 22).toFixed(2) + 's');
    [[1, 0], [0.82, 0.55], [1.18, 1.1]].forEach(function (strand) {
      flow.appendChild(s('path', { 'class': 'strand', d: sinePath(-b.wl, b.len, b.wl, b.amp * strand[0], strand[1]) }));
    });
    clip.appendChild(flow);
    g.appendChild(clip);
    root.appendChild(g);
  }

  function drawPrism() {
    var fig = document.getElementById('prism');
    var root = document.getElementById('beams');
    var defs = fig.querySelector('defs');
    // Geometry matches the static polygon in index.html: the white beam meets
    // the left face at (436,192); the coloured beams leave the right face at
    // (551,162).
    var beams = [
      { x: 0, y: 251, angle: -7.8, len: 440, wl: 40, amp: 12, cls: 'sig-in' },
      { x: 551, y: 162, angle: -15, len: 520, wl: 30, amp: 11, cls: 'sig-sec' },
      { x: 551, y: 162, angle: -1.5, len: 520, wl: 46, amp: 14, cls: 'sig-seo' },
      { x: 551, y: 162, angle: 13, len: 520, wl: 22, amp: 8, cls: 'sig-geo' }
    ];
    beams.forEach(function (b, i) { drawBeam(root, defs, b, i); });

    // Don't burn a blur filter's worth of GPU on an animation nobody can see.
    if ('IntersectionObserver' in window) {
      new IntersectionObserver(function (entries) {
        fig.classList.toggle('is-paused', !entries[0].isIntersecting);
      }).observe(fig);
    }
  }

  // --------------------------------------------------------------- traces --

  // Deterministic noise, seeded per module + scan, so a given result always
  // draws the same trace instead of reshuffling on every re-render.
  function rng(seed) {
    return function () {
      seed = (seed + 0x6D2B79F5) | 0;
      var t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function hash(str) {
    var x = 2166136261;
    for (var i = 0; i < str.length; i++) { x ^= str.charCodeAt(i); x = Math.imul(x, 16777619); }
    return x >>> 0;
  }

  function statusKey(f) {
    if (f.status === 'fail') return f.severity === 'error' ? 'error' : 'warn';
    return f.status; // pass | info | skipped
  }
  var RANK = { error: 0, warn: 1, skipped: 2, info: 3, pass: 4 };
  var LABEL = { error: 'Error', warn: 'Warn', skipped: 'Skip', info: 'Info', pass: 'Pass' };

  // [level, roughness] in 0..1, where level 0 is the top of the box. Failing
  // checks sit low and jagged, passing checks high and quiet — the trace is a
  // literal left-to-right reading of this module's checks, worst first.
  var PROFILE = {
    error: [0.8, 0.34], warn: [0.62, 0.2], skipped: [0.5, 0.03], info: [0.42, 0.08], pass: [0.24, 0.06]
  };

  function tracePath(list, seed, W, H) {
    var n = list.length;
    if (!n) return 'M0,' + H / 2 + 'L' + W + ',' + H / 2;
    var r = rng(seed);
    var ph = [r() * 6.28, r() * 6.28, r() * 6.28];
    var S = 110, d = '';
    for (var i = 0; i <= S; i++) {
      var u = i / S;
      var pos = u * n - 0.5;
      var k0 = Math.min(n - 1, Math.max(0, Math.floor(pos)));
      var k1 = Math.min(n - 1, k0 + 1);
      var t = pos < 0 ? 0 : pos - Math.floor(pos);
      t = (1 - Math.cos(t * Math.PI)) / 2;
      var p0 = PROFILE[statusKey(list[k0])], p1 = PROFILE[statusKey(list[k1])];
      var level = p0[0] + (p1[0] - p0[0]) * t;
      var rough = p0[1] + (p1[1] - p0[1]) * t;
      var wobble = 0.5 * Math.sin(u * 23 + ph[0]) + 0.3 * Math.sin(u * 61 + ph[1]) + 0.2 * Math.sin(u * 137 + ph[2]);
      var y = level + rough * 0.5 * (0.75 * wobble + 0.25 * (r() - 0.5) * 2);
      y = Math.min(0.96, Math.max(0.04, y));
      d += (d ? 'L' : 'M') + (u * W).toFixed(2) + ',' + (y * H).toFixed(2);
    }
    return d;
  }

  // ------------------------------------------------------------- readout --

  var WORDS = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten'];
  function count(n) { return n < WORDS.length ? WORDS[n] : String(n); }

  function tally(list) {
    var t = { error: 0, warn: 0, skipped: 0, info: 0, pass: 0 };
    list.forEach(function (f) { t[statusKey(f)]++; });
    return t;
  }

  function verdictLine(t, total) {
    var toFix = t.error + t.warn;
    if (!total) return 'no reading';
    if (toFix) return count(toFix) + ' to fix';
    if (t.pass) return 'clean signal';
    return 'nothing conclusive';
  }

  function detailLine(t, total) {
    if (!total) return 'This module returned no checks for this page.';
    var parts = [t.pass + ' of ' + total + ' checks pass'];
    if (t.error) parts.push(t.error + (t.error === 1 ? ' error' : ' errors'));
    if (t.warn) parts.push(t.warn + (t.warn === 1 ? ' warning' : ' warnings'));
    if (t.info) parts.push(t.info + ' info');
    if (t.skipped) parts.push(t.skipped + ' skipped');
    return parts.join(' · ');
  }

  // Criteria arrive as either human names ("Referrer-Policy") or check IDs
  // ("security-sri"). An ID shows as its check's title from the scan trace;
  // failing that, the slug minus its redundant module prefix.
  var checkTitles = {};
  function criterionLabel(f) {
    var c = f.criterion || f.module || '';
    if (checkTitles[c]) return checkTitles[c];
    var prefix = (f.module || '') + '-';
    if (prefix.length > 1 && c.indexOf(prefix) === 0) c = c.slice(prefix.length).replace(/-/g, ' ');
    return c;
  }

  function findingRow(f) {
    var key = statusKey(f);
    var li = h('li', 'finding is-' + key);
    li.appendChild(h('span', 'f-status', LABEL[key] || key));
    var body = h('div', 'f-body');
    body.appendChild(h('p', 'f-criterion', criterionLabel(f)));
    if (key !== 'pass') {
      var observed = key === 'skipped' ? f.reason : f.observed;
      if (observed) body.appendChild(h('p', 'f-observed', observed));
      if (f.required) body.appendChild(h('p', 'f-required', 'want: ' + f.required));
      if (f.suggestedFix) body.appendChild(h('p', 'f-fix', f.suggestedFix));
    }
    li.appendChild(body);
    return li;
  }

  // ------------------------------------------------------------- results --

  var els = {
    form: document.getElementById('scanForm'),
    input: document.getElementById('urlInput'),
    button: document.getElementById('scanButton'),
    status: document.getElementById('status'),
    prism: document.getElementById('prism'),
    results: document.getElementById('results'),
    host: document.getElementById('scanHost'),
    count: document.getElementById('scanCount'),
    url: document.getElementById('scanUrl'),
    panels: document.getElementById('panels'),
    title: document.getElementById('readoutTitle'),
    sub: document.getElementById('readoutSub'),
    findings: document.getElementById('findings')
  };

  var state = { byModule: {}, selected: 'security' };

  function select(id, focus) {
    state.selected = id;
    var tabs = els.panels.querySelectorAll('[role="tab"]');
    for (var i = 0; i < tabs.length; i++) {
      var on = tabs[i].getAttribute('data-module') === id;
      tabs[i].setAttribute('aria-selected', on ? 'true' : 'false');
      tabs[i].tabIndex = on ? 0 : -1;
      if (on && focus) tabs[i].focus();
    }
    var mod = MODULES.filter(function (m) { return m.id === id; })[0];
    var list = state.byModule[id] || [];
    var t = tally(list);

    els.title.textContent = '';
    els.title.appendChild(h('b', null, mod.name + ':'));
    els.title.appendChild(document.createTextNode(' ' + verdictLine(t, list.length)));
    els.sub.textContent = detailLine(t, list.length);

    els.findings.textContent = '';
    if (!list.length) {
      els.findings.appendChild(h('li', 'findings-empty', 'No checks in this module ran against this page.'));
    }
    list.forEach(function (f) { els.findings.appendChild(findingRow(f)); });
  }

  function panel(mod, list, seed) {
    var t = tally(list);
    var btn = h('button', 'panel ' + mod.cls);
    btn.type = 'button';
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-controls', 'findings');
    btn.setAttribute('data-module', mod.id);
    btn.id = 'tab-' + mod.id;

    var W = 100, H = 160;
    var box = h('span', 'panel-box');
    var svg = s('svg', { viewBox: '0 0 ' + W + ' ' + H, preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' });
    // The dashed line splits "needs attention" (left) from "passing" (right),
    // because the checks are drawn worst-first.
    var notPass = list.length - t.pass;
    if (notPass > 0 && t.pass > 0) {
      var x = (notPass / list.length) * W;
      svg.appendChild(s('line', { 'class': 'boundary', x1: x, y1: 0, x2: x, y2: H }));
    }
    svg.appendChild(s('path', { 'class': 'trace trace--ghost', d: tracePath(list, seed ^ 0x9e3779b9, W, H) }));
    svg.appendChild(s('path', { 'class': 'trace', d: tracePath(list, seed, W, H) }));
    box.appendChild(svg);
    btn.appendChild(box);
    btn.appendChild(h('span', 'panel-name', mod.name));
    btn.appendChild(h('span', 'panel-meta', list.length ? t.pass + ' / ' + list.length + ' pass' : 'no reading'));

    btn.addEventListener('click', function () { select(mod.id, false); });
    return btn;
  }

  els.panels.addEventListener('keydown', function (e) {
    var dir = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (e.key === 'Home' || e.key === 'End') dir = e.key === 'Home' ? -99 : 99;
    if (!dir) return;
    e.preventDefault();
    var idx = MODULES.map(function (m) { return m.id; }).indexOf(state.selected);
    idx = Math.max(0, Math.min(MODULES.length - 1, idx + dir));
    select(MODULES[idx].id, true);
  });

  function render(data) {
    var findings = data.findings || [];
    var byModule = {};
    MODULES.forEach(function (m) { byModule[m.id] = []; });
    findings.forEach(function (f) { if (byModule[f.module]) byModule[f.module].push(f); });
    MODULES.forEach(function (m) {
      byModule[m.id].sort(function (a, b) { return RANK[statusKey(a)] - RANK[statusKey(b)]; });
    });
    state.byModule = byModule;

    var host = data.url;
    try { host = new URL(data.url).host; } catch (e) { /* show the raw URL */ }
    els.host.textContent = host;
    els.url.textContent = data.url;
    var nChecks = ((data.trace || {}).checks || []).length;
    els.count.textContent = (nChecks ? nChecks + ' checks · ' : '') + findings.length + (findings.length === 1 ? ' result' : ' results');

    els.panels.textContent = '';
    MODULES.forEach(function (m) { els.panels.appendChild(panel(m, byModule[m.id], hash(m.id + data.url))); });

    // Open on the loudest signal: most errors, then most warnings.
    var pick = MODULES.slice().sort(function (a, b) {
      var ta = tally(byModule[a.id]), tb = tally(byModule[b.id]);
      return (tb.error - ta.error) || (tb.warn - ta.warn);
    })[0];
    select(pick.id, false);

    els.results.hidden = false;
    els.results.scrollIntoView({ behavior: reducedMotion.matches ? 'auto' : 'smooth', block: 'start' });
    els.results.focus({ preventScroll: true });
  }

  // ---------------------------------------------------------------- form --

  // Third-party scripts are optional and server-driven via /api/config: an
  // empty Turnstile site key or GA4 ID means no script at all, and a page
  // that behaves as if the feature didn't exist.
  var turnstile = { active: false, token: '', widget: null };

  // GA4, loaded the way Google's snippet does it, minus the inline <script>
  // the CSP forbids. gtag must push the arguments object itself, not an
  // array — that's what gtag.js reads off dataLayer.
  function setupAnalytics(id) {
    if (!id) return;
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { window.dataLayer.push(arguments); };
    window.gtag('js', new Date());
    window.gtag('config', id);
    var script = document.createElement('script');
    script.async = true;
    script.src = 'https://www.googletagmanager.com/gtag/js?id=' + encodeURIComponent(id);
    document.head.appendChild(script);
  }

  // One event per scan attempt, carrying only the outcome — never the URL
  // the visitor typed, which is theirs, not ours to hand to Google.
  function track(outcome) {
    if (typeof window.gtag === 'function') window.gtag('event', 'scan', { outcome: outcome });
  }

  function setupTurnstile(data) {
    if (!data.sitekey) return;
    turnstile.active = true;
    var script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.async = true;
    script.onload = function () {
      turnstile.widget = window.turnstile.render('#turnstileWidget', {
        sitekey: data.sitekey,
        action: data.action,
        theme: 'dark',
        callback: function (token) { turnstile.token = token; },
        'expired-callback': function () { turnstile.token = ''; },
        'error-callback': function () { turnstile.token = ''; }
      });
    };
    document.head.appendChild(script);
  }

  fetch('/api/config')
    .then(function (r) { return r.json(); })
    .then(function (data) {
      setupAnalytics(data.gaMeasurementId);
      setupTurnstile(data);
    })
    .catch(function () { /* fail open to no widget and no analytics, not a broken page */ });

  function setStatus(text, isError) {
    els.status.textContent = text;
    els.status.classList.toggle('is-error', !!isError);
  }

  function setScanning(on) {
    els.form.classList.toggle('is-scanning', on);
    els.prism.classList.toggle('is-scanning', on);
    els.button.disabled = on;
    els.input.disabled = on;
    els.button.setAttribute('aria-busy', on ? 'true' : 'false');
    els.button.textContent = on ? 'Scanning' : 'Scan';
  }

  // ------------------------------------------------------------ scan log --

  // The scan log replays what the server actually did — each request it made
  // and each check it ran, with that check's real result — paced so the work
  // is visible instead of the answer just appearing. It invents nothing:
  // while the request is in flight it shows only the two steps already under
  // way server-side (the public-address guard and the page fetch), marked
  // pending; everything after that comes from the response's trace. Skip
  // flushes the rest at once.
  var MIN_SCAN_MS = 6500;   // floor from submit to results, network wait included
  var MIN_GAP_MS = 45;      // fastest a check line may land
  var MAX_GAP_MS = 220;     // slowest

  var log = {
    el: document.getElementById('scanLog'),
    lines: document.getElementById('logLines'),
    clock: document.getElementById('logClock'),
    skip: document.getElementById('logSkip'),
    t0: 0, timer: null, skipping: false, wake: []
  };
  var TAG = { security: 'SEC', seo: 'SEO', geo: 'GEO' };
  var MOD_CLS = { security: 'sig-sec', seo: 'sig-seo', geo: 'sig-geo' };

  function logLine(tag, text, right, cls) {
    var li = h('li', 'log-line' + (cls ? ' ' + cls : ''));
    li.appendChild(h('span', 'log-tag', tag));
    li.appendChild(h('span', 'log-text', text));
    li.appendChild(h('span', 'log-lead'));
    li.appendChild(h('span', 'log-right', right || ''));
    log.lines.appendChild(li);
    log.lines.scrollTop = log.lines.scrollHeight;
    return li;
  }
  function settle(li, right, cls) {
    li.classList.remove('is-pending');
    if (cls) li.classList.add(cls);
    li.querySelector('.log-right').textContent = right;
  }
  function tickClock() {
    var t = (performance.now() - log.t0) / 1000;
    log.clock.textContent = (t < 10 ? '0' : '') + t.toFixed(1) + ' s';
  }
  function logStart() {
    log.lines.textContent = '';
    log.el.hidden = false;
    log.skipping = false;
    log.skip.disabled = false;
    log.t0 = performance.now();
    clearInterval(log.timer);
    log.timer = setInterval(tickClock, 100);
    tickClock();
  }
  function logStop() {
    clearInterval(log.timer);
    tickClock();
    log.skip.disabled = true;
  }

  // A delay the Skip button can cut short.
  function wait(ms) {
    if (log.skipping || ms <= 0) return Promise.resolve();
    return new Promise(function (resolve) {
      var t = setTimeout(done, ms);
      log.wake.push(done);
      function done() { clearTimeout(t); resolve(); }
    });
  }
  log.skip.addEventListener('click', function () {
    log.skipping = true;
    log.skip.disabled = true;
    var pending = log.wake;
    log.wake = [];
    pending.forEach(function (f) { f(); });
  });

  // steps: [[fn, msAfter], …], run in order.
  function pace(steps) {
    return steps.reduce(function (p, step) {
      return p.then(function () { step[0](); return wait(step[1]); });
    }, Promise.resolve());
  }

  function size(n) { return n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB'; }
  function fetchResult(ev) {
    if (ev.error) return ev.error;
    return ev.status + ' · ' + size(ev.bytes || 0) + ' · ' + ev.ms + ' ms';
  }

  function replay(data, addrLine, pageLine) {
    var tr = data.trace || {};
    checkTitles = {};
    (tr.checks || []).forEach(function (c) { checkTitles[c.id] = c.title; });
    settle(addrLine, 'public', 'is-pass');
    settle(pageLine, fetchResult(tr.page || {}));

    var steps = [];
    (tr.fetches || []).forEach(function (ev) {
      steps.push([function () { logLine('GET', ev.what, fetchResult(ev), ev.error ? 'is-skipped' : ''); }, 320]);
    });

    var checks = tr.checks || [];
    var mods = MODULES.filter(function (m) {
      return checks.some(function (c) { return c.module === m.id; });
    }).map(function (m) { return m.name; });
    steps.push([function () { logLine('RUN', checks.length + ' checks · ' + mods.join(', '), ''); }, 360]);

    var findings = data.findings || [];
    var ordered = [];
    MODULES.forEach(function (m) {
      findings.forEach(function (f) { if (f.module === m.id) ordered.push(f); });
    });
    // Spread the check lines over whatever is left of the floor, within
    // sensible per-line bounds — a big result scrolls faster, a small one
    // doesn't crawl.
    var fixed = steps.reduce(function (a, st) { return a + st[1]; }, 0);
    var left = MIN_SCAN_MS - (performance.now() - log.t0) - fixed;
    var gap = Math.round(Math.max(MIN_GAP_MS, Math.min(MAX_GAP_MS, left / Math.max(1, ordered.length))));
    ordered.forEach(function (f) {
      var k = statusKey(f);
      steps.push([function () {
        logLine(TAG[f.module] || String(f.module).toUpperCase(), criterionLabel(f), LABEL[k] || k, 'is-' + k + ' ' + (MOD_CLS[f.module] || ''));
      }, gap]);
    });

    steps.push([function () {
      var t = tally(findings);
      logLine('DONE', (t.error + t.warn) + ' to fix · ' + t.pass + ' pass · ' + t.info + ' info',
        'server ' + ((tr.elapsedMs || 0) / 1000).toFixed(2) + ' s', 'is-done');
      logStop();
    }, 500]);
    return pace(steps);
  }

  function hostOf(raw) {
    try { return new URL(raw.indexOf('://') < 0 ? 'https://' + raw : raw).host || raw; } catch (e) { return raw; }
  }

  els.input.addEventListener('input', function () {
    els.input.removeAttribute('aria-invalid');
    if (els.status.classList.contains('is-error')) setStatus('', false);
  });

  els.form.addEventListener('submit', function (e) {
    e.preventDefault();
    var url = els.input.value.trim();
    if (!url) {
      els.input.setAttribute('aria-invalid', 'true');
      setStatus('Paste a URL to scan, like example.com.', true);
      els.input.focus();
      return;
    }
    if (turnstile.active && !turnstile.token) {
      setStatus('Complete the verification check first.', true);
      return;
    }

    setScanning(true);
    setStatus('Scanning ' + hostOf(url) + '…', false);
    els.results.hidden = true;
    logStart();
    var addrLine = logLine('ADDR', hostOf(url) + ' · public-address check', '', 'is-pending');
    var pageLine = logLine('GET', 'page', '', 'is-pending');

    fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, turnstileToken: turnstile.token })
    })
      .then(function (r) {
        if (!r.ok) {
          return r.text().then(function (t) {
            var err = new Error((t || '').trim() || 'The scan failed (HTTP ' + r.status + '). Try again.');
            err.badInput = r.status === 400;
            err.status = r.status;
            throw err;
          });
        }
        return r.json();
      })
      .then(function (data) {
        return replay(data, addrLine, pageLine).then(function () {
          setScanning(false);
          setStatus('', false);
          render(data);
          track('ok');
        });
      })
      .catch(function (err) {
        setScanning(false);
        if (addrLine.classList.contains('is-pending')) settle(addrLine, '—', 'is-skipped');
        if (pageLine.classList.contains('is-pending')) settle(pageLine, '—', 'is-skipped');
        logLine('STOP', err.message || 'The scan failed.', '', 'is-error');
        logStop();
        track(err.status === 429 ? 'rate_limited' : err.status === 403 ? 'not_verified' : 'error');
        if (err.badInput) els.input.setAttribute('aria-invalid', 'true');
        setStatus(err.message || 'The scan failed. Try again.', true);
        els.input.focus();
      })
      .then(function () {
        // Turnstile tokens are single-use; every attempt needs a fresh one.
        if (turnstile.widget != null && window.turnstile) {
          turnstile.token = '';
          window.turnstile.reset(turnstile.widget);
        }
      });
  });

  drawPrism();
})();
