# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# web/page.py
#
# Single-file dashboard UI. Deliberately dependency-free (no CDN, no build
# step, no external fonts) so it works on isolated / air-gapped SOC networks.
# Everything — layout, theming, icons, the activity sparkline — is inline.
from __future__ import annotations

DASHBOARD_PAGE = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>CassandraCTI — Live Threat Feed</title>
<style>
  /* ---- Design tokens ------------------------------------------------- */
  :root {
    --bg: #0a0e15;
    --bg-glow: radial-gradient(1100px 520px at 82% -12%, rgba(110,168,254,.10), transparent 60%),
               radial-gradient(820px 460px at -6% -4%, rgba(167,139,250,.08), transparent 55%);
    --s1: #111826; --s2: #161f2e; --s3: #1c2637;
    --border: #212c3d; --border-2: #2c3a4f;
    --text: #e6ebf3; --dim: #8a97ab; --faint: #5c6a80;
    --accent: #6ea8fe; --accent-2: #a78bfa;
    --ransom: #f26d78; --redflag: #f5a524; --rss: #38bdf8; --other: #a78bfa;
    --live: #34d399;
    --shadow: 0 1px 2px rgba(0,0,0,.4), 0 10px 30px -14px rgba(0,0,0,.7);
    --shadow-hover: 0 1px 2px rgba(0,0,0,.4), 0 18px 42px -18px rgba(0,0,0,.85);
    --radius: 14px; --radius-sm: 9px;
  }
  :root[data-theme="light"] {
    --bg: #eef1f7;
    --bg-glow: radial-gradient(1100px 520px at 82% -12%, rgba(59,111,224,.10), transparent 60%),
               radial-gradient(820px 460px at -6% -4%, rgba(139,92,246,.08), transparent 55%);
    --s1: #ffffff; --s2: #f3f6fb; --s3: #e9eef6;
    --border: #e3e9f2; --border-2: #d2dbe8;
    --text: #101726; --dim: #5a6678; --faint: #94a0b2;
    --accent: #3b6fe0; --accent-2: #8b5cf6;
    --ransom: #e0384a; --redflag: #c77b0a; --rss: #1782d6; --other: #7c5cff;
    --live: #0ea371;
    --shadow: 0 1px 2px rgba(16,24,40,.06), 0 12px 28px -16px rgba(16,24,40,.22);
    --shadow-hover: 0 1px 2px rgba(16,24,40,.08), 0 18px 40px -18px rgba(16,24,40,.3);
  }
  @media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) {
      --bg: #eef1f7;
      --bg-glow: radial-gradient(1100px 520px at 82% -12%, rgba(59,111,224,.10), transparent 60%),
                 radial-gradient(820px 460px at -6% -4%, rgba(139,92,246,.08), transparent 55%);
      --s1: #ffffff; --s2: #f3f6fb; --s3: #e9eef6;
      --border: #e3e9f2; --border-2: #d2dbe8;
      --text: #101726; --dim: #5a6678; --faint: #94a0b2;
      --accent: #3b6fe0; --accent-2: #8b5cf6;
      --ransom: #e0384a; --redflag: #c77b0a; --rss: #1782d6; --other: #7c5cff;
      --live: #0ea371;
      --shadow: 0 1px 2px rgba(16,24,40,.06), 0 12px 28px -16px rgba(16,24,40,.22);
      --shadow-hover: 0 1px 2px rgba(16,24,40,.08), 0 18px 40px -18px rgba(16,24,40,.3);
    }
  }

  /* ---- Base ---------------------------------------------------------- */
  *, *::before, *::after { box-sizing: border-box; }
  * { margin: 0; padding: 0; }
  html { -webkit-text-size-adjust: 100%; }
  body {
    background: var(--bg-glow), var(--bg);
    background-attachment: fixed;
    color: var(--text);
    font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
    min-height: 100vh;
  }
  ::selection { background: color-mix(in srgb, var(--accent) 35%, transparent); }
  a { color: inherit; }
  ::-webkit-scrollbar { width: 11px; height: 11px; }
  ::-webkit-scrollbar-thumb { background: var(--border-2); border-radius: 99px; border: 3px solid transparent; background-clip: padding-box; }
  ::-webkit-scrollbar-thumb:hover { background: var(--faint); background-clip: padding-box; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 6px; }

  .wrap { max-width: 1180px; margin: 0 auto; padding: 0 20px; }

  /* ---- Top bar ------------------------------------------------------- */
  header {
    position: sticky; top: 0; z-index: 20;
    background: color-mix(in srgb, var(--bg) 82%, transparent);
    backdrop-filter: saturate(140%) blur(12px);
    -webkit-backdrop-filter: saturate(140%) blur(12px);
    border-bottom: 1px solid var(--border);
  }
  .topbar { display: flex; align-items: center; gap: 16px; padding: 13px 0; }
  .brand { display: flex; align-items: center; gap: 12px; }
  .logo { width: 34px; height: 34px; flex: none; filter: drop-shadow(0 3px 10px color-mix(in srgb, var(--accent) 40%, transparent)); }
  .logo .a { stop-color: var(--accent); }
  .logo .b { stop-color: var(--accent-2); }
  .brand-text { display: flex; flex-direction: column; line-height: 1.15; }
  .brand-name { font-size: 16px; font-weight: 700; letter-spacing: .2px; }
  .brand-name b { font-weight: 700;
    background: linear-gradient(92deg, var(--accent), var(--accent-2));
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; }
  .brand-sub { font-size: 11px; color: var(--faint); letter-spacing: .5px; text-transform: uppercase; }

  .status {
    display: inline-flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--dim);
    padding: 5px 11px 5px 9px; border: 1px solid var(--border); border-radius: 999px; background: var(--s1);
  }
  .status .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--faint); box-shadow: 0 0 0 0 transparent; }
  .status.on .dot { background: var(--live); box-shadow: 0 0 0 4px color-mix(in srgb, var(--live) 22%, transparent); animation: pulse 1.8s infinite; }
  .status.paused .dot { background: var(--redflag); }
  .status.err .dot { background: var(--ransom); }
  @keyframes pulse { 0%,100% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--live) 45%, transparent); } 70% { box-shadow: 0 0 0 6px transparent; } }

  .spacer { flex: 1 1 auto; }
  .icon-btn {
    display: inline-grid; place-items: center; width: 36px; height: 36px; flex: none;
    background: var(--s1); border: 1px solid var(--border); color: var(--dim);
    border-radius: 10px; cursor: pointer; transition: .15s;
  }
  .icon-btn:hover { color: var(--text); border-color: var(--border-2); background: var(--s2); }
  .icon-btn svg { width: 18px; height: 18px; }
  .icon-btn .moon { display: none; }
  :root[data-theme="light"] .icon-btn .sun { display: none; }
  :root[data-theme="light"] .icon-btn .moon { display: block; }
  @media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) .icon-btn .sun { display: none; }
    :root:not([data-theme="dark"]) .icon-btn .moon { display: block; }
  }

  /* ---- Stat bar ------------------------------------------------------ */
  .stats { display: grid; grid-template-columns: 1.5fr repeat(4, 1fr); gap: 12px; padding: 20px 0 6px; }
  .stat {
    position: relative; overflow: hidden;
    background: var(--s1); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 14px 16px; box-shadow: var(--shadow);
  }
  .stat::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--tone, var(--accent)); opacity: .85; }
  .stat[data-k="total"]     { --tone: var(--accent); }
  .stat[data-k="ransomware"]{ --tone: var(--ransom); }
  .stat[data-k="redflag"]   { --tone: var(--redflag); }
  .stat[data-k="rss"]       { --tone: var(--rss); }
  .stat[data-k="live"]      { --tone: var(--live); }
  .stat-top { display: flex; align-items: center; gap: 7px; color: var(--dim); font-size: 11.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; }
  .stat-top .ic { width: 14px; height: 14px; color: var(--tone, var(--accent)); }
  .stat-val { font-size: 27px; font-weight: 700; letter-spacing: -.5px; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .stat.total { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .stat.total .stat-body { min-width: 0; }
  #spark { width: 128px; height: 42px; flex: none; }
  #spark .area { fill: color-mix(in srgb, var(--accent) 20%, transparent); stroke: none; }
  #spark .line { fill: none; stroke: var(--accent); stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; vector-effect: non-scaling-stroke; }
  .spark-cap { font-size: 10px; color: var(--faint); text-transform: uppercase; letter-spacing: .5px; text-align: right; margin-top: 2px; }

  /* ---- Toolbar ------------------------------------------------------- */
  .toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 14px 0 4px; }
  .search { position: relative; display: flex; align-items: center; }
  .search svg { position: absolute; left: 11px; width: 16px; height: 16px; color: var(--faint); pointer-events: none; }
  .search input {
    background: var(--s1); border: 1px solid var(--border); color: var(--text);
    border-radius: 10px; padding: 9px 12px 9px 34px; width: 280px; max-width: 62vw; outline: none; font: inherit; transition: .15s;
  }
  .search input::placeholder { color: var(--faint); }
  .search input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent); }
  .chips { display: flex; gap: 7px; flex-wrap: wrap; }
  .chip {
    display: inline-flex; align-items: center; gap: 6px; font-size: 12px; padding: 6px 11px;
    border-radius: 999px; cursor: pointer; user-select: none;
    background: var(--s1); border: 1px solid var(--border); color: var(--dim); transition: .13s;
  }
  .chip:hover { color: var(--text); border-color: var(--border-2); }
  .chip .cdot { width: 7px; height: 7px; border-radius: 50%; background: var(--tone, var(--other)); }
  .chip[data-k="ransomware"] { --tone: var(--ransom); }
  .chip[data-k="redflag"] { --tone: var(--redflag); }
  .chip[data-k="rss"] { --tone: var(--rss); }
  .chip[data-k="other"] { --tone: var(--other); }
  .chip b { color: var(--text); font-variant-numeric: tabular-nums; font-weight: 600; }
  .chip.active { color: var(--text); border-color: color-mix(in srgb, var(--tone, var(--accent)) 60%, var(--border)); background: color-mix(in srgb, var(--tone, var(--accent)) 14%, var(--s1)); }
  button.btn {
    background: var(--s1); border: 1px solid var(--border); color: var(--dim);
    border-radius: 10px; padding: 8px 13px; cursor: pointer; font: inherit; font-size: 13px;
    display: inline-flex; align-items: center; gap: 7px; transition: .13s;
  }
  button.btn:hover { color: var(--text); border-color: var(--border-2); background: var(--s2); }
  button.btn svg { width: 15px; height: 15px; }

  /* ---- Feed ---------------------------------------------------------- */
  main { padding: 16px 0 60px; }
  .card {
    position: relative; background: var(--s1); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 13px 16px 13px 18px; margin-bottom: 10px;
    box-shadow: var(--shadow); transition: transform .14s ease, box-shadow .14s ease, border-color .14s ease;
  }
  .card::before { content: ""; position: absolute; left: 0; top: 12px; bottom: 12px; width: 3px; border-radius: 3px; background: var(--tone, var(--other)); }
  .card[data-k="ransomware"] { --tone: var(--ransom); }
  .card[data-k="redflag"] { --tone: var(--redflag); }
  .card[data-k="rss"] { --tone: var(--rss); }
  .card[data-k="other"] { --tone: var(--other); }
  .card:hover { transform: translateY(-2px); box-shadow: var(--shadow-hover); border-color: var(--border-2); }
  .card.fresh { animation: slidein .4s cubic-bezier(.16,1,.3,1); }
  @keyframes slidein { from { opacity: 0; transform: translateY(-10px) scale(.99); } to { opacity: 1; transform: none; } }
  .meta { display: flex; gap: 9px; align-items: center; margin-bottom: 5px; flex-wrap: wrap; }
  .badge {
    display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 600;
    padding: 3px 9px 3px 7px; border-radius: 999px; letter-spacing: .2px;
    color: var(--tone, var(--other));
    background: color-mix(in srgb, var(--tone, var(--other)) 13%, transparent);
    border: 1px solid color-mix(in srgb, var(--tone, var(--other)) 32%, transparent);
  }
  .badge .ic { width: 12px; height: 12px; }
  .time { font-size: 11.5px; color: var(--faint); font-variant-numeric: tabular-nums; margin-left: auto; }
  .title { font-size: 14.5px; line-height: 1.4; }
  .title a { color: var(--text); text-decoration: none; font-weight: 600; }
  .title a:hover { color: var(--accent); text-decoration: underline; text-underline-offset: 2px; }
  .summary { color: var(--dim); font-size: 13px; margin-top: 5px; overflow: hidden;
             display: -webkit-box; -webkit-line-clamp: 3; line-clamp: 3; -webkit-box-orient: vertical; }

  .empty { text-align: center; color: var(--faint); padding: 70px 0; }
  .empty svg { width: 46px; height: 46px; opacity: .55; margin-bottom: 14px; }
  .empty .big { display: block; color: var(--dim); font-size: 15px; font-weight: 600; margin-bottom: 4px; }

  @media (max-width: 720px) {
    .stats { grid-template-columns: 1fr 1fr; }
    .stat.total { grid-column: 1 / -1; }
    .brand-sub { display: none; }
  }
  @media (prefers-reduced-motion: reduce) {
    * { animation: none !important; transition: none !important; }
  }
</style>
</head>
<body>
<header>
  <div class="wrap topbar">
    <div class="brand">
      <svg class="logo" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <defs><linearGradient id="cg" x1="2" y1="2" x2="22" y2="22" gradientUnits="userSpaceOnUse">
          <stop class="a" offset="0"/><stop class="b" offset="1"/>
        </linearGradient></defs>
        <path d="M12 2.4l7.6 2.8v5.9c0 4.8-3.3 8.2-7.6 10.5C7.7 19.3 4.4 15.9 4.4 11.1V5.2L12 2.4Z"
              stroke="url(#cg)" stroke-width="1.6" stroke-linejoin="round"/>
        <circle cx="12" cy="10.2" r="2.35" stroke="url(#cg)" stroke-width="1.6"/>
        <path d="M8.9 15.6c1.9-1.4 4.3-1.4 6.2 0" stroke="url(#cg)" stroke-width="1.6" stroke-linecap="round"/>
      </svg>
      <div class="brand-text">
        <span class="brand-name">Cassandra<b>CTI</b></span>
        <span class="brand-sub">Live Threat Feed</span>
      </div>
    </div>
    <span class="status" id="live"><span class="dot"></span><span id="live-label">connecting…</span></span>
    <span class="spacer"></span>
    <button class="icon-btn" id="theme" title="Toggle light / dark" aria-label="Toggle theme">
      <svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
        <circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>
      </svg>
      <svg class="moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/>
      </svg>
    </button>
  </div>
</header>

<div class="wrap">
  <section class="stats">
    <div class="stat total" data-k="total">
      <div class="stat-body">
        <div class="stat-top">Total events</div>
        <div class="stat-val" id="s-total">0</div>
      </div>
      <div>
        <svg id="spark" viewBox="0 0 100 42" preserveAspectRatio="none" aria-hidden="true">
          <path class="area" d=""></path><path class="line" d=""></path>
        </svg>
        <div class="spark-cap">last 30 min</div>
      </div>
    </div>
    <div class="stat" data-k="ransomware">
      <div class="stat-top"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>Ransomware</div>
      <div class="stat-val" id="s-ransomware">0</div>
    </div>
    <div class="stat" data-k="redflag">
      <div class="stat-top"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 21V4M5 4h12l-2.4 3.4L17 11H5"/></svg>Red flags</div>
      <div class="stat-val" id="s-redflag">0</div>
    </div>
    <div class="stat" data-k="rss">
      <div class="stat-top"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="18" r="1.5"/><path d="M5 11a8 8 0 0 1 8 8M5 5a14 14 0 0 1 14 14"/></svg>RSS / news</div>
      <div class="stat-val" id="s-rss">0</div>
    </div>
    <div class="stat" data-k="live">
      <div class="stat-top"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2.3"/><path d="M7 8a6 6 0 0 0 0 8M17 8a6 6 0 0 1 0 8M4 5a10 10 0 0 0 0 14M20 5a10 10 0 0 1 0 14"/></svg>Live clients</div>
      <div class="stat-val" id="s-live">1</div>
    </div>
  </section>

  <div class="toolbar">
    <label class="search">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/></svg>
      <input type="search" id="search" placeholder="Filter title / summary…" aria-label="Filter events">
    </label>
    <div id="chips" class="chips"></div>
    <span class="spacer"></span>
    <button class="btn" id="pause"><svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/></svg><span>Pause</span></button>
    <button class="btn" id="clear"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13"/></svg><span>Clear</span></button>
  </div>

  <main id="feed" role="feed" aria-label="Threat intelligence feed">
    <div class="empty" id="empty">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/></svg>
      <span class="big">Waiting for events…</span>
      Connected sources will stream in here in real time.
    </div>
  </main>
</div>

<script>
(function () {
  "use strict";
  var feed = document.getElementById("feed");
  var empty = document.getElementById("empty");
  var liveEl = document.getElementById("live");
  var liveLabel = document.getElementById("live-label");
  var searchEl = document.getElementById("search");
  var chipsEl = document.getElementById("chips");
  var sparkArea = document.querySelector("#spark .area");
  var sparkLine = document.querySelector("#spark .line");
  var statEls = {
    total: document.getElementById("s-total"),
    ransomware: document.getElementById("s-ransomware"),
    redflag: document.getElementById("s-redflag"),
    rss: document.getElementById("s-rss"),
    live: document.getElementById("s-live")
  };
  var MAX_CARDS = 300;
  var paused = false, pending = [];
  var activeSource = null, query = "";
  var knownSources = {};
  var visible = [];
  var counts = { total: 0, ransomware: 0, redflag: 0, rss: 0, other: 0 };
  var baseTitle = document.title, unseen = 0;

  // ---- Theme -------------------------------------------------------------
  var root = document.documentElement;
  try {
    var saved = localStorage.getItem("cti-theme");
    if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
    else root.removeAttribute("data-theme");
  } catch (e) {}
  document.getElementById("theme").onclick = function () {
    var cur = root.getAttribute("data-theme");
    if (!cur) cur = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    var next = cur === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("cti-theme", next); } catch (e) {}
  };

  // ---- Icons -------------------------------------------------------------
  var ICONS = {
    ransomware: '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    redflag: '<path d="M5 21V4M5 4h12l-2.4 3.4L17 11H5"/>',
    rss: '<circle cx="6" cy="18" r="1.5"/><path d="M5 11a8 8 0 0 1 8 8M5 5a14 14 0 0 1 14 14"/>',
    other: '<circle cx="12" cy="12" r="2.3"/><path d="M7 8a6 6 0 0 0 0 8M17 8a6 6 0 0 1 0 8"/>'
  };
  function icon(k) {
    return '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
           'stroke-linecap="round" stroke-linejoin="round">' + (ICONS[k] || ICONS.other) + '</svg>';
  }

  // ---- Helpers -----------------------------------------------------------
  function kind(source) {
    if (/ransomware/i.test(source)) return "ransomware";
    if (/red\.?flag/i.test(source)) return "redflag";
    if (/^rss:/i.test(source)) return "rss";
    return "other";
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function fmt(n) { return (n || 0).toLocaleString(); }
  function relTime(iso) {
    if (!iso) return "";
    var t = Date.parse(iso); if (isNaN(t)) return "";
    var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 60) return Math.floor(s) + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }
  function matches(ev) {
    if (activeSource && ev.source !== activeSource) return false;
    if (query) {
      var hay = ((ev.title || "") + " " + (ev.summary || "")).toLowerCase();
      if (hay.indexOf(query) === -1) return false;
    }
    return true;
  }

  // ---- Rendering ---------------------------------------------------------
  function card(ev, fresh) {
    var k = kind(ev.source);
    var div = document.createElement("div");
    div.className = "card" + (fresh ? " fresh" : "");
    div.setAttribute("data-k", k);
    var when = ev.published_at || ev.first_seen_at || "";
    div.innerHTML =
      '<div class="meta"><span class="badge" data-k="' + k + '">' + icon(k) + esc(ev.source) + '</span>' +
      '<span class="time" title="' + esc(when) + '">' + relTime(when) + '</span></div>' +
      '<div class="title">' + (ev.url
        ? '<a href="' + esc(ev.url) + '" target="_blank" rel="noopener noreferrer">' + esc(ev.title || ev.url) + '</a>'
        : esc(ev.title || "(untitled)")) + '</div>' +
      (ev.summary ? '<div class="summary">' + esc(ev.summary) + '</div>' : "");
    return div;
  }
  function rebuildChips() {
    var frag = document.createDocumentFragment();
    Object.keys(knownSources).sort().forEach(function (src) {
      var c = document.createElement("span");
      c.className = "chip" + (activeSource === src ? " active" : "");
      c.setAttribute("data-k", kind(src));
      c.innerHTML = '<span class="cdot"></span>' + esc(src) + ' <b>' + knownSources[src] + '</b>';
      c.onclick = function () {
        activeSource = (activeSource === src) ? null : src;
        rebuildChips(); applyFilter();
      };
      frag.appendChild(c);
    });
    chipsEl.innerHTML = "";
    chipsEl.appendChild(frag);
  }
  function renderStats() {
    statEls.total.textContent = fmt(counts.total);
    statEls.ransomware.textContent = fmt(counts.ransomware);
    statEls.redflag.textContent = fmt(counts.redflag);
    statEls.rss.textContent = fmt(counts.rss);
  }
  function applyFilter() {
    feed.querySelectorAll(".card").forEach(function (c) { c.remove(); });
    var frag = document.createDocumentFragment();
    visible.forEach(function (ev) { if (matches(ev)) frag.appendChild(card(ev, false)); });
    feed.appendChild(frag);
    if (empty) empty.style.display = feed.querySelector(".card") ? "none" : "block";
  }

  // ---- Activity sparkline (rolling 30 x 1-min buckets) -------------------
  var SPARK_N = 30;
  var spark = [];
  for (var i = 0; i < SPARK_N; i++) spark.push(0);
  function drawSpark() {
    var max = 1;
    for (var i = 0; i < spark.length; i++) if (spark[i] > max) max = spark[i];
    var n = spark.length, line = "", area = "";
    for (var j = 0; j < n; j++) {
      var x = n > 1 ? (j / (n - 1)) * 100 : 0;
      var y = 40 - (spark[j] / max) * 34 - 3;
      line += (j === 0 ? "M" : "L") + x.toFixed(2) + " " + y.toFixed(2) + " ";
    }
    area = "M0 42 " + line.replace(/^M/, "L") + "L100 42 Z";
    sparkLine.setAttribute("d", line.trim());
    sparkArea.setAttribute("d", area);
  }
  setInterval(function () { spark.push(0); if (spark.length > SPARK_N) spark.shift(); drawSpark(); }, 60000);

  // ---- Ingest ------------------------------------------------------------
  function addEvent(ev, fresh) {
    if (!ev || !ev.source) return;
    var k = kind(ev.source);
    knownSources[ev.source] = (knownSources[ev.source] || 0) + 1;
    counts.total++; counts[k]++;
    spark[spark.length - 1]++;
    visible.unshift(ev);
    if (visible.length > MAX_CARDS) visible.pop();
    renderStats(); rebuildChips(); drawSpark();
    if (matches(ev)) {
      feed.insertBefore(card(ev, fresh), feed.firstChild);
      if (empty) empty.style.display = "none";
    }
    var cards = feed.querySelectorAll(".card");
    while (cards.length > MAX_CARDS) { cards[cards.length - 1].remove(); cards = feed.querySelectorAll(".card"); }
    if (fresh && document.hidden) { unseen++; document.title = "(" + unseen + ") " + baseTitle; }
  }
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) { unseen = 0; document.title = baseTitle; }
  });

  // ---- Controls ----------------------------------------------------------
  var pauseBtn = document.getElementById("pause");
  pauseBtn.onclick = function () {
    paused = !paused;
    pauseBtn.querySelector("span").textContent = paused ? "Resume" : "Pause";
    liveEl.classList.toggle("paused", paused);
    liveLabel.textContent = paused ? "paused" : "live";
    if (!paused) { pending.forEach(function (ev) { addEvent(ev, true); }); pending = []; }
  };
  document.getElementById("clear").onclick = function () {
    visible = []; knownSources = {};
    counts = { total: 0, ransomware: 0, redflag: 0, rss: 0, other: 0 };
    feed.querySelectorAll(".card").forEach(function (c) { c.remove(); });
    renderStats(); rebuildChips();
    if (empty) empty.style.display = "block";
  };
  searchEl.oninput = function () { query = this.value.trim().toLowerCase(); applyFilter(); };

  // ---- Data: history, then live stream -----------------------------------
  var qs = new URLSearchParams(location.search);
  var token = qs.get("token");
  var tokenQ = token ? "?token=" + encodeURIComponent(token) : "";
  function withToken(path) { return path + (token ? (path.indexOf("?") === -1 ? "?" : "&") + "token=" + encodeURIComponent(token) : ""); }

  fetch(withToken("/api/events?limit=200"))
    .then(function (r) { return r.ok ? r.json() : { events: [] }; })
    .then(function (data) {
      (data.events || []).reverse().forEach(function (ev) { addEvent(ev, false); });
    })
    .catch(function () {});

  function pollStats() {
    fetch(withToken("/api/stats"))
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) { if (s && typeof s.live_clients === "number") statEls.live.textContent = fmt(s.live_clients); })
      .catch(function () {});
  }
  pollStats();
  setInterval(pollStats, 15000);

  function connect() {
    var es = new EventSource("/api/stream" + tokenQ);
    es.onopen = function () {
      liveEl.classList.remove("err"); liveEl.classList.add("on");
      liveLabel.textContent = paused ? "paused" : "live";
    };
    es.onmessage = function (m) {
      var ev; try { ev = JSON.parse(m.data); } catch (e) { return; }
      if (paused) { pending.push(ev); return; }
      addEvent(ev, true);
    };
    es.onerror = function () {
      liveEl.classList.remove("on"); liveEl.classList.add("err");
      liveLabel.textContent = "reconnecting…";
      es.close(); setTimeout(connect, 3000);
    };
  }

  drawSpark();
  connect();
  setInterval(function () { applyFilter(); }, 30000); // refresh relative times
})();
</script>
</body>
</html>
"""
