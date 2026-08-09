# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# web/page.py
#
# Single-file SOC command-center dashboard. Deliberately dependency-free (no
# CDN, no build step, no external fonts) so it works on isolated / air-gapped
# networks. Dense, terminal-grade: monospace data, hairline grid, log-style
# feed. Layout, theming, icons, charts, per-category filters, sort, range,
# copy/export, deep-link URL state, keyboard nav, the detail view, the optional
# inventory match and AI-brief affordances are all inline.
from __future__ import annotations

DASHBOARD_PAGE = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>CassandraCTI — Live Threat Feed</title>
<style>
  :root {
    --bg: #06090f; --panel: #0b0f16; --panel2: #0f141d; --hover: #131a25;
    --border: #1a2230; --border-2: #27313f; --grid: #141b26;
    --text: #dbe2ec; --dim: #8592a6; --faint: #5a6576;
    --accent: #6ea8fe; --accent-2: #a78bfa;
    --ransomware: #f26d78; --redflag: #f5a524; --rss: #38bdf8;
    --vuln: #a78bfa; --ioc: #2dd4bf; --other: #8b97ab;
    --live: #35d07f; --up: #f5a524; --down: #64748b;
    --mono: ui-monospace, "SF Mono", SFMono-Regular, "JetBrains Mono", "Roboto Mono", Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --r: 6px;
  }
  :root[data-theme="light"] {
    --bg: #f4f6fa; --panel: #ffffff; --panel2: #f6f8fc; --hover: #eef2f8;
    --border: #e2e8f1; --border-2: #cfd8e4; --grid: #eceff5;
    --text: #10151f; --dim: #55606f; --faint: #8a95a5;
    --accent: #2f6bdd; --accent-2: #7c5cff;
    --ransomware: #dc2f42; --redflag: #b9770a; --rss: #1782d6;
    --vuln: #7c5cff; --ioc: #0d9488; --other: #64748b;
    --live: #0f9d58; --up: #b9770a; --down: #94a3b8;
  }
  @media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) {
      --bg: #f4f6fa; --panel: #ffffff; --panel2: #f6f8fc; --hover: #eef2f8;
      --border: #e2e8f1; --border-2: #cfd8e4; --grid: #eceff5;
      --text: #10151f; --dim: #55606f; --faint: #8a95a5;
      --accent: #2f6bdd; --accent-2: #7c5cff;
      --ransomware: #dc2f42; --redflag: #b9770a; --rss: #1782d6;
      --vuln: #7c5cff; --ioc: #0d9488; --other: #64748b;
      --live: #0f9d58; --up: #b9770a; --down: #94a3b8;
    }
  }

  *, *::before, *::after { box-sizing: border-box; }
  * { margin: 0; padding: 0; }
  html { -webkit-text-size-adjust: 100%; }
  body { background: var(--bg); color: var(--text); font: 13px/1.5 var(--sans); -webkit-font-smoothing: antialiased; min-height: 100vh; }
  .mono { font-family: var(--mono); font-variant-numeric: tabular-nums; }
  svg.ic { width: 14px; height: 14px; flex: none; }  /* default size for dynamic icons */
  ::selection { background: color-mix(in srgb, var(--accent) 35%, transparent); }
  a { color: inherit; }
  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-thumb { background: var(--border-2); border-radius: 99px; border: 3px solid transparent; background-clip: padding-box; }
  :focus-visible { outline: 1px solid var(--accent); outline-offset: 1px; }
  mark { background: color-mix(in srgb, var(--accent) 30%, transparent); color: inherit; border-radius: 2px; padding: 0 1px; }
  .wrap { max-width: 1320px; margin: 0 auto; padding: 0 16px; }

  /* Header */
  header { position: sticky; top: 0; z-index: 20; background: color-mix(in srgb, var(--bg) 88%, transparent);
    backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); }
  .topbar { display: flex; align-items: center; gap: 14px; height: 50px; }
  .brand { display: flex; align-items: center; gap: 10px; }
  .logo { width: 26px; height: 26px; flex: none; }
  .logo .a { stop-color: var(--accent); } .logo .b { stop-color: var(--accent-2); }
  .brand-name { font-size: 14px; font-weight: 700; letter-spacing: .3px; }
  .brand-name b { background: linear-gradient(92deg, var(--accent), var(--accent-2)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; }
  .clock { font-family: var(--mono); font-size: 12px; color: var(--dim); letter-spacing: .5px; }
  .status { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-family: var(--mono); text-transform: uppercase; letter-spacing: .6px;
    color: var(--dim); padding: 3px 9px 3px 8px; border: 1px solid var(--border); border-radius: 3px; background: var(--panel); }
  .status .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--faint); }
  .status.on .dot { background: var(--live); box-shadow: 0 0 0 3px color-mix(in srgb, var(--live) 22%, transparent); animation: pulse 1.8s infinite; }
  .status.paused .dot { background: var(--redflag); } .status.err .dot { background: var(--ransomware); }
  @keyframes pulse { 0%,100% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--live) 45%, transparent); } 70% { box-shadow: 0 0 0 5px transparent; } }
  .spacer { flex: 1 1 auto; }
  .ibtn { display: inline-grid; place-items: center; width: 30px; height: 30px; flex: none; background: var(--panel); border: 1px solid var(--border);
    color: var(--dim); border-radius: 4px; cursor: pointer; transition: .12s; }
  .ibtn:hover { color: var(--text); border-color: var(--border-2); background: var(--panel2); }
  .ibtn.on { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); }
  .ibtn svg { width: 16px; height: 16px; }
  .ibtn .moon { display: none; }
  :root[data-theme="light"] .ibtn .sun { display: none; } :root[data-theme="light"] .ibtn .moon { display: block; }
  @media (prefers-color-scheme: light) { :root:not([data-theme="dark"]) .ibtn .sun { display: none; } :root:not([data-theme="dark"]) .ibtn .moon { display: block; } }

  /* Tabs */
  .tabs { display: flex; gap: 0; overflow-x: auto; scrollbar-width: none; border-top: 1px solid var(--border); }
  .tabs::-webkit-scrollbar { display: none; }
  .tab { display: inline-flex; align-items: center; gap: 7px; white-space: nowrap; cursor: pointer; padding: 9px 14px; border: 0;
    background: transparent; color: var(--dim); font: inherit; font-size: 11.5px; font-weight: 700; text-transform: uppercase; letter-spacing: .7px;
    border-bottom: 2px solid transparent; transition: .12s; }
  .tab:hover { color: var(--text); background: var(--panel); }
  .tab .ic { width: 14px; height: 14px; }
  .tab.active { color: var(--text); border-bottom-color: var(--accent); background: var(--panel); }
  .tab .cnt { font-family: var(--mono); font-size: 10.5px; color: var(--faint); }
  .tab.active .cnt { color: var(--accent); }

  main { padding: 14px 0 60px; }

  /* Panels */
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: var(--r); }
  .ph { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 8px 12px; border-bottom: 1px solid var(--border); }
  .ph h2 { font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: .7px; color: var(--dim); }
  .ph .hint { font-size: 10.5px; color: var(--faint); font-family: var(--mono); }
  .pb { padding: 12px; }

  /* Overview stat strip */
  .ovbar { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
  .ovbar h1 { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: var(--dim); }
  .seg { display: inline-flex; border: 1px solid var(--border); border-radius: 4px; overflow: hidden; }
  .seg button { border: 0; border-left: 1px solid var(--border); background: var(--panel); color: var(--dim); font: inherit; font-size: 11px;
    font-family: var(--mono); font-weight: 600; padding: 5px 11px; cursor: pointer; transition: .1s; }
  .seg button:first-child { border-left: 0; } .seg button.on { background: var(--hover); color: var(--text); }
  .strip { display: grid; grid-template-columns: repeat(6, 1fr); border: 1px solid var(--border); border-radius: var(--r); overflow: hidden; background: var(--panel); }
  .cell { padding: 11px 14px; border-left: 1px solid var(--border); position: relative; }
  .cell:first-child { border-left: 0; }
  .cell .cl { font-size: 9.5px; font-weight: 700; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); display: flex; align-items: center; gap: 5px; }
  .cell .cl .ic { width: 12px; height: 12px; color: var(--tone, var(--accent)); }
  .cell .cv { font-family: var(--mono); font-size: 23px; font-weight: 600; letter-spacing: -.5px; margin-top: 5px; line-height: 1; color: var(--text); }
  .cell .cx { display: flex; align-items: center; gap: 8px; margin-top: 6px; height: 16px; }
  .cell .cspark { width: 54px; height: 16px; } .cell .cspark path.l { fill: none; stroke: var(--tone, var(--accent)); stroke-width: 1.4; vector-effect: non-scaling-stroke; } .cell .cspark path.a { fill: color-mix(in srgb, var(--tone, var(--accent)) 15%, transparent); stroke: none; }
  .delta { font-family: var(--mono); font-size: 11px; font-weight: 700; display: inline-flex; align-items: center; gap: 2px; }
  .delta.up { color: var(--up); } .delta.down { color: var(--down); } .delta.flat { color: var(--faint); }
  .delta svg { width: 10px; height: 10px; }
  .cell[data-k="total"] { --tone: var(--accent); } .cell[data-k="new"] { --tone: var(--rss); } .cell[data-k="crit"] { --tone: var(--ransomware); }
  .cell[data-k="sources"] { --tone: var(--vuln); } .cell[data-k="sent"] { --tone: var(--ioc); } .cell[data-k="live"] { --tone: var(--live); }

  #chart { width: 100%; height: 128px; display: block; }
  #chart .g { stroke: var(--grid); stroke-width: 1; }
  #chart .bar { fill: var(--accent); opacity: .8; } #chart .bar:hover { opacity: 1; fill: var(--accent-2); }
  .cgrid { display: grid; grid-template-columns: 2fr 1fr; gap: 12px; margin-top: 12px; }
  .cgrid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px; }

  /* mini bar list */
  .bl { display: flex; flex-direction: column; }
  .br { display: grid; grid-template-columns: 120px 1fr 46px; gap: 10px; align-items: center; padding: 5px 0; font-size: 12px; }
  .br .lbl { color: var(--dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: flex; align-items: center; gap: 6px; }
  .br .cdot { width: 7px; height: 7px; border-radius: 2px; flex: none; background: var(--tone, var(--other)); }
  .trk { height: 6px; border-radius: 2px; background: var(--grid); overflow: hidden; } .fil { height: 100%; background: var(--tone, var(--accent)); }
  .br .n { text-align: right; font-family: var(--mono); font-size: 12px; color: var(--text); font-weight: 600; }

  /* data table (source health / groups) */
  .dt { width: 100%; }
  .dtr { display: grid; align-items: center; gap: 10px; padding: 6px 0; font-size: 12px; border-top: 1px solid var(--grid); }
  .dtr:first-child { border-top: 0; }
  .health .dtr { grid-template-columns: 9px 1fr 44px 66px; }
  .groups .dtr { grid-template-columns: 1fr 44px; }
  .hdot { width: 7px; height: 7px; border-radius: 50%; background: var(--live); } .hdot.stale { background: var(--redflag); } .hdot.old { background: var(--faint); }
  .dtr .s { color: var(--dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .dtr .n { text-align: right; font-family: var(--mono); color: var(--text); font-weight: 600; }
  .dtr .a { text-align: right; font-family: var(--mono); color: var(--faint); font-size: 11px; }

  .critline { display: grid; grid-template-columns: 3px 52px 150px 1fr; gap: 10px; align-items: center; padding: 6px 0; font-size: 12.5px; border-top: 1px solid var(--grid); cursor: pointer; }
  .critline:first-child { border-top: 0; } .critline:hover { background: var(--hover); }
  .critline .tk { width: 3px; height: 15px; border-radius: 2px; background: var(--tone); }
  .critline .tt { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* Toolbar */
  .toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
  .search { position: relative; display: flex; align-items: center; }
  .search svg { position: absolute; left: 9px; width: 14px; height: 14px; color: var(--faint); pointer-events: none; }
  .search input { background: var(--panel); border: 1px solid var(--border); color: var(--text); border-radius: 4px; padding: 7px 10px 7px 29px;
    width: 230px; max-width: 56vw; outline: none; font: inherit; font-size: 12.5px; }
  .search input:focus { border-color: var(--accent); }
  select.f, button.b { background: var(--panel); border: 1px solid var(--border); color: var(--dim); border-radius: 4px; font: inherit; font-size: 12px; cursor: pointer; outline: none; }
  select.f { padding: 7px 8px; max-width: 180px; color: var(--text); } select.f:focus { border-color: var(--accent); }
  button.b { padding: 7px 11px; display: inline-flex; align-items: center; gap: 6px; transition: .12s; }
  button.b:hover { color: var(--text); border-color: var(--border-2); background: var(--panel2); }
  button.b.on { color: var(--text); border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); background: color-mix(in srgb, var(--accent) 12%, var(--panel)); }
  button.b svg { width: 13px; height: 13px; }
  .rescount { font-family: var(--mono); font-size: 11.5px; color: var(--faint); }

  /* Log feed table */
  .log { border: 1px solid var(--border); border-radius: var(--r); overflow: hidden; background: var(--panel); }
  .logh, .ln { display: grid; grid-template-columns: 3px 56px 150px minmax(0, 1fr) 78px; align-items: center; gap: 12px; }
  .logh { padding: 8px 12px; font-size: 9.5px; font-weight: 700; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); border-bottom: 1px solid var(--border); background: var(--panel2); }
  .ln { padding: 8px 12px; border-bottom: 1px solid var(--grid); cursor: pointer; transition: background .1s; }
  .ln:last-child { border-bottom: 0; } .ln:hover { background: var(--hover); }
  .ln.inv-hit { box-shadow: inset 2px 0 0 var(--accent); }
  .ln .tk { width: 3px; height: 18px; border-radius: 2px; background: var(--tone, var(--other)); }
  .ln[data-k="ransomware"] { --tone: var(--ransomware); } .ln[data-k="redflag"] { --tone: var(--redflag); }
  .ln[data-k="rss"] { --tone: var(--rss); } .ln[data-k="vuln"] { --tone: var(--vuln); } .ln[data-k="ioc"] { --tone: var(--ioc); } .ln[data-k="other"] { --tone: var(--other); }
  .ln .lt { font-family: var(--mono); font-size: 11.5px; color: var(--faint); }
  .ln .lsrc { display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; font-weight: 600; color: var(--tone, var(--other)); overflow: hidden; }
  .ln .lsrc svg { width: 12px; height: 12px; flex: none; } .ln .lsrc span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .ev { display: flex; align-items: baseline; gap: 9px; min-width: 0; }
  .ev .ind { font-family: var(--mono); font-size: 12px; color: var(--tone, var(--text)); flex: none; }
  .ev .tt { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12.5px; }
  .ev .tags { display: inline-flex; gap: 5px; flex: none; }
  .tg { font-family: var(--mono); font-size: 10px; color: var(--faint); border: 1px solid var(--border); border-radius: 3px; padding: 1px 5px; white-space: nowrap; }
  .tg.warn { color: var(--ransomware); border-color: color-mix(in srgb, var(--ransomware) 40%, transparent); }
  .tg.on { color: var(--live); border-color: color-mix(in srgb, var(--live) 40%, transparent); }
  .lact { display: inline-flex; gap: 3px; justify-content: flex-end; opacity: 0; transition: opacity .1s; }
  .ln:hover .lact { opacity: 1; }
  .la { display: inline-grid; place-items: center; width: 24px; height: 24px; border: 1px solid var(--border); border-radius: 4px; background: var(--panel2); color: var(--dim); cursor: pointer; }
  .la:hover { color: var(--text); border-color: var(--border-2); } .la.ai:hover { color: var(--accent); } .la svg { width: 13px; height: 13px; }
  @media (max-width: 780px) {
    .logh, .ln { grid-template-columns: 3px 48px minmax(0,1fr) 56px; }
    .logh .h-src, .ln .lsrc { display: none; }
    .strip { grid-template-columns: 1fr 1fr 1fr; } .cgrid, .cgrid2 { grid-template-columns: 1fr; }
  }

  .empty { text-align: center; color: var(--faint); padding: 54px 0; }
  .empty svg { width: 40px; height: 40px; opacity: .45; margin-bottom: 10px; }
  .empty .big { display: block; color: var(--dim); font-size: 14px; font-weight: 600; margin-bottom: 3px; }

  .sk { background: linear-gradient(90deg, var(--panel2) 25%, var(--hover) 37%, var(--panel2) 63%); background-size: 400% 100%; animation: shimmer 1.3s infinite; border-radius: 3px; }
  @keyframes shimmer { 0% { background-position: 100% 0; } 100% { background-position: -100% 0; } }
  .sk-row { height: 34px; border-bottom: 1px solid var(--grid); } .sk-cell { height: 74px; }

  /* Detail modal */
  .modal { position: fixed; inset: 0; z-index: 50; display: grid; place-items: center; padding: 18px; background: rgba(2,5,10,.66); }
  .modal[hidden] { display: none; }
  .mcard { width: 660px; max-width: 100%; max-height: 88vh; overflow: auto; background: var(--panel); border: 1px solid var(--border-2); border-radius: 8px; }
  .mtop { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--border); position: sticky; top: 0; background: var(--panel); }
  .mtop .mt-src { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 700; color: var(--tone, var(--other)); }
  .mtop .mt-src svg { width: 14px; height: 14px; }
  .mtop .time { font-family: var(--mono); font-size: 11.5px; color: var(--faint); }
  .mbody { padding: 16px; }
  .mbody h3 { font-size: 15.5px; line-height: 1.4; margin-bottom: 8px; }
  .msum { color: var(--dim); font-size: 13px; line-height: 1.55; margin-bottom: 16px; }
  .seclabel { font-size: 9.5px; font-weight: 700; letter-spacing: .9px; text-transform: uppercase; color: var(--faint); margin: 0 0 8px; }
  .kv { border: 1px solid var(--border); border-radius: 5px; overflow: hidden; margin-bottom: 16px; }
  .kv .r { display: grid; grid-template-columns: 130px 1fr; gap: 12px; padding: 7px 12px; font-size: 12.5px; }
  .kv .r:nth-child(even) { background: var(--panel2); }
  .kv .r + .r { border-top: 1px solid var(--grid); }
  .kv .k { color: var(--faint); text-transform: uppercase; font-size: 10.5px; letter-spacing: .5px; align-self: center; }
  .kv .v { color: var(--text); word-break: break-word; } .kv .v.mono { font-family: var(--mono); font-size: 12px; }
  .lnk { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
  .lnk a, .acts button { display: inline-flex; align-items: center; gap: 7px; text-decoration: none; font: inherit; font-size: 12px; font-weight: 600;
    padding: 8px 12px; border-radius: 5px; border: 1px solid var(--border); background: var(--panel2); color: var(--text); cursor: pointer; transition: .12s; }
  .lnk a:hover, .acts button:hover { border-color: var(--border-2); background: var(--hover); }
  .lnk a svg, .acts button svg { width: 13px; height: 13px; }
  .lnk a.primary { background: var(--accent); color: #fff; border-color: transparent; } .lnk a.primary:hover { filter: brightness(1.08); background: var(--accent); }
  .acts { display: flex; gap: 8px; flex-wrap: wrap; }
  .acts button.ai { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 35%, transparent); background: transparent; }
  .ai-out { margin-top: 14px; font-size: 12.5px; line-height: 1.55; color: var(--text); background: var(--panel2); border: 1px solid var(--border); border-left: 2px solid var(--accent); border-radius: 5px; padding: 11px 13px; }
  .ai-out .ai-h { display: flex; align-items: center; gap: 6px; font-size: 9.5px; font-weight: 700; letter-spacing: .7px; text-transform: uppercase; color: var(--accent); margin-bottom: 7px; }
  .ai-out .ai-h svg { width: 12px; height: 12px; }
  .ai-out p { margin: 0 0 7px; } .ai-out p:last-child { margin-bottom: 0; } .ai-out ul { margin: 4px 0 7px; padding-left: 18px; } .ai-out li { margin: 2px 0; }
  .ai-out.err { color: var(--redflag); border-left-color: var(--redflag); } .ai-out.err .ai-h { color: var(--redflag); }

  .toast { position: fixed; left: 50%; bottom: 22px; transform: translateX(-50%); z-index: 60; background: var(--panel2); color: var(--text);
    border: 1px solid var(--border-2); border-radius: 5px; padding: 8px 14px; font-size: 12.5px; font-family: var(--mono); }
  .toast[hidden] { display: none; }
  @media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
</style>
</head>
<body>
<header>
  <div class="wrap topbar">
    <div class="brand">
      <svg class="logo" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <defs><linearGradient id="cg" x1="2" y1="2" x2="22" y2="22" gradientUnits="userSpaceOnUse"><stop class="a" offset="0"/><stop class="b" offset="1"/></linearGradient></defs>
        <path d="M12 2.4l7.6 2.8v5.9c0 4.8-3.3 8.2-7.6 10.5C7.7 19.3 4.4 15.9 4.4 11.1V5.2L12 2.4Z" stroke="url(#cg)" stroke-width="1.7" stroke-linejoin="round"/>
        <circle cx="12" cy="10.2" r="2.3" stroke="url(#cg)" stroke-width="1.7"/><path d="M8.9 15.6c1.9-1.4 4.3-1.4 6.2 0" stroke="url(#cg)" stroke-width="1.7" stroke-linecap="round"/>
      </svg>
      <span class="brand-name">Cassandra<b>CTI</b></span>
    </div>
    <span class="clock" id="clock">--:--:--</span>
    <span class="status" id="live"><span class="dot"></span><span id="live-label">connecting</span></span>
    <span class="spacer"></span>
    <button class="ibtn" id="sound" title="Sound alerts on critical events" aria-label="Toggle sound alerts">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9v6h4l5 4V5L8 9H4Z"/><path d="M16 8a5 5 0 0 1 0 8M18.5 5.5a9 9 0 0 1 0 13"/></svg>
    </button>
    <button class="ibtn" id="theme" title="Toggle light / dark" aria-label="Toggle theme">
      <svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
      <svg class="moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>
    </button>
  </div>
  <div class="wrap"><nav class="tabs" id="tabs"></nav></div>
</header>

<div class="wrap"><main id="view"></main></div>
<div class="modal" id="modal" hidden><div class="mcard" id="mcard"></div></div>
<div class="toast" id="toast" hidden></div>

<script>
(function () {
  "use strict";
  var view = document.getElementById("view"), tabsEl = document.getElementById("tabs");
  var liveEl = document.getElementById("live"), liveLabel = document.getElementById("live-label");
  var modal = document.getElementById("modal"), mcard = document.getElementById("mcard"), toastEl = document.getElementById("toast");
  var SCHEME = "https" + "://";

  // Clock
  function tick() { var d = new Date(), p = function (n) { return (n < 10 ? "0" : "") + n; }; document.getElementById("clock").textContent = p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds()); }
  tick(); setInterval(tick, 1000);

  // Theme
  var rootEl = document.documentElement;
  try { var sv = localStorage.getItem("cti-theme"); if (sv === "light" || sv === "dark") rootEl.setAttribute("data-theme", sv); } catch (e) {}
  document.getElementById("theme").onclick = function () {
    var cur = rootEl.getAttribute("data-theme"); if (!cur) cur = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    var next = cur === "dark" ? "light" : "dark"; rootEl.setAttribute("data-theme", next); try { localStorage.setItem("cti-theme", next); } catch (e) {}
  };

  // Icons
  var ICONS = {
    overview: '<path d="M4 13h6V4H4zM14 20h6V4h-6zM4 20h6v-4H4z"/>', all: '<path d="M4 6h16M4 12h16M4 18h10"/>',
    ransomware: '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    redflag: '<path d="M5 21V4M5 4h12l-2.4 3.4L17 11H5"/>',
    rss: '<circle cx="6" cy="18" r="1.5"/><path d="M5 11a8 8 0 0 1 8 8M5 5a14 14 0 0 1 14 14"/>',
    vuln: '<path d="M12 3l8 3v6c0 4.5-3.2 7.6-8 9-4.8-1.4-8-4.5-8-9V6z"/><path d="M12 9v4M12 16h.01"/>',
    ioc: '<circle cx="12" cy="12" r="7"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>',
    other: '<circle cx="12" cy="12" r="2.3"/><path d="M7 8a6 6 0 0 0 0 8M17 8a6 6 0 0 1 0 8"/>',
    ai: '<path d="M12 3l1.8 4.2L18 9l-4.2 1.8L12 15l-1.8-4.2L6 9l4.2-1.8z"/><path d="M18 15l.9 2.1L21 18l-2.1.9L18 21l-.9-2.1L15 18l2.1-.9z"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
    open: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
    down: '<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>', up: '<path d="M12 19V6M6 12l6-6 6 6"/>', dn: '<path d="M12 5v13M18 12l-6 6-6-6"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>', info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>'
  };
  function svg(k, cls) { return '<svg class="' + (cls || "ic") + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + (ICONS[k] || ICONS.other) + "</svg>"; }

  // Helpers
  function kind(s) { s = (s || "").toLowerCase();
    if (s.indexOf("ransomware") >= 0) return "ransomware";
    if (s.indexOf("red.flag") >= 0 || s.indexOf("redflag") >= 0) return "redflag";
    if (s.indexOf("cisa.kev") >= 0 || s.indexOf("kev") === 0) return "vuln";
    if (s.indexOf("abuse.ch") >= 0 || s.indexOf("ioc") === 0) return "ioc";
    if (s.indexOf("rss:") === 0) return "rss"; return "other"; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function reEsc(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
  function fmt(n) { return (n || 0).toLocaleString(); }
  function tOf(e) { return e.published_at || e.first_seen_at || ""; }
  function relTime(iso) { if (!iso) return ""; var t = Date.parse(iso); if (isNaN(t)) return ""; var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 60) return Math.floor(s) + "s"; if (s < 3600) return Math.floor(s / 60) + "m"; if (s < 86400) return Math.floor(s / 3600) + "h"; return Math.floor(s / 86400) + "d"; }
  function highlight(x, terms) { if (!S.inv || !terms.length) return x; var p = terms.filter(Boolean).map(reEsc).join("|"); if (!p) return x;
    try { return x.replace(new RegExp("(" + p + ")", "ig"), "<mark>$1</mark>"); } catch (e) { return x; } }
  function invMatch(e) { if (!invTerms.length) return false; var h = ((e.title || "") + " " + (e.summary || "") + " " + JSON.stringify(e.meta || {})).toLowerCase();
    for (var i = 0; i < invTerms.length; i++) if (invTerms[i] && h.indexOf(invTerms[i].toLowerCase()) >= 0) return true; return false; }
  function critScore(e) { var k = kind(e.source), m = e.meta || {};
    if (k === "ransomware") return 100; if (k === "vuln") return m.ransomware_use ? 95 : 78; if (k === "redflag") return 60;
    if (k === "ioc") return m.status === "online" ? 55 : 42; if (k === "rss") return 20; return 10; }
  function isCrit(e) { var k = kind(e.source); return k === "ransomware" || (k === "vuln" && (e.meta || {}).ransomware_use); }
  function indicator(e) { var m = e.meta || {}; return m.ioc || m.cve || ""; }
  function summ(e) { var s = (e.summary || "").trim(); return (!s || s.toLowerCase() === "n/a") ? "" : s; }
  function renderBrief(text) {
    var lines = String(text || "").split(/\r?\n/), out = "", inList = false;
    function cl() { if (inList) { out += "</ul>"; inList = false; } }
    lines.forEach(function (raw) { var line = raw.replace(/\*\*/g, "").replace(/__/g, "").trim(); if (!line) { cl(); return; }
      var m = line.match(/^(?:[-*•]|\d+[.)])\s+(.*)$/);
      if (m) { if (!inList) { out += "<ul>"; inList = true; } out += "<li>" + esc(m[1].replace(/[*_`]/g, "")) + "</li>"; }
      else { cl(); out += "<p>" + esc(line.replace(/^#+\s*/, "").replace(/[*_`]/g, "")) + "</p>"; } });
    cl(); return out || "<p>" + esc(text) + "</p>";
  }
  function sparkPaths(v, w, h) { var n = v.length; if (!n) return { l: "", a: "" }; var max = 1, i; for (i = 0; i < n; i++) if (v[i] > max) max = v[i];
    var line = ""; for (var j = 0; j < n; j++) { var x = n > 1 ? (j / (n - 1)) * w : 0, y = h - 1 - (v[j] / max) * (h - 2); line += (j === 0 ? "M" : "L") + x.toFixed(1) + " " + y.toFixed(1) + " "; }
    return { l: line.trim(), a: "M0 " + h + " " + line.replace(/^M/, "L") + "L" + w + " " + h + " Z" }; }
  function toast(m) { toastEl.textContent = m; toastEl.hidden = false; clearTimeout(toast._t); toast._t = setTimeout(function () { toastEl.hidden = true; }, 1500); }
  function copy(text) { function done() { toast("copied " + text); }
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).then(done, fb); } else fb();
    function fb() { var ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0"; document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); done(); } catch (e) { toast("copy failed"); } document.body.removeChild(ta); } }
  function download(name, text, mime) { var b = new Blob([text], { type: mime }), u = URL.createObjectURL(b), a = document.createElement("a"); a.href = u; a.download = name; document.body.appendChild(a); a.click(); document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(u); }, 1000); }

  // State
  var S = { tab: "overview", q: "", sort: "new", range: "all", period: "7d", inv: false, sound: false, filters: {} };
  var MAX = 800, store = [], byCid = {}, cidSeq = 0, stats = null, loaded = false;
  var meta = { inventory: { enabled: false, terms: [] }, llm: { enabled: false } }, invTerms = [], aiOn = false;
  var paused = false, pending = [];

  var TABS = [
    { id: "overview", label: "Overview", ic: "overview" },
    { id: "all", label: "Live feed", ic: "all", kinds: null, filters: [{ id: "source", label: "Source", get: function (e) { return e.source; } }] },
    { id: "ransomware", label: "Ransomware", ic: "ransomware", kinds: ["ransomware"], filters: [
      { id: "group", label: "Group", get: function (e) { return e.meta.group_name; } },
      { id: "country", label: "Country", get: function (e) { return e.meta.country_display; } },
      { id: "sector", label: "Sector", get: function (e) { return e.meta.activity; } }] },
    { id: "rss", label: "RSS", ic: "rss", kinds: ["rss"], filters: [
      { id: "feed", label: "Feed", get: function (e) { return e.source; } },
      { id: "tag", label: "Tag", getMulti: function (e) { return e.tags || []; } }] },
    { id: "redflag", label: "Red flags", ic: "redflag", kinds: ["redflag"], filters: [] },
    { id: "vuln", label: "Vulnerabilities", ic: "vuln", kinds: ["vuln"],
      filters: [{ id: "vendor", label: "Vendor", get: function (e) { return e.meta.vendor; } }],
      toggles: [{ id: "ransomOnly", label: "Ransom-linked", test: function (e) { return !!e.meta.ransomware_use; } }] },
    { id: "ioc", label: "IOCs", ic: "ioc", kinds: ["ioc"], filters: [
      { id: "malware", label: "Malware", get: function (e) { return e.meta.malware; } },
      { id: "type", label: "Type", get: function (e) { return e.meta.ioc_type; } }] }
  ];
  function tabDef(id) { for (var i = 0; i < TABS.length; i++) if (TABS[i].id === id) return TABS[i]; return TABS[0]; }
  function tabCount(t) { if (!t.kinds) return store.length; var n = 0; for (var i = 0; i < store.length; i++) if (t.kinds.indexOf(kind(store[i].source)) >= 0) n++; return n; }

  // URL state
  function readURL() { var p = new URLSearchParams(location.search);
    if (p.get("tab")) S.tab = p.get("tab"); S.q = p.get("q") || ""; S.sort = p.get("sort") || "new"; S.range = p.get("range") || "all";
    S.period = p.get("period") || "7d"; S.inv = p.get("inv") === "1"; S.sound = p.get("sound") === "1";
    var t = tabDef(S.tab), fs = S.filters[S.tab] = S.filters[S.tab] || {};
    (t.filters || []).forEach(function (f) { if (p.get("f_" + f.id)) fs[f.id] = p.get("f_" + f.id); });
    (t.toggles || []).forEach(function (tg) { if (p.get("t_" + tg.id) === "1") fs[tg.id] = true; }); }
  function writeURL() { var p = new URLSearchParams(); if (token) p.set("token", token); p.set("tab", S.tab);
    if (S.q) p.set("q", S.q); if (S.sort !== "new") p.set("sort", S.sort); if (S.range !== "all") p.set("range", S.range);
    if (S.tab === "overview" && S.period !== "7d") p.set("period", S.period); if (S.inv) p.set("inv", "1"); if (S.sound) p.set("sound", "1");
    var t = tabDef(S.tab), fs = S.filters[S.tab] || {};
    (t.filters || []).forEach(function (f) { if (fs[f.id]) p.set("f_" + f.id, fs[f.id]); });
    (t.toggles || []).forEach(function (tg) { if (fs[tg.id]) p.set("t_" + tg.id, "1"); });
    try { history.replaceState(null, "", location.pathname + "?" + p.toString()); } catch (e) {} }

  function ingest(e, fresh) { if (!e || !e.source) return; e.meta = e.meta || {}; e._cid = "c" + (cidSeq++); e._fresh = !!fresh;
    byCid[e._cid] = e; store.unshift(e); if (store.length > MAX) { var g = store.pop(); if (g) delete byCid[g._cid]; }
    if (fresh && S.sound && isCrit(e)) beep(); }

  var actx = null;
  function beep() { try { actx = actx || new (window.AudioContext || window.webkitAudioContext)(); var o = actx.createOscillator(), g = actx.createGain();
    o.type = "sine"; o.frequency.value = 880; o.connect(g); g.connect(actx.destination);
    g.gain.setValueAtTime(0.0001, actx.currentTime); g.gain.exponentialRampToValueAtTime(0.12, actx.currentTime + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, actx.currentTime + 0.34);
    o.start(); o.stop(actx.currentTime + 0.35); } catch (e) {} }
  var soundBtn = document.getElementById("sound");
  soundBtn.onclick = function () { S.sound = !S.sound; soundBtn.classList.toggle("on", S.sound); if (S.sound) beep(); writeURL(); };

  function renderTabs() { tabsEl.innerHTML = ""; TABS.forEach(function (t) { var b = document.createElement("button");
    b.className = "tab" + (S.tab === t.id ? " active" : ""); var cnt = t.id === "overview" ? "" : ' <span class="cnt">' + tabCount(t) + "</span>";
    b.innerHTML = svg(t.ic) + "<span>" + t.label + "</span>" + cnt; b.onclick = function () { S.tab = t.id; scrollTo(0, 0); render(); }; tabsEl.appendChild(b); }); }

  // Overview
  var CAT = [{ k: "ransomware", label: "Ransomware" }, { k: "vuln", label: "Vulnerabilities" }, { k: "ioc", label: "IOCs" }, { k: "redflag", label: "Red flags" }, { k: "rss", label: "RSS / news" }, { k: "other", label: "Other" }];
  function deltaChip(cur, prev) { if (!prev && !cur) return ""; var cls, ic, txt;
    if (prev === 0) { cls = cur > 0 ? "up" : "flat"; ic = cur > 0 ? "up" : ""; txt = cur > 0 ? "new" : "="; }
    else { var pct = Math.round(((cur - prev) / prev) * 100); cls = pct > 0 ? "up" : (pct < 0 ? "down" : "flat"); ic = pct > 0 ? "up" : (pct < 0 ? "dn" : ""); txt = (pct > 0 ? "+" : "") + pct + "%"; }
    return '<span class="delta ' + cls + '">' + (ic ? svg(ic) : "") + txt + "</span>"; }
  function bars(rows, tone) { var max = 1; rows.forEach(function (r) { if (r.v > max) max = r.v; }); var o = '<div class="bl">';
    rows.forEach(function (r) { o += '<div class="br" style="--tone:' + (tone ? tone(r) : "var(--accent)") + '"><span class="lbl">' + (r.dot ? '<span class="cdot"></span>' : "") + esc(r.label) +
      '</span><span class="trk"><span class="fil" style="width:' + Math.round((r.v / max) * 100) + '%"></span></span><span class="n">' + fmt(r.v) + "</span></div>"; }); return o + "</div>"; }
  function chartData() { var s = stats || {};
    if (S.period === "24h") return { pts: (s.activity_hourly || []).map(function (d) { return { label: d.hour.slice(11) + "h", v: d.count }; }), x0: "-24h", x1: "now" };
    var daily = s.activity || [], slice = S.period === "7d" ? daily.slice(-7) : daily;
    return { pts: slice.map(function (d) { return { label: d.date.slice(5), v: d.count }; }), x0: (slice[0] || { date: "" }).date.slice(5), x1: "today" }; }
  function panel(title, hint, body) { return '<div class="panel"><div class="ph"><h2>' + title + "</h2>" + (hint ? '<span class="hint">' + hint + "</span>" : "") + '</div><div class="pb">' + body + "</div></div>"; }
  function renderOverview() {
    var s = stats, win = (s && s.windows && s.windows[S.period]) || { cur: 0, prev: 0 };
    var perLabel = S.period === "24h" ? "24H" : (S.period === "7d" ? "7D" : "30D");
    var cd = chartData(), chartVals = cd.pts.map(function (p) { return p.v; });
    var dailyVals = (s ? s.activity || [] : []).map(function (d) { return d.count; });
    var critCount = store.filter(isCrit).length;

    var html = '<div class="ovbar"><h1>Operations overview</h1><div class="seg" id="period">' +
      ["24h", "7d", "30d"].map(function (p) { return '<button data-p="' + p + '"' + (S.period === p ? ' class="on"' : "") + ">" + p + "</button>"; }).join("") + "</div></div>";
    if (!loaded) { html += '<div class="strip">' + "123456".split("").map(function () { return '<div class="cell"><div class="sk sk-cell"></div></div>'; }).join("") + "</div>"; view.innerHTML = html; return; }

    var cells = [
      { k: "total", ic: "all", cl: "Total events", cv: s.total, spark: dailyVals.slice(-14) },
      { k: "new", ic: "rss", cl: "New · " + perLabel, cv: win.cur, delta: [win.cur, win.prev], spark: chartVals },
      { k: "crit", ic: "ransomware", cl: "Critical", cv: critCount },
      { k: "sources", ic: "vuln", cl: "Sources", cv: Object.keys(s.per_source || {}).length },
      { k: "sent", ic: "ai", cl: "Alerts sent", cv: (s.deliveries || {}).sent_ok || 0 },
      { k: "live", ic: "ioc", cl: "Live clients", cv: s.live_clients || 0 }
    ];
    html += '<div class="strip">';
    cells.forEach(function (c) { var sp = c.spark && c.spark.length ? sparkPaths(c.spark, 54, 16) : null;
      html += '<div class="cell" data-k="' + c.k + '"><div class="cl">' + svg(c.ic) + c.cl + '</div><div class="cv">' + fmt(c.cv) + '</div><div class="cx">' +
        (c.delta ? deltaChip(c.delta[0], c.delta[1]) : "") + (sp ? '<svg class="cspark" viewBox="0 0 54 16" preserveAspectRatio="none"><path class="a" d="' + sp.a + '"/><path class="l" d="' + sp.l + '"/></svg>' : "") + "</div></div>"; });
    html += "</div>";

    var max = 1; chartVals.forEach(function (v) { if (v > max) max = v; });
    var n = cd.pts.length, bw = 100 / Math.max(1, n), chart = '<svg id="chart" viewBox="0 0 100 40" preserveAspectRatio="none">';
    [0, 0.33, 0.66, 1].forEach(function (g) { chart += '<line class="g" x1="0" y1="' + (40 * g).toFixed(1) + '" x2="100" y2="' + (40 * g).toFixed(1) + '"/>'; });
    cd.pts.forEach(function (d, i) { var h = (d.v / max) * 37, x = i * bw + bw * 0.16, w = bw * 0.68, y = 40 - h; chart += '<rect class="bar" data-i="' + i + '" x="' + x.toFixed(2) + '" y="' + y.toFixed(2) + '" width="' + w.toFixed(2) + '" height="' + Math.max(0.4, h).toFixed(2) + '"></rect>'; });
    chart += "</svg>";
    html += '<div style="margin-top:12px">' + panel("Activity", '<span id="chart-read">peak ' + fmt(max) + " · " + esc(cd.x0) + " → " + esc(cd.x1) + "</span>", chart) + "</div>";

    var catRows = CAT.map(function (c) { return { k: c.k, label: c.label, v: (s.per_category || {})[c.k] || 0, dot: true }; }).filter(function (r) { return r.v > 0; }).sort(function (a, b) { return b.v - a.v; });
    var srcRows = Object.keys(s.per_source || {}).map(function (k) { return { label: k, v: s.per_source[k], dot: true, k: kind(k) }; }).sort(function (a, b) { return b.v - a.v; }).slice(0, 8);
    html += '<div class="cgrid">' + panel("Top sources", "", bars(srcRows, function (r) { return "var(--" + r.k + ")"; })) + panel("By category", "", bars(catRows, function (r) { return "var(--" + r.k + ")"; })) + "</div>";

    var groups = {}; store.forEach(function (e) { if (kind(e.source) === "ransomware") { var g = (e.meta || {}).group_name || "Unknown"; groups[g] = (groups[g] || 0) + 1; } });
    var grpRows = Object.keys(groups).map(function (g) { return { label: g, v: groups[g] }; }).sort(function (a, b) { return b.v - a.v; }).slice(0, 8);
    var grpBody = grpRows.length ? '<div class="dt groups">' + grpRows.map(function (r) { return '<div class="dtr"><span class="s">' + esc(r.label) + '</span><span class="n">' + fmt(r.v) + "</span></div>"; }).join("") + "</div>" : '<div class="empty" style="padding:20px 0">No ransomware events loaded.</div>';

    var sl = s.source_last || {};
    var hrows = Object.keys(s.per_source || {}).map(function (src) { var last = sl[src], age = last ? (Date.now() - Date.parse(last)) / 3600000 : 999; return { src: src, n: s.per_source[src], last: last, age: age }; }).sort(function (a, b) { return a.age - b.age; });
    var healthBody = '<div class="dt health">' + hrows.map(function (r) { var c = r.age < 6 ? "" : (r.age < 48 ? "stale" : "old");
      return '<div class="dtr"><span class="hdot ' + c + '"></span><span class="s">' + esc(r.src) + '</span><span class="n">' + fmt(r.n) + '</span><span class="a">' + (r.last ? relTime(r.last) + " ago" : "—") + "</span></div>"; }).join("") + "</div>";
    html += '<div class="cgrid2">' + panel("Ransomware groups", "most active", grpBody) + panel("Source health", "last event", healthBody) + "</div>";

    var crit = store.filter(isCrit).slice(0, 7); if (!crit.length) crit = store.filter(function (e) { return ["ransomware", "vuln", "redflag"].indexOf(kind(e.source)) >= 0; }).slice(0, 7);
    var critBody = crit.length ? crit.map(function (e) { var k = kind(e.source); return '<div class="critline" data-cid="' + e._cid + '" style="--tone:var(--' + k + ')"><span class="tk"></span><span class="lt mono" style="color:var(--faint)">' + relTime(tOf(e)) + '</span><span class="lsrc" style="color:var(--' + k + ')">' + svg(k) + "<span>" + esc(e.source) + '</span></span><span class="tt">' + esc(e.title || "") + "</span></div>"; }).join("") : '<div class="empty" style="padding:20px 0">Nothing critical yet.</div>';
    html += '<div style="margin-top:12px">' + panel("Latest critical", "", critBody) + "</div>";
    view.innerHTML = html;

    view.querySelectorAll("#period button").forEach(function (b) { b.onclick = function () { S.period = this.getAttribute("data-p"); writeURL(); renderOverview(); }; });
    var read = document.getElementById("chart-read");
    view.querySelectorAll("#chart .bar").forEach(function (r) { r.addEventListener("mouseenter", function () { var p = cd.pts[+this.getAttribute("data-i")]; if (read && p) read.textContent = p.label + " · " + fmt(p.v) + " events"; }); });
    var ce = document.getElementById("chart"); if (ce) ce.addEventListener("mouseleave", function () { if (read) read.textContent = "peak " + fmt(max) + " · " + cd.x0 + " → " + cd.x1; });
    view.querySelectorAll(".critline").forEach(function (r) { r.onclick = function () { openDetail(byCid[this.getAttribute("data-cid")]); }; });
  }

  // Feed
  function uniq(events, f, multi) { var seen = {}, out = []; events.forEach(function (e) { (multi ? (f(e) || []) : [f(e)]).forEach(function (v) { if (v && !seen[v]) { seen[v] = 1; out.push(v); } }); }); return out.sort(); }
  function withinRange(e) { if (S.range === "all") return true; var t = Date.parse(tOf(e)); if (isNaN(t)) return true; var h = { "24h": 24, "7d": 168, "30d": 720 }[S.range] || 1e9; return (Date.now() - t) <= h * 3600000; }
  function tags(e, k, m) { var o = "";
    if (k === "vuln") { if (m.vendor) o += '<span class="tg">' + esc(m.vendor + (m.product ? "·" + m.product : "")) + "</span>"; if (m.ransomware_use) o += '<span class="tg warn">ransom</span>'; if (m.due_date) o += '<span class="tg">due ' + esc(m.due_date) + "</span>"; }
    else if (k === "ransomware") { if (m.country_display) o += '<span class="tg">' + esc((m.country_flag ? m.country_flag + " " : "") + m.country_display) + "</span>"; if (m.activity) o += '<span class="tg">' + esc(m.activity) + "</span>"; }
    else if (k === "ioc") { if (m.malware) o += '<span class="tg warn">' + esc(m.malware) + "</span>"; if (m.ioc_type) o += '<span class="tg">' + esc(m.ioc_type) + "</span>"; if (m.status) o += '<span class="tg' + (m.status === "online" ? " on" : "") + '">' + esc(m.status) + "</span>"; }
    else if (k === "rss" && e.tags) e.tags.slice(0, 2).forEach(function (t) { o += '<span class="tg">' + esc(t) + "</span>"; });
    return o; }
  function rowHTML(e) {
    var k = kind(e.source), m = e.meta || {}, ind = "";
    if (k === "vuln" && m.cve) ind = '<span class="ind">' + esc(m.cve) + "</span>";
    else if (k === "ioc" && m.ioc) ind = '<span class="ind">' + esc(m.ioc) + "</span>";
    else if (k === "ransomware" && m.group_name) ind = '<span class="ind">' + esc(m.group_name) + "</span>";
    var titleTxt = highlight(esc(e.title || e.url || "(untitled)"), invTerms);
    var acts = "";
    if (indicator(e)) acts += '<button class="la" data-copy="' + esc(indicator(e)) + '" title="Copy">' + svg("copy") + "</button>";
    if (aiOn) acts += '<button class="la ai" data-ai="' + e._cid + '" title="AI brief">' + svg("ai") + "</button>";
    acts += '<button class="la" data-detail="' + e._cid + '" title="Details">' + svg("info") + "</button>";
    return '<div class="ln' + (S.inv && invMatch(e) ? " inv-hit" : "") + '" data-k="' + k + '" data-cid="' + e._cid + '">' +
      '<span class="tk"></span><span class="lt">' + relTime(tOf(e)) + '</span>' +
      '<span class="lsrc">' + svg(k) + "<span>" + esc(e.source) + "</span></span>" +
      '<span class="ev">' + ind + '<span class="tt">' + titleTxt + '</span><span class="tags">' + tags(e, k, m) + "</span></span>" +
      '<span class="lact">' + acts + "</span></div>";
  }
  function currentItems(t) { var fs = S.filters[t.id] || (S.filters[t.id] = {}), q = S.q.trim().toLowerCase();
    var items = store.filter(function (e) { if (t.kinds && t.kinds.indexOf(kind(e.source)) < 0) return false; if (S.inv && !invMatch(e)) return false; if (!withinRange(e)) return false;
      var ok = true; (t.filters || []).forEach(function (f) { var v = fs[f.id]; if (!v) return; if (f.getMulti) { if ((f.getMulti(e) || []).indexOf(v) < 0) ok = false; } else if (f.get(e) !== v) ok = false; });
      (t.toggles || []).forEach(function (tg) { if (fs[tg.id] && !tg.test(e)) ok = false; });
      if (ok && q) { if ((((e.title || "") + " " + (e.summary || "") + " " + JSON.stringify(e.meta || {})).toLowerCase()).indexOf(q) < 0) ok = false; } return ok; });
    if (S.sort === "old") items = items.slice().reverse();
    else if (S.sort === "crit") items = items.slice().sort(function (a, b) { return critScore(b) - critScore(a) || (Date.parse(tOf(b)) - Date.parse(tOf(a))); });
    return items; }
  function renderFeed(t) {
    var fs = S.filters[t.id] || (S.filters[t.id] = {}), base = store.filter(function (e) { return !t.kinds || t.kinds.indexOf(kind(e.source)) >= 0; }), items = currentItems(t);
    var html = '<div class="toolbar"><label class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/></svg>' +
      '<input type="search" id="q" placeholder="filter…  ( / )" value="' + esc(S.q) + '"></label>';
    (t.filters || []).forEach(function (f) { var opts = uniq(base, f.get || f.getMulti, !!f.getMulti);
      html += '<select class="f" data-f="' + f.id + '"><option value="">' + esc(f.label) + " · all</option>" + opts.map(function (o) { return '<option value="' + esc(o) + '"' + (fs[f.id] === o ? " selected" : "") + ">" + esc(o) + "</option>"; }).join("") + "</select>"; });
    (t.toggles || []).forEach(function (tg) { html += '<button class="b' + (fs[tg.id] ? " on" : "") + '" data-toggle="' + tg.id + '">' + esc(tg.label) + "</button>"; });
    html += '<select class="f" id="range">' + [["all", "any time"], ["24h", "24h"], ["7d", "7d"], ["30d", "30d"]].map(function (o) { return '<option value="' + o[0] + '"' + (S.range === o[0] ? " selected" : "") + ">" + o[1] + "</option>"; }).join("") + "</select>";
    html += '<select class="f" id="sort">' + [["new", "newest"], ["old", "oldest"], ["crit", "criticality"]].map(function (o) { return '<option value="' + o[0] + '"' + (S.sort === o[0] ? " selected" : "") + ">" + o[1] + "</option>"; }).join("") + "</select>";
    html += '<span class="spacer"></span><span class="rescount">' + fmt(items.length) + " rows</span>";
    if (meta.inventory && meta.inventory.enabled) html += '<button class="b' + (S.inv ? " on" : "") + '" id="inv" title="Match only my inventory">' + svg("vuln") + "INV</button>";
    html += '<button class="b" id="csv" title="Export CSV">' + svg("down") + 'CSV</button>';
    html += '<button class="b" id="json" title="Export JSON">JSON</button>';
    html += '<button class="b" id="pause">' + (paused ? "resume" : "pause") + "</button></div>";

    html += '<div class="log"><div class="logh"><span></span><span>TIME</span><span class="h-src">SOURCE</span><span>EVENT</span><span></span></div>';
    if (!loaded) html += "12345678".split("").map(function () { return '<div class="sk sk-row"></div>'; }).join("");
    else if (items.length) html += items.map(rowHTML).join("");
    else html += '<div class="empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/></svg><span class="big">' + (base.length ? "No rows match your filters." : "Waiting for events…") + "</span>" + (base.length ? "Adjust filters, range or search." : "Connected sources stream in here.") + "</div>";
    html += "</div>";
    view.innerHTML = html;

    var qi = document.getElementById("q"); if (qi) qi.oninput = function () { S.q = this.value; writeURL(); scheduleRender(); };
    view.querySelectorAll("select.f[data-f]").forEach(function (sel) { sel.onchange = function () { fs[this.getAttribute("data-f")] = this.value; writeURL(); render(); }; });
    view.querySelectorAll("[data-toggle]").forEach(function (b) { b.onclick = function () { var id = this.getAttribute("data-toggle"); fs[id] = !fs[id]; writeURL(); render(); }; });
    var rg = document.getElementById("range"); if (rg) rg.onchange = function () { S.range = this.value; writeURL(); render(); };
    var so = document.getElementById("sort"); if (so) so.onchange = function () { S.sort = this.value; writeURL(); render(); };
    var inv = document.getElementById("inv"); if (inv) inv.onclick = function () { S.inv = !S.inv; writeURL(); render(); };
    var csv = document.getElementById("csv"); if (csv) csv.onclick = function () { exportCSV(items); };
    var js = document.getElementById("json"); if (js) js.onclick = function () { download("cassandra-" + t.id + ".json", JSON.stringify(items.map(cleanEv), null, 2), "application/json"); };
    var pb = document.getElementById("pause"); if (pb) pb.onclick = function () { paused = !paused; liveEl.classList.toggle("paused", paused); liveLabel.textContent = paused ? "paused" : "live"; if (!paused) { pending.forEach(function (e) { ingest(e, true); }); pending = []; render(); pollStats(); } else render(); };
  }
  function cleanEv(e) { return { source: e.source, title: e.title, url: e.url, summary: e.summary, published_at: e.published_at, tags: e.tags, meta: e.meta }; }
  function exportCSV(items) { var cols = ["source", "kind", "title", "url", "published_at", "indicator", "malware", "group", "vendor", "product", "ransomware_use"], rows = [cols.join(",")];
    items.forEach(function (e) { var m = e.meta || {}; rows.push([e.source, kind(e.source), e.title, e.url || "", tOf(e), indicator(e), m.malware || "", m.group_name || "", m.vendor || "", m.product || "", m.ransomware_use ? "yes" : ""].map(function (v) { return '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"'; }).join(",")); });
    download("cassandra-" + S.tab + ".csv", rows.join("\n"), "text/csv"); }

  // Detail
  var LBL = { cve: "CVE", vendor: "Vendor", product: "Product", due_date: "Due date", ransomware_use: "Ransomware", group_name: "Group", victim: "Victim", country_display: "Country", activity: "Sector", website: "Website", malware: "Malware", ioc: "Indicator", ioc_type: "Type", confidence: "Confidence", status: "Status", feed: "Feed" };
  var KVO = ["cve", "vendor", "product", "due_date", "ransomware_use", "group_name", "victim", "country_display", "activity", "malware", "ioc", "ioc_type", "confidence", "status", "website", "feed"];
  function kvrow(k, v, mono) { return '<div class="r"><span class="k">' + esc(k) + '</span><span class="v' + (mono ? " mono" : "") + '">' + v + "</span></div>"; }
  function openDetail(e) { if (!e) return; var k = kind(e.source), m = e.meta || {}, kv = "";
    KVO.forEach(function (key) { var v = m[key]; if (v === undefined || v === "" || v === null) return;
      if (key === "country_display") v = (m.country_flag ? m.country_flag + " " : "") + v; else if (key === "ransomware_use") v = v ? "Yes" : "No"; else if (key === "confidence") v = v + "%";
      kv += kvrow(LBL[key] || key, esc(String(v)), key === "ioc" || key === "cve"); });
    kv += kvrow("First seen", e.first_seen_at ? relTime(e.first_seen_at) + ' ago <span style="color:var(--faint)">· ' + esc(e.first_seen_at) + "</span>" : "—");
    kv += kvrow("Published", e.published_at ? relTime(e.published_at) + ' ago <span style="color:var(--faint)">· ' + esc(e.published_at) + "</span>" : "—");
    var links = "", ind = indicator(e);
    if (e.url) links += '<a class="primary" href="' + esc(e.url) + '" target="_blank" rel="noopener noreferrer">' + svg("open") + "Open source</a>";
    if (m.cve) links += '<a href="' + SCHEME + "nvd.nist.gov/vuln/detail/" + encodeURIComponent(m.cve) + '" target="_blank" rel="noopener noreferrer">' + svg("open") + "NVD</a>";
    if (m.ioc) links += '<a href="' + SCHEME + "www.virustotal.com/gui/search/" + encodeURIComponent(m.ioc) + '" target="_blank" rel="noopener noreferrer">' + svg("open") + "VirusTotal</a>";
    if (m.leak_url) links += '<a href="' + esc(m.leak_url) + '" target="_blank" rel="noopener noreferrer">' + svg("open") + "Leak site</a>";
    var acts = ""; if (ind) acts += '<button data-copy="' + esc(ind) + '">' + svg("copy") + "Copy " + (m.cve ? "CVE" : "IOC") + "</button>";
    if (aiOn) acts += '<button class="ai" data-ai-modal="' + e._cid + '">' + svg("ai") + "AI brief</button>";
    var s = summ(e);
    mcard.innerHTML = '<div class="mtop" style="--tone:var(--' + k + ')"><span class="mt-src">' + svg(k) + esc(e.source) + '</span><span class="time">' + relTime(tOf(e)) + ' ago</span><span class="spacer"></span><button class="ibtn" id="mclose" aria-label="Close">' + svg("x") + '</button></div>' +
      '<div class="mbody"><h3>' + esc(e.title || "(untitled)") + "</h3>" + (s ? '<div class="msum">' + esc(s) + "</div>" : "") +
      '<div class="seclabel">Details</div><div class="kv">' + kv + "</div>" +
      (links ? '<div class="seclabel">Links</div><div class="lnk">' + links + "</div>" : "") +
      (acts ? '<div class="seclabel">Actions</div><div class="acts">' + acts + "</div>" : "") + "<div id='mai'></div></div>";
    modal.hidden = false; document.getElementById("mclose").onclick = closeDetail;
    var aib = mcard.querySelector("[data-ai-modal]"); if (aib) aib.onclick = function () { aiBrief(e, document.getElementById("mai")); };
  }
  function closeDetail() { modal.hidden = true; mcard.innerHTML = ""; }
  modal.addEventListener("click", function (e) { if (e.target === modal) closeDetail(); });
  mcard.addEventListener("click", function (e) { var cp = e.target.closest ? e.target.closest("[data-copy]") : null; if (cp) copy(cp.getAttribute("data-copy")); });

  function aiBrief(e, out) { if (!out) out = document.createElement("div"); out.className = "ai-out"; out.innerHTML = '<div class="ai-h">' + svg("ai") + "AI brief</div><p>Analyzing…</p>";
    fetch(withToken("/api/ai/summarize"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ event: cleanEv(e) }) })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) { if (res.ok && res.j.text) { out.className = "ai-out"; out.innerHTML = '<div class="ai-h">' + svg("ai") + "AI brief</div>" + renderBrief(res.j.text); } else { out.className = "ai-out err"; out.innerHTML = '<div class="ai-h">' + svg("ai") + "AI brief</div><p>" + esc(res.j.error || "AI request failed.") + "</p>"; } })
      .catch(function () { out.className = "ai-out err"; out.innerHTML = '<div class="ai-h">' + svg("ai") + "AI brief</div><p>Network error.</p>"; });
    return out; }

  view.addEventListener("click", function (e) { var t = e.target; if (!t.closest) return;
    var cp = t.closest("[data-copy]"); if (cp) { e.stopPropagation(); copy(cp.getAttribute("data-copy")); return; }
    var ab = t.closest("[data-ai]"); if (ab) { e.stopPropagation(); openDetail(byCid[ab.getAttribute("data-ai")]); setTimeout(function () { var mo = document.getElementById("mai"); if (mo) aiBrief(byCid[ab.getAttribute("data-ai")], mo); }, 0); return; }
    var db = t.closest("[data-detail]"); if (db) { e.stopPropagation(); openDetail(byCid[db.getAttribute("data-detail")]); return; }
    var ln = t.closest(".ln"); if (ln) openDetail(byCid[ln.getAttribute("data-cid")]); });

  document.addEventListener("keydown", function (e) { if (e.key === "Escape") { if (!modal.hidden) closeDetail(); return; }
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName || "")) return;
    if (e.key === "/") { var q = document.getElementById("q"); if (q) { e.preventDefault(); q.focus(); } return; }
    if (e.key >= "1" && e.key <= "7") { var i = +e.key - 1; if (TABS[i]) { S.tab = TABS[i].id; render(); } return; }
    if (e.key.toLowerCase() === "e") { var t = tabDef(S.tab); if (t.kinds !== undefined) exportCSV(currentItems(t)); } });

  var pf = false; function scheduleRender() { if (pf) return; pf = true; requestAnimationFrame(function () { pf = false; render(); }); }
  function render() { renderTabs(); writeURL(); var t = tabDef(S.tab); if (t.id === "overview") renderOverview(); else renderFeed(t); }

  var qs = new URLSearchParams(location.search), token = qs.get("token"), tokenQ = token ? "?token=" + encodeURIComponent(token) : "";
  function withToken(p) { return p + (token ? (p.indexOf("?") === -1 ? "?" : "&") + "token=" + encodeURIComponent(token) : ""); }
  function pollStats() { fetch(withToken("/api/stats")).then(function (r) { return r.ok ? r.json() : null; }).then(function (s) { if (s) { stats = s; if (S.tab === "overview" && loaded) renderOverview(); } }).catch(function () {}); }
  function loadMeta() { fetch(withToken("/api/meta")).then(function (r) { return r.ok ? r.json() : null; }).then(function (m) { if (!m) return; meta = m; invTerms = (m.inventory && m.inventory.terms) || []; aiOn = !!(m.llm && m.llm.enabled && (m.llm.available !== false)); render(); }).catch(function () {}); }

  readURL(); soundBtn.classList.toggle("on", S.sound); render();
  fetch(withToken("/api/events?limit=1000")).then(function (r) { return r.ok ? r.json() : { events: [] }; })
    .then(function (data) { (data.events || []).reverse().forEach(function (e) { ingest(e, false); }); loaded = true; render(); pollStats(); })
    .catch(function () { loaded = true; render(); });
  function connect() { var es = new EventSource("/api/stream" + tokenQ);
    es.onopen = function () { liveEl.classList.remove("err"); liveEl.classList.add("on"); liveLabel.textContent = paused ? "paused" : "live"; };
    es.onmessage = function (m) { var e; try { e = JSON.parse(m.data); } catch (x) { return; } if (paused) { pending.push(e); return; } ingest(e, true); scheduleRender(); };
    es.onerror = function () { liveEl.classList.remove("on"); liveEl.classList.add("err"); liveLabel.textContent = "reconnect"; es.close(); setTimeout(connect, 3000); }; }
  loadMeta(); connect(); pollStats(); setInterval(pollStats, 15000); setInterval(function () { if (S.tab !== "overview" && loaded) scheduleRender(); }, 30000);
})();
</script>
</body>
</html>
"""
