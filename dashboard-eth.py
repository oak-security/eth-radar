#!/usr/bin/env python3
"""
ETH Radar — Dashboard Server
Port: 18793
"""

import json
import os
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer as HTTPServer
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

# ── Data loading ──────────────────────────────────────────────────────────────

BASE = os.path.dirname(os.path.abspath(__file__))

def load_json(name):
    with open(os.path.join(BASE, name), encoding="utf-8") as f:
        return json.load(f)

findings_raw    = load_json("findings-merged-eth.json")

# ── SQLite in-memory DB ───────────────────────────────────────────────────────

def build_db(findings):
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("""
        CREATE TABLE findings (
            firm TEXT, report TEXT, date TEXT, title TEXT,
            severity TEXT, category TEXT, tech_stack TEXT
        )
    """)
    conn.executemany(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?)",
        [(f.get("firm",""), f.get("report","") or f.get("report_name",""),
          f.get("add_date","") or f.get("date",""), f.get("title",""),
          f.get("severity",""), f.get("category",""), f.get("tech_stack",""))
         for f in findings]
    )
    conn.execute("CREATE INDEX idx_firm ON findings(firm)")
    conn.execute("CREATE INDEX idx_sev  ON findings(severity)")
    conn.execute("CREATE INDEX idx_cat  ON findings(category)")
    conn.execute("CREATE INDEX idx_date ON findings(date)")
    conn.commit()
    return conn

DB = build_db(findings_raw)
DB_LOCK = threading.Lock()
stats           = load_json("stats-eth.json")
rekt_stats      = load_json("rekt-stats-eth.json")
rekt_incidents  = load_json("rekt-incidents-eth.json")

# ── Derived data (computed once at startup) ───────────────────────────────────

# Findings: normalise add_date → date
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

def findings_by_year_severity():
    """Returns {year: {severity: count}}"""
    agg = defaultdict(lambda: defaultdict(int))
    for f in findings_raw:
        d = f.get("add_date") or f.get("date", "")
        yr = d[:4] if d else "Unknown"
        sev = f.get("severity", "Unknown")
        agg[yr][sev] += 1
    return {yr: dict(v) for yr, v in sorted(agg.items())}

def top_categories(n=15):
    cats = defaultdict(int)
    for f in findings_raw:
        cats[f.get("category", "Other")] += 1
    return sorted(cats.items(), key=lambda x: -x[1])[:n]

def by_firm():
    firms = defaultdict(int)
    for f in findings_raw:
        firms[f.get("firm", "unknown")] += 1
    return sorted(firms.items(), key=lambda x: -x[1])

def by_tech_stack():
    ts = defaultdict(int)
    for f in findings_raw:
        ts[f.get("tech_stack", "Other")] += 1
    return sorted(ts.items(), key=lambda x: -x[1])

year_sev   = findings_by_year_severity()
top_cats   = top_categories(15)
firm_data  = by_firm()
stack_data = by_tech_stack()
sev_data   = sorted(stats["by_severity"].items(), key=lambda x: -x[1])

incidents = rekt_incidents["incidents"]

# Top 10 incidents by amount
top10_incidents = sorted(
    [i for i in incidents if isinstance(i.get("amount_usd"), (int, float))],
    key=lambda x: -x["amount_usd"]
)[:10]

# Incidents by year
inc_by_year = dict(sorted(rekt_stats["by_year"].items()))

# Top vuln types (merge near-duplicates)
raw_vuln = rekt_stats["by_vuln_type"]
vuln_merge = defaultdict(int)
for k, v in raw_vuln.items():
    if "Logic" in k:          vuln_merge["Logic Error / Business Logic"] += v
    elif "Oracle" in k or "Price Man" in k: vuln_merge["Oracle / Price Manipulation"] += v
    elif "Access" in k:       vuln_merge["Access Control"] += v
    elif "Unknown" in k.title(): vuln_merge["Unknown"] += v
    else:                      vuln_merge[k] += v
top_vuln = sorted(vuln_merge.items(), key=lambda x: -x[1])[:10]

# Filters for table dropdowns
all_firms    = sorted(set(f.get("firm","") for f in findings_raw if f.get("firm")))
all_sevs     = SEVERITY_ORDER
all_cats     = sorted(set(f.get("category","") for f in findings_raw if f.get("category")))
all_years    = sorted(set((f.get("add_date") or f.get("date",""))[:4] for f in findings_raw if (f.get("add_date") or f.get("date",""))))


# ── HTML page ─────────────────────────────────────────────────────────────────

def fmt_usd(n):
    if n >= 1e9:   return f"${n/1e9:.2f}B"
    if n >= 1e6:   return f"${n/1e6:.1f}M"
    if n >= 1e3:   return f"${n/1e3:.0f}K"
    return f"${n:.0f}"

def build_html():
    # JSON blobs for JS
    j_year_sev      = json.dumps(year_sev)
    j_top_cats      = json.dumps(top_cats)
    j_firm_data     = json.dumps(firm_data)
    j_stack_data    = json.dumps(stack_data)
    j_sev_data      = json.dumps(sev_data)
    j_top10         = json.dumps(top10_incidents)
    j_inc_by_year   = json.dumps(inc_by_year)
    j_top_vuln      = json.dumps(top_vuln)
    # findings and incidents are served via /findings and /incidents endpoints
    j_firms         = json.dumps(all_firms)
    j_sevs          = json.dumps(all_sevs)
    j_cats          = json.dumps(all_cats)
    j_years         = json.dumps(all_years)
    j_firm_details  = json.dumps(dict(firm_data))

    total_loss      = rekt_stats["total_loss_usd"]
    total_incidents = rekt_stats["total_incidents"]
    total_findings  = stats["total_findings"]
    total_firms_n   = stats["total_firms"]
    date_range      = stats["date_range"]
    ch_pct          = stats["critical_high_pct"]
    other_pct       = stats["other_pct"]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<base href="/">
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>ETH Radar</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f7f6f5;color:#1a1a1a;min-height:100vh;padding:24px 28px}}
a{{color:#168804;text-decoration:none}}
a:hover{{text-decoration:underline}}
h1{{font-size:1.55rem;font-weight:700;color:#000;letter-spacing:-.02em}}
h2{{font-size:1.05rem;font-weight:600;color:#333;margin-bottom:14px;letter-spacing:-.01em}}
header{{margin-bottom:20px;padding:32px 40px;border-radius:16px;background:#fff;box-shadow:0 2px 8px rgba(0,0,0,0.06)}}
header p{{color:#666;font-size:.82rem;margin-top:4px}}

/* Date range filter bar */
.filter-bar{{background:#fff;border-radius:10px;padding:14px 20px;margin-bottom:20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;box-shadow:0 1px 3px rgba(0,0,0,0.08)}}
.filter-bar label{{color:#666;font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em}}
.filter-bar select{{background:#f7f6f5;color:#1a1a1a;border:1px solid #ddd;border-radius:6px;padding:5px 10px;font-size:.82rem;outline:none;cursor:pointer}}
.filter-bar select:focus{{border-color:#168804}}
.filter-bar .range-display{{color:#168804;font-size:.85rem;font-weight:600;margin-left:4px}}
.filter-bar .sep{{color:#ccc}}
#resetBtn,#incResetBtn{{background:transparent;border:1px solid #ddd;color:#666;border-radius:6px;padding:5px 12px;font-size:.78rem;cursor:pointer;margin-left:auto}}
#resetBtn:hover,#incResetBtn:hover{{border-color:#168804;color:#168804}}

/* KPI strip */
.kpis{{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:28px}}
.kpi{{background:#fff;border-radius:10px;padding:14px 20px;flex:1;min-width:130px;box-shadow:0 1px 3px rgba(0,0,0,0.08)}}
.kpi-val{{font-size:1.55rem;font-weight:700;color:#000;line-height:1}}
.kpi-label{{font-size:.73rem;color:#666;margin-top:5px;text-transform:uppercase;letter-spacing:.06em}}
.kpi-sub{{font-size:.8rem;color:#888;margin-top:2px}}

/* Cards / grid */
.grid{{display:grid;gap:20px;margin-bottom:28px}}
.grid-2{{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}}
.grid-3{{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}}
.card{{background:#fff;border-radius:12px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,0.08)}}

/* Canvas charts */
canvas{{display:block;width:100%!important}}

/* Severity colours */
.sev-Critical{{color:#c0392b}}
.sev-High{{color:#e67e22}}
.sev-Medium{{color:#f1c40f}}
.sev-Low{{color:#3498db}}
.sev-Informational{{color:#95a5a6}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:600}}
.badge-Critical{{background:rgba(192,57,43,.25);color:#e74c3c}}
.badge-High{{background:rgba(230,126,34,.25);color:#e67e22}}
.badge-Medium{{background:rgba(241,196,15,.2);color:#f1c40f}}
.badge-Low{{background:rgba(52,152,219,.25);color:#5dade2}}
.badge-Informational{{background:rgba(149,165,166,.2);color:#bdc3c7}}

/* Incidents KPI row */
.inc-kpis{{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}}
.inc-kpi{{background:#fff;border-radius:8px;padding:12px 16px;flex:1;min-width:110px;box-shadow:0 1px 3px rgba(0,0,0,0.08)}}
.inc-kpi-val{{font-size:1.3rem;font-weight:700;color:#000}}
.inc-kpi-label{{font-size:.7rem;color:#666;margin-top:3px;text-transform:uppercase;letter-spacing:.06em}}

/* Incidents table */
.table-wrap{{overflow-x:auto;margin-top:20px}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
th{{text-align:left;padding:8px 10px;color:#666;font-weight:600;text-transform:uppercase;font-size:.68rem;letter-spacing:.05em;border-bottom:1px solid #ddd}}
td{{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top;color:#333}}
tr:hover td{{background:#f7f6f5}}
td.amt{{font-weight:700;color:#b45309;white-space:nowrap}}

/* Filter section */
.filters{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;align-items:center}}
select,input{{background:#fff;color:#1a1a1a;border:1px solid #ddd;border-radius:6px;padding:6px 10px;font-size:.8rem;outline:none}}
select:focus,input:focus{{border-color:#168804}}
input[type=text]{{flex:1;min-width:200px}}
.pagination{{display:flex;gap:8px;align-items:center;margin-top:14px;justify-content:flex-end}}
.pagination button{{background:#fff;color:#333;border:1px solid #ddd;border-radius:6px;padding:5px 12px;cursor:pointer;font-size:.8rem}}
.pagination button:hover{{background:#f7f6f5;border-color:#168804}}
.pagination button:disabled{{opacity:.4;cursor:default}}
.pg-info{{font-size:.8rem;color:#666}}
.findings-table td{{max-width:360px;white-space:normal;word-break:break-word}}
.findings-table td:first-child{{white-space:nowrap}}

/* Tab Navigation */
.tab-nav{{display:flex;gap:8px;margin:20px auto;max-width:1400px;padding:0 20px}}
.tab-btn{{background:#fff;color:#666;border:1px solid #ddd;border-radius:8px;padding:12px 24px;cursor:pointer;font-size:1rem;font-weight:600;transition:all .2s}}
.tab-btn:hover{{background:#f7f6f5;color:#333}}
.tab-btn.active{{background:#168804;color:#fff;border-color:#168804}}
.tab-content{{display:none}}
.tab-content.active{{display:block}}

/* Network Health Tab */
.network-header{{display:flex;justify-content:space-between;align-items:center;margin:20px auto;max-width:1400px;padding:0 20px}}
.network-header h2{{margin:0;color:#333}}
.refresh-info{{color:#666;font-size:.85rem}}
.network-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;max-width:1400px;margin:0 auto;padding:0 20px}}
.network-card{{background:#fff;border-radius:12px;padding:20px;border:1px solid #ddd;box-shadow:0 1px 3px rgba(0,0,0,0.08)}}
.network-card.healthy{{border-left:4px solid #168804}}
.network-card.busy{{border-left:4px solid #b45309}}
.network-card.congested{{border-left:4px solid #dc2626}}
.network-card.offline{{border-left:4px solid #999;opacity:.6}}
.network-name{{font-size:1.2rem;font-weight:700;color:#333;margin-bottom:12px;display:flex;align-items:center;gap:8px}}
.network-name .status-dot{{width:10px;height:10px;border-radius:50%;animation:pulse 2s infinite}}
.status-dot.green{{background:#168804}}
.status-dot.yellow{{background:#b45309}}
.status-dot.red{{background:#dc2626}}
.status-dot.gray{{background:#999}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.5}}}}
.network-stats{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.net-stat{{background:#f7f6f5;border-radius:8px;padding:12px}}
.net-stat-val{{font-size:1.4rem;font-weight:700;color:#333}}
.net-stat-label{{font-size:.75rem;color:#666;margin-top:2px}}
.net-stat-val.gas{{color:#403359}}
.net-stat-val.util-low{{color:#168804}}
.net-stat-val.util-mid{{color:#b45309}}
.net-stat-val.util-high{{color:#dc2626}}
.network-legend{{display:flex;gap:20px;justify-content:center;margin:24px auto;color:#666;font-size:.85rem}}
.legend-item{{display:flex;align-items:center;gap:6px}}
.dot{{width:10px;height:10px;border-radius:50%}}
.dot.green{{background:#168804}}
.dot.yellow{{background:#b45309}}
.dot.red{{background:#dc2626}}
.l2-badge{{background:#403359;color:#fff;font-size:.65rem;padding:2px 6px;border-radius:4px;margin-left:8px;font-weight:600}}
.network-note{{max-width:1400px;margin:0 auto 20px;padding:0 20px;color:#666;font-size:.85rem;line-height:1.5}}
.network-note strong{{color:#333}}

/* Security Alerts Tab */
.alerts-header{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin:20px auto;max-width:1000px;padding:0 20px}}
.alerts-header h2{{margin:0;color:#333}}
.alerts-controls{{display:flex;align-items:center;gap:16px;flex-wrap:wrap}}
.alerts-controls select{{background:#fff;color:#333;border:1px solid #ddd;border-radius:6px;padding:8px 12px;font-size:.9rem}}
.alerts-feed{{max-width:1000px;margin:0 auto;padding:0 20px}}
.alert-item{{background:#fff;border-radius:12px;padding:20px;margin-bottom:16px;border-left:4px solid #403359;transition:transform .2s;box-shadow:0 1px 3px rgba(0,0,0,0.08)}}
.alert-item:hover{{transform:translateX(4px)}}
.alert-item.peckshield{{border-left-color:#dc2626}}
.alert-item.zachxbt{{border-left-color:#403359}}
.alert-item.slowmist{{border-left-color:#168804}}
.alert-item.certik{{border-left-color:#f59e0b}}
.alert-item.scamsniffer{{border-left-color:#8b5cf6}}
.alert-item.rekt{{border-left-color:#000}}
.alert-meta{{display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap}}
.alert-source{{font-size:.75rem;padding:3px 8px;border-radius:4px;font-weight:600}}
.alert-source.peckshield{{background:#dc2626;color:#fff}}
.alert-source.zachxbt{{background:#403359;color:#fff}}
.alert-source.slowmist{{background:#168804;color:#fff}}
.alert-source.certik{{background:#f59e0b;color:#fff}}
.alert-source.scamsniffer{{background:#8b5cf6;color:#fff}}
.alert-source.rekt{{background:#000;color:#fff}}
.alert-date{{color:#666;font-size:.8rem}}
.alert-title{{font-size:1.1rem;font-weight:600;color:#e2e8f0;margin-bottom:8px}}
.alert-title a{{color:#e2e8f0;text-decoration:none}}
.alert-title a:hover{{color:#3b82f6}}
.alert-desc{{color:#333;font-size:.9rem;line-height:1.5}}
.alert-loading{{text-align:center;color:#64748b;padding:40px}}
.alerts-note{{max-width:1000px;margin:20px auto;padding:0 20px;color:#666;font-size:.85rem;text-align:center}}
.alerts-note a{{color:#168804}}

/* Tab Headers */
.tab-header{{max-width:1200px;margin:20px 0;padding:0}}
.tab-header h2{{margin:0;color:#333}}
.tab-header p{{color:#666;margin-top:4px;font-size:0.9rem}}

/* Incidents Tab */
.incidents-header{{max-width:1200px;margin:20px auto;padding:0 20px}}
.incidents-header h2{{margin:0;color:#333}}
</style>
</head>
<body>

<header>
  <div style="display:flex;align-items:center;gap:24px">
    <img src="logo.jpg" alt="ETH Radar" style="height:100px;width:100px;border-radius:16px;box-shadow:0 4px 12px rgba(0,0,0,0.15)">
    <div>
      <h1 style="font-size:2.2rem;margin:0;color:#000">ETH Radar</h1>
      <p style="color:#666;font-size:1rem;margin:6px 0 0 0">Ethereum Threat Intelligence Dashboard</p>
    </div>
  </div>
</header>

<!-- TAB NAVIGATION -->
<div class="tab-nav">
  <button class="tab-btn active" onclick="showTab('security')">🔒 Audit Findings</button>
  <button class="tab-btn" onclick="showTab('incidents')">⚡ Incident Data</button>
  <button class="tab-btn" onclick="showTab('network')">📡 Network Health</button>
  <button class="tab-btn" onclick="showTab('alerts')">🚨 Alert Aggregator</button>
</div>

<!-- SECURITY TAB -->
<div id="securityTab" class="tab-content active">

<div class="tab-header">
  <h2>🔒 Aggregated Audit Findings</h2>
  <p>Data from {date_range}</p>
</div>

<!-- DATE RANGE FILTER -->
<div class="filter-bar">
  <label>Date Range</label>
  <select id="yearFrom"></select>
  <span class="sep">→</span>
  <select id="yearTo"></select>
  <span class="range-display" id="rangeDisplay"></span>
  <button id="resetBtn" onclick="resetRange()">Reset</button>
</div>

<!-- KPI STRIP (dynamic) -->
<div class="kpis">
  <div class="kpi"><div class="kpi-val" id="kTotalFindings">—</div><div class="kpi-label">Total Findings</div></div>
  <div class="kpi"><div class="kpi-val" id="kFirms">{total_firms_n}</div><div class="kpi-label">Audit Firms</div></div>
  <div class="kpi"><div class="kpi-val" id="kCH">—</div><div class="kpi-label">Critical + High</div><div class="kpi-sub" id="kCHn"></div></div>
  <div class="kpi"><div class="kpi-val" id="kAvgPerReport">—</div><div class="kpi-label">Avg Findings / Report</div></div>
  <div class="kpi"><div class="kpi-val" id="kRekt">—</div><div class="kpi-label">Rekt Incidents</div></div>
  <div class="kpi"><div class="kpi-val" id="kLoss">—</div><div class="kpi-label">Total Losses</div></div>
</div>

<!-- PARTICIPATING FIRMS -->
<div class="card" style="margin-bottom:20px">
  <h2>Participating Firms</h2>
  <div id="firmChips" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:4px"></div>
</div>

<!-- ROW 1: Year chart + Severity donut -->
<div class="grid grid-2" style="margin-bottom:20px">
  <div class="card">
    <h2>Findings by Year — Severity Breakdown</h2>
    <canvas id="cYear" height="220"></canvas>
  </div>
  <div class="card">
    <h2>Severity Distribution</h2>
    <canvas id="cSev" height="220"></canvas>
  </div>
</div>

<!-- ROW 2: Categories + Tech Stack donut -->
<div class="grid grid-2" style="margin-bottom:20px">
  <div class="card">
    <h2>Top 15 Vulnerability Categories</h2>
    <canvas id="cCat" height="340"></canvas>
  </div>
</div>


</div><!-- END securityTab -->

<!-- INCIDENTS TAB -->
<div id="incidentsTab" class="tab-content">
  <div class="incidents-header">
    <h2>⚡ Real-World Incidents</h2>
    <p style="color:#64748b;margin-top:4px">Historical exploit and hack data · {date_range}</p>
  </div>

  <!-- DATE RANGE FILTER -->
  <div class="filter-bar" style="max-width:1200px;margin:20px auto;padding:0 20px">
    <label>Date Range</label>
    <select id="incYearFrom"></select>
    <span class="sep">→</span>
    <select id="incYearTo"></select>
    <span class="range-display" id="incRangeDisplay"></span>
    <button id="incResetBtn" onclick="resetIncidentRange()">Reset</button>
  </div>

  <!-- KPI row -->
  <div class="inc-kpis" style="max-width:1200px;margin:20px auto;padding:0 20px">
    <div class="inc-kpi"><div class="inc-kpi-val" id="incKpiTotal">{total_incidents}</div><div class="inc-kpi-label">Total Incidents</div></div>
    <div class="inc-kpi"><div class="inc-kpi-val" id="incKpiLoss">{fmt_usd(total_loss)}</div><div class="inc-kpi-label">Total Losses</div></div>
    <div class="inc-kpi"><div class="inc-kpi-val" id="incKpiPeak">{max(rekt_stats['by_year'].values())}</div><div class="inc-kpi-label">Peak Year</div></div>
    <div class="inc-kpi"><div class="inc-kpi-val" id="incKpiAvg">{fmt_usd(total_loss/total_incidents)}</div><div class="inc-kpi-label">Avg Loss/Incident</div></div>
  </div>

  <div class="grid grid-2" style="max-width:1200px;margin:0 auto 20px;padding:0 20px">
    <div class="card">
      <h2 style="font-size:.85rem;color:#94a3b8;margin-bottom:10px">Incidents by Year</h2>
      <canvas id="cIncYear" height="200"></canvas>
    </div>
    <div class="card">
      <h2 style="font-size:.85rem;color:#94a3b8;margin-bottom:10px">Top Vulnerability Types</h2>
      <canvas id="cVuln" height="200"></canvas>
    </div>
  </div>

  <div class="card" style="max-width:1200px;margin:0 auto 20px;padding:20px">
    <h2 style="font-size:.85rem;color:#94a3b8;margin-bottom:10px">Top 10 Incidents by Loss</h2>
    <div class="table-wrap">
      <table id="incTable">
        <thead><tr>
          <th>#</th><th>Protocol</th><th>Date</th><th>Loss</th><th>Vuln Type</th><th>Audit</th>
        </tr></thead>
        <tbody id="incBody"></tbody>
      </table>
    </div>
  </div>
</div><!-- END incidentsTab -->

<!-- NETWORK HEALTH TAB -->
<div id="networkTab" class="tab-content">
  <div class="network-header">
    <h2>📡 Live Network Status</h2>
    <div class="refresh-info">Auto-refreshes every 30s · <span id="lastUpdate">Loading...</span></div>
  </div>
  
  <div class="network-grid" id="networkGrid">
    <!-- Cards will be injected by JS -->
  </div>
  
  <div class="network-legend">
    <span class="legend-item"><span class="dot green"></span> Healthy (&lt;50% util)</span>
    <span class="legend-item"><span class="dot yellow"></span> Busy (50-80% util)</span>
    <span class="legend-item"><span class="dot red"></span> Congested (&gt;80% util)</span>
  </div>
  
  <div class="network-note">
    <strong>ℹ️ Note on L2 metrics:</strong> Layer 2 networks (marked with <span class="l2-badge" style="display:inline;vertical-align:middle">L2</span>) produce blocks differently than Ethereum mainnet. 
    Arbitrum creates blocks every ~0.25s, while Optimism/Base use ~2s blocks. 
    This means "utilization %" isn't meaningful for L2s (shown as N/A). 
    TPS (transactions per second) provides a better comparison across all networks.
  </div>
</div><!-- END networkTab -->

<!-- SECURITY ALERTS TAB -->
<div id="alertsTab" class="tab-content">
  <div class="alerts-header">
    <h2>🚨 Security Alerts Feed</h2>
    <div class="alerts-controls">
      <span class="refresh-info">Auto-refreshes every 7 min · <span id="alertsLastUpdate">Loading...</span></span>
    </div>
  </div>
  
  <div class="alerts-feed" id="alertsFeed">
    <div class="alert-loading">Loading security alerts...</div>
  </div>
  
  <div class="alerts-note">
  </div>
</div><!-- END alertsTab -->

<script>
// ── Colour palettes ───────────────────────────────────────────────────────────
const SEV_COLORS = {{
  Critical:"#c0392b", High:"#e67e22", Medium:"#f1c40f",
  Low:"#3498db", Informational:"#95a5a6"
}};
const PALETTE = [
  "#3498db","#2ecc71","#9b59b6","#e67e22","#1abc9c",
  "#e74c3c","#f39c12","#16a085","#8e44ad","#d35400",
  "#27ae60","#2980b9","#c0392b","#7f8c8d","#f1c40f",
  "#6c5ce7","#00cec9","#fd79a8","#55efc4","#fdcb6e",
  "#a29bfe","#74b9ff"
];

// ── Raw data (full, never mutated) ────────────────────────────────────────────
// findings and incidents loaded async from /findings and /incidents
let findings     = [];
let allIncidents = [];
const ALL_FIRMS  = {j_firms};
const ALL_SEVS   = {j_sevs};
const ALL_CATS   = {j_cats};
const ALL_YEARS  = {j_years};
const FIRM_DETAILS = {j_firm_details};

// ── Date range state ──────────────────────────────────────────────────────────
let rangeFrom = ALL_YEARS[0];
let rangeTo   = ALL_YEARS[ALL_YEARS.length - 1];


// Incidents-specific date range
let incRangeFrom = ALL_YEARS[0];
let incRangeTo   = ALL_YEARS[ALL_YEARS.length - 1];
function inRange(dateStr) {{
  if (!dateStr) return true;
  const yr = dateStr.slice(0,4);
  return yr >= rangeFrom && yr <= rangeTo;
}}

function filteredFindings() {{
  return findings.filter(f => inRange(f.date));
}}
function filteredIncidents() {{
  return allIncidents.filter(i => {{
    const yr = (i.date_iso||i.date||"").slice(0,4);
    return yr >= incRangeFrom && yr <= incRangeTo;
  }});
}}

// ── Aggregation helpers ───────────────────────────────────────────────────────
function aggYearSev(ff) {{
  const out = {{}};
  ff.forEach(f => {{
    const yr = (f.date||"").slice(0,4) || "Unknown";
    const sev = f.severity || "Unknown";
    if(!out[yr]) out[yr] = {{}};
    out[yr][sev] = (out[yr][sev]||0) + 1;
  }});
  return out;
}}
function aggTopCats(ff, n=15) {{
  const m = {{}};
  ff.forEach(f => {{ const c = f.category||"Other"; m[c]=(m[c]||0)+1; }});
  return Object.entries(m).sort((a,b)=>b[1]-a[1]).slice(0,n);
}}
function aggSev(ff) {{
  const m = {{}};
  ff.forEach(f => {{ const s = f.severity||"Unknown"; m[s]=(m[s]||0)+1; }});
  return Object.entries(m).sort((a,b)=>b[1]-a[1]);
}}
function aggStack(ff) {{
  const m = {{}};
  ff.forEach(f => {{ const s = f.tech_stack||"Unknown"; m[s]=(m[s]||0)+1; }});
  return Object.entries(m).sort((a,b)=>b[1]-a[1]);
}}
function aggIncYear(ii) {{
  const m = {{}};
  ii.forEach(i => {{
    const yr = (i.date_iso||i.date||"").slice(0,4);
    if(yr) m[yr]=(m[yr]||0)+1;
  }});
  return m;
}}
function aggVuln(ii, n=10) {{
  const m = {{}};
  ii.forEach(i => {{ const v=i.llm_vuln_type||i.vuln_type||"Unknown"; m[v]=(m[v]||0)+1; }});
  return Object.entries(m).sort((a,b)=>b[1]-a[1]).slice(0,n);
}}
function fmtUsd(n) {{
  if(n>=1e9) return "$"+(n/1e9).toFixed(2)+"B";
  if(n>=1e6) return "$"+(n/1e6).toFixed(1)+"M";
  if(n>=1e3) return "$"+(n/1e3).toFixed(0)+"K";
  return "$"+n.toFixed(0);
}}

// ── Canvas helpers ────────────────────────────────────────────────────────────
const DPR = window.devicePixelRatio || 1;
function ctx(id) {{
  const c = document.getElementById(id);
  const w = c.parentElement.offsetWidth - 40;
  c.width = w;
  c.style.width = w + 'px';
  return c.getContext('2d');
}}

function drawHBar(canvasId, labels, values, colors, maxVal) {{
  const cx = ctx(canvasId);
  const canvas = cx.canvas;
  const n = labels.length;
  const barH = 18, gap = 6, padL = 160, padR = 60, padT = 10, padB = 20;
  const h = n * (barH + gap) + padT + padB;
  canvas.height = h;
  cx.clearRect(0,0,canvas.width,h);
  const W = canvas.width;
  const barW = W - padL - padR;
  const max = maxVal || Math.max(...values);

  cx.font = "11px system-ui";
  cx.textBaseline = "middle";

  values.forEach((v,i) => {{
    const y = padT + i * (barH + gap);
    const bw = (v / max) * barW;
    // label
    cx.fillStyle = "#666";
    cx.textAlign = "right";
    const lbl = labels[i].length > 22 ? labels[i].slice(0,21)+"…" : labels[i];
    cx.fillText(lbl, padL - 6, y + barH/2);
    // bar
    cx.fillStyle = Array.isArray(colors) ? colors[i % colors.length] : colors;
    cx.beginPath();
    cx.roundRect(padL, y, Math.max(bw,2), barH, 3);
    cx.fill();
    // value
    cx.fillStyle = "#333";
    cx.textAlign = "left";
    cx.fillText(v.toLocaleString(), padL + bw + 5, y + barH/2);
  }});
}}

function drawStackedBar(canvasId, data) {{
  // data: {{{{year: {{{{sev: count}}}}}}
  const cx = ctx(canvasId);
  const canvas = cx.canvas;
  const years = Object.keys(data).sort();
  const sevs = ["Critical","High","Medium","Low","Informational"];
  const n = years.length;
  const padL = 40, padR = 20, padT = 30, padB = 40;
  const W = canvas.width;
  const barSlot = (W - padL - padR) / n;
  const barW = barSlot * 0.65;
  // compute totals for Y-axis
  const totals = years.map(yr => sevs.reduce((a,s) => a + (data[yr][s]||0), 0));
  const maxY = Math.max(...totals) * 1.05;
  const chartH = canvas.height - padT - padB;

  cx.clearRect(0,0,W,canvas.height);

  // Axes
  cx.strokeStyle = "#ddd"; cx.lineWidth = 1;
  for(let g=0;g<=4;g++) {{
    const y = padT + chartH * g/4;
    cx.beginPath(); cx.moveTo(padL,y); cx.lineTo(W-padR,y); cx.stroke();
    cx.fillStyle="#888"; cx.font="10px system-ui"; cx.textAlign="right"; cx.textBaseline="middle";
    cx.fillText(Math.round(maxY*(1-g/4)).toLocaleString(), padL-4, y);
  }}

  years.forEach((yr, xi) => {{
    const x = padL + xi * barSlot + (barSlot - barW)/2;
    let yOff = padT + chartH;
    sevs.forEach(sev => {{
      const cnt = data[yr][sev] || 0;
      if(!cnt) return;
      const bh = (cnt / maxY) * chartH;
      yOff -= bh;
      cx.fillStyle = SEV_COLORS[sev];
      cx.fillRect(x, yOff, barW, bh);
    }});
    // year label
    cx.fillStyle="#666"; cx.font="11px system-ui"; cx.textAlign="center"; cx.textBaseline="top";
    cx.fillText(yr, x + barW/2, padT + chartH + 5);
    // total label
    cx.fillStyle="#333"; cx.textBaseline="bottom";
    cx.fillText(totals[xi].toLocaleString(), x + barW/2, padT + chartH - (totals[xi]/maxY)*chartH - 2);
  }});

  // Legend
  const legX = padL; let lx = legX;
  cx.textBaseline="middle"; cx.font="10px system-ui";
  sevs.forEach(s => {{
    cx.fillStyle=SEV_COLORS[s]; cx.fillRect(lx,8,10,10);
    cx.fillStyle="#666"; cx.textAlign="left";
    cx.fillText(s, lx+13, 13);
    lx += cx.measureText(s).width + 28;
  }});
}}

function drawDonut(canvasId, labels, values, colors) {{
  const cx = ctx(canvasId);
  const canvas = cx.canvas;
  const W = canvas.width, H = canvas.height;
  cx.clearRect(0,0,W,H);
  const cx0 = W * 0.38, cy0 = H/2, r = Math.min(cx0, H/2) * 0.82, inner = r * 0.52;
  const total = values.reduce((a,b)=>a+b,0);
  let angle = -Math.PI/2;
  const cols = colors || PALETTE;

  values.forEach((v,i) => {{
    const sweep = (v/total) * 2 * Math.PI;
    cx.beginPath();
    cx.moveTo(cx0,cy0);
    cx.arc(cx0,cy0,r,angle,angle+sweep);
    cx.closePath();
    cx.fillStyle = cols[i%cols.length];
    cx.fill();
    angle += sweep;
  }});
  // hole
  cx.beginPath(); cx.arc(cx0,cy0,inner,0,2*Math.PI);
  cx.fillStyle="#f7f6f5"; cx.fill();
  // centre total
  cx.fillStyle="#333"; cx.font="bold 16px system-ui"; cx.textAlign="center"; cx.textBaseline="middle";
  cx.fillText(total.toLocaleString(), cx0, cy0);
  cx.font="10px system-ui"; cx.fillStyle="#666";
  cx.fillText("total", cx0, cy0+16);

  // Legend
  const legX = W * 0.72, legTop = 8;
  cx.font="11px system-ui"; cx.textBaseline="middle";
  const maxShow = Math.min(labels.length, Math.floor((H - 16) / 19));
  labels.slice(0,maxShow).forEach((lbl,i) => {{
    const ly = legTop + i * 19;
    cx.fillStyle = cols[i%cols.length];
    cx.fillRect(legX, ly + 4, 10, 10);
    cx.fillStyle="#666"; cx.textAlign="left";
    const pct = ((values[i]/total)*100).toFixed(1);
    const text = (lbl.length>18 ? lbl.slice(0,17)+"…" : lbl) + " " + pct + "%";
    cx.fillText(text, legX+14, ly+9);
  }});
}}

function drawSimpleBar(canvasId, labels, values, color) {{
  const cx = ctx(canvasId);
  const canvas = cx.canvas;
  const W = canvas.width, H = canvas.height;
  cx.clearRect(0,0,W,H);
  const n = labels.length;
  const padL = 40, padR = 20, padT = 20, padB = 30;
  const barSlot = (W-padL-padR)/n;
  const barW = barSlot*0.65;
  const max = Math.max(...values)*1.1;
  const chartH = H - padT - padB;

  // grid
  cx.strokeStyle="#ddd"; cx.lineWidth=1;
  [0,.5,1].forEach(f => {{
    const y = padT + chartH*(1-f);
    cx.beginPath(); cx.moveTo(padL,y); cx.lineTo(W-padR,y); cx.stroke();
    cx.fillStyle="#888"; cx.font="9px system-ui"; cx.textAlign="right"; cx.textBaseline="middle";
    cx.fillText(Math.round(max*f), padL-3, y);
  }});

  values.forEach((v,i) => {{
    const x = padL + i*barSlot + (barSlot-barW)/2;
    const bh = (v/max)*chartH;
    const y = padT + chartH - bh;
    cx.fillStyle = typeof color==="string" ? color : color[i%color.length];
    cx.fillRect(x, y, barW, bh);
    cx.fillStyle="#666"; cx.font="10px system-ui"; cx.textAlign="center"; cx.textBaseline="top";
    cx.fillText(labels[i], x+barW/2, padT+chartH+4);
    cx.fillStyle="#333"; cx.textBaseline="bottom";
    cx.fillText(v, x+barW/2, y-1);
  }});
}}

// ── Render charts + KPIs (all dynamic) ───────────────────────────────────────
function renderAll() {{
  const ff = filteredFindings();
  const ii = filteredIncidents();

  // KPIs
  const sevMap = {{}};
  ff.forEach(f => {{ const s=f.severity||"Unknown"; sevMap[s]=(sevMap[s]||0)+1; }});
  const ch = (sevMap.Critical||0)+(sevMap.High||0);
  const other = sevMap.Other||0;
  const totalLoss = ii.reduce((a,i)=>a+(i.amount_usd||0),0);
  document.getElementById("kTotalFindings").textContent = ff.length.toLocaleString();
  document.getElementById("kCH").textContent = ff.length ? (100*ch/ff.length).toFixed(1)+"%" : "—";
  document.getElementById("kCHn").textContent = ch.toLocaleString()+" findings";
  const reports = new Set(ff.map(f=>f.firm+"|"+f.report).filter(k=>k.length>1));
  const avgPerReport = reports.size ? (ff.length/reports.size).toFixed(1) : "—";
  document.getElementById("kAvgPerReport").textContent = avgPerReport;
  document.getElementById("kRekt").textContent = ii.length;
  document.getElementById("kLoss").textContent = fmtUsd(totalLoss);
  document.getElementById("rangeDisplay").textContent = rangeFrom===rangeTo ? rangeFrom : rangeFrom+" – "+rangeTo;

  // 1. Year stacked bar
  drawStackedBar("cYear", aggYearSev(ff));

  // 2. Severity donut
  const sevEntries = aggSev(ff);
  drawDonut("cSev", sevEntries.map(d=>d[0]), sevEntries.map(d=>d[1]),
            sevEntries.map(d=>SEV_COLORS[d[0]]||"#607d8b"));

  // 3. Top 15 categories
  const cats = aggTopCats(ff);
  drawHBar("cCat", cats.map(d=>d[0]), cats.map(d=>d[1]), PALETTE, null);

  // 5. Incidents by year
  const iy = aggIncYear(ii);
  const iyYears = Object.keys(iy).sort();
  drawSimpleBar("cIncYear", iyYears, iyYears.map(y=>iy[y]), "#e67e22");

  // 6. Top vuln types
  const vl = aggVuln(ii);
  drawHBar("cVuln", vl.map(d=>d[0]), vl.map(d=>d[1]), "#e74c3c", null);

  // 7. Top 10 incidents table
  renderIncidents(ii);
}}

// ── Incidents table ───────────────────────────────────────────────────────────
function renderIncidents(ii) {{
  const top10 = [...ii].sort((a,b)=>(b.amount_usd||0)-(a.amount_usd||0)).slice(0,10);
  const tbody = document.getElementById("incBody");
  tbody.innerHTML = top10.map((inc,i) => {{
    const amt = inc.amount_usd ? "$"+Number(inc.amount_usd).toLocaleString() : "N/A";
    const audit = inc.llm_audit_status||inc.audit_yn||inc.audit_status||"unknown";
    const auditBadge = /audited/i.test(audit) && !/un/i.test(audit)
      ? '<span style="color:#2ecc71">✓ Audited</span>'
      : /unaudited/i.test(audit) ? '<span style="color:#e74c3c">✗ Unaudited</span>'
      : '<span style="color:#64748b">—</span>';
    const title = inc.title.replace(/ - Rekt.*$/i,"").replace(/Rekt$/i,"").trim();
    return `<tr>
      <td style="color:#64748b">${{i+1}}</td>
      <td style="font-weight:600">${{title}}</td>
      <td style="color:#94a3b8;white-space:nowrap">${{inc.date_iso||inc.date||""}}</td>
      <td class="amt">${{amt}}</td>
      <td style="color:#94a3b8;font-size:.75rem">${{inc.llm_vuln_type||inc.vuln_type||"Unknown"}}</td>
      <td>${{auditBadge}}</td>
    </tr>`;
  }}).join("");
}}

// ── Firm chips ────────────────────────────────────────────────────────────────
function renderFirmChips() {{
  const container = document.getElementById("firmChips");
  ALL_FIRMS.forEach(firm => {{
    const count = FIRM_DETAILS[firm] || 0;
    const chip = document.createElement("div");
    chip.style.cssText = "background:#2d3248;border-radius:20px;padding:5px 12px;font-size:.78rem;color:#94a3b8;display:flex;gap:6px;align-items:center";
    chip.innerHTML = `<span style="color:#e2e8f0;font-weight:500">${{firm}}</span>`;
    container.appendChild(chip);
  }});
}}

// ── Date range controls ───────────────────────────────────────────────────────
function buildRangeControls() {{
  const fromEl = document.getElementById("yearFrom");
  const toEl   = document.getElementById("yearTo");
  ALL_YEARS.forEach(yr => {{
    const o1 = document.createElement("option"); o1.value=yr; o1.textContent=yr; fromEl.appendChild(o1);
    const o2 = document.createElement("option"); o2.value=yr; o2.textContent=yr; toEl.appendChild(o2);
  }});
  fromEl.value = rangeFrom;
  toEl.value   = rangeTo;
  fromEl.addEventListener("change", () => {{
    rangeFrom = fromEl.value;
    if(rangeTo < rangeFrom) {{ rangeTo = rangeFrom; toEl.value = rangeTo; }}
    renderAll();
  }});
  toEl.addEventListener("change", () => {{
    rangeTo = toEl.value;
    if(rangeFrom > rangeTo) {{ rangeFrom = rangeTo; fromEl.value = rangeFrom; }}
    renderAll();
  }});
}}

function resetRange() {{
  rangeFrom = ALL_YEARS[0];
  rangeTo   = ALL_YEARS[ALL_YEARS.length-1];
  document.getElementById("yearFrom").value = rangeFrom;
  document.getElementById("yearTo").value   = rangeTo;
  renderAll();
}}

// -- Incidents date range controls --
function buildIncidentRangeControls() {{
  const fromEl = document.getElementById("incYearFrom");
  const toEl   = document.getElementById("incYearTo");
  if (!fromEl || !toEl) return;
  ALL_YEARS.forEach(yr => {{
    const o1 = document.createElement("option"); o1.value=yr; o1.textContent=yr; fromEl.appendChild(o1);
    const o2 = document.createElement("option"); o2.value=yr; o2.textContent=yr; toEl.appendChild(o2);
  }});
  fromEl.value = incRangeFrom;
  toEl.value   = incRangeTo;
  fromEl.addEventListener("change", () => {{
    incRangeFrom = fromEl.value;
    if(incRangeTo < incRangeFrom) {{ incRangeTo = incRangeFrom; toEl.value = incRangeTo; }}
    renderIncidentsTab();
  }});
  toEl.addEventListener("change", () => {{
    incRangeTo = toEl.value;
    if(incRangeFrom > incRangeTo) {{ incRangeFrom = incRangeTo; fromEl.value = incRangeFrom; }}
    renderIncidentsTab();
  }});
}}

function resetIncidentRange() {{
  incRangeFrom = ALL_YEARS[0];
  incRangeTo   = ALL_YEARS[ALL_YEARS.length-1];
  document.getElementById("incYearFrom").value = incRangeFrom;
  document.getElementById("incYearTo").value   = incRangeTo;
  renderIncidentsTab();
}}

function renderIncidentsTab() {{
  const ii = filteredIncidents();
  const totalInc = ii.length;
  const totalLoss = ii.reduce((a, i) => a + (i.amount_usd || 0), 0);
  const byYear = {{}};
  ii.forEach(i => {{
    const yr = (i.date_iso||i.date||"").slice(0,4);
    byYear[yr] = (byYear[yr]||0) + 1;
  }});
  const peakYear = Object.values(byYear).length ? Math.max(...Object.values(byYear)) : 0;
  const avgLoss = totalInc > 0 ? totalLoss / totalInc : 0;
  document.getElementById("incKpiTotal").textContent = totalInc.toLocaleString();
  document.getElementById("incKpiLoss").textContent = "$" + (totalLoss/1e6).toFixed(1) + "M";
  document.getElementById("incKpiPeak").textContent = peakYear;
  document.getElementById("incKpiAvg").textContent = "$" + (avgLoss/1e6).toFixed(1) + "M";
  const rangeEl = document.getElementById("incRangeDisplay");
  if (rangeEl) rangeEl.textContent = ii.length + " incidents in selected range";
  const iy = aggIncYear(ii);
  const iyYears = Object.keys(iy).sort();
  drawSimpleBar("cIncYear", iyYears, iyYears.map(y=>iy[y]), "#e67e22");
  const vl = aggVuln(ii);
  drawHBar("cVuln", vl.map(d=>d[0]), vl.map(d=>d[1]), "#e74c3c", null);
  renderIncidents(ii);
}}

// ── Init (load data async, then render) ───────────────────────────────────────
window.addEventListener("load", async () => {{
  buildRangeControls();
  buildIncidentRangeControls();
  renderFirmChips();

  // Show loading state
  document.getElementById("kTotalFindings").textContent = "Loading…";

  // Fetch findings and incidents in parallel
  try {{
    const [fRes, iRes] = await Promise.all([
      fetch("./findings?per_page=25000"),
      fetch("./incidents")
    ]);
    const fData  = await fRes.json();
    findings     = fData.results || fData;  // support both paginated and legacy
    allIncidents = await iRes.json();
  }} catch(e) {{
    console.error("Failed to load data:", e);
    document.getElementById("kTotalFindings").textContent = "Error";
    return;
  }}

  renderAll();
}});
window.addEventListener("resize", () => {{
  if (findings.length > 0) renderAll();
}});

// ── Tab Navigation ─────────────────────────────────────────────────────────────
function showTab(tab) {{
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById(tab + 'Tab').classList.add('active');
  event.target.classList.add('active');
  if (tab === 'network') fetchNetworkData();
  if (tab === 'alerts') fetchAlerts();
  if (tab === 'incidents') setTimeout(renderIncidentsTab, 50);
  if (tab === 'security') setTimeout(renderAll, 50);
}}

// ── Network Health ─────────────────────────────────────────────────────────────
const NETWORKS = [
  {{ id: 'mainnet', name: 'Ethereum', icon: 'Ξ', blockTime: 12 }},
  {{ id: 'arbitrum', name: 'Arbitrum', icon: '🔵', blockTime: 0.25, isL2: true }},
  {{ id: 'optimism', name: 'Optimism', icon: '🔴', blockTime: 2, isL2: true }},
  {{ id: 'base', name: 'Base', icon: '🟦', blockTime: 2, isL2: true }},
  {{ id: 'polygon', name: 'Polygon', icon: '🟣', blockTime: 2 }},
  {{ id: 'zksync', name: 'zkSync Era', icon: '⚡', blockTime: 1, isL2: true }},
  {{ id: 'scroll', name: 'Scroll', icon: '📜', blockTime: 3, isL2: true }},
  {{ id: 'linea', name: 'Linea', icon: '🟢', blockTime: 3, isL2: true }}
];

let networkInterval = null;

async function fetchNetworkData() {{
  const grid = document.getElementById('networkGrid');
  const updateEl = document.getElementById('lastUpdate');
  
  // Show loading state on first load
  if (grid.children.length === 0) {{
    grid.innerHTML = NETWORKS.map(n => `
      <div class="network-card" id="card-${{n.id}}">
        <div class="network-name">${{n.icon}} ${{n.name}} <span class="status-dot gray"></span></div>
        <div class="network-stats">
          <div class="net-stat"><div class="net-stat-val">...</div><div class="net-stat-label">Gas (gwei)</div></div>
          <div class="net-stat"><div class="net-stat-val">...</div><div class="net-stat-label">Utilization</div></div>
          <div class="net-stat"><div class="net-stat-val">...</div><div class="net-stat-label">Tx/Block</div></div>
          <div class="net-stat"><div class="net-stat-val">...</div><div class="net-stat-label">Base Fee</div></div>
        </div>
      </div>
    `).join('');
  }}
  
  // Fetch all networks via server proxy
  let allData = {{}};
  try {{
    const res = await fetch('./network');
    const json = await res.json();
    allData = json.networks || {{}};
  }} catch (e) {{
    console.error('Failed to fetch network data:', e);
  }}
  
  const results = NETWORKS.map(n => {{
    const data = allData[n.id];
    return {{ network: n, data: data && !data.error ? data : null, error: data?.error || null }};  
  }});
  
  // Update cards
  results.forEach(({{ network, data, error }}) => {{
    const card = document.getElementById(`card-${{network.id}}`);
    if (!card) return;
    
    if (error || !data) {{
      card.className = 'network-card offline';
      card.querySelector('.status-dot').className = 'status-dot gray';
      return;
    }}
    
    const util = data.block?.utilization || 0;
    const isL2 = network.isL2;
    
    // For L2s, status is always healthy (utilization doesn't apply the same way)
    const statusClass = isL2 ? 'healthy' : (util < 50 ? 'healthy' : util < 80 ? 'busy' : 'congested');
    const dotClass = isL2 ? 'green' : (util < 50 ? 'green' : util < 80 ? 'yellow' : 'red');
    const utilClass = util < 50 ? 'util-low' : util < 80 ? 'util-mid' : 'util-high';
    
    card.className = `network-card ${{statusClass}}`;
    
    const gasGwei = data.oracle?.normal?.gwei || (data.baseFee / 1e9).toFixed(2);
    const baseFeeGwei = (data.baseFee / 1e9).toFixed(2);
    const txCount = data.block?.transactionCount || 0;
    
    // Calculate TPS: tx per block / block time
    const tps = (txCount / network.blockTime).toFixed(1);
    
    card.innerHTML = `
      <div class="network-name">${{network.icon}} ${{network.name}} <span class="status-dot ${{dotClass}}"></span>${{isL2 ? '<span class="l2-badge">L2</span>' : ''}}</div>
      <div class="network-stats">
        <div class="net-stat"><div class="net-stat-val gas">${{gasGwei}}</div><div class="net-stat-label">Gas (gwei)</div></div>
        <div class="net-stat"><div class="net-stat-val">${{tps}}</div><div class="net-stat-label">TPS</div></div>
        <div class="net-stat"><div class="net-stat-val ${{isL2 ? '' : utilClass}}">${{isL2 ? 'N/A' : util + '%'}}</div><div class="net-stat-label">Utilization</div></div>
        <div class="net-stat"><div class="net-stat-val">${{baseFeeGwei}}</div><div class="net-stat-label">Base Fee</div></div>
      </div>
    `;
  }});
  
  updateEl.textContent = `Last updated: ${{new Date().toLocaleTimeString()}}`;
  
  // Set up auto-refresh
  if (!networkInterval) {{
    networkInterval = setInterval(fetchNetworkData, 30000);
  }}
}}

// ── Security Alerts ────────────────────────────────────────────────────────────
let alertsData = [];
let alertsInterval = null;

async function fetchAlerts() {{
  const feed = document.getElementById('alertsFeed');
  const updateEl = document.getElementById('alertsLastUpdate');
  
  try {{
    const res = await fetch('./alerts');
    const json = await res.json();
    alertsData = json.alerts || [];
    renderAlerts();
    updateEl.textContent = `Last updated: ${{new Date().toLocaleTimeString()}}`;
  }} catch (e) {{
    feed.innerHTML = '<div class="alert-loading">Failed to load alerts. Please try again.</div>';
    console.error('Alerts fetch error:', e);
  }}
  
  // Auto-refresh every 7 minutes (rate limit safe with 5 sources)
  if (!alertsInterval) {{
    alertsInterval = setInterval(fetchAlerts, 420000);
  }}
}}

function renderAlerts() {{
  const feed = document.getElementById('alertsFeed');
  const filtered = alertsData;
  
  if (filtered.length === 0) {{
    feed.innerHTML = '<div class="alert-loading">No alerts found.</div>';
    return;
  }}
  
  const sourceLabels = {{peckshield: 'PeckShield', zachxbt: 'zachxbt', slowmist: 'SlowMist', certik: 'CertiK', scamsniffer: 'ScamSniffer', rekt: 'Rekt News'}};
  feed.innerHTML = filtered.map(a => {{
    const sourceLabel = sourceLabels[a.source] || a.source;
    const dateStr = formatAlertDate(a.date);
    return `
      <div class="alert-item ${{a.source}}">
        <div class="alert-meta">
          <span class="alert-source ${{a.source}}">${{sourceLabel}}</span>
          <span class="alert-date">${{dateStr}}</span>
        </div>
        <div class="alert-title"><a href="${{a.link}}" target="_blank">${{escapeHtml(a.title)}}</a></div>
        <div class="alert-desc">${{escapeHtml(a.desc)}}${{a.desc.length >= 300 ? '...' : ''}}</div>
      </div>
    `;
  }}).join('');
}}

function formatAlertDate(dateStr) {{
  try {{
    const d = new Date(dateStr);
    if (isNaN(d)) return dateStr;
    // Show precise date and time
    return d.toLocaleString('en-US', {{ 
      month: 'short', 
      day: 'numeric', 
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    }});
  }} catch {{
    return dateStr;
  }}
}}

function escapeHtml(str) {{
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}}
</script>
</body>
</html>"""

HTML_PAGE = build_html().encode("utf-8")
STATS_JSON = json.dumps({
    "findings": stats,
    "rekt": rekt_stats,
}).encode("utf-8")
INCIDENTS_JSON = json.dumps(incidents).encode("utf-8")

# ── HTTP server ───────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # quiet

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/data":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(STATS_JSON))
            self.end_headers()
            self.wfile.write(STATS_JSON)
        elif path == "/findings":
            qs       = parse_qs(urlparse(self.path).query)
            firm     = qs.get("firm",     [None])[0]
            severity = qs.get("severity", [None])[0]
            category = qs.get("category", [None])[0]
            year     = qs.get("year",     [None])[0]
            q        = qs.get("q",        [None])[0]
            page     = int(qs.get("page",     ["0"])[0])
            per_page = min(int(qs.get("per_page", ["200"])[0]), 25000)

            where, params = [], []
            if firm:     where.append("firm=?");      params.append(firm)
            if severity: where.append("severity=?");  params.append(severity)
            if category: where.append("category=?");  params.append(category)
            if year:     where.append("date LIKE ?");  params.append(f"{year}%")
            if q:        where.append("title LIKE ?"); params.append(f"%{q}%")

            where_clause = ("WHERE " + " AND ".join(where)) if where else ""
            with DB_LOCK:
                total = DB.execute(
                    f"SELECT COUNT(*) FROM findings {where_clause}", params
                ).fetchone()[0]
                rows = DB.execute(
                    f"SELECT firm,report,date,title,severity,category,tech_stack "
                    f"FROM findings {where_clause} LIMIT ? OFFSET ?",
                    params + [per_page, page * per_page]
                ).fetchall()

            cols = ["firm","report","date","title","severity","category","tech_stack"]
            result = {
                "total": total, "page": page, "per_page": per_page,
                "results": [dict(zip(cols, r)) for r in rows]
            }
            body = json.dumps(result).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/incidents":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(INCIDENTS_JSON))
            self.end_headers()
            self.wfile.write(INCIDENTS_JSON)
        elif path == "/alerts":
            # Fetch Twitter alerts from security accounts
            import urllib.request
            from datetime import datetime
            
            TWITTER_BEARER = os.environ.get('TWITTER_BEARER', '')
            
            ACCOUNTS = [
                ('1128606567354359808', 'PeckShieldAlert', 'peckshield'),
                ('3012852462', 'zachxbt', 'zachxbt'),
                ('988385053800517632', 'SlowMist_Team', 'slowmist'),
                ('1494146332528885767', 'CertiKAlert', 'certik'),
                ('1527875389439508481', 'realScamSniffer', 'scamsniffer'),
            ]
            
            alerts = []
            
            for user_id, name, source_key in ACCOUNTS:
                try:
                    req = urllib.request.Request(
                        f'https://api.twitter.com/2/users/{user_id}/tweets?max_results=10&tweet.fields=created_at,text',
                        headers={
                            'Authorization': f'Bearer {TWITTER_BEARER}',
                            'User-Agent': 'EthHealthMonitor/1.0'
                        }
                    )
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        data = json.loads(resp.read().decode('utf-8'))
                        for tweet in data.get('data', []):
                            # Skip retweets and replies
                            text = tweet.get('text', '')
                            if text.startswith('RT @') or text.startswith('@'):
                                continue
                            alerts.append({
                                'source': source_key,
                                'title': f"@{name}",
                                'link': f"https://twitter.com/{name}/status/{tweet.get('id','')}",
                                'date': tweet.get('created_at', ''),
                                'desc': text[:400]
                            })
                except Exception as e:
                    print(f'Twitter API error ({name}): {e}')
            

            # Fetch RSS feeds (no rate limits!)
            RSS_FEEDS = [
                ("https://rekt.news/rss/feed.xml", "rekt"),
            ]
            
            import xml.etree.ElementTree as ET
            for feed_url, source_key in RSS_FEEDS:
                try:
                    req = urllib.request.Request(feed_url, headers={"User-Agent": "EthRadar/1.0"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        root = ET.fromstring(resp.read())
                        for item in root.findall(".//item")[:5]:
                            title = item.find("title")
                            link = item.find("link")
                            pub_date = item.find("pubDate")
                            desc_el = item.find("description")
                            if title is not None:
                                date_str = ""
                                if pub_date is not None and pub_date.text:
                                    try:
                                        from email.utils import parsedate_to_datetime
                                        dt = parsedate_to_datetime(pub_date.text)
                                        date_str = dt.isoformat()
                                    except:
                                        date_str = pub_date.text or ""
                                desc_text = ""
                                if desc_el is not None and desc_el.text:
                                    import html
                                    desc_text = html.unescape(desc_el.text)[:300]
                                alerts.append({
                                    "source": source_key,
                                    "title": (title.text or "").replace("<![CDATA[", "").replace("]]>", ""),
                                    "link": link.text if link is not None else "",
                                    "date": date_str,
                                    "desc": desc_text
                                })
                except Exception as e:
                    print(f"RSS error ({source_key}): {e}")

            # Sort by date (newest first)
            def parse_date(d):
                try:
                    return datetime.fromisoformat(d.replace('Z', '+00:00'))
                except:
                    return datetime.min
            
            alerts.sort(key=lambda x: parse_date(x['date']), reverse=True)
            
            body = json.dumps({'alerts': alerts[:50], 'timestamp': int(__import__('time').time())}).encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/network":
            # Proxy to ethgastracker API for all networks
            import urllib.request
            networks = ['mainnet', 'arbitrum', 'optimism', 'base', 'polygon', 'zksync', 'scroll', 'linea']
            results = {}
            for net in networks:
                try:
                    req = urllib.request.Request(
                        f'https://www.ethgastracker.com/api/gas/latest/{net}',
                        headers={'User-Agent': 'EthHealthMonitor/1.0'}
                    )
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        results[net] = json.loads(resp.read().decode('utf-8')).get('data')
                except Exception as e:
                    results[net] = {'error': str(e)}
            body = json.dumps({'networks': results, 'timestamp': int(__import__('time').time())}).encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(HTML_PAGE))
            self.end_headers()
            self.wfile.write(HTML_PAGE)
        elif path == "/logo.jpg":
            try:
                with open(os.path.join(BASE, "logo.jpg"), "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Length", len(data))
                self.end_headers()
                self.wfile.write(data)
            except:
                self.send_error(404)
        elif path == "/banner.jpg":
            try:
                with open(os.path.join(BASE, "banner.jpg"), "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Length", len(data))
                self.end_headers()
                self.wfile.write(data)
            except:
                self.send_error(404)
        else:
            self.send_error(404)

if __name__ == "__main__":
    port = 18793
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"ETH Radar running on http://localhost:{port}")
    server.serve_forever()
