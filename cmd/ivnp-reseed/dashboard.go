package main

import (
	"encoding/json"
	"io"
	"strings"
)

// RenderDashboard writes the standalone real-time web dashboard HTML to w.
func RenderDashboard(w io.Writer, stats DetailedStatsResponse) error {
	statsJSON, err := json.Marshal(stats)
	if err != nil {
		statsJSON = []byte("{}")
	}

	html := strings.Replace(dashboardHTMLTemplate, "{{INITIAL_DATA}}", string(statsJSON), 1)
	_, err = io.WriteString(w, html)
	return err
}

const dashboardHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IVNP Reseed Indexer & Network Monitor</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f2937;
      --card-hover: #1a2234;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #38bdf8;
      --accent: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --purple: #a855f7;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text-main);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.5;
      padding: 24px;
      max-width: 1280px;
      margin: 0 auto;
    }
    header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 28px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--card-border);
    }
    .header-left h1 {
      font-size: 1.65rem;
      font-weight: 700;
      letter-spacing: -0.025em;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .header-left p {
      color: var(--text-muted);
      font-size: 0.9rem;
      margin-top: 4px;
    }
    .status-badges {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      border-radius: 9999px;
      font-size: 0.8rem;
      font-weight: 600;
      background: #1e293b;
      color: var(--text-main);
      border: 1px solid var(--card-border);
    }
    .badge-live {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.3);
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      background-color: #10b981;
      border-radius: 50%;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(1.2); }
    }
    .btn-toggle {
      background: #1e293b;
      color: var(--text-main);
      border: 1px solid var(--card-border);
      padding: 6px 12px;
      border-radius: 8px;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-toggle:hover { background: #334155; }
    .grid-kpi {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
      transition: border-color 0.15s ease, background 0.15s ease;
    }
    .card:hover {
      background: var(--card-hover);
      border-color: #374151;
    }
    .card-title {
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      font-weight: 600;
      margin-bottom: 8px;
    }
    .card-value {
      font-size: 1.85rem;
      font-weight: 700;
      color: #fff;
      line-height: 1.1;
    }
    .card-sub {
      margin-top: 6px;
      font-size: 0.8rem;
      color: var(--text-muted);
    }
    .section-title {
      font-size: 1.15rem;
      font-weight: 600;
      color: #fff;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .downloads-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    @media (min-width: 1080px) {
      .downloads-grid {
        grid-template-columns: 1.85fr 1fr;
      }
    }
    .download-card {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .su3-layout {
      display: grid;
      grid-template-columns: 1fr;
      gap: 20px;
      height: 100%;
    }
    @media (min-width: 680px) {
      .su3-layout {
        grid-template-columns: 240px 1fr;
      }
    }
    .su3-left {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .su3-right {
      border-top: 1px solid var(--card-border);
      padding-top: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    @media (min-width: 680px) {
      .su3-right {
        border-top: none;
        border-left: 1px solid var(--card-border);
        padding-top: 0;
        padding-left: 20px;
      }
    }
    .method-box {
      background: rgba(15, 23, 42, 0.7);
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 10px 12px;
    }
    .method-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 4px;
      color: var(--primary);
      font-weight: 600;
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .method-text {
      color: var(--text-muted);
      line-height: 1.4;
      font-size: 0.76rem;
    }
    .pkg-stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 10px;
    }
    .pkg-stat-item {
      background: rgba(30, 41, 59, 0.4);
      border: 1px solid rgba(51, 65, 85, 0.4);
      border-radius: 8px;
      padding: 10px;
    }
    .pkg-stat-label {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-muted);
      font-weight: 600;
      margin-bottom: 4px;
    }
    .pkg-stat-val {
      font-size: 1.25rem;
      font-weight: 700;
      color: #fff;
      line-height: 1.1;
    }
    .pkg-stat-sub {
      font-size: 0.72rem;
      color: var(--text-muted);
      margin-top: 4px;
    }
    .ip-ratio-bar {
      height: 6px;
      background: #1e293b;
      border-radius: 9999px;
      overflow: hidden;
      display: flex;
      margin-top: 6px;
    }
    .ip-ratio-bar-dual { background: #10b981; transition: width 0.3s ease; }
    .ip-ratio-bar-v4 { background: #38bdf8; transition: width 0.3s ease; }
    .ip-ratio-bar-v6 { background: #a855f7; transition: width 0.3s ease; }
    .download-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
    }
    .download-header h3 {
      font-size: 1.05rem;
      font-weight: 600;
      color: #fff;
    }
    .fmt-pill {
      font-size: 0.72rem;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 6px;
      text-transform: uppercase;
    }
    .fmt-su3 { background: rgba(56, 189, 248, 0.15); color: var(--primary); border: 1px solid rgba(56, 189, 248, 0.3); }
    .download-meta {
      font-size: 0.82rem;
      color: var(--text-muted);
      margin-bottom: 16px;
    }
    .download-actions {
      display: flex;
      gap: 10px;
    }
    .btn-dl {
      flex: 1;
      text-align: center;
      background: #2563eb;
      color: #fff;
      text-decoration: none;
      font-weight: 600;
      font-size: 0.85rem;
      padding: 10px 16px;
      border-radius: 8px;
      transition: background 0.15s ease;
      display: inline-flex;
      justify-content: center;
      align-items: center;
      gap: 6px;
    }
    .btn-dl:hover { background: #1d4ed8; }
    .btn-copy {
      background: #1e293b;
      color: var(--text-main);
      border: 1px solid var(--card-border);
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-copy:hover { background: #334155; }
    .heatmap-section {
      margin-bottom: 28px;
    }
    .heatmap-desc {
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 12px;
    }
    .heatmap-grid {
      display: grid;
      grid-template-columns: repeat(32, 1fr);
      gap: 4px;
      background: #0f172a;
      padding: 14px;
      border-radius: 12px;
      border: 1px solid var(--card-border);
    }
    .bucket-cell {
      aspect-ratio: 1;
      border-radius: 3px;
      background: #1e293b;
      cursor: pointer;
      transition: transform 0.1s ease, filter 0.1s ease;
      position: relative;
    }
    .bucket-cell:hover {
      transform: scale(1.35);
      z-index: 10;
      filter: brightness(1.3);
      box-shadow: 0 0 8px rgba(56, 189, 248, 0.5);
    }
    .analytics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }
    th, td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid #1f2937;
    }
    th {
      color: var(--text-muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    td.val {
      text-align: right;
      font-weight: 600;
      color: #fff;
    }
    footer {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding-top: 20px;
      border-top: 1px solid var(--card-border);
      font-size: 0.82rem;
      color: var(--text-muted);
    }
    footer a { color: var(--primary); text-decoration: none; }
    footer a:hover { text-decoration: underline; }
    #tooltip {
      position: fixed;
      display: none;
      background: #0f172a;
      color: #fff;
      padding: 6px 10px;
      border-radius: 6px;
      font-size: 0.75rem;
      border: 1px solid #334155;
      pointer-events: none;
      z-index: 100;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.5);
    }
    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #10b981;
      color: #fff;
      padding: 10px 18px;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
      z-index: 2000;
      display: none;
      transition: opacity 0.3s ease;
    }
  </style>
</head>
<body>

  <header>
    <div class="header-left">
      <h1>
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"></path>
          <path d="M2 12h20"></path>
        </svg>
        IVNP Reseed Indexer
      </h1>
      <p>Continuous I2P Network DHT Crawler & Accessible Floodfill Reseed Service</p>
    </div>
    <div class="status-badges">
      <span class="badge badge-live">
        <span class="pulse-dot"></span>
        ACTIVE CRAWLER
      </span>
      <span class="badge" id="badge-mode" style="text-transform: uppercase; color: #38bdf8;">Mode: EXPANSION</span>
      <span class="badge" id="badge-netid">NetID: 2</span>
      <span class="badge" id="badge-uptime">Uptime: 0s</span>
      <button class="btn-toggle" id="btn-refresh-toggle" onclick="toggleAutoRefresh()">Auto-refresh: ON (3s)</button>
    </div>
  </header>

  <!-- Key Metrics Row -->
  <section class="grid-kpi">
    <div class="card">
      <div class="card-title">Total Indexed Peers</div>
      <div class="card-value" id="kpi-total-peers">-</div>
      <div class="card-sub">Bounded memory store (max 5,000)</div>
    </div>
    <div class="card">
      <div class="card-title">Directly Reachable</div>
      <div class="card-value" style="color: #34d399;" id="kpi-reachable-peers">-</div>
      <div class="card-sub" id="kpi-reachable-ratio">Health ratio: -%</div>
    </div>
    <div class="card">
      <div class="card-title">Accessible Floodfills</div>
      <div class="card-value" style="color: #38bdf8;" id="kpi-floodfill-peers">-</div>
      <div class="card-sub" id="kpi-floodfill-ratio">Reseed quota: ≥35%</div>
    </div>
    <div class="card">
      <div class="card-title">256 K-Bucket Coverage</div>
      <div class="card-value" style="color: #a855f7;" id="kpi-bucket-coverage">-</div>
      <div class="card-sub" id="kpi-bucket-detail">- / 256 buckets active</div>
    </div>
    <div class="card">
      <div class="card-title">Median Latency (p50)</div>
      <div class="card-value" style="color: #f59e0b;" id="kpi-p50-rtt">- ms</div>
      <div class="card-sub" id="kpi-p90-rtt">p90: - ms | p99: - ms</div>
    </div>
    <div class="card">
      <div class="card-title">Next Archive Refresh</div>
      <div class="card-value" style="color: #60a5fa;" id="kpi-next-refresh">-</div>
      <div class="card-sub">Periodic 5-minute cycle</div>
    </div>
  </section>

  <!-- Download Archives & Verification Keys Row -->
  <div class="section-title">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
    Reseed Package &amp; Signing Public Key
  </div>
  <section class="downloads-grid">
    <div class="card download-card">
      <div class="su3-layout">
        <!-- Left: Download actions and metadata -->
        <div class="su3-left">
          <div>
            <div class="download-header">
              <h3>Standard I2P SU3 Archive</h3>
              <span class="fmt-pill fmt-su3">ZIP / RSA-4096</span>
            </div>
            <p class="download-meta">Compatible with all standard I2P routers (Java I2P, i2pd &amp; IVNP). Fully signed with SHA-512 and RSA-4096.</p>
            <div style="font-size: 0.82rem; margin-bottom: 12px; color: #d1d5db; display: flex; flex-direction: column; gap: 4px;">
              <div>Package Peers: <strong id="su3-peers" style="color: #fff;">-</strong></div>
              <div>Archive Size: <strong id="su3-size" style="color: #fff;">- KB</strong></div>
              <div>Archive ETag: <code id="su3-etag" style="color: #94a3b8; font-size: 0.75rem;">-</code></div>
            </div>
          </div>
          <div class="download-actions" style="margin-top: 14px;">
            <a href="/i2pseeds.su3?netid=2" id="btn-dl-su3" class="btn-dl">Download SU3</a>
            <button class="btn-copy" onclick="copyLink('/i2pseeds.su3?netid=2')">Copy URL</button>
          </div>
        </div>

        <!-- Right (Next to download): Package Generation Strategy & Telemetry -->
        <div class="su3-right">
          <!-- Generation Method & Filter Strategy -->
          <div class="method-box">
            <div class="method-header">
              <span>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: -1px; margin-right: 4px;"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
                Generation Strategy
              </span>
              <span id="pkg-filter-badge" style="font-size: 0.68rem; padding: 2px 6px; border-radius: 4px; background: rgba(16, 185, 129, 0.15); color: #34d399; font-weight: 600; text-transform: none;">Reachable Only</span>
            </div>
            <div class="method-text" id="pkg-method-text">
              256 K-Bucket Stratified Sampling &bull; Java I2P 256-node Head-Start (1 peer/bucket) &bull; /16 IPv4 Subnet Anti-Sybil (max 1/subnet) &bull; Max-5 Bucket Leveling
            </div>
          </div>

          <!-- 4 Metrics Tiles: Floodfill Ratio, IP Stack Distribution, Availability, Latency -->
          <div class="pkg-stats-grid">
            <!-- 1. Floodfill Ratio -->
            <div class="pkg-stat-item">
              <div class="pkg-stat-label">Floodfill Ratio</div>
              <div class="pkg-stat-val" id="pkg-metric-ff" style="color: #38bdf8;">-%</div>
              <div class="pkg-stat-sub" id="pkg-metric-ff-sub">- floodfills</div>
            </div>

            <!-- 2. IP Stack Distribution (Dual-Stack vs IPv4 Only) -->
            <div class="pkg-stat-item">
              <div class="pkg-stat-label">IP Stack Ratio</div>
              <div class="pkg-stat-val" style="font-size: 1rem; display: flex; justify-content: space-between; align-items: baseline;">
                <span id="pkg-metric-dual" style="color: #10b981;">Dual: -%</span>
                <span id="pkg-metric-v4" style="color: #38bdf8; font-size: 0.8rem;">IPv4: -%</span>
              </div>
              <div class="ip-ratio-bar">
                <div class="ip-ratio-bar-dual" id="bar-dual" style="width: 0%;" title="Dual-Stack"></div>
                <div class="ip-ratio-bar-v4" id="bar-v4" style="width: 0%;" title="IPv4 Only"></div>
                <div class="ip-ratio-bar-v6" id="bar-v6" style="width: 0%;" title="IPv6 Only"></div>
              </div>
              <div class="pkg-stat-sub" id="pkg-metric-ip-sub">Dual: - | IPv4: -</div>
            </div>

            <!-- 3. Average Availability -->
            <div class="pkg-stat-item">
              <div class="pkg-stat-label">Average Availability</div>
              <div class="pkg-stat-val" id="pkg-metric-avail" style="color: #34d399;">-%</div>
              <div class="pkg-stat-sub" id="pkg-metric-avail-sub">Direct Reachable: -%</div>
            </div>

            <!-- 4. Package Latency -->
            <div class="pkg-stat-item">
              <div class="pkg-stat-label">Package Latency</div>
              <div class="pkg-stat-val" id="pkg-metric-rtt" style="color: #f59e0b;">- ms</div>
              <div class="pkg-stat-sub" id="pkg-metric-rtt-sub">p50: - ms | p90: - ms</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="card download-card">
      <div>
        <div class="download-header">
          <h3>Reseed RSA-4096 Public Key</h3>
          <span class="fmt-pill" style="background: rgba(16, 185, 129, 0.15); color: var(--accent); border: 1px solid rgba(16, 185, 129, 0.3);">X.509 CRT / RSA</span>
        </div>
        <p class="download-meta">Required by client routers to verify SU3 signatures. Signer: <code id="signer-id-display" style="color: #38bdf8; font-family: monospace;">-</code></p>
        <div style="font-size: 0.85rem; margin-bottom: 12px; color: #d1d5db;">
          Certificate: <strong id="cert-filename">-</strong> | Spec: <strong>4096-bit RSA (SHA-512)</strong>
        </div>
      </div>
      <div class="download-actions">
        <a href="/reseed-rsa.crt" id="btn-dl-cert" class="btn-dl" style="background: #059669;" download>Download .crt</a>
        <button class="btn-copy" onclick="copyPublicKey()" title="Copy RSA Public Key / Certificate PEM to Clipboard">Copy Key</button>
        <button class="btn-copy" onclick="toggleKeyModal()" title="View Certificate and Public Key PEM">View</button>
      </div>
    </div>
  </section>

  <!-- 256 K-Bucket Heatmap -->
  <section class="heatmap-section">
    <div class="section-title">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
      256 K-Bucket DHT Keyspace Distribution (Prefix 0x00 – 0xFF)
    </div>
    <div class="heatmap-desc">
      Even distribution across all 256 DHT key-space buckets ensures newly bootstrapped routers discover floodfills across the entire keyspace and mitigates eclipse attacks.
    </div>
    <div class="heatmap-grid" id="heatmap-grid">
      <!-- Generated by JS -->
    </div>
  </section>

  <!-- Analytics & Network Diversity Row -->
  <section class="analytics-grid">
    <div class="card">
      <div class="section-title" style="margin-bottom: 8px;">Latency Breakdown (EWMA RTT)</div>
      <table>
        <thead>
          <tr><th>Percentile / Metric</th><th style="text-align: right;">Observed Latency</th></tr>
        </thead>
        <tbody>
          <tr><td>Fastest (Min)</td><td class="val" id="rtt-min">- ms</td></tr>
          <tr><td>50th Percentile (p50 Median)</td><td class="val" id="rtt-p50">- ms</td></tr>
          <tr><td>90th Percentile (p90)</td><td class="val" id="rtt-p90">- ms</td></tr>
          <tr><td>99th Percentile (p99)</td><td class="val" id="rtt-p99">- ms</td></tr>
          <tr><td>Slowest (Max)</td><td class="val" id="rtt-max">- ms</td></tr>
          <tr><td>Average EWMA</td><td class="val" id="rtt-avg">- ms</td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <div class="section-title" style="margin-bottom: 8px;">Network & Subnet Diversity</div>
      <table>
        <thead>
          <tr><th>Diversity Dimension</th><th style="text-align: right;">Unique Count</th></tr>
        </thead>
        <tbody>
          <tr><td>Unique IPv4 /16 Subnets</td><td class="val" id="div-subnets">-</td></tr>
          <tr><td>Unique IPv4 Endpoints</td><td class="val" id="div-ipv4">-</td></tr>
          <tr><td>Unique IPv6 Endpoints</td><td class="val" id="div-ipv6">-</td></tr>
          <tr><td>Unique Router Families</td><td class="val" id="div-families">-</td></tr>
          <tr><td>Package Floodfill Ratio</td><td class="val" id="pkg-floodfill-ratio">-%</td></tr>
          <tr><td>Package Dual-Stack Ratio</td><td class="val" id="pkg-dual-ratio">-%</td></tr>
          <tr><td>Package Average Availability</td><td class="val" id="pkg-avg-avail">-%</td></tr>
          <tr><td>Archive ETag</td><td class="val" id="pkg-etag">-</td></tr>
        </tbody>
      </table>
    </div>
  </section>

  <footer>
    <div>
      Endpoints: <a href="/stats" target="_blank">/stats (JSON)</a> &bull; <a href="/health" target="_blank">/health</a> &bull; Rate limit: 15 probes/sec &bull; Cooldown: 10m
    </div>
    <div>
      Powered by <strong>IVNP</strong> &bull; Version <span id="footer-version">active-dev</span>
    </div>
  </footer>

  <div id="tooltip"></div>

  <script id="initial-data" type="application/json">
{{INITIAL_DATA}}
  </script>

  <script>
    let autoRefresh = true;
    let refreshIntervalMs = 3000;
    let timerId = null;
    let etaSeconds = 0;

    function formatUptime(seconds) {
      if (seconds < 60) return seconds + 's';
      const m = Math.floor(seconds / 60);
      const s = seconds % 60;
      if (m < 60) return m + 'm ' + s + 's';
      const h = Math.floor(m / 60);
      return h + 'h ' + (m % 60) + 'm';
    }

    function formatETA(sec) {
      if (sec <= 0) return 'Generating...';
      const m = Math.floor(sec / 60);
      const s = sec % 60;
      return String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
    }

    function renderStats(data) {
      if (!data) return;

      document.getElementById('badge-netid').textContent = 'NetID: ' + (data.network_id || 2);
      document.getElementById('badge-uptime').textContent = 'Uptime: ' + formatUptime(data.uptime_seconds || 0);
      document.getElementById('footer-version').textContent = data.version || 'active-dev';

      // KPI
      document.getElementById('kpi-total-peers').textContent = (data.total_indexed || 0).toLocaleString();
      document.getElementById('kpi-reachable-peers').textContent = (data.reachable_peers || 0).toLocaleString();
      const reachRatio = data.total_indexed > 0 ? ((data.reachable_peers / data.total_indexed) * 100).toFixed(1) : '0';
      document.getElementById('kpi-reachable-ratio').textContent = 'Reachability: ' + reachRatio + '%';

      document.getElementById('kpi-floodfill-peers').textContent = (data.floodfill_peers || 0).toLocaleString();
      const ffRatio = data.total_indexed > 0 ? ((data.floodfill_peers / data.total_indexed) * 100).toFixed(1) : '0';
      document.getElementById('kpi-floodfill-ratio').textContent = 'Pool ratio: ' + ffRatio + '% (Quota ≥35%)';

      const covered = data.kbuckets ? data.kbuckets.covered_buckets : 0;
      const coveragePct = data.kbuckets ? data.kbuckets.coverage_percent.toFixed(1) : '0';
      document.getElementById('kpi-bucket-coverage').textContent = coveragePct + '%';
      document.getElementById('kpi-bucket-detail').textContent = covered + ' / 256 buckets active';

      const p50 = data.rtt ? data.rtt.p50_ms : 0;
      const p90 = data.rtt ? data.rtt.p90_ms : 0;
      const p99 = data.rtt ? data.rtt.p99_ms : 0;
      document.getElementById('kpi-p50-rtt').textContent = p50 + ' ms';
      document.getElementById('kpi-p90-rtt').textContent = 'p90: ' + p90 + ' ms | p99: ' + p99 + ' ms';

      etaSeconds = data.package ? data.package.next_refresh_eta_seconds : 0;
      document.getElementById('kpi-next-refresh').textContent = formatETA(etaSeconds);

      // Package info
      const pkgPeers = data.package ? data.package.peer_count : (data.published_peers || 0);
      document.getElementById('su3-peers').textContent = pkgPeers;

      const su3Size = data.package && data.package.su3_size_bytes ? (data.package.su3_size_bytes / 1024).toFixed(1) : '0';
      document.getElementById('su3-size').textContent = su3Size + ' KB';

      // Update download links with netid
      const netid = data.network_id || 2;
      document.getElementById('btn-dl-su3').href = '/i2pseeds.su3?netid=' + netid;

      if (data.signer_id) {
        const signerEl = document.getElementById('signer-id-display');
        if (signerEl) signerEl.textContent = data.signer_id;
        const certName = data.signer_id.replace(/@/g, '_at_') + '.crt';
        const certFileEl = document.getElementById('cert-filename');
        if (certFileEl) certFileEl.textContent = certName;
        const dlCert = document.getElementById('btn-dl-cert');
        if (dlCert) {
          dlCert.setAttribute('download', certName);
        }
      }
      if (data.certificate_pem) {
        cachedCertPEM = data.certificate_pem;
      }
      if (data.public_key_pem) {
        cachedPubKeyPEM = data.public_key_pem;
      }

      // Latency table
      if (data.rtt) {
        document.getElementById('rtt-min').textContent = data.rtt.min_ms + ' ms';
        document.getElementById('rtt-p50').textContent = data.rtt.p50_ms + ' ms';
        document.getElementById('rtt-p90').textContent = data.rtt.p90_ms + ' ms';
        document.getElementById('rtt-p99').textContent = data.rtt.p99_ms + ' ms';
        document.getElementById('rtt-max').textContent = data.rtt.max_ms + ' ms';
        document.getElementById('rtt-avg').textContent = data.rtt.avg_ms + ' ms';
      }

      // Diversity table
      if (data.diversity) {
        const subnets = (data.diversity.unique_ipv4_subnets_16 !== undefined && data.diversity.unique_ipv4_subnets_16 > 0)
          ? data.diversity.unique_ipv4_subnets_16
          : (data.diversity.unique_ipv4_subnets_24 || 0);
        document.getElementById('div-subnets').textContent = subnets.toLocaleString();
        document.getElementById('div-ipv4').textContent = data.diversity.unique_ipv4_count.toLocaleString();
        document.getElementById('div-ipv6').textContent = data.diversity.unique_ipv6_count.toLocaleString();
        document.getElementById('div-families').textContent = data.diversity.unique_families.toLocaleString();
      }
      if (data.exploration_mode) {
        const modeBadge = document.getElementById('badge-mode');
        if (modeBadge) {
          modeBadge.textContent = 'Mode: ' + data.exploration_mode.toUpperCase();
          if (data.exploration_mode === 'maintenance') {
            modeBadge.style.color = '#34d399';
          } else {
            modeBadge.style.color = '#38bdf8';
          }
        }
      }
      if (data.package) {
        const pkg = data.package;
        const ffRatio = (pkg.floodfill_ratio * 100).toFixed(1);
        const ffEl = document.getElementById('pkg-metric-ff');
        if (ffEl) ffEl.textContent = ffRatio + '%';
        const ffSub = document.getElementById('pkg-metric-ff-sub');
        if (ffSub) ffSub.textContent = (pkg.floodfill_count || 0) + ' / ' + (pkg.peer_count || 0) + ' floodfills';

        const dualRatio = (pkg.dual_stack_ratio * 100).toFixed(1);
        const v4Ratio = (pkg.ipv4_only_ratio * 100).toFixed(1);
        const dualEl = document.getElementById('pkg-metric-dual');
        if (dualEl) dualEl.textContent = 'Dual: ' + dualRatio + '%';
        const v4El = document.getElementById('pkg-metric-v4');
        if (v4El) v4El.textContent = 'IPv4: ' + v4Ratio + '%';
        const ipSub = document.getElementById('pkg-metric-ip-sub');
        if (ipSub) {
          let text = 'Dual: ' + (pkg.dual_stack_count || 0) + ' | IPv4: ' + (pkg.ipv4_only_count || 0);
          if (pkg.ipv6_only_count > 0) text += ' | IPv6: ' + pkg.ipv6_only_count;
          ipSub.textContent = text;
        }
        const barDual = document.getElementById('bar-dual');
        if (barDual) barDual.style.width = (pkg.dual_stack_ratio * 100) + '%';
        const barV4 = document.getElementById('bar-v4');
        if (barV4) barV4.style.width = (pkg.ipv4_only_ratio * 100) + '%';
        const barV6 = document.getElementById('bar-v6');
        if (barV6) barV6.style.width = (pkg.ipv6_only_ratio * 100) + '%';

        const availPct = (pkg.average_availability * 100).toFixed(1);
        const availEl = document.getElementById('pkg-metric-avail');
        if (availEl) availEl.textContent = availPct + '%';
        const availSub = document.getElementById('pkg-metric-avail-sub');
        if (availSub) {
          const reachPct = (pkg.directly_reachable_ratio * 100).toFixed(1);
          availSub.textContent = 'Reachable: ' + reachPct + '% (' + (pkg.directly_reachable_count || 0) + ')';
        }

        const pkgRTT = pkg.rtt;
        const rttEl = document.getElementById('pkg-metric-rtt');
        if (rttEl) {
          const avgMs = pkgRTT ? pkgRTT.avg_ms : 0;
          rttEl.textContent = avgMs + ' ms';
        }
        const rttSub = document.getElementById('pkg-metric-rtt-sub');
        if (rttSub) {
          const p50 = pkgRTT ? pkgRTT.p50_ms : 0;
          const p90 = pkgRTT ? pkgRTT.p90_ms : 0;
          rttSub.textContent = 'p50: ' + p50 + ' ms | p90: ' + p90 + ' ms';
        }

        if (pkg.generation_method) {
          const methodEl = document.getElementById('pkg-method-text');
          if (methodEl) methodEl.textContent = pkg.generation_method;
        }
        const filterBadge = document.getElementById('pkg-filter-badge');
        if (filterBadge) {
          filterBadge.textContent = pkg.require_reachable_filter ? 'Directly Reachable Only' : 'Bootstrap Mode';
          if (pkg.require_reachable_filter) {
            filterBadge.style.background = 'rgba(16, 185, 129, 0.15)';
            filterBadge.style.color = '#34d399';
          } else {
            filterBadge.style.background = 'rgba(245, 158, 11, 0.15)';
            filterBadge.style.color = '#f59e0b';
          }
        }
        const etagEl = document.getElementById('su3-etag');
        if (etagEl) etagEl.textContent = pkg.etag || 'N/A';

        document.getElementById('pkg-floodfill-ratio').textContent = ffRatio + '% (' + (pkg.floodfill_count || 0) + ' nodes)';
        const dualTableEl = document.getElementById('pkg-dual-ratio');
        if (dualTableEl) dualTableEl.textContent = dualRatio + '% (' + (pkg.dual_stack_count || 0) + ' nodes)';
        const availTableEl = document.getElementById('pkg-avg-avail');
        if (availTableEl) availTableEl.textContent = availPct + '%';
        document.getElementById('pkg-etag').textContent = pkg.etag || 'N/A';
      }

      // Heatmap update
      renderHeatmap(data.kbuckets ? data.kbuckets.distribution : []);
    }

    function renderHeatmap(distribution) {
      const container = document.getElementById('heatmap-grid');
      container.innerHTML = '';

      let maxCount = 1;
      if (distribution && distribution.length > 0) {
        for (let i = 0; i < 256; i++) {
          if (distribution[i] > maxCount) maxCount = distribution[i];
        }
      }

      const tooltip = document.getElementById('tooltip');

      for (let i = 0; i < 256; i++) {
        const cell = document.createElement('div');
        cell.className = 'bucket-cell';
        const count = (distribution && distribution[i]) ? distribution[i] : 0;
        const hex = '0x' + i.toString(16).padStart(2, '0').toUpperCase();

        if (count === 0) {
          cell.style.background = '#1e293b';
        } else {
          // Gradient from teal/cyan to bright emerald
          const ratio = Math.min(1.0, count / maxCount);
          const r = Math.round(16 * ratio + 30 * (1 - ratio));
          const g = Math.round(185 * ratio + 41 * (1 - ratio));
          const b = Math.round(129 * ratio + 59 * (1 - ratio));
          cell.style.background = 'rgb(' + r + ',' + g + ',' + b + ')';
        }

        cell.onmouseenter = (e) => {
          tooltip.style.display = 'block';
          tooltip.innerHTML = '<strong>Bucket ' + hex + ' (' + i + ')</strong><br>Peers: ' + count;
          moveTooltip(e);
        };
        cell.onmousemove = moveTooltip;
        cell.onmouseleave = () => { tooltip.style.display = 'none'; };

        container.appendChild(cell);
      }
    }

    function moveTooltip(e) {
      const tooltip = document.getElementById('tooltip');
      tooltip.style.left = (e.clientX + 14) + 'px';
      tooltip.style.top = (e.clientY + 14) + 'px';
    }

    let cachedCertPEM = '';
    let cachedPubKeyPEM = '';
    let currentKeyTab = 'cert';

    function showToast(msg) {
      const toast = document.getElementById('toast');
      if (!toast) {
        alert(msg);
        return;
      }
      toast.textContent = msg;
      toast.style.display = 'block';
      toast.style.opacity = '1';
      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => { toast.style.display = 'none'; }, 300);
      }, 2500);
    }

    function copyLink(path) {
      const url = window.location.origin + path;
      navigator.clipboard.writeText(url).then(() => {
        showToast('Copied URL: ' + url);
      }).catch(() => {
        prompt('Copy this URL:', url);
      });
    }

    function copyPublicKey() {
      const textToCopy = cachedCertPEM || cachedPubKeyPEM;
      if (textToCopy) {
        navigator.clipboard.writeText(textToCopy).then(() => {
          showToast('Copied RSA certificate PEM to clipboard!');
        }).catch(() => {
          prompt('Copy RSA Certificate PEM:', textToCopy);
        });
        return;
      }
      fetch('/reseed-rsa.crt')
        .then(r => r.text())
        .then(txt => {
          cachedCertPEM = txt;
          navigator.clipboard.writeText(txt).then(() => {
            showToast('Copied RSA certificate PEM to clipboard!');
          }).catch(() => {
            prompt('Copy RSA Certificate PEM:', txt);
          });
        })
        .catch(err => {
          alert('Failed to load public key: ' + err);
        });
    }

    function toggleKeyModal() {
      const modal = document.getElementById('key-modal');
      if (!modal) return;
      if (modal.style.display === 'flex') {
        modal.style.display = 'none';
      } else {
        modal.style.display = 'flex';
        switchKeyTab(currentKeyTab);
      }
    }

    function switchKeyTab(tab) {
      currentKeyTab = tab;
      const display = document.getElementById('key-pem-display');
      const tabCert = document.getElementById('tab-cert');
      const tabPub = document.getElementById('tab-pubkey');
      if (!display || !tabCert || !tabPub) return;

      if (tab === 'cert') {
        tabCert.style.background = '#334155';
        tabCert.style.color = '#fff';
        tabPub.style.background = '#1e293b';
        tabPub.style.color = 'var(--text-main)';
        if (cachedCertPEM) {
          display.textContent = cachedCertPEM;
        } else {
          display.textContent = 'Loading certificate...';
          fetch('/reseed-rsa.crt').then(r => r.text()).then(t => {
            cachedCertPEM = t;
            if (currentKeyTab === 'cert') display.textContent = t;
          }).catch(e => { display.textContent = 'Error: ' + e; });
        }
      } else {
        tabPub.style.background = '#334155';
        tabPub.style.color = '#fff';
        tabCert.style.background = '#1e293b';
        tabCert.style.color = 'var(--text-main)';
        if (cachedPubKeyPEM) {
          display.textContent = cachedPubKeyPEM;
        } else {
          display.textContent = 'Loading public key...';
          fetch('/reseed-rsa.pub.pem').then(r => r.text()).then(t => {
            cachedPubKeyPEM = t;
            if (currentKeyTab === 'pubkey') display.textContent = t;
          }).catch(e => { display.textContent = 'Error: ' + e; });
        }
      }
    }

    function copyDisplayedKey() {
      const display = document.getElementById('key-pem-display');
      if (!display || !display.textContent) return;
      navigator.clipboard.writeText(display.textContent).then(() => {
        showToast('Copied key to clipboard!');
      }).catch(() => {
        prompt('Copy key:', display.textContent);
      });
    }

    function toggleAutoRefresh() {
      autoRefresh = !autoRefresh;
      const btn = document.getElementById('btn-refresh-toggle');
      if (autoRefresh) {
        btn.textContent = 'Auto-refresh: ON (3s)';
        btn.style.color = '#fff';
        startPolling();
      } else {
        btn.textContent = 'Auto-refresh: OFF';
        btn.style.color = '#9ca3af';
        stopPolling();
      }
    }

    function fetchLatest() {
      fetch('/stats')
        .then(r => r.json())
        .then(data => renderStats(data))
        .catch(err => console.warn('poll failed:', err));
    }

    function startPolling() {
      stopPolling();
      timerId = setInterval(fetchLatest, refreshIntervalMs);
    }

    function stopPolling() {
      if (timerId) clearInterval(timerId);
      timerId = null;
    }

    // Initialize with embedded bootstrap JSON
    try {
      const initial = JSON.parse(document.getElementById('initial-data').textContent);
      renderStats(initial);
    } catch(e) {
      console.warn('initial parse failed', e);
    }

    // Start auto-refresh polling
    startPolling();

    // 1-second countdown ticker for Next Archive Refresh
    setInterval(() => {
      if (etaSeconds > 0) {
        etaSeconds--;
        document.getElementById('kpi-next-refresh').textContent = formatETA(etaSeconds);
        if (etaSeconds === 0) {
          fetchLatest();
        }
      }
    }, 1000);
  </script>

  <div id="key-modal" style="display: none; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.7); z-index: 1000; align-items: center; justify-content: center; padding: 20px;">
    <div class="card" style="max-width: 680px; width: 100%; max-height: 85vh; display: flex; flex-direction: column;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <h3 style="color: #fff; font-size: 1.1rem;">RSA-4096 Reseed Signing Key &amp; Certificate</h3>
        <button onclick="toggleKeyModal()" style="background: none; border: none; color: var(--text-muted); font-size: 1.5rem; cursor: pointer; line-height: 1;">&times;</button>
      </div>
      <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 12px;">
        Save this certificate to your router's reseed certificates directory (e.g. <code>~/.i2p/certificates/reseed/</code> or <code>/var/lib/i2pd/certificates/reseed/</code>).
      </p>
      <div style="display: flex; gap: 8px; margin-bottom: 10px;">
        <button id="tab-cert" class="btn-copy" style="background: #334155; color: #fff;" onclick="switchKeyTab('cert')">X.509 Certificate (.crt)</button>
        <button id="tab-pubkey" class="btn-copy" onclick="switchKeyTab('pubkey')">RSA Public Key (PEM)</button>
      </div>
      <pre id="key-pem-display" style="background: #090d16; border: 1px solid var(--card-border); border-radius: 8px; padding: 12px; font-size: 0.75rem; color: #34d399; overflow-y: auto; flex: 1; font-family: monospace; user-select: all; white-space: pre-wrap; word-break: break-all;"></pre>
      <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 14px;">
        <button class="btn-copy" onclick="copyDisplayedKey()">Copy to Clipboard</button>
        <button class="btn-copy" onclick="toggleKeyModal()">Close</button>
      </div>
    </div>
  </div>

  <div id="toast"></div>
</body>
</html>
`
