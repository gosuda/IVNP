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
    .download-card {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
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
      <div>
        <div class="download-header">
          <h3>Standard I2P SU3 Archive</h3>
          <span class="fmt-pill fmt-su3">ZIP / RSA-4096</span>
        </div>
        <p class="download-meta">Compatible with all standard I2P routers (Java I2P, i2pd &amp; IVNP). Fully signed with SHA-512 and RSA-4096.</p>
        <div style="font-size: 0.85rem; margin-bottom: 12px; color: #d1d5db;">
          Peers: <strong id="su3-peers">-</strong> | Archive Size: <strong id="su3-size">- KB</strong>
        </div>
      </div>
      <div class="download-actions">
        <a href="/i2pseeds.su3?netid=2" id="btn-dl-su3" class="btn-dl">Download SU3</a>
        <button class="btn-copy" onclick="copyLink('/i2pseeds.su3?netid=2')">Copy URL</button>
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
        const pkgFFRatio = (data.package.floodfill_ratio * 100).toFixed(1);
        document.getElementById('pkg-floodfill-ratio').textContent = pkgFFRatio + '% (' + data.package.floodfill_count + ' nodes)';
        document.getElementById('pkg-etag').textContent = data.package.etag || 'N/A';
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
