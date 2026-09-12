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
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IVNP Reseed</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    /* Hallmark · genre: modern-minimal · macrostructure: Stat-Led · theme: Cobalt
     * H4 knobs: number=tabular display, qualifier=below, secondary=row of four
     * nav: N9 edge-aligned · footer: Ft2 inline · enrichment: none
     * pre-emit critique: P5 H4 E5 S4 R5 V4 */
    :root {
      --color-paper: oklch(98.5% 0.004 250);
      --color-paper-2: oklch(96% 0.007 250);
      --color-ink: oklch(24% 0.02 258);
      --color-ink-2: oklch(34% 0.018 257);
      --color-muted: oklch(50% 0.014 257);
      --color-rule: oklch(89% 0.008 254);
      --color-rule-2: oklch(82% 0.010 254);
      --color-accent: oklch(55% 0.20 256);
      --color-accent-ink: oklch(99% 0.003 256);
      --color-focus: oklch(55% 0.20 256);
      --color-graphite: oklch(23% 0.016 260);
      --color-graphite-2: oklch(30% 0.014 260);
      --color-graphite-ink: oklch(93% 0.006 258);
      --color-graphite-muted: oklch(66% 0.012 258);
      --color-ok: oklch(58% 0.16 160);

      --font-display: "Space Grotesk", ui-sans-serif, system-ui, sans-serif;
      --font-body: "Inter", ui-sans-serif, system-ui, sans-serif;
      --font-mono: "JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace;

      --space-2xs: 0.25rem;
      --space-xs: 0.5rem;
      --space-sm: 0.75rem;
      --space-md: 1rem;
      --space-lg: 1.5rem;
      --space-xl: 2.5rem;
      --space-2xl: 4rem;
      --space-3xl: 6rem;

      --text-xs: 0.75rem;
      --text-sm: 0.875rem;
      --text-base: 1rem;
      --text-md: 1.25rem;
      --text-lg: 1.5625rem;
      --text-figure: clamp(3.5rem, 8vw + 1rem, 6rem);

      --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
      --dur-micro: 120ms;
      --dur-short: 220ms;

      --z-tooltip: 600;
      --z-toast: 500;
      --z-sticky: 200;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { overflow-x: clip; }
    body {
      background: var(--color-paper);
      color: var(--color-ink-2);
      font-family: var(--font-body);
      font-weight: 400;
      font-size: var(--text-base);
      line-height: 1.55;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
    code {
      font-family: var(--font-mono);
      font-size: 0.82em;
      background: var(--color-paper-2);
      border: 1px solid var(--color-rule);
      border-radius: 4px;
      padding: 0.1em 0.4em;
      color: var(--color-ink);
      word-break: break-all;
    }
    h1, h2, h3 {
      font-family: var(--font-display);
      font-weight: 600;
      color: var(--color-ink);
      letter-spacing: -0.02em;
      line-height: 1.15;
      font-style: normal;
      overflow-wrap: anywhere;
      min-width: 0;
    }
    .mono {
      font-family: var(--font-mono);
      font-variant-numeric: tabular-nums;
    }
    .btn {
      font-family: var(--font-body);
      font-size: var(--text-sm);
      font-weight: 500;
      border-radius: 6px;
      padding: 0.55rem 1rem;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      white-space: nowrap;
      border: 1px solid transparent;
      transition: background-color var(--dur-short) var(--ease-out),
                  border-color var(--dur-short) var(--ease-out),
                  color var(--dur-short) var(--ease-out),
                  transform var(--dur-micro) var(--ease-out);
    }
    .btn:active { transform: translateY(1px); }
    .btn:focus-visible {
      outline: 2px solid var(--color-focus);
      outline-offset: 2px;
    }
    .btn-primary {
      background: var(--color-accent);
      color: var(--color-accent-ink);
      border-color: var(--color-accent);
    }
    .btn-primary:hover { background: oklch(50% 0.21 256); }
    .btn-outline {
      background: transparent;
      color: var(--color-ink);
      border-color: var(--color-rule-2);
    }
    .btn-outline:hover { border-color: var(--color-accent); color: var(--color-accent); }
    .btn-ghost {
      background: transparent;
      color: var(--color-ink-2);
      border-color: var(--color-rule-2);
    }
    .btn-ghost:hover { background: var(--color-paper-2); color: var(--color-ink); }
    .btn-ghost-dark {
      background: transparent;
      color: var(--color-graphite-ink);
      border-color: var(--color-graphite-2);
    }
    .btn-ghost-dark:hover { border-color: var(--color-graphite-muted); }
    .btn.is-disabled {
      opacity: 0.5;
      cursor: not-allowed;
      pointer-events: none;
    }

    .topbar {
      position: sticky;
      top: 0;
      z-index: var(--z-sticky);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: var(--space-md);
      flex-wrap: wrap;
      padding: var(--space-md) clamp(1rem, 4vw, 3rem);
      border-bottom: 1px solid var(--color-rule);
      background: oklch(98.5% 0.004 250 / 0.85);
      backdrop-filter: blur(8px);
    }
    .wordmark {
      font-family: var(--font-display);
      font-weight: 600;
      font-size: 1.05rem;
      letter-spacing: -0.01em;
      color: var(--color-ink);
      text-decoration: none;
    }
    .wordmark-sep { color: var(--color-accent); margin: 0 0.3em; }
    .topbar-status {
      display: flex;
      align-items: center;
      gap: var(--space-sm);
      flex-wrap: wrap;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      font-family: var(--font-mono);
      font-size: var(--text-xs);
      font-weight: 500;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--color-ink-2);
      border: 1px solid var(--color-rule);
      border-radius: 999px;
      padding: 4px 10px;
    }
    .pip {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--color-ok);
      flex-shrink: 0;
    }
    .status-pill.is-paused .pip { background: var(--color-muted); }
    .meta-mono {
      font-family: var(--font-mono);
      font-size: var(--text-xs);
      letter-spacing: 0.04em;
      color: var(--color-muted);
      font-variant-numeric: tabular-nums;
    }
    #btn-refresh-toggle { padding: 0.3rem 0.7rem; font-size: var(--text-xs); }

    main {
      max-width: 72rem;
      margin: 0 auto;
      padding: 0 clamp(1rem, 4vw, 3rem) var(--space-3xl);
    }

    .hero {
      display: grid;
      grid-template-columns: 1fr;
      gap: var(--space-xl);
      padding: var(--space-2xl) 0 var(--space-xl);
      align-items: end;
    }
    @media (min-width: 60rem) {
      .hero { grid-template-columns: 1.15fr minmax(0, 1fr); }
    }
    .hero-title {
      font-size: var(--text-md);
      font-weight: 500;
      color: var(--color-muted);
      margin-bottom: var(--space-sm);
    }
    .hero-figure {
      font-family: var(--font-display);
      font-weight: 600;
      font-size: var(--text-figure);
      line-height: 1;
      letter-spacing: -0.03em;
      color: var(--color-ink);
      font-variant-numeric: tabular-nums;
    }
    .hero-qualifier {
      margin-top: var(--space-sm);
      font-size: var(--text-md);
      color: var(--color-ink-2);
      max-width: 34ch;
    }
    .stat-strip {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: var(--space-md) var(--space-lg);
      margin-top: var(--space-xl);
      padding-top: var(--space-lg);
      border-top: 1px solid var(--color-rule);
    }
    @media (min-width: 40rem) {
      .stat-strip { grid-template-columns: repeat(4, 1fr); }
    }
    .stat dt {
      font-family: var(--font-mono);
      font-size: var(--text-xs);
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--color-muted);
      margin-bottom: 4px;
    }
    .stat dd {
      font-family: var(--font-display);
      font-size: var(--text-lg);
      font-weight: 600;
      color: var(--color-ink);
      font-variant-numeric: tabular-nums;
      line-height: 1.2;
    }
    .stat dd small {
      font-family: var(--font-body);
      font-size: var(--text-xs);
      font-weight: 400;
      color: var(--color-muted);
    }

    .artifact {
      background: var(--color-graphite);
      color: var(--color-graphite-ink);
      border-radius: 10px;
      padding: var(--space-lg);
      box-shadow: 0 1px 2px oklch(24% 0.02 258 / 0.08);
      min-width: 0;
    }
    .artifact-label {
      font-family: var(--font-mono);
      font-size: var(--text-xs);
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--color-graphite-muted);
    }
    .artifact-name {
      font-family: var(--font-mono);
      font-size: var(--text-md);
      font-weight: 500;
      color: var(--color-graphite-ink);
      margin-top: var(--space-2xs);
      word-break: break-all;
    }
    .artifact-meta {
      margin: var(--space-md) 0;
      border-top: 1px solid var(--color-graphite-2);
    }
    .artifact-meta > div {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: var(--space-md);
      padding: var(--space-xs) 0;
      border-bottom: 1px solid var(--color-graphite-2);
    }
    .artifact-meta dt {
      font-size: var(--text-sm);
      color: var(--color-graphite-muted);
    }
    .artifact-meta dd {
      font-family: var(--font-mono);
      font-size: var(--text-sm);
      color: var(--color-graphite-ink);
      font-variant-numeric: tabular-nums;
      text-align: right;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .artifact-actions {
      display: flex;
      gap: var(--space-sm);
      flex-wrap: wrap;
    }
    .artifact-actions .btn { flex: 1; min-width: 8rem; }

    section { padding-top: var(--space-2xl); }
    .section-title {
      font-size: var(--text-lg);
      margin-bottom: var(--space-sm);
    }
    .section-note {
      color: var(--color-muted);
      font-size: var(--text-sm);
      max-width: 65ch;
      margin-bottom: var(--space-lg);
    }

    .setup-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: var(--space-lg);
    }
    @media (min-width: 60rem) {
      .setup-grid { grid-template-columns: minmax(0, 0.9fr) minmax(0, 1.4fr); }
    }
    .card {
      background: var(--color-paper);
      border: 1px solid var(--color-rule);
      border-radius: 10px;
      padding: var(--space-lg);
      min-width: 0;
    }
    .card-label {
      font-family: var(--font-mono);
      font-size: var(--text-xs);
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--color-muted);
    }
    .card-value-mono {
      display: block;
      font-family: var(--font-mono);
      font-size: var(--text-sm);
      color: var(--color-ink);
      margin-top: var(--space-2xs);
      word-break: break-all;
    }
    .card-note {
      font-size: var(--text-sm);
      color: var(--color-ink-2);
      margin: var(--space-sm) 0;
    }
    .cert-meta {
      font-family: var(--font-mono);
      font-size: var(--text-xs);
      color: var(--color-muted);
      margin-bottom: var(--space-md);
    }
    .card-actions {
      display: flex;
      gap: var(--space-sm);
      flex-wrap: wrap;
    }

    .tabs {
      display: inline-flex;
      gap: 2px;
      background: var(--color-paper-2);
      border: 1px solid var(--color-rule);
      border-radius: 8px;
      padding: 3px;
      margin-bottom: var(--space-md);
    }
    .tab {
      font-family: var(--font-body);
      font-size: var(--text-sm);
      font-weight: 500;
      color: var(--color-muted);
      background: transparent;
      border: none;
      border-radius: 6px;
      padding: 0.4rem 0.9rem;
      cursor: pointer;
      white-space: nowrap;
      transition: color var(--dur-short) var(--ease-out),
                  background-color var(--dur-short) var(--ease-out);
    }
    .tab:hover { color: var(--color-ink); }
    .tab:focus-visible {
      outline: 2px solid var(--color-focus);
      outline-offset: 2px;
    }
    .tab.is-active {
      background: var(--color-paper);
      color: var(--color-ink);
      box-shadow: 0 1px 2px oklch(24% 0.02 258 / 0.08);
    }
    .steps { display: none; }
    .steps.is-active {
      display: block;
      animation: steps-in 150ms var(--ease-out);
    }
    @keyframes steps-in {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    .steps li {
      font-size: var(--text-sm);
      color: var(--color-ink-2);
      margin-left: 1.2rem;
      padding-left: var(--space-2xs);
      margin-bottom: var(--space-sm);
    }
    .steps li::marker {
      font-family: var(--font-mono);
      color: var(--color-muted);
    }
    .url-row {
      display: flex;
      align-items: center;
      gap: var(--space-sm);
      margin-top: var(--space-md);
      padding-top: var(--space-md);
      border-top: 1px solid var(--color-rule);
    }
    .url-row .url-text {
      flex: 1;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      display: block;
      padding: 0.45rem 0.7rem;
    }
    .url-row .btn { flex-shrink: 0; }

    .heatmap-grid {
      display: grid;
      grid-template-columns: repeat(16, 1fr);
      gap: 3px;
      border: 1px solid var(--color-rule);
      border-radius: 10px;
      padding: var(--space-md);
      background: var(--color-paper);
    }
    @media (min-width: 60rem) {
      .heatmap-grid { grid-template-columns: repeat(32, 1fr); }
    }
    .bucket-cell {
      aspect-ratio: 1;
      border-radius: 2px;
      background: var(--color-paper-2);
    }
    @media (hover: hover) and (pointer: fine) {
      .bucket-cell:hover {
        outline: 1.5px solid var(--color-accent);
        outline-offset: 1px;
      }
    }
    .heatmap-legend {
      display: flex;
      align-items: center;
      gap: var(--space-xs);
      margin-top: var(--space-sm);
      font-family: var(--font-mono);
      font-size: var(--text-xs);
      color: var(--color-muted);
    }
    .legend-chip {
      width: 10px;
      height: 10px;
      border-radius: 2px;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: 1fr;
      column-gap: var(--space-2xl);
    }
    @media (min-width: 40rem) {
      .detail-grid { grid-template-columns: 1fr 1fr; }
    }
    .detail-row {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: var(--space-md);
      padding: var(--space-xs) 0;
      border-bottom: 1px solid var(--color-rule);
    }
    .detail-row dt {
      font-size: var(--text-sm);
      color: var(--color-ink-2);
    }
    .detail-row dd {
      font-family: var(--font-mono);
      font-size: var(--text-sm);
      font-weight: 500;
      color: var(--color-ink);
      font-variant-numeric: tabular-nums;
      text-align: right;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .footer {
      max-width: 72rem;
      margin: 0 auto;
      padding: var(--space-lg) clamp(1rem, 4vw, 3rem) var(--space-xl);
      border-top: 1px solid var(--color-rule);
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: var(--space-sm);
      font-size: var(--text-xs);
      color: var(--color-muted);
      font-family: var(--font-mono);
    }
    .footer a { color: var(--color-accent); text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
    .footer a:focus-visible {
      outline: 2px solid var(--color-focus);
      outline-offset: 2px;
    }

    #tooltip {
      position: fixed;
      display: none;
      background: var(--color-graphite);
      color: var(--color-graphite-ink);
      padding: 6px 10px;
      border-radius: 6px;
      font-size: var(--text-xs);
      font-family: var(--font-mono);
      font-variant-numeric: tabular-nums;
      pointer-events: none;
      z-index: var(--z-tooltip);
      box-shadow: 0 4px 12px oklch(24% 0.02 258 / 0.25);
    }
    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: var(--color-ink);
      color: var(--color-paper);
      padding: 10px 16px;
      border-radius: 6px;
      font-size: var(--text-sm);
      z-index: var(--z-toast);
      display: none;
      box-shadow: 0 4px 12px oklch(24% 0.02 258 / 0.25);
    }

    dialog {
      position: fixed;
      inset: 0;
      margin: auto;
      width: min(680px, calc(100% - 2rem));
      height: fit-content;
      max-height: min(85vh, 40rem);
      border: 1px solid var(--color-rule);
      border-radius: 10px;
      padding: var(--space-lg);
      background: var(--color-paper);
      color: var(--color-ink-2);
      display: flex;
      flex-direction: column;
    }
    dialog:not([open]) { display: none; }
    dialog::backdrop {
      background: oklch(24% 0.02 258 / 0.45);
    }
    .modal-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: var(--space-md);
      margin-bottom: var(--space-md);
    }
    .modal-head h3 { font-size: var(--text-md); }
    #key-pem-display {
      background: var(--color-graphite);
      color: var(--color-graphite-ink);
      border-radius: 8px;
      padding: var(--space-md);
      font-family: var(--font-mono);
      font-size: var(--text-xs);
      line-height: 1.5;
      overflow-y: auto;
      flex: 1;
      min-height: 10rem;
      white-space: pre-wrap;
      word-break: break-all;
      user-select: all;
      margin: var(--space-md) 0;
    }
    .modal-actions {
      display: flex;
      justify-content: flex-end;
      gap: var(--space-sm);
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 150ms !important;
        transition-duration: 150ms !important;
      }
    }
  </style>
</head>
<body>

  <header class="topbar">
    <a class="wordmark" href="/">IVNP<span class="wordmark-sep">/</span>Reseed</a>
    <div class="topbar-status">
      <span class="status-pill" id="status-live"><span class="pip"></span>Live</span>
      <span class="meta-mono" id="badge-mode">—</span>
      <span class="meta-mono" id="badge-uptime" title="Uptime">—</span>
      <button class="btn btn-ghost" id="btn-refresh-toggle">Pause</button>
    </div>
  </header>

  <main>
    <section class="hero" style="padding-top: var(--space-2xl);">
      <div class="hero-main">
        <h1 class="hero-title">I2P reseed service</h1>
        <div class="hero-figure" id="hero-figure" aria-live="polite">—</div>
        <p class="hero-qualifier">peers in the current signed archive, refreshed from the live crawl.</p>
        <dl class="stat-strip">
          <div class="stat"><dt>Indexed</dt><dd id="stat-indexed">—</dd></div>
          <div class="stat"><dt>Reachable</dt><dd id="stat-reachable">—</dd></div>
          <div class="stat"><dt>Floodfills</dt><dd id="stat-floodfills">—</dd></div>
          <div class="stat"><dt>Next rebuild</dt><dd id="stat-next">—</dd></div>
        </dl>
      </div>
      <div class="artifact">
        <span class="artifact-label">Reseed archive</span>
        <div class="artifact-name" id="su3-name">i2pseeds.su3</div>
        <dl class="artifact-meta">
          <div><dt>Peers</dt><dd id="su3-peers">—</dd></div>
          <div><dt>Size</dt><dd id="su3-size">—</dd></div>
          <div><dt>Format</dt><dd>SU3 · ZIP · RSA-4096</dd></div>
          <div><dt>ETag</dt><dd id="su3-etag">—</dd></div>
        </dl>
        <div class="artifact-actions">
          <a class="btn btn-primary" id="btn-dl-su3" href="/i2pseeds.su3">Download archive</a>
          <button class="btn btn-ghost-dark" id="btn-copy-su3">Copy URL</button>
        </div>
      </div>
    </section>

    <section class="setup">
      <h2 class="section-title">Add this reseed to your router</h2>
      <div class="setup-grid">
        <div class="card cert-card">
          <span class="card-label">Signer certificate</span>
          <span class="card-value-mono" id="signer-id-display">—</span>
          <p class="card-note">Clients verify the archive signature against this certificate. Install it as <code id="cert-filename">reseed.crt</code> in the client’s reseed certificate directory.</p>
          <div class="cert-meta">X.509 · RSA-4096 · SHA-512</div>
          <div class="card-actions">
            <a class="btn btn-outline" href="/reseed-rsa.crt" id="btn-dl-cert" download>Download .crt</a>
            <button class="btn btn-ghost" id="btn-copy-key">Copy PEM</button>
            <button class="btn btn-ghost" id="btn-view-key">View</button>
          </div>
        </div>
        <div class="card install-card">
          <div class="tabs" role="tablist" aria-label="Client">
            <button class="tab is-active" role="tab" id="tab-java" aria-selected="true" aria-controls="panel-java" data-tab="java">Java I2P</button>
            <button class="tab" role="tab" id="tab-i2pd" aria-selected="false" aria-controls="panel-i2pd" data-tab="i2pd">i2pd</button>
            <button class="tab" role="tab" id="tab-ivnp" aria-selected="false" aria-controls="panel-ivnp" data-tab="ivnp">IVNP</button>
          </div>
          <ol class="steps is-active" id="panel-java" role="tabpanel" aria-labelledby="tab-java">
            <li>Save the certificate as <code>~/.i2p/certificates/reseed/<span class="js-cert-name">…</span></code></li>
            <li>In the router console open <code>http://127.0.0.1:7657/configreseed</code>, add the reseed URL below, then choose <em>Save changes</em> and <em>Reseed now</em>.</li>
          </ol>
          <ol class="steps" id="panel-i2pd" role="tabpanel" aria-labelledby="tab-i2pd">
            <li>Save the certificate as <code>~/.i2pd/certificates/reseed/<span class="js-cert-name">…</span></code> — system service: <code>/var/lib/i2pd/certificates/reseed/</code></li>
            <li>Run once with <code>i2pd --reseed.urls=<span class="js-su3-url">…</span></code>, or set <code>reseed.urls</code> in <code>i2pd.conf</code>.</li>
          </ol>
          <ol class="steps" id="panel-ivnp" role="tabpanel" aria-labelledby="tab-ivnp">
            <li>Add the reseed URL below to <code>reseed.endpoints</code> in the router config (web console → <em>Config → Reseed</em>).</li>
            <li>Trusted signers ship inside IVNP’s embedded certificate bundle — no file install needed for pre-trusted signers. Trigger via <em>Actions → Reseed</em>.</li>
          </ol>
          <div class="url-row">
            <code class="url-text" id="su3-url-text">—</code>
            <button class="btn btn-ghost" id="btn-copy-url">Copy URL</button>
          </div>
        </div>
      </div>
    </section>

    <section class="coverage">
      <h2 class="section-title">Keyspace coverage</h2>
      <p class="section-note">Peers indexed per DHT bucket, prefixes <code>0x00</code>–<code>0xFF</code>. Sparse buckets get extra lookups on each pass.</p>
      <div class="heatmap-grid" id="heatmap-grid"></div>
      <div class="heatmap-legend">
        <span>0</span>
        <span class="legend-chip" style="background: oklch(92% 0.03 256);"></span>
        <span class="legend-chip" style="background: oklch(80% 0.09 256);"></span>
        <span class="legend-chip" style="background: oklch(68% 0.15 256);"></span>
        <span class="legend-chip" style="background: var(--color-accent);"></span>
        <span id="legend-max">max —</span>
      </div>
    </section>

    <section class="detail">
      <h2 class="section-title">Network detail</h2>
      <div class="card">
        <dl class="detail-grid">
          <div>
            <div class="detail-row"><dt>Reachable peers</dt><dd id="d-reachable">—</dd></div>
            <div class="detail-row"><dt>Floodfill peers</dt><dd id="d-floodfill">—</dd></div>
            <div class="detail-row"><dt>Median RTT (p50)</dt><dd id="d-rtt-p50">—</dd></div>
            <div class="detail-row"><dt>p90 RTT</dt><dd id="d-rtt-p90">—</dd></div>
            <div class="detail-row"><dt>Bucket coverage</dt><dd id="d-coverage">—</dd></div>
          </div>
          <div>
            <div class="detail-row"><dt>Unique IPv4 /16 subnets</dt><dd id="d-subnets">—</dd></div>
            <div class="detail-row"><dt>Unique IPv6 endpoints</dt><dd id="d-ipv6">—</dd></div>
            <div class="detail-row"><dt>Router families</dt><dd id="d-families">—</dd></div>
            <div class="detail-row"><dt>Dual-stack share</dt><dd id="d-dual">—</dd></div>
            <div class="detail-row"><dt>Avg peer availability</dt><dd id="d-avail">—</dd></div>
          </div>
        </dl>
      </div>
    </section>
  </main>

  <footer class="footer">
    <span>IVNP reseed · v<span id="footer-version">dev</span> · netid <span id="footer-netid">2</span></span>
    <span><a href="/stats">/stats</a> · <a href="/health">/health</a></span>
  </footer>

  <dialog id="key-modal" aria-labelledby="key-modal-title">
    <div class="modal-head">
      <h3 id="key-modal-title">Signer certificate</h3>
      <button class="btn btn-ghost" id="btn-modal-close">Close</button>
    </div>
    <div class="tabs" role="tablist" aria-label="Key material">
      <button class="tab is-active" role="tab" id="tab-cert" aria-selected="true" data-mtab="cert">Certificate (.crt)</button>
      <button class="tab" role="tab" id="tab-pubkey" aria-selected="false" data-mtab="pubkey">Public key (PEM)</button>
    </div>
    <pre id="key-pem-display">Loading…</pre>
    <div class="modal-actions">
      <button class="btn btn-outline" id="btn-copy-displayed">Copy to clipboard</button>
    </div>
  </dialog>

  <div id="tooltip" role="tooltip"></div>
  <div id="toast" role="status"></div>

  <script id="initial-data" type="application/json">
{{INITIAL_DATA}}
  </script>

  <script>
    let autoRefresh = true;
    let refreshIntervalMs = 3000;
    let timerId = null;
    let etaSeconds = 0;
    let refreshCycleMin = 0;
    let cachedCertPEM = '';
    let cachedPubKeyPEM = '';
    let certFileName = 'reseed.crt';
    let su3URL = '';
    let firstRender = true;
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function formatUptime(seconds) {
      if (seconds < 60) return seconds + 's';
      const m = Math.floor(seconds / 60);
      const s = seconds % 60;
      if (m < 60) return m + 'm ' + s + 's';
      const h = Math.floor(m / 60);
      return h + 'h ' + (m % 60) + 'm';
    }

    function formatETA(sec) {
      if (sec <= 0) return 'building';
      const m = Math.floor(sec / 60);
      const s = sec % 60;
      return String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
    }

    function signerCertName(signerID) {
      const clean = (signerID || 'reseed').replace(/@/g, '_at_').replace(/[\/\\:]/g, '_');
      return clean + '.crt';
    }

    function countUp(el, target) {
      if (reducedMotion || !isFinite(target)) {
        el.textContent = Number(target || 0).toLocaleString();
        return;
      }
      const dur = 900;
      const start = performance.now();
      function tick(now) {
        const t = Math.min(1, (now - start) / dur);
        const eased = 1 - Math.pow(1 - t, 3);
        el.textContent = Math.round(target * eased).toLocaleString();
        if (t < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    }

    function renderStats(data) {
      if (!data) return;
      const pkg = data.package || {};
      const netid = data.network_id || 2;

      document.getElementById('badge-uptime').textContent = formatUptime(data.uptime_seconds || 0);
      const modeEl = document.getElementById('badge-mode');
      if (data.exploration_mode) {
        modeEl.textContent = data.exploration_mode.toUpperCase();
      }
      document.getElementById('footer-version').textContent = data.version || 'dev';
      document.getElementById('footer-netid').textContent = netid;

      // Hero figure: peers published in the current archive.
      const published = pkg.peer_count || data.published_peers || 0;
      const heroEl = document.getElementById('hero-figure');
      if (firstRender) {
        countUp(heroEl, published);
      } else {
        heroEl.textContent = published.toLocaleString();
      }

      document.getElementById('stat-indexed').textContent = (data.total_indexed || 0).toLocaleString();
      const reachRatio = data.total_indexed > 0 ? (data.reachable_peers / data.total_indexed * 100).toFixed(0) : '0';
      document.getElementById('stat-reachable').innerHTML =
        (data.reachable_peers || 0).toLocaleString() + ' <small>' + reachRatio + '%</small>';
      const ffRatio = data.total_indexed > 0 ? (data.floodfill_peers / data.total_indexed * 100).toFixed(0) : '0';
      document.getElementById('stat-floodfills').innerHTML =
        (data.floodfill_peers || 0).toLocaleString() + ' <small>' + ffRatio + '%</small>';

      etaSeconds = pkg.next_refresh_eta_seconds || 0;
      refreshCycleMin = Math.round((pkg.refresh_interval_seconds || 0) / 60);
      renderNextStat();

      // Archive card
      document.getElementById('su3-peers').textContent = published.toLocaleString();
      const su3Size = pkg.su3_size_bytes ? (pkg.su3_size_bytes / 1024).toFixed(1) : null;
      document.getElementById('su3-size').textContent = su3Size ? su3Size + ' KB' : '—';
      document.getElementById('su3-etag').textContent = pkg.etag || '—';
      su3URL = window.location.origin + '/i2pseeds.su3?netid=' + netid;
      document.getElementById('btn-dl-su3').href = '/i2pseeds.su3?netid=' + netid;
      document.getElementById('su3-url-text').textContent = su3URL;
      document.querySelectorAll('.js-su3-url').forEach(el => { el.textContent = su3URL; });
      const dlBtn = document.getElementById('btn-dl-su3');
      if (!pkg.su3_size_bytes) {
        dlBtn.classList.add('is-disabled');
        dlBtn.setAttribute('aria-disabled', 'true');
        dlBtn.textContent = 'Archive building…';
      } else {
        dlBtn.classList.remove('is-disabled');
        dlBtn.removeAttribute('aria-disabled');
        dlBtn.textContent = 'Download archive';
      }

      // Certificate card + per-client instructions
      if (data.signer_id) {
        document.getElementById('signer-id-display').textContent = data.signer_id;
        certFileName = signerCertName(data.signer_id);
        document.getElementById('cert-filename').textContent = certFileName;
        document.querySelectorAll('.js-cert-name').forEach(el => { el.textContent = certFileName; });
        document.getElementById('btn-dl-cert').setAttribute('download', certFileName);
      }
      if (data.certificate_pem) cachedCertPEM = data.certificate_pem;
      if (data.public_key_pem) cachedPubKeyPEM = data.public_key_pem;

      // Network detail
      document.getElementById('d-reachable').textContent =
        (data.reachable_peers || 0).toLocaleString() + ' of ' + (data.total_indexed || 0).toLocaleString();
      document.getElementById('d-floodfill').textContent =
        (data.floodfill_peers || 0).toLocaleString() + ' (' + ffRatio + '%)';
      const rtt = data.rtt || {};
      document.getElementById('d-rtt-p50').textContent = (rtt.p50_ms || 0) + ' ms';
      document.getElementById('d-rtt-p90').textContent = (rtt.p90_ms || 0) + ' ms';
      if (data.kbuckets) {
        document.getElementById('d-coverage').textContent =
          data.kbuckets.covered_buckets + ' / ' + data.kbuckets.total_buckets +
          ' (' + data.kbuckets.coverage_percent.toFixed(0) + '%)';
      }
      if (data.diversity) {
        const div = data.diversity;
        const subnets = div.unique_ipv4_subnets_16 > 0 ? div.unique_ipv4_subnets_16 : (div.unique_ipv4_subnets_24 || 0);
        document.getElementById('d-subnets').textContent = subnets.toLocaleString();
        document.getElementById('d-ipv6').textContent = (div.unique_ipv6_count || 0).toLocaleString();
        document.getElementById('d-families').textContent = (div.unique_families || 0).toLocaleString();
      }
      if (pkg.dual_stack_ratio !== undefined) {
        document.getElementById('d-dual').textContent = (pkg.dual_stack_ratio * 100).toFixed(0) + '%';
      }
      if (pkg.average_availability !== undefined) {
        document.getElementById('d-avail').textContent = (pkg.average_availability * 100).toFixed(0) + '%';
      }

      renderHeatmap(data.kbuckets ? data.kbuckets.distribution : []);
      firstRender = false;
    }

    function renderNextStat() {
      const el = document.getElementById('stat-next');
      const eta = formatETA(etaSeconds);
      el.innerHTML = refreshCycleMin > 0
        ? eta + ' <small>every ' + refreshCycleMin + 'm</small>'
        : eta;
    }

    function renderHeatmap(distribution) {
      const container = document.getElementById('heatmap-grid');
      container.innerHTML = '';
      const tooltip = document.getElementById('tooltip');

      let maxCount = 0;
      if (distribution) {
        for (let i = 0; i < 256; i++) {
          if (distribution[i] > maxCount) maxCount = distribution[i];
        }
      }
      document.getElementById('legend-max').textContent = 'max ' + maxCount;

      for (let i = 0; i < 256; i++) {
        const cell = document.createElement('div');
        cell.className = 'bucket-cell';
        const count = (distribution && distribution[i]) ? distribution[i] : 0;
        const hex = '0x' + i.toString(16).padStart(2, '0').toUpperCase();

        if (count === 0 || maxCount === 0) {
          cell.style.background = 'var(--color-paper-2)';
        } else {
          const ratio = Math.min(1, count / maxCount);
          const l = 92 - ratio * 37;
          const c = 0.03 + ratio * 0.17;
          cell.style.background = 'oklch(' + l.toFixed(1) + '% ' + c.toFixed(3) + ' 256)';
        }

        cell.onmouseenter = (e) => {
          tooltip.style.display = 'block';
          tooltip.textContent = 'Bucket ' + hex + ' · ' + count + ' peers';
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

    function showToast(msg) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.style.display = 'block';
      setTimeout(() => { toast.style.display = 'none'; }, 4000);
    }

    function flashCopied(btn, label) {
      const original = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = original; }, 2500);
      if (label) showToast(label);
    }

    function copyText(text, btn) {
      navigator.clipboard.writeText(text).then(() => {
        flashCopied(btn);
      }).catch(() => {
        prompt('Copy manually:', text);
      });
    }

    function copyURL(url, btn) {
      copyText(url || window.location.origin + '/i2pseeds.su3', btn);
    }

    function copyPublicKey() {
      const text = cachedCertPEM || cachedPubKeyPEM;
      if (text) {
        copyText(text, document.getElementById('btn-copy-key'));
        return;
      }
      fetch('/reseed-rsa.crt')
        .then(r => r.text())
        .then(t => {
          cachedCertPEM = t;
          copyText(t, document.getElementById('btn-copy-key'));
        })
        .catch(() => showToast('Could not load the certificate. Try Download instead.'));
    }

    // Install-instruction tabs
    document.querySelectorAll('.install-card .tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.install-card .tab').forEach(t => {
          t.classList.remove('is-active');
          t.setAttribute('aria-selected', 'false');
        });
        tab.classList.add('is-active');
        tab.setAttribute('aria-selected', 'true');
        document.querySelectorAll('.steps').forEach(p => p.classList.remove('is-active'));
        document.getElementById('panel-' + tab.dataset.tab).classList.add('is-active');
      });
    });

    // Key material modal
    const keyModal = document.getElementById('key-modal');
    let currentKeyTab = 'cert';

    function loadKeyTab(tab) {
      currentKeyTab = tab;
      document.querySelectorAll('#key-modal .tab').forEach(t => {
        const active = t.dataset.mtab === tab;
        t.classList.toggle('is-active', active);
        t.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      const display = document.getElementById('key-pem-display');
      const cached = tab === 'cert' ? cachedCertPEM : cachedPubKeyPEM;
      if (cached) {
        display.textContent = cached;
        return;
      }
      display.textContent = 'Loading…';
      const url = tab === 'cert' ? '/reseed-rsa.crt' : '/reseed-rsa.pub.pem';
      fetch(url).then(r => r.text()).then(t => {
        if (tab === 'cert') cachedCertPEM = t; else cachedPubKeyPEM = t;
        if (currentKeyTab === tab) display.textContent = t;
      }).catch(() => {
        display.textContent = 'Could not load key material.';
      });
    }

    document.querySelectorAll('#key-modal .tab').forEach(tab => {
      tab.addEventListener('click', () => loadKeyTab(tab.dataset.mtab));
    });

    document.getElementById('btn-view-key').addEventListener('click', () => {
      loadKeyTab(currentKeyTab);
      keyModal.showModal();
    });
    document.getElementById('btn-modal-close').addEventListener('click', () => keyModal.close());
    keyModal.addEventListener('click', (e) => {
      if (e.target === keyModal) keyModal.close();
    });
    document.getElementById('btn-copy-displayed').addEventListener('click', (e) => {
      const display = document.getElementById('key-pem-display');
      if (display.textContent) copyText(display.textContent, e.currentTarget);
    });

    document.getElementById('btn-copy-su3').addEventListener('click', (e) => copyURL(su3URL, e.currentTarget));
    document.getElementById('btn-copy-url').addEventListener('click', (e) => copyURL(su3URL, e.currentTarget));
    document.getElementById('btn-copy-key').addEventListener('click', copyPublicKey);

    function toggleAutoRefresh() {
      autoRefresh = !autoRefresh;
      const btn = document.getElementById('btn-refresh-toggle');
      const pill = document.getElementById('status-live');
      if (autoRefresh) {
        btn.textContent = 'Pause';
        pill.classList.remove('is-paused');
        pill.lastChild.textContent = 'Live';
        startPolling();
      } else {
        btn.textContent = 'Resume';
        pill.classList.add('is-paused');
        pill.lastChild.textContent = 'Paused';
        stopPolling();
      }
    }
    document.getElementById('btn-refresh-toggle').addEventListener('click', toggleAutoRefresh);

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

    try {
      const initial = JSON.parse(document.getElementById('initial-data').textContent);
      renderStats(initial);
    } catch(e) {
      console.warn('initial parse failed', e);
    }

    startPolling();

    setInterval(() => {
      if (etaSeconds > 0) {
        etaSeconds--;
        renderNextStat();
        if (etaSeconds === 0) fetchLatest();
      }
    }, 1000);
  </script>
</body>
</html>
`
