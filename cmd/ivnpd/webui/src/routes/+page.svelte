<script lang="ts">
	import { onMount } from 'svelte';
	import Header from '$lib/components/Header.svelte';
	import RouterHeroCard from '$lib/components/RouterHeroCard.svelte';
	import BandwidthChartCard from '$lib/components/BandwidthChartCard.svelte';
	import TunnelMatrixCard from '$lib/components/TunnelMatrixCard.svelte';
	import NetDBExplorerCard from '$lib/components/NetDBExplorerCard.svelte';
	import DestinationsServicesCard from '$lib/components/DestinationsServicesCard.svelte';
	import DiagnosticsCard from '$lib/components/DiagnosticsCard.svelte';
	import {
		applyMetrics,
		authRequired,
		fetchDestinations,
		fetchMetrics,
		fetchNetDB,
		fetchStatus,
		fetchTunnels,
		collectionState,
		markMetricsInterrupted,
		metricsStreamState,
		metricsEventURL,
		refreshDashboard,
		routerStatus,
		setAccessToken
	} from '$lib/api';
	import type { ObservabilityMetricsResponse } from '$lib/types';

	let eventSource: EventSource | null = null;
	let summaryTimer: number | null = null;
	let netdbTimer: number | null = null;
	let fallbackTimer: number | null = null;
	let accessToken = '';
	let authenticating = false;
	let authError = '';
	let disposed = false;
	let lastStreamSample = 0;

	function stopFallback(): void {
		if (fallbackTimer !== null) window.clearInterval(fallbackTimer);
		fallbackTimer = null;
	}

	function startFallback(): void {
		if (fallbackTimer !== null) return;
		fallbackTimer = window.setInterval(() => {
			if (!$collectionState.metrics.loading) void fetchMetrics();
		}, 2000);
	}

	function connectMetrics(): void {
		eventSource?.close();
		metricsStreamState.set('connecting');
		lastStreamSample = Date.now();
		eventSource = new EventSource(metricsEventURL());
		eventSource.addEventListener('metrics', (event) => {
			try {
				const envelope = JSON.parse((event as MessageEvent<string>).data) as { type: 'metrics'; metrics: ObservabilityMetricsResponse };
				applyMetrics(envelope.metrics);
				lastStreamSample = Date.now();
				metricsStreamState.set('open');
				stopFallback();
			} catch {
				metricsStreamState.set('error');
				markMetricsInterrupted('Metrics stream data could not be read');
				startFallback();
			}
		});
		eventSource.addEventListener('error', () => {
			metricsStreamState.set('error');
			if (!$collectionState.metrics.loading) void fetchMetrics();
			startFallback();
		});
	}

	async function initialize(): Promise<void> {
		await refreshDashboard();
		if (disposed) return;
		connectMetrics();
		summaryTimer = window.setInterval(() => {
			if (!$collectionState.status.loading) void fetchStatus();
			if (!$collectionState.tunnels.loading) void fetchTunnels();
			if (!$collectionState.destinations.loading) void fetchDestinations();
			if (Date.now() - lastStreamSample > 5000 && fallbackTimer === null) {
				metricsStreamState.set('error');
				if (!$collectionState.metrics.loading) void fetchMetrics();
				startFallback();
			}
		}, 5000);
		netdbTimer = window.setInterval(() => {
			if (!$collectionState.netdb.loading) void fetchNetDB();
		}, 15000);
	}

	async function authenticate(): Promise<void> {
		if (!accessToken.trim() || authenticating) return;
		authenticating = true;
		authError = '';
		setAccessToken(accessToken);
		const status = await fetchStatus();
		if (!status) {
			authError = $authRequired ? 'The bearer token was rejected.' : 'Router status could not be collected. Check the connection and retry.';
			authenticating = false;
			return;
		}
		await Promise.all([fetchMetrics(), fetchTunnels(), fetchNetDB(), fetchDestinations()]);
		connectMetrics();
		authenticating = false;
	}

	onMount(() => {
		void initialize();
		return () => {
			disposed = true;
			metricsStreamState.set('closed');
			eventSource?.close();
			if (summaryTimer !== null) window.clearInterval(summaryTimer);
			if (netdbTimer !== null) window.clearInterval(netdbTimer);
			stopFallback();
		};
	});
</script>

<svelte:head>
	<title>IVNP Router Console</title>
	<meta name="description" content="Local operations console for the embedded IVNP I2P router" />
</svelte:head>

<div id="top" class="page-shell">
	<Header />

	{#if $authRequired}
		<main class="access-main">
			<section class="access-panel" aria-labelledby="access-title">
				<h1 id="access-title">Bearer token required</h1>
				<p>This console is bound for remote access. Enter the token configured in <code>IVNPD_WEBUI_TOKEN</code>. It remains in this browser tab only.</p>
				<form on:submit|preventDefault={authenticate}>
					<label for="access-token">Access token</label>
					<input class="input" id="access-token" type="password" bind:value={accessToken} autocomplete="current-password" required minlength="16" />
					{#if authError}<p class="auth-error" role="alert">{authError}</p>{/if}
					<button class="button button--primary" type="submit" disabled={authenticating || accessToken.trim().length < 16} aria-busy={authenticating}>
						{authenticating ? 'Checking token' : 'Open console'}
					</button>
				</form>
			</section>
		</main>
	{:else}
		<main class="dashboard" aria-label="IVNP router dashboard">
			<div class="hero"><RouterHeroCard /></div>
			<div class="destinations"><DestinationsServicesCard /></div>
			<div class="bandwidth"><BandwidthChartCard /></div>
			<div class="tunnels"><TunnelMatrixCard /></div>
			<div class="netdb"><NetDBExplorerCard /></div>
			<div class="diagnostics"><DiagnosticsCard /></div>
		</main>
	{/if}

	<footer class="page-footer">
		<span>IVNP {$routerStatus?.version ?? ''}</span>
		<span>Browser metrics stream: {$metricsStreamState}</span>
		<span>Network {$routerStatus?.network_id ?? '—'}</span>
	</footer>
</div>

<style>
	.page-shell {
		min-height: 100vh;
	}

	.dashboard {
		display: grid;
		grid-template-columns: repeat(12, minmax(0, 1fr));
		gap: var(--space-3);
		max-width: 112rem;
		margin: 0 auto;
		padding: var(--space-3);
	}

	.dashboard > div {
		min-width: 0;
	}

	.hero,
	.destinations,
	.netdb,
	.diagnostics {
		grid-column: 1 / -1;
	}

	.bandwidth {
		grid-column: span 5;
	}

	.tunnels {
		grid-column: span 7;
	}

	.dashboard > div > :global(.cell) {
		height: 100%;
	}

	.access-main {
		display: grid;
		place-items: center;
		min-height: calc(100vh - 10rem);
		padding: var(--space-6) var(--space-4);
	}

	.access-panel {
		width: min(34rem, 100%);
		padding: clamp(var(--space-5), 5vw, var(--space-8));
		border: var(--rule-heavy) solid var(--color-ink);
		background: var(--color-paper);
		box-shadow: 10px 10px 0 var(--color-shadow);
	}

	.access-panel h1 {
		margin: var(--space-2) 0 var(--space-4);
		font-size: clamp(2rem, 7vw, 3.5rem);
		letter-spacing: -0.055em;
		line-height: 0.95;
	}

	.access-panel > p:not(.cell-note) {
		color: var(--color-muted);
		line-height: 1.55;
	}

	.access-panel code {
		color: var(--color-ink);
		font-family: var(--font-label);
		font-size: 0.9em;
	}

	.access-panel form {
		display: grid;
		gap: var(--space-3);
		margin-top: var(--space-6);
	}

	.access-panel label {
		font-size: var(--text-sm);
		font-weight: 700;
	}

	.auth-error {
		margin: 0;
		padding: var(--space-2);
		border-left: 3px solid var(--color-danger);
		background: var(--color-danger-soft);
		color: var(--color-danger);
		font-size: var(--text-sm);
	}

	.page-footer {
		display: flex;
		justify-content: space-between;
		gap: var(--space-4);
		padding: var(--space-4) clamp(var(--space-4), 3vw, var(--space-8));
		border-top: var(--rule-heavy) solid var(--color-ink);
		color: var(--color-muted);
		font-family: var(--font-label);
		font-size: var(--text-xs);
		letter-spacing: 0.055em;
		text-transform: uppercase;
	}

	@media (max-width: 1120px) {
		.hero,
		.bandwidth,
		.tunnels,
		.netdb,
		.destinations,
		.diagnostics {
			grid-column: span 12;
		}
	}


	@media (max-width: 520px) {
		.dashboard {
			gap: var(--space-2);
			padding: var(--space-2);
		}

		.page-footer {
			align-items: flex-start;
			flex-direction: column;
		}
	}
</style>
