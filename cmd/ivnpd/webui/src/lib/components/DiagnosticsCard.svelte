<script lang="ts">
	import LiveChart from './LiveChart.svelte';
	import { formatBytes, metrics, telemetryHistory } from '../api';

	$: history = $telemetryHistory;
	$: heapSeries = [{ label: 'Heap', values: history.map((point) => point.heapBytes), tone: 'accent' as const }];
	$: goroutineSeries = [{ label: 'Goroutines', values: history.map((point) => point.goroutines), tone: 'ink' as const }];
</script>

<section class="cell diagnostics-cell" aria-labelledby="diagnostics-title">
	<div class="cell-head">
		<div>
			<p class="cell-note">Go runtime</p>
			<h2 class="cell-title" id="diagnostics-title">Process diagnostics</h2>
		</div>
		<strong>{formatBytes($metrics?.process.heap_inuse_bytes ?? 0)} heap</strong>
	</div>

	<div class="process-charts">
		<div>
			<span class="label">Heap in use</span>
			<LiveChart series={heapSeries} label="Heap memory use over the last 120 seconds" zeroBased={false} height={110} />
		</div>
		<div>
			<span class="label">Goroutines</span>
			<LiveChart series={goroutineSeries} label="Goroutine count over the last 120 seconds" zeroBased={false} height={110} />
		</div>
	</div>

	<div class="diagnostic-grid">
		<div><span>Heap objects</span><strong>{$metrics?.process.heap_objects.toLocaleString() ?? '0'}</strong></div>
		<div><span>Total allocated</span><strong>{formatBytes($metrics?.process.allocated_bytes_total ?? 0)}</strong></div>
		<div><span>GC cycles</span><strong>{$metrics?.process.gc_cycles.toLocaleString() ?? '0'}</strong></div>
		<div><span>GC pause total</span><strong>{(($metrics?.process.gc_pause_ns ?? 0) / 1_000_000).toFixed(1)} ms</strong></div>
		<div><span>Transport sessions</span><strong>{$metrics?.transport.sessions.toLocaleString() ?? '0'}</strong></div>
		<div><span>Handshake failures</span><strong>{$metrics?.transport.handshake_failures.toLocaleString() ?? '0'}</strong></div>
		<div><span>Proxy requests</span><strong>{$metrics?.proxy.requests.toLocaleString() ?? '0'}</strong></div>
		<div><span>Proxy active</span><strong>{$metrics?.proxy.active.toLocaleString() ?? '0'}</strong></div>
	</div>
</section>

<style>
	.diagnostics-cell {
		display: grid;
		align-content: start;
		gap: var(--space-5);
	}

	.cell-head > strong {
		font-size: var(--text-sm);
		white-space: nowrap;
	}

	.process-charts {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: var(--space-4);
	}

	.process-charts > div {
		display: grid;
		gap: var(--space-2);
		min-width: 0;
	}

	.diagnostic-grid {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		border-block: var(--rule-heavy) solid var(--color-ink);
	}

	.diagnostic-grid > div {
		display: grid;
		gap: var(--space-1);
		min-width: 0;
		padding: var(--space-3);
		border-left: var(--rule-thin) solid var(--color-rule);
		border-bottom: var(--rule-thin) solid var(--color-rule);
	}

	.diagnostic-grid > div:nth-child(4n + 1) {
		border-left: 0;
	}

	.diagnostic-grid > div:nth-last-child(-n + 4) {
		border-bottom: 0;
	}

	.diagnostic-grid span {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.diagnostic-grid strong {
		min-width: 0;
		font-size: var(--text-sm);
		overflow-wrap: anywhere;
	}

	@media (max-width: 650px) {
		.process-charts {
			grid-template-columns: 1fr;
		}

		.diagnostic-grid {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.diagnostic-grid > div:nth-child(odd) {
			border-left: 0;
		}

		.diagnostic-grid > div:nth-child(even) {
			border-left: var(--rule-thin) solid var(--color-rule);
		}

		.diagnostic-grid > div:nth-last-child(-n + 4) {
			border-bottom: var(--rule-thin) solid var(--color-rule);
		}

		.diagnostic-grid > div:nth-last-child(-n + 2) {
			border-bottom: 0;
		}
	}
</style>
