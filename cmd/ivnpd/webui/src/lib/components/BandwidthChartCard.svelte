<script lang="ts">
	import LiveChart from './LiveChart.svelte';
	import DataStatus from './DataStatus.svelte';
	import { formatBytes, formatRate, metrics, telemetryHistory } from '../api';

	$: history = $telemetryHistory;
	$: timestamps = history.map((point) => point.timestamp);
	$: chartSeries = [
		{ label: 'Inbound', values: history.map((point) => point.inRate), tone: 'accent' as const },
		{ label: 'Outbound', values: history.map((point) => point.outRate), tone: 'ink' as const, dashed: true }
	];
</script>

<section class="cell bandwidth-cell" aria-labelledby="bandwidth-title">
	<div class="cell-head">
		<div>
			<h2 class="cell-title" id="bandwidth-title">Transport throughput</h2>
		</div>
		<div class="legend" aria-label="Chart legend">
			<span><i class="accent"></i>Inbound</span>
			<span><i class="ink"></i>Outbound</span>
		</div>
	</div>

	<DataStatus resource="metrics" />
	<LiveChart series={chartSeries} {timestamps} unit="bytes/s" formatValue={formatRate} label="Inbound and outbound transport throughput" height={176} />

	<div class="readouts">
		<div>
			<span>Latest inbound</span>
			<strong>{$metrics ? formatRate($metrics.bandwidth.in_rate_bps) : '—'}</strong>
		</div>
		<div>
			<span>Latest outbound</span>
			<strong>{$metrics ? formatRate($metrics.bandwidth.out_rate_bps) : '—'}</strong>
		</div>
		<div>
			<span>Received total</span>
			<strong>{$metrics ? formatBytes($metrics.bandwidth.in_total_bytes) : '—'}</strong>
		</div>
		<div>
			<span>Sent total</span>
			<strong>{$metrics ? formatBytes($metrics.bandwidth.out_total_bytes) : '—'}</strong>
		</div>
	</div>
	<div class="tunnel-limit">
		<span>Configured tunnel bandwidth limit <strong>{$metrics ? formatRate($metrics.bandwidth.rate_limit_bps) : '—'}</strong></span>
		<p>This limit applies to tunnel traffic, not the combined transport throughput shown above.</p>
	</div>
</section>

<style>
	.bandwidth-cell {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		min-height: 22rem;
	}

	.legend {
		display: flex;
		gap: var(--space-4);
		color: var(--color-muted);
		font-size: var(--text-xs);
		white-space: nowrap;
	}

	.legend span {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
	}

	.legend i {
		display: block;
		width: 1rem;
		height: var(--rule-heavy);
	}

	.legend .accent {
		background: var(--color-accent);
	}

	.legend .ink {
		border-top: var(--rule-heavy) dashed var(--color-ink);
	}

	.readouts {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		border-top: var(--rule-heavy) solid var(--color-ink);
	}

	.readouts > div {
		display: grid;
		gap: var(--space-1);
		min-width: 0;
		padding: var(--space-3);
		border-left: var(--rule-thin) solid var(--color-rule);
	}

	.readouts > div:first-child {
		padding-left: 0;
		border-left: 0;
	}

	.readouts span {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.readouts strong {
		min-width: 0;
		font-size: var(--text-sm);
		overflow-wrap: anywhere;
	}

	.tunnel-limit {
		padding-top: var(--space-3);
		border-top: var(--rule-thin) solid var(--color-rule);
		font-size: var(--text-xs);
		color: var(--color-muted);
	}

	.tunnel-limit strong {
		margin-left: var(--space-2);
		color: var(--color-ink);
		white-space: nowrap;
	}

	.tunnel-limit p { margin: var(--space-2) 0 0; }

	@media (max-width: 720px) {
		.readouts {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.readouts > div:nth-child(odd) {
			padding-left: 0;
			border-left: 0;
		}
	}

	@media (max-width: 420px) {
		.cell-head {
			display: grid;
		}
	}
</style>
