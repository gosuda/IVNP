<script lang="ts">
	import LiveChart from './LiveChart.svelte';
	import { formatDuration, telemetryHistory, tunnelsData } from '../api';

	$: history = $telemetryHistory;
	$: activeSeries = [{ label: 'Active tunnels', values: history.map((point) => point.activeTunnels), tone: 'accent' as const }];
	$: successSeries = [{ label: 'Build success', values: history.map((point) => point.buildSuccessRate), tone: 'ink' as const }];
	$: attempts = ($tunnelsData?.build_successes ?? 0) + ($tunnelsData?.build_failures ?? 0);
	$: successRate = attempts > 0 ? (($tunnelsData?.build_successes ?? 0) / attempts) * 100 : 0;
	$: displayedTunnels = $tunnelsData?.tunnels.slice(0, 8) ?? [];

</script>

<section class="cell tunnel-cell" aria-labelledby="tunnel-title">
	<div class="cell-head">
		<div>
			<p class="cell-note">Creator pools</p>
			<h2 class="cell-title" id="tunnel-title">Tunnels</h2>
		</div>
		<strong class="build-rate">{successRate.toFixed(1)}% build success</strong>
	</div>

	<div class="pool-grid">
		<div>
			<span>Exploratory in</span>
			<strong>{$tunnelsData?.exploratory_inbound_active ?? 0} / {$tunnelsData?.exploratory_inbound_target ?? 0}</strong>
			<progress max={Math.max(1, $tunnelsData?.exploratory_inbound_target ?? 0)} value={$tunnelsData?.exploratory_inbound_active ?? 0} aria-label="Exploratory inbound pool fill"></progress>
		</div>
		<div>
			<span>Exploratory out</span>
			<strong>{$tunnelsData?.exploratory_outbound_active ?? 0} / {$tunnelsData?.exploratory_outbound_target ?? 0}</strong>
			<progress max={Math.max(1, $tunnelsData?.exploratory_outbound_target ?? 0)} value={$tunnelsData?.exploratory_outbound_active ?? 0} aria-label="Exploratory outbound pool fill"></progress>
		</div>
		<div>
			<span>Client in</span>
			<strong>{$tunnelsData?.client_inbound_active ?? 0} / {$tunnelsData?.client_inbound_target ?? 0}</strong>
			<progress max={Math.max(1, $tunnelsData?.client_inbound_target ?? 0)} value={$tunnelsData?.client_inbound_active ?? 0} aria-label="Client inbound pool fill"></progress>
		</div>
		<div>
			<span>Client out</span>
			<strong>{$tunnelsData?.client_outbound_active ?? 0} / {$tunnelsData?.client_outbound_target ?? 0}</strong>
			<progress max={Math.max(1, $tunnelsData?.client_outbound_target ?? 0)} value={$tunnelsData?.client_outbound_active ?? 0} aria-label="Client outbound pool fill"></progress>
		</div>
	</div>

	<div class="trace-grid">
		<div>
			<span class="label">Active circuits</span>
			<LiveChart series={activeSeries} label="Active tunnels over the last 120 seconds" height={92} />
		</div>
		<div>
			<span class="label">Build success %</span>
			<LiveChart series={successSeries} label="Tunnel build success rate over the last 120 seconds" height={92} />
		</div>
	</div>

	<div class="tunnel-list">
		<div class="list-head">
			<span>ID</span><span>Class</span><span>Direction</span><span>Hops</span><span>Expires</span>
		</div>
		{#if displayedTunnels.length > 0}
			{#each displayedTunnels as tunnel (tunnel.id)}
				<div class="tunnel-row">
					<strong>{tunnel.id}</strong>
					<span>{tunnel.destination_name || tunnel.kind}</span>
					<span>{tunnel.direction}</span>
					<span>{tunnel.hop_count}</span>
					<span class:expiring={tunnel.state === 'expiring'}>{formatDuration(tunnel.remaining_seconds)}</span>
				</div>
			{/each}
		{:else}
			<div class="empty compact">No live creator tunnels</div>
		{/if}
	</div>
</section>

<style>
	.tunnel-cell {
		display: grid;
		align-content: start;
		gap: var(--space-5);
	}

	.build-rate {
		font-size: var(--text-sm);
		white-space: nowrap;
	}

	.pool-grid {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		border-block: var(--rule-heavy) solid var(--color-ink);
	}

	.pool-grid > div {
		position: relative;
		display: grid;
		gap: var(--space-1);
		padding: var(--space-3);
		border-left: var(--rule-thin) solid var(--color-rule);
		overflow: clip;
	}

	.pool-grid > div:first-child {
		border-left: 0;
	}

	.pool-grid span {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.pool-grid strong {
		font-size: var(--text-lg);
	}

	.pool-grid progress {
		position: absolute;
		left: 0;
		bottom: 0;
		width: 100%;
		height: 3px;
		border: 0;
		appearance: none;
		background: var(--color-rule);
		accent-color: var(--color-accent);
	}

	.pool-grid progress::-webkit-progress-bar {
		background: var(--color-rule);
	}

	.pool-grid progress::-webkit-progress-value {
		background: var(--color-accent);
	}

	.pool-grid progress::-moz-progress-bar {
		background: var(--color-accent);
	}

	.trace-grid {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: var(--space-4);
	}

	.trace-grid > div {
		display: grid;
		gap: var(--space-2);
		min-width: 0;
	}

	.tunnel-list {
		border-top: var(--rule-heavy) solid var(--color-ink);
	}

	.list-head,
	.tunnel-row {
		display: grid;
		grid-template-columns: 0.7fr 1.5fr 1fr 0.5fr 0.9fr;
		gap: var(--space-3);
		align-items: center;
		min-width: 0;
		padding: var(--space-2) 0;
		border-bottom: var(--rule-thin) solid var(--color-rule);
		font-size: var(--text-xs);
	}

	.list-head {
		color: var(--color-muted);
		font-weight: 650;
		letter-spacing: 0.06em;
		text-transform: uppercase;
	}

	.tunnel-row span,
	.tunnel-row strong {
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.expiring {
		color: var(--color-accent);
		font-weight: 700;
	}

	.compact {
		min-height: 4rem;
	}

	@media (max-width: 700px) {
		.pool-grid {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.pool-grid > div:nth-child(3) {
			border-left: 0;
		}

		.trace-grid {
			grid-template-columns: 1fr;
		}
	}

	@media (max-width: 480px) {
		.tunnel-list {
			overflow-x: auto;
		}

		.list-head,
		.tunnel-row {
			min-width: 31rem;
		}
	}
</style>
