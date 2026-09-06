<script lang="ts">
	import LiveChart from './LiveChart.svelte';
	import DataStatus from './DataStatus.svelte';
	import QuickActionsCard from './QuickActionsCard.svelte';
	import { formatDuration, telemetryHistory, tunnelsData } from '../api';

	let listOpen = false;
	let showAll = false;
	$: history = $telemetryHistory;
	$: timestamps = history.map((point) => point.timestamp);
	$: activeSeries = [{ label: 'Active tunnels', values: history.map((point) => point.activeTunnels), tone: 'accent' as const }];
	$: successSeries = [{ label: 'Cumulative build success', values: history.map((point) => point.buildSuccessRate), tone: 'ink' as const }];
	$: attempts = $tunnelsData ? $tunnelsData.build_successes + $tunnelsData.build_failures : null;
	$: successRate = $tunnelsData && attempts !== null && attempts > 0 ? ($tunnelsData.build_successes / attempts) * 100 : null;
	$: pools = $tunnelsData ? [
		{ label: 'Exploratory in', active: $tunnelsData.exploratory_inbound_active, target: $tunnelsData.exploratory_inbound_target },
		{ label: 'Exploratory out', active: $tunnelsData.exploratory_outbound_active, target: $tunnelsData.exploratory_outbound_target },
		{ label: 'Client in', active: $tunnelsData.client_inbound_active, target: $tunnelsData.client_inbound_target },
		{ label: 'Client out', active: $tunnelsData.client_outbound_active, target: $tunnelsData.client_outbound_target }
	] : [];
	$: displayedTunnels = $tunnelsData ? (showAll ? $tunnelsData.tunnels : $tunnelsData.tunnels.slice(0, 8)) : [];
</script>

<section class="cell tunnel-cell" aria-labelledby="tunnel-title">
	<div class="cell-head">
		<h2 class="cell-title" id="tunnel-title">Tunnels</h2>
		<div class="build-rate">
			<strong>{successRate === null ? '—' : `${successRate.toFixed(1)}%`}</strong>
			<span>Cumulative build success</span>
		</div>
	</div>
	<DataStatus resource="tunnels" />

	{#if $tunnelsData}
		<div class="pool-grid">
			{#each pools as pool}
				<div>
					<span>{pool.label}</span>
					<strong>{pool.active} / {pool.target}</strong>
					<span>active / target</span>
					<span class:deficit={pool.active < pool.target}>{pool.target === 0 ? 'No target configured' : pool.active < pool.target ? `${pool.target - pool.active} below target` : 'Target met'}</span>
					{#if pool.target > 0}
						<progress max={pool.target} value={Math.min(pool.active, pool.target)} aria-label={`${pool.label}: ${pool.active} active of ${pool.target} target`}></progress>
					{/if}
				</div>
			{/each}
		</div>
		<p class="pool-capacity">Pool capacity: exploratory {$tunnelsData.exploratory_pool_capacity} · client {$tunnelsData.client_pool_capacity}</p>
		<div class="build-summary">
			<p>{attempts === 0 ? 'No completed build attempts.' : `${$tunnelsData.build_successes} successful / ${attempts} completed attempts.`} Success is cumulative, not a rate for the chart window.</p>
			<details><summary>Cumulative counters</summary>
			<dl>
				<div><dt>Builds total</dt><dd>{$tunnelsData.builds_total}</dd></div>
				<div><dt>Failures</dt><dd>{$tunnelsData.build_failures}</dd></div>
				<div><dt>Forwarded messages</dt><dd>{$tunnelsData.forwarded_messages}</dd></div>
			</dl>
			</details>
		</div>
	{:else}
		<p class="data-empty">Tunnel pool counts and build results are not available yet.</p>
	{/if}

	<details><summary>Tunnel history</summary>
	<div class="traces">
		<DataStatus resource="metrics" />
		<div class="trace-grid">
			<div>
				<h3>Active tunnels</h3>
				<LiveChart series={activeSeries} {timestamps} unit="tunnels" label="Active tunnel count" height={110} />
			</div>
			<div>
				<h3>Cumulative build success</h3>
				<LiveChart series={successSeries} {timestamps} unit="% completed attempts" maxValue={100} label="Cumulative tunnel build success percentage" height={110} emptyMessage={history.length ? 'No completed build attempts in these samples.' : 'Waiting for telemetry samples.'} />
			</div>
		</div>
	</div>
	</details>

	{#if $tunnelsData}
		<details class="tunnel-list" bind:open={listOpen}>
			<summary>Individual tunnels <span>{listOpen ? displayedTunnels.length : 0} of {$tunnelsData.tunnels.length} shown</span></summary>
			{#if $tunnelsData.tunnels.length > 8}
				<div class="list-controls">
					<button class="button" type="button" aria-expanded={showAll} on:click={() => (showAll = !showAll)}>{showAll ? 'Show first 8' : `View all ${$tunnelsData.tunnels.length}`}</button>
				</div>
			{/if}
			{#if displayedTunnels.length > 0}
				<div class="table-scroll" role="region" aria-label="Individual tunnel details">
					<table>
						<thead><tr><th>ID</th><th>Class / destination</th><th>Direction</th><th>Hops</th><th>Expires in</th><th>State</th></tr></thead>
						<tbody>
							{#each displayedTunnels as tunnel (tunnel.id)}
								<tr>
									<td><strong>{tunnel.id}</strong></td>
									<td>{tunnel.kind}{#if tunnel.destination_name}<br />{tunnel.destination_name}{/if}</td>
									<td>{tunnel.direction}</td>
									<td>{tunnel.hop_count}</td>
									<td>{formatDuration(tunnel.remaining_seconds)}</td>
									<td class:expiring={tunnel.state === 'expiring'}>{tunnel.state}</td>
								</tr>
								<tr class="route-row"><td colspan="6">
									<details>
										<summary>Route details for {tunnel.id}</summary>
										<dl class="route-details">
											<div><dt>Expires at</dt><dd>{new Date(tunnel.expires_at).toLocaleString()}</dd></div>
											{#if tunnel.owner}<div><dt>Owner</dt><dd>{tunnel.owner}</dd></div>{/if}
											{#if tunnel.gateway}<div><dt>Gateway</dt><dd>{tunnel.gateway}</dd></div>{/if}
											{#if tunnel.gateway_tunnel_id !== undefined}<div><dt>Gateway tunnel</dt><dd>{tunnel.gateway_tunnel_id}</dd></div>{/if}
											{#if tunnel.hops?.length}<div><dt>Hop path</dt><dd><ol>{#each tunnel.hops as hop}<li>{hop}</li>{/each}</ol></dd></div>{/if}
										</dl>
									</details>
								</td></tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else}
				<p class="data-empty">No live creator tunnels.</p>
			{/if}
		</details>
	{/if}
	<QuickActionsCard action="probe" />
</section>

<style>
	.tunnel-cell { display: grid; align-content: start; gap: var(--space-4); min-width: 0; }
	.cell-head { align-items: start; }
	.build-rate { display: grid; gap: var(--space-1); text-align: right; }
	.build-rate strong { font-size: var(--text-lg); }
	.build-rate span { color: var(--color-muted); font-size: var(--text-xs); }
	.pool-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border-block: var(--rule-heavy) solid var(--color-ink); }
	.pool-grid > div { position: relative; display: grid; gap: var(--space-1); padding: var(--space-3); border-left: var(--rule-thin) solid var(--color-rule); }
	.pool-grid > div:first-child { border-left: 0; }
	.pool-grid span { color: var(--color-muted); font-size: var(--text-xs); }
	.pool-grid strong { font-size: var(--text-lg); }
	.pool-grid .deficit { color: var(--color-ink); font-weight: 600; }
	.pool-grid progress { position: absolute; left: 0; bottom: 0; width: 100%; height: 3px; border: 0; appearance: none; background: var(--color-rule); accent-color: var(--color-accent); }
	.pool-grid progress::-webkit-progress-bar { background: var(--color-rule); }
	.pool-grid progress::-webkit-progress-value { background: var(--color-accent); }
	.pool-grid progress::-moz-progress-bar { background: var(--color-accent); }
	.pool-capacity, .build-summary p, .data-empty { margin: 0; color: var(--color-muted); font-size: var(--text-xs); }
	.build-summary { display: grid; gap: var(--space-3); }
	dl { margin: 0; }
	.build-summary dl { display: flex; flex-wrap: wrap; gap: var(--space-3) var(--space-5); }
	dl > div { display: grid; gap: var(--space-1); }
	dt { color: var(--color-muted); font-size: var(--text-xs); }
	dd { margin: 0; font-size: var(--text-sm); overflow-wrap: anywhere; }
	.traces { display: grid; gap: var(--space-3); }
	.trace-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-4); }
	.trace-grid > div { display: grid; align-content: start; gap: var(--space-2); min-width: 0; }
	h3 { margin: 0; font-size: var(--text-sm); }
	.tunnel-list { min-width: 0; border-top: var(--rule-thin) solid var(--color-rule); }
	summary { padding-block: var(--space-3); font-size: var(--text-sm); font-weight: 600; cursor: pointer; }
	summary span { margin-left: var(--space-2); color: var(--color-muted); font-size: var(--text-xs); font-weight: 400; }
	summary:hover { color: var(--color-accent); }
	summary:active { background: var(--color-paper-2); }
	summary:focus-visible, .table-scroll:focus-visible { outline: 3px solid var(--color-focus); outline-offset: 2px; }
	.list-controls { display: flex; justify-content: flex-end; margin-bottom: var(--space-3); }
	.table-scroll { max-width: 100%; overflow-x: auto; }
	table { width: 100%; min-width: 36rem; border-collapse: collapse; text-align: left; font-size: var(--text-xs); }
	th, td { padding: var(--space-2); border-bottom: var(--rule-thin) solid var(--color-rule); vertical-align: top; }
	th { color: var(--color-muted); font-weight: 600; }
	.expiring { color: var(--color-accent); font-weight: 700; }
	.route-row summary { padding: 0; font-size: var(--text-xs); font-weight: 400; }
	.route-details { display: grid; gap: var(--space-3); padding-block: var(--space-3); }
	.route-details dd { max-width: 32rem; font-size: var(--text-xs); }
	ol { margin: 0; padding-left: var(--space-4); }
	@media (max-width: 700px) {
		.pool-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
		.pool-grid > div:nth-child(3) { border-left: 0; }
		.trace-grid { grid-template-columns: minmax(0, 1fr); }
	}
	@media (max-width: 420px) {
		.cell-head { display: grid; }
		.build-rate { text-align: left; }
		summary span { display: block; margin: var(--space-1) 0 0; }
	}
</style>
