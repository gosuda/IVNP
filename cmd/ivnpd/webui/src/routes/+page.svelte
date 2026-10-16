<script lang="ts">
	import { destinationsData, history, metrics, routerStatus, tunnelsData } from '$lib/api';
	import { formatBytes, formatCount, formatDuration, formatPercent, formatRate } from '$lib/format';
	import { listedServices, serviceState, serviceTone } from '$lib/health';
	import type { Tone } from '$lib/types';
	import StatusStrip from '$lib/components/StatusStrip.svelte';
	import Metric from '$lib/components/Metric.svelte';
	import LiveChart from '$lib/components/LiveChart.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Identifier from '$lib/components/Identifier.svelte';
	import InlineError from '$lib/components/InlineError.svelte';
	import Operations from '$lib/components/Operations.svelte';
	import ActivityLog from '$lib/components/ActivityLog.svelte';

	const times = $derived($history.map((sample) => sample.t));
	const pools = $derived(
		$tunnelsData
			? [
					{ label: 'Exploratory in', active: $tunnelsData.exploratory_inbound_active, target: $tunnelsData.exploratory_inbound_target },
					{ label: 'Exploratory out', active: $tunnelsData.exploratory_outbound_active, target: $tunnelsData.exploratory_outbound_target },
					{ label: 'Client in', active: $tunnelsData.client_inbound_active, target: $tunnelsData.client_inbound_target },
					{ label: 'Client out', active: $tunnelsData.client_outbound_active, target: $tunnelsData.client_outbound_target }
				]
			: []
	);
	const poolsMet = $derived(pools.filter((pool) => pool.target === 0 || pool.active >= pool.target).length);
	const recentTotal = $derived($tunnelsData ? $tunnelsData.recent_build_successes + $tunnelsData.recent_build_failures : 0);
	const recentTone = $derived.by((): Tone => {
		if (!$tunnelsData || recentTotal === 0) return 'neutral';
		const rate = $tunnelsData.recent_build_successes / recentTotal;
		return rate >= 0.6 ? 'ok' : rate >= 0.3 ? 'warn' : 'crit';
	});
	const poolTone = (active: number, target: number): Tone => (target === 0 ? 'neutral' : active >= target ? 'ok' : active === 0 ? 'crit' : 'warn');
	const reachabilityTone: Record<string, Tone> = { reachable: 'ok', testing: 'neutral', firewalled: 'warn', disabled: 'crit' };
</script>

<div class="page">
	<StatusStrip />

	<section class="metrics" aria-label="Key metrics">
		<Metric
			label="Active tunnels"
			value={$metrics ? formatCount($metrics.tunnels.active) : '—'}
			sub={$tunnelsData ? `${poolsMet} of 4 pools at target` : undefined}
			tone={$tunnelsData ? (poolsMet === 4 ? 'ok' : 'warn') : 'neutral'}
			href="/tunnels/"
		/>
		<Metric
			label="Recent tunnel builds"
			value={$tunnelsData && recentTotal > 0 ? formatPercent($tunnelsData.recent_build_successes, recentTotal) : '—'}
			sub={$tunnelsData ? (recentTotal > 0 ? `${$tunnelsData.recent_build_successes} of ${recentTotal} in the last ${Math.round($tunnelsData.recent_window_seconds / 60)} min` : 'No builds completed recently') : undefined}
			tone={recentTone}
		/>
		<Metric
			label="Throughput"
			value={$metrics ? formatRate($metrics.bandwidth.in_rate_bps + $metrics.bandwidth.out_rate_bps) : '—'}
			sub={$metrics ? `${formatRate($metrics.bandwidth.in_rate_bps)} in · ${formatRate($metrics.bandwidth.out_rate_bps)} out` : undefined}
		/>
		<Metric
			label="Known routers"
			value={$metrics ? formatCount($metrics.netdb.routers) : '—'}
			sub={$metrics ? `${formatCount($metrics.netdb.floodfills)} floodfills` : undefined}
			tone={$metrics ? ($metrics.netdb.routers >= 50 ? 'ok' : 'warn') : 'neutral'}
			href="/network/"
		/>
		<Metric
			label="Uptime"
			value={$routerStatus ? formatDuration($routerStatus.uptime_seconds) : '—'}
			sub={$routerStatus ? `Reachability: ${$routerStatus.reachability}` : undefined}
			tone={$routerStatus ? reachabilityTone[$routerStatus.reachability] : 'neutral'}
		/>
	</section>

	<div class="grid">
		<section class="panel span-8" aria-labelledby="throughput-title">
			<div class="panel-head">
				<h2 id="throughput-title">Transport throughput</h2>
				{#if $metrics}<span class="muted">Tunnel limit {formatRate($metrics.bandwidth.rate_limit_bps)} · peak {formatRate($metrics.bandwidth.peak_rate_bps)}</span>{/if}
			</div>
			<InlineError resource="history" />
			<LiveChart
				label="Inbound and outbound transport throughput"
				{times}
				series={[
					{ label: 'Inbound', values: $history.map((sample) => sample.in_rate_bps), tone: 'accent' },
					{ label: 'Outbound', values: $history.map((sample) => sample.out_rate_bps), tone: 'ink', dashed: true }
				]}
				formatValue={(value) => formatRate(value, 0)}
				height={190}
			/>
			{#if $metrics}
				<dl class="props totals">
					<div><dt>Received since start</dt><dd>{formatBytes($metrics.bandwidth.in_total_bytes)}</dd></div>
					<div><dt>Sent since start</dt><dd>{formatBytes($metrics.bandwidth.out_total_bytes)}</dd></div>
					<div><dt>Transport sessions</dt><dd>{formatCount($metrics.transport.sessions)}</dd></div>
					<div><dt>Handshake failures</dt><dd>{formatCount($metrics.transport.handshake_failures)}</dd></div>
				</dl>
			{/if}
		</section>

		<section class="panel span-4" aria-labelledby="pools-title">
			<div class="panel-head">
				<h2 id="pools-title">Tunnel pools</h2>
				<a href="/tunnels/">All tunnels</a>
			</div>
			<InlineError resource="tunnels" />
			{#if $tunnelsData}
				<ul class="pools">
					{#each pools as pool (pool.label)}
						{@const tone = poolTone(pool.active, pool.target)}
						<li>
							<div class="pool-line">
								<span>{pool.label}</span>
								<strong>{pool.active}<span class="muted"> / {pool.target}</span></strong>
							</div>
							<meter
								min="0"
								max={Math.max(pool.target, 1)}
								value={Math.min(pool.active, Math.max(pool.target, 1))}
								data-tone={tone}
								aria-label={`${pool.label}: ${pool.active} of ${pool.target}`}
							></meter>
						</li>
					{/each}
				</ul>
			{:else}
				<p class="empty">Waiting for tunnel pools.</p>
			{/if}
		</section>

		<section class="panel span-7" aria-labelledby="services-title">
			<div class="panel-head">
				<h2 id="services-title">Local services</h2>
				<a href="/settings/?group=services">Configure</a>
			</div>
			<InlineError resource="status" />
			{#if $routerStatus}
				<div class="table-scroll">
					<table class="data">
						<thead><tr><th>Service</th><th>State</th><th>Address</th></tr></thead>
						<tbody>
							{#each listedServices($routerStatus) as { key, name, service } (key)}
								<tr>
									<td><strong>{name}</strong></td>
									<td><Badge tone={serviceTone(service)}>{serviceState(service)}</Badge></td>
									<td>
										{#if service.enabled && service.address}
											<Identifier value={service.address} label={`${name} address`} full />
										{:else}
											<span class="muted">{service.address || 'No address configured'}</span>
										{/if}
									</td>
								</tr>
							{/each}
							<tr>
								<td><strong>Address book</strong></td>
								<td><Badge tone={$routerStatus.services.addressbook.enabled ? 'ok' : 'neutral'}>{$routerStatus.services.addressbook.enabled ? 'On' : 'Off'}</Badge></td>
								<td class="muted">{$routerStatus.services.addressbook.subscriptions} subscriptions</td>
							</tr>
						</tbody>
					</table>
				</div>
			{/if}
		</section>

		<section class="panel span-5" aria-labelledby="destinations-title">
			<div class="panel-head">
				<h2 id="destinations-title">Destinations</h2>
				<a href="/destinations/">All destinations</a>
			</div>
			<InlineError resource="destinations" />
			{#if $destinationsData}
				{#if $destinationsData.destinations.length === 0}
					<p class="empty">No local destinations are registered.</p>
				{:else}
					<ul class="destinations">
						{#each $destinationsData.destinations.slice(0, 6) as destination (destination.name)}
							<li>
								<a class="name" href={`/destinations/${encodeURIComponent(destination.name)}/`}>{destination.name}</a>
								{#if destination.default}<Badge tone="info">Default</Badge>{/if}
								<Identifier value={destination.address} label={`${destination.name} address`} head={14} tail={10} />
							</li>
						{/each}
					</ul>
				{/if}
			{/if}
		</section>

		<section class="panel span-6" aria-labelledby="operations-title">
			<div class="panel-head"><h2 id="operations-title">Operations</h2></div>
			<Operations operations={['reseed', 'probe']} />
		</section>

		<section class="panel span-6" aria-labelledby="activity-title">
			<div class="panel-head"><h2 id="activity-title">Recent activity</h2></div>
			<ActivityLog />
		</section>

		{#if $routerStatus}
			<section class="panel span-12" aria-labelledby="identity-title">
				<div class="panel-head"><h2 id="identity-title">Router identity and transports</h2></div>
				<dl class="props">
					<div><dt>Router B32</dt><dd><Identifier value={$routerStatus.router_b32} label="router B32" head={16} tail={12} /></dd></div>
					<div><dt>Router hash</dt><dd><Identifier value={$routerStatus.router_hash} label="router hash" head={12} tail={8} /></dd></div>
					<div><dt>Lifecycle</dt><dd>{$routerStatus.state}</dd></div>
					<div><dt>Network ID</dt><dd>{$routerStatus.network_id}</dd></div>
					<div><dt>Family</dt><dd>{$routerStatus.family || 'None'}</dd></div>
					<div><dt>Floodfill</dt><dd>{$routerStatus.floodfill_configured ? ($routerStatus.floodfill_advertised ? 'Configured, advertised' : 'Configured, not yet advertised') : 'Off'}</dd></div>
					<div><dt>Transit routing</dt><dd>{$routerStatus.transit_configured ? 'On' : 'Off'}</dd></div>
				</dl>
				<div class="table-scroll transports">
					<table class="data">
						<thead><tr><th>Transport</th><th>State</th><th class="num">Sessions</th><th class="num">Limit</th><th>Bind</th><th>Advertised</th></tr></thead>
						<tbody>
							{#each Object.entries($routerStatus.transports) as [name, transport] (name)}
								<tr>
									<td><strong>{name.toUpperCase()}</strong></td>
									<td><Badge tone={transport.enabled ? 'ok' : 'neutral'}>{transport.enabled ? 'On' : 'Off'}</Badge></td>
									<td class="num">{formatCount(transport.active_sessions)}</td>
									<td class="num">{formatCount(transport.max_sessions)}</td>
									<td class="mono">{transport.bind_address || '—'}</td>
									<td class="mono">{transport.advertised_address || 'Not advertised'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		{#if $metrics}
			<section class="panel span-12" aria-labelledby="process-title">
				<details>
					<summary><h2 id="process-title" class="inline">Process diagnostics</h2> <span class="muted">{formatBytes($metrics.process.heap_inuse_bytes)} heap · {formatCount($metrics.process.goroutines)} goroutines</span></summary>
					<div class="process">
						<LiveChart label="Heap in use" {times} series={[{ label: 'Heap in use', values: $history.map((s) => s.heap_inuse_bytes), tone: 'accent' }]} formatValue={(v) => formatBytes(v, 0)} zeroBased={false} height={120} />
						<LiveChart label="Goroutines" {times} series={[{ label: 'Goroutines', values: $history.map((s) => s.goroutines), tone: 'ink' }]} zeroBased={false} height={120} />
					</div>
					<dl class="props">
						<div><dt>Heap objects</dt><dd>{formatCount($metrics.process.heap_objects)}</dd></div>
						<div><dt>Allocated since start</dt><dd>{formatBytes($metrics.process.allocated_bytes_total)}</dd></div>
						<div><dt>GC cycles</dt><dd>{formatCount($metrics.process.gc_cycles)}</dd></div>
						<div><dt>GC pause total</dt><dd>{($metrics.process.gc_pause_ns / 1e6).toFixed(1)} ms</dd></div>
						<div><dt>Proxy requests</dt><dd>{formatCount($metrics.proxy.requests)} ({formatCount($metrics.proxy.failures)} failed)</dd></div>
						<div><dt>Proxy connections open</dt><dd>{formatCount($metrics.proxy.active)}</dd></div>
					</dl>
				</details>
			</section>
		{/if}
	</div>
</div>

<style>
	.metrics {
		display: grid;
		grid-template-columns: repeat(5, minmax(0, 1fr));
		gap: var(--space-3);
	}

	.metrics :global(.metric) {
		border: var(--rule-thin) solid var(--color-rule);
		border-left-width: 3px;
	}

	.grid {
		display: grid;
		grid-template-columns: repeat(12, minmax(0, 1fr));
		gap: var(--space-3);
	}

	.span-4 {
		grid-column: span 4;
	}

	.span-5 {
		grid-column: span 5;
	}

	.span-6 {
		grid-column: span 6;
	}

	.span-7 {
		grid-column: span 7;
	}

	.span-8 {
		grid-column: span 8;
	}

	.span-12 {
		grid-column: 1 / -1;
	}

	.totals {
		margin-top: var(--space-4);
	}

	.pools {
		display: grid;
		gap: var(--space-4);
		padding: 0;
		list-style: none;
	}

	.pool-line {
		display: flex;
		justify-content: space-between;
		gap: var(--space-2);
		margin-bottom: var(--space-1);
		font-size: var(--text-sm);
	}

	meter {
		display: block;
		width: 100%;
		height: 0.5rem;
		border: 0;
		background: var(--color-paper-3);
	}

	meter::-webkit-meter-bar {
		height: 0.5rem;
		border: 0;
		border-radius: 0;
		background: var(--color-paper-3);
	}

	meter::-webkit-meter-optimum-value {
		background: var(--color-ok);
	}

	meter[data-tone='warn']::-webkit-meter-optimum-value {
		background: var(--color-warn-mark);
	}

	meter[data-tone='crit']::-webkit-meter-optimum-value {
		background: var(--color-crit);
	}

	meter::-moz-meter-bar {
		background: var(--color-ok);
	}

	meter[data-tone='warn']::-moz-meter-bar {
		background: var(--color-warn-mark);
	}

	meter[data-tone='crit']::-moz-meter-bar {
		background: var(--color-crit);
	}

	.destinations {
		display: grid;
		gap: var(--space-3);
		padding: 0;
		list-style: none;
	}

	.destinations li {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2) var(--space-3);
		padding-bottom: var(--space-3);
		border-bottom: var(--rule-thin) solid var(--color-rule);
	}

	.name {
		font-weight: 700;
		text-underline-offset: 0.2em;
	}

	.transports {
		margin-top: var(--space-5);
	}

	summary .inline {
		display: inline;
		font-size: var(--text-lg);
	}

	.process {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: var(--space-4);
		margin-block: var(--space-4);
	}

	@media (max-width: 1180px) {
		.metrics {
			grid-template-columns: repeat(3, minmax(0, 1fr));
		}

		.span-4,
		.span-5,
		.span-6,
		.span-7,
		.span-8 {
			grid-column: 1 / -1;
		}
	}

	@media (max-width: 640px) {
		.metrics {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.process {
			grid-template-columns: minmax(0, 1fr);
		}
	}
</style>
