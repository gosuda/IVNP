<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { tunnelsData } from '$lib/api';
	import { formatCount, formatDuration, formatPercent, tunnelLabel } from '$lib/format';
	import Badge from '$lib/components/Badge.svelte';
	import InlineError from '$lib/components/InlineError.svelte';
	import Metric from '$lib/components/Metric.svelte';
	import Operations from '$lib/components/Operations.svelte';

	const kind = $derived(page.url.searchParams.get('kind') ?? 'all');
	const direction = $derived(page.url.searchParams.get('direction') ?? 'all');
	let query = $state(page.url.searchParams.get('q') ?? '');

	function setFilter(name: string, value: string): void {
		const url = new URL(page.url);
		if (value === 'all' || value === '') url.searchParams.delete(name);
		else url.searchParams.set(name, value);
		void goto(url, { replaceState: true, keepFocus: true, noScroll: true });
	}

	const rows = $derived(
		($tunnelsData?.tunnels ?? []).filter((tunnel) => {
			if (kind !== 'all' && tunnel.kind !== kind) return false;
			if (direction !== 'all' && tunnel.direction !== direction) return false;
			const needle = query.trim().toLowerCase();
			if (!needle) return true;
			return `${tunnel.id} ${tunnelLabel(tunnel.id)} ${tunnel.destination_name ?? ''} ${tunnel.gateway ?? ''} ${(tunnel.hops ?? []).join(' ')}`
				.toLowerCase()
				.includes(needle);
		})
	);
	const recentTotal = $derived($tunnelsData ? $tunnelsData.recent_build_successes + $tunnelsData.recent_build_failures : 0);
</script>

<div class="page">
	<div class="page-head">
		<h1>Tunnels</h1>
		{#if $tunnelsData}<span class="muted">{formatCount($tunnelsData.tunnels.length)} live creator tunnels</span>{/if}
	</div>
	<InlineError resource="tunnels" />

	{#if $tunnelsData}
		<section class="summary" aria-label="Build summary">
			<Metric
				label="Recent build success"
				value={recentTotal > 0 ? formatPercent($tunnelsData.recent_build_successes, recentTotal) : '—'}
				sub={recentTotal > 0 ? `${$tunnelsData.recent_build_successes} of ${recentTotal} in ${Math.round($tunnelsData.recent_window_seconds / 60)} min` : 'No recent builds'}
			/>
			<Metric label="Builds since start" value={formatCount($tunnelsData.builds_total)} sub={`${formatCount($tunnelsData.build_failures)} failed`} />
			<Metric label="Exploratory pool" value={`${$tunnelsData.exploratory_inbound_active + $tunnelsData.exploratory_outbound_active}`} sub={`capacity ${$tunnelsData.exploratory_pool_capacity}`} />
			<Metric label="Client pool" value={`${$tunnelsData.client_inbound_active + $tunnelsData.client_outbound_active}`} sub={`capacity ${$tunnelsData.client_pool_capacity}`} />
			<Metric label="Messages forwarded" value={formatCount($tunnelsData.forwarded_messages)} sub="as a transit participant" />
		</section>

		{#if !$tunnelsData.peer_identities}
			<p class="notice" data-tone="info">
				Hop identities are hidden because this console is reachable from other hosts. Start ivnpd with <code class="mono">-webui-show-peers</code> to show them.
			</p>
		{/if}

		<section class="panel" aria-labelledby="list-title">
			<div class="panel-head">
				<h2 id="list-title">Live tunnels</h2>
				<span class="muted">{rows.length} shown</span>
			</div>
			<div class="filters" role="group" aria-label="Filter tunnels">
				<label>
					<span class="label">Kind</span>
					<select class="select" value={kind} onchange={(event) => setFilter('kind', event.currentTarget.value)}>
						<option value="all">All</option>
						<option value="exploratory">Exploratory</option>
						<option value="client">Client</option>
					</select>
				</label>
				<label>
					<span class="label">Direction</span>
					<select class="select" value={direction} onchange={(event) => setFilter('direction', event.currentTarget.value)}>
						<option value="all">Both</option>
						<option value="inbound">Inbound</option>
						<option value="outbound">Outbound</option>
					</select>
				</label>
				<label class="grow">
					<span class="label">Find</span>
					<input class="input" type="search" bind:value={query} onchange={() => setFilter('q', query)} placeholder="Tunnel ID, destination, or hop B32" />
				</label>
			</div>
			{#if rows.length === 0}
				<p class="empty">No tunnels match these filters.</p>
			{:else}
				<div class="table-scroll">
					<table class="data">
						<thead>
							<tr><th>Tunnel</th><th>Kind</th><th>Destination</th><th>Direction</th><th class="num">Hops</th><th class="num">Expires in</th><th>State</th></tr>
						</thead>
						<tbody>
							{#each rows as tunnel (tunnel.id)}
								<tr>
									<td><a class="mono" href={`/tunnels/${tunnel.id}/`}>{tunnelLabel(tunnel.id)}</a></td>
									<td>{tunnel.kind}</td>
									<td>
										{#if tunnel.destination_name}
											<a href={`/destinations/${encodeURIComponent(tunnel.destination_name)}/`}>{tunnel.destination_name}</a>
										{:else}<span class="muted">Router</span>{/if}
									</td>
									<td>{tunnel.direction}</td>
									<td class="num">{tunnel.hop_count}</td>
									<td class="num">{formatDuration(tunnel.remaining_seconds)}</td>
									<td><Badge tone={tunnel.state === 'expiring' ? 'warn' : 'ok'}>{tunnel.state === 'expiring' ? 'Renewing' : 'Established'}</Badge></td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>

		<section class="panel" aria-labelledby="probe-title">
			<div class="panel-head"><h2 id="probe-title">Tunnel test</h2></div>
			<Operations operations={['probe']} />
		</section>
	{:else}
		<p class="empty">Waiting for tunnel data.</p>
	{/if}
</div>

<style>
	.summary {
		display: grid;
		grid-template-columns: repeat(5, minmax(0, 1fr));
		gap: var(--space-3);
	}

	.summary :global(.metric) {
		border: var(--rule-thin) solid var(--color-rule);
		border-left-width: 3px;
	}

	.filters {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-3);
		margin-bottom: var(--space-4);
	}

	.filters label {
		display: grid;
		gap: var(--space-1);
		min-width: 10rem;
	}

	.filters .grow {
		flex: 1 1 18rem;
	}

	td a {
		font-weight: 600;
		text-underline-offset: 0.2em;
	}

	td a:hover {
		color: var(--color-accent);
	}

	@media (max-width: 1100px) {
		.summary {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
	}
</style>
