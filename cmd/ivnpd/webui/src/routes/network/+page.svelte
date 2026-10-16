<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { errorMessage, history, metrics, routerStatus, searchNetDB } from '$lib/api';
	import { decodeCaps, formatAgoSeconds, formatCount, formatPercent } from '$lib/format';
	import type { NetDBResponse } from '$lib/types';
	import Badge from '$lib/components/Badge.svelte';
	import Identifier from '$lib/components/Identifier.svelte';
	import LiveChart from '$lib/components/LiveChart.svelte';
	import Metric from '$lib/components/Metric.svelte';
	import Operations from '$lib/components/Operations.svelte';

	const limit = 50;
	let query = $state(page.url.searchParams.get('q') ?? '');
	let response = $state<NetDBResponse | null>(null);
	let searching = $state(false);
	let searchError = $state('');
	const applied = $derived(page.url.searchParams.get('q') ?? '');
	const linkPeers = $derived($routerStatus?.capabilities.peer_identities ?? false);

	async function load(value: string): Promise<void> {
		searching = true;
		try {
			response = await searchNetDB(value, limit);
			searchError = '';
		} catch (error) {
			searchError = errorMessage(error);
		} finally {
			searching = false;
		}
	}

	$effect(() => {
		void load(applied);
		const timer = window.setInterval(() => !searching && void load(applied), 15_000);
		return () => window.clearInterval(timer);
	});

	function submit(event: SubmitEvent): void {
		event.preventDefault();
		const url = new URL(page.url);
		if (query.trim()) url.searchParams.set('q', query.trim());
		else url.searchParams.delete('q');
		void goto(url, { replaceState: true, keepFocus: true, noScroll: true });
	}
</script>

<div class="page">
	<div class="page-head"><h1>Network database</h1></div>

	<section class="summary" aria-label="NetDB totals">
		<Metric label="Known routers" value={$metrics ? formatCount($metrics.netdb.routers) : '—'} tone={$metrics ? ($metrics.netdb.routers >= 50 ? 'ok' : 'warn') : 'neutral'} sub="50 required for readiness" />
		<Metric label="Floodfills" value={$metrics ? formatCount($metrics.netdb.floodfills) : '—'} />
		<Metric
			label="Lookup failures"
			value={$metrics ? formatPercent($metrics.netdb.lookup_failures, $metrics.netdb.lookups) : '—'}
			sub={$metrics ? `${formatCount($metrics.netdb.lookup_failures)} of ${formatCount($metrics.netdb.lookups)} since start` : undefined}
		/>
		<Metric
			label="Store failures"
			value={$metrics ? formatPercent($metrics.netdb.store_failures, $metrics.netdb.stores) : '—'}
			sub={$metrics ? `${formatCount($metrics.netdb.store_failures)} of ${formatCount($metrics.netdb.stores)} since start` : undefined}
		/>
	</section>

	<div class="grid">
		<section class="panel" aria-labelledby="growth-title">
			<div class="panel-head"><h2 id="growth-title">Known routers over time</h2></div>
			<LiveChart
				label="Known routers and floodfills"
				times={$history.map((sample) => sample.t)}
				series={[
					{ label: 'Routers', values: $history.map((sample) => sample.netdb_routers), tone: 'accent' },
					{ label: 'Floodfills', values: $history.map((sample) => sample.floodfills), tone: 'ink', dashed: true }
				]}
				height={150}
			/>
		</section>
		<section class="panel" aria-labelledby="reseed-title">
			<div class="panel-head"><h2 id="reseed-title">Bootstrap</h2></div>
			{#if $routerStatus}
				<dl class="props compact">
					<div><dt>Reseed sources</dt><dd>{$routerStatus.reseed.endpoints}</dd></div>
					<div><dt>Attempts</dt><dd>{$routerStatus.reseed.attempts}</dd></div>
					<div><dt>Succeeded</dt><dd>{$routerStatus.reseed.successes}</dd></div>
					<div><dt>Failed</dt><dd>{$routerStatus.reseed.failures}</dd></div>
				</dl>
			{/if}
			<Operations operations={['reseed']} />
		</section>
	</div>

	<section class="panel" aria-labelledby="records-title">
		<div class="panel-head">
			<h2 id="records-title">Router records</h2>
			{#if response}
				<span class="muted">
					{applied ? `${formatCount(response.matched)} match “${applied}”` : `${formatCount(response.matched)} records`}{response.matched > response.routers.length ? `, showing the ${response.routers.length} most recently seen` : ''}
				</span>
			{/if}
		</div>
		<form class="search" role="search" onsubmit={submit}>
			<label class="visually-hidden" for="netdb-query">Search router records</label>
			<input id="netdb-query" class="input" type="search" bind:value={query} placeholder="Hash, B32, IP address, version, or caps letter" autocomplete="off" spellcheck="false" />
			<button class="button" type="submit" disabled={searching} aria-busy={searching}>{searching ? 'Searching' : 'Search'}</button>
		</form>
		{#if searchError}<p class="notice" data-tone="crit" role="alert">{searchError}</p>{/if}
		{#if response && response.routers.length === 0}
			<p class="empty">{applied ? `No router records match “${applied}”.` : 'The network database is empty. Start a reseed to bootstrap.'}</p>
		{:else if response}
			<div class="table-scroll">
				<table class="data">
					<thead><tr><th>Router</th><th>Caps</th><th>Version</th><th>Transports</th><th class="num">Last seen</th></tr></thead>
					<tbody>
						{#each response.routers as router (router.hash)}
							<tr>
								<td>
									<Identifier value={router.b32} href={linkPeers ? `/peers/${router.b32}/` : undefined} label="router B32" copy={false} head={12} tail={8} />
									{#if router.floodfill}<Badge tone="info">Floodfill</Badge>{/if}
								</td>
								<td class="mono" title={decodeCaps(router.caps).map((flag) => flag.label).join(', ')}>{router.caps || '—'}</td>
								<td>{router.version || '—'}</td>
								<td>{router.transports?.join(', ') || '—'}</td>
								<td class="num">{formatAgoSeconds(router.last_seen_ago_seconds)}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{:else if !searchError}
			<p class="empty">Loading router records.</p>
		{/if}
	</section>
</div>

<style>
	.summary {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		gap: var(--space-3);
	}

	.summary :global(.metric) {
		border: var(--rule-thin) solid var(--color-rule);
		border-left-width: 3px;
	}

	.grid {
		display: grid;
		grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
		gap: var(--space-3);
	}

	.compact {
		grid-template-columns: repeat(2, minmax(0, 1fr));
		margin-bottom: var(--space-4);
	}

	.search {
		display: flex;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
	}

	td :global(.badge) {
		margin-left: var(--space-2);
	}

	@media (max-width: 960px) {
		.summary {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.grid {
			grid-template-columns: minmax(0, 1fr);
		}
	}
</style>
