<script lang="ts">
	import LiveChart from './LiveChart.svelte';
	import { fetchNetDB, netdbData, shortHash, telemetryHistory } from '../api';

	let query = '';
	let searching = false;
	$: history = $telemetryHistory;
	$: chartSeries = [
		{ label: 'Routers', values: history.map((point) => point.routers), tone: 'accent' as const },
		{ label: 'Floodfills', values: history.map((point) => point.floodfills), tone: 'ink' as const, dashed: true }
	];

	async function search(): Promise<void> {
		if (searching) return;
		searching = true;
		await fetchNetDB(query, 50);
		searching = false;
	}

	async function clearSearch(): Promise<void> {
		query = '';
		await search();
	}
</script>

<section class="cell netdb-cell" aria-labelledby="netdb-title">
	<div class="cell-head">
		<div>
			<p class="cell-note">Kademlia directory</p>
			<h2 class="cell-title" id="netdb-title">Network database</h2>
		</div>
		<div class="counts">
			<strong>{$netdbData?.total_routers ?? 0}</strong><span>routers</span>
			<strong>{$netdbData?.floodfill_routers ?? 0}</strong><span>floodfills</span>
		</div>
	</div>

	<LiveChart series={chartSeries} label="Known routers and floodfills over the last 120 seconds" height={118} />

	<form class="search" on:submit|preventDefault={search} role="search">
		<label class="sr-only" for="netdb-query">Search router hash, address, version, or capability</label>
		<input
			class="input"
			id="netdb-query"
			type="search"
			bind:value={query}
			placeholder="Hash, B32, address, version, or caps"
			autocomplete="off"
		/>
		<button class="button" type="submit" disabled={searching} aria-busy={searching}>{searching ? 'Searching' : 'Search'}</button>
		{#if query}
			<button class="button" type="button" on:click={clearSearch}>Clear</button>
		{/if}
	</form>

	<div class="router-table">
		<div class="table-head"><span>Router</span><span>Transport</span><span>Version</span><span>Seen</span></div>
		{#if ($netdbData?.routers.length ?? 0) > 0}
			{#each $netdbData?.routers ?? [] as router (router.hash)}
				<div class="router-row">
					<div>
						<strong title={router.b32}>{shortHash(router.b32, 12, 6)}</strong>
						{#if router.floodfill}<span class="flag">floodfill</span>{/if}
					</div>
					<span>{router.transports.join(' + ') || '—'}</span>
					<span>{router.version || '—'}</span>
					<span>{router.last_seen_ago_seconds}s</span>
				</div>
			{/each}
		{:else}
			<div class="empty compact">No routers match this query</div>
		{/if}
	</div>
</section>

<style>
	.netdb-cell {
		display: grid;
		align-content: start;
		gap: var(--space-4);
	}

	.counts {
		display: grid;
		grid-template-columns: auto auto;
		gap: 0 var(--space-2);
		align-items: baseline;
		font-size: var(--text-xs);
		text-align: right;
	}

	.counts strong {
		font-size: var(--text-lg);
	}

	.counts span {
		color: var(--color-muted);
	}

	.search {
		display: flex;
		gap: var(--space-2);
	}

	.search .input {
		min-width: 0;
	}

	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}

	.router-table {
		max-height: 20rem;
		overflow: auto;
		border-top: var(--rule-heavy) solid var(--color-ink);
	}

	.table-head,
	.router-row {
		display: grid;
		grid-template-columns: minmax(8rem, 1.7fr) 1fr 0.7fr 0.5fr;
		gap: var(--space-3);
		align-items: center;
		min-width: 34rem;
		padding: var(--space-2) var(--space-1);
		border-bottom: var(--rule-thin) solid var(--color-rule);
		font-size: var(--text-xs);
	}

	.table-head {
		position: sticky;
		top: 0;
		z-index: 1;
		background: var(--color-paper);
		color: var(--color-muted);
		font-weight: 650;
		letter-spacing: 0.06em;
		text-transform: uppercase;
	}

	.router-row > span,
	.router-row strong {
		display: block;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.router-row > div {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-width: 0;
	}

	.flag {
		flex: 0 0 auto;
		padding: 0.12rem 0.3rem;
		border: var(--rule-thin) solid var(--color-accent);
		color: var(--color-accent);
		font-size: 0.62rem;
		font-weight: 700;
		letter-spacing: 0.05em;
		text-transform: uppercase;
	}

	.compact {
		min-height: 5rem;
	}

	@media (max-width: 540px) {
		.cell-head {
			display: grid;
		}

		.counts {
			width: fit-content;
			text-align: left;
		}

		.search {
			display: grid;
			grid-template-columns: 1fr 1fr;
		}

		.search .input {
			grid-column: 1 / -1;
		}
	}
</style>
