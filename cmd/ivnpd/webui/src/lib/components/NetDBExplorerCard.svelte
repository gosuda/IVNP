<script lang="ts">
	import DataStatus from './DataStatus.svelte';
	import QuickActionsCard from './QuickActionsCard.svelte';
	import { collectionState, fetchNetDB, netdbData, netdbQuery, shortHash } from '../api';

	const resultLimit = 50;
	let query = $netdbQuery;
	let searching = false;

	async function search(): Promise<void> {
		if (searching) return;
		searching = true;
		try {
			await fetchNetDB(query, resultLimit);
		} finally {
			searching = false;
		}
	}

	async function clearSearch(): Promise<void> {
		query = '';
		await search();
	}
</script>

<section class="cell netdb-cell" aria-labelledby="netdb-title">
	<h2 class="cell-title" id="netdb-title">Network database</h2>
	<DataStatus resource="netdb" />

	{#if $netdbData}
		<dl class="counts">
			<div><dt>Known routers</dt><dd>{$netdbData.total_routers.toLocaleString()}</dd></div>
			<div><dt>Floodfills</dt><dd>{$netdbData.floodfill_routers.toLocaleString()}</dd></div>
			<div>
				<dt>Lookup failures</dt>
				<dd>{$netdbData.lookups_failed.toLocaleString()} <span>of {$netdbData.lookups_total.toLocaleString()} lookups</span></dd>
			</div>
		</dl>
	{:else}
		<p class="unavailable">Router counts and lookup activity are unavailable until a collection succeeds.</p>
	{/if}

	<details class="explorer">
		<summary>Search router records</summary>
		<div class="explorer-content">
			<form class="search" on:submit|preventDefault={search} role="search">
				<label for="netdb-query">Router hash, B32, address, version, or capability</label>
				<div class="search-controls">
					<input class="input" id="netdb-query" type="search" bind:value={query} autocomplete="off" />
					<button class="button" type="submit" disabled={searching} aria-busy={searching}>{searching ? 'Searching' : 'Search'}</button>
					{#if query || $netdbQuery}
						<button class="button" type="button" on:click={clearSearch} disabled={searching}>Clear</button>
					{/if}
				</div>
			</form>

			{#if $netdbData}
				<div class="result-scope">
					<p><strong>{$netdbData.routers.length.toLocaleString()} returned</strong> · limit {resultLimit} per collection</p>
					<p>{$netdbQuery ? `Applied search: “${$netdbQuery}”` : 'No search filter applied.'} Automatic refresh keeps this filter.</p>
					<p>Known-router and floodfill totals cover the entire database, not search matches. The API does not report a total match count.</p>
				</div>
				{#if $netdbData.routers.length > 0}
					<ul class="router-list" aria-label="Returned router records">
						{#each $netdbData.routers as router (router.hash)}
							<li>
								<details class="router-record">
									<summary>
										<span class="router-identity"><strong>{shortHash(router.hash, 12, 6)}</strong>{#if router.floodfill}<span class="flag">Floodfill</span>{/if}</span>
										<span class="router-version">Version {router.version || 'unavailable'}</span>
										<span class="router-transports">{router.transports?.join(' + ') || 'No transports reported'}</span>
									</summary>
									<dl class="router-details">
										<div><dt>Hash</dt><dd>{router.hash}</dd></div>
										<div><dt>B32</dt><dd>{router.b32}</dd></div>
										<div><dt>Capabilities</dt><dd>{router.caps || 'Not reported'}</dd></div>
										<div><dt>Last seen</dt><dd>{router.last_seen_ago_seconds.toLocaleString()} seconds ago at collection</dd></div>
										<div><dt>Published</dt><dd>{router.published > 0 ? new Date(router.published).toLocaleString() : 'Not reported'}</dd></div>
										<div><dt>Addresses</dt><dd>{#if router.addresses?.length}{#each router.addresses as address}<span class="address">{address}</span>{/each}{:else}Not reported{/if}</dd></div>
									</dl>
								</details>
							</li>
						{/each}
					</ul>
				{:else if $collectionState.netdb.error}
					<p class="empty compact">The last successful collection returned no router records. The latest request failed; retry to update these results.</p>
				{:else if $netdbQuery}
					<p class="empty compact">No routers matched “{$netdbQuery}” at the last collection.</p>
				{:else}
					<p class="empty compact">The network database returned no router records.</p>
				{/if}
			{:else if $collectionState.netdb.error}
				<p class="empty compact">Router records could not be collected. Retry the collection or submit a search.</p>
			{:else}
				<p class="empty compact">Waiting for the first router collection.</p>
			{/if}
		</div>
	</details>

	<QuickActionsCard action="reseed" />
</section>

<style>
	.netdb-cell,
	.explorer-content {
		display: grid;
		align-content: start;
		gap: var(--space-4);
	}

	.counts {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-4) var(--space-6);
		margin: 0;
	}

	.counts dt,
	.router-details dt {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.counts dd {
		margin: var(--space-1) 0 0;
		font-size: var(--text-xl);
		font-weight: 650;
	}

	.counts dd span {
		font-size: var(--text-xs);
		font-weight: 400;
		color: var(--color-muted);
	}

	summary {
		cursor: pointer;
		padding-block: var(--space-3);
		font-size: var(--text-sm);
		font-weight: 650;
	}

	summary:hover {
		color: var(--color-accent);
	}

	summary:focus-visible {
		outline: 3px solid var(--color-focus);
		outline-offset: 2px;
	}

	.explorer {
		min-width: 0;
		border-top: var(--rule-thin) solid var(--color-rule);
	}

	.search {
		display: grid;
		gap: var(--space-2);
	}

	.search label,
	.result-scope,
	.unavailable {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.search-controls {
		display: flex;
		gap: var(--space-2);
	}

	.search .input {
		min-width: 0;
		flex: 1;
	}

	.result-scope p {
		margin: 0 0 var(--space-1);
		overflow-wrap: anywhere;
	}

	.result-scope strong {
		color: var(--color-ink);
	}

	.router-list {
		list-style: none;
		padding: 0;
		margin: 0;
		border-top: var(--rule-heavy) solid var(--color-ink);
	}

	.router-record {
		border-bottom: var(--rule-thin) solid var(--color-rule);
	}

	.router-record summary {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2) var(--space-4);
		font-size: var(--text-xs);
		font-weight: 400;
	}

	.router-record summary::before {
		content: '+';
		color: var(--color-accent);
		font-weight: 700;
	}

	.router-record[open] summary::before {
		content: '−';
	}

	.router-identity {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		flex: 1;
		min-width: 0;
	}

	.router-identity strong,
	.router-version,
	.router-transports {
		overflow-wrap: anywhere;
	}

	.flag {
		color: var(--color-accent);
		font-weight: 650;
	}

	.router-details {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: var(--space-3) var(--space-4);
		margin: 0 0 var(--space-4);
	}

	.router-details dd {
		margin: var(--space-1) 0 0;
		font-size: var(--text-xs);
		overflow-wrap: anywhere;
	}

	.address {
		display: block;
	}

	.compact {
		min-height: 5rem;
	}

	@media (max-width: 540px) {
		.search-controls {
			display: grid;
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.search .input {
			grid-column: 1 / -1;
		}

		.router-identity {
			flex-basis: calc(100% - 2rem);
		}

		.router-details {
			grid-template-columns: minmax(0, 1fr);
		}
	}
</style>
