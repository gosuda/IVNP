<script lang="ts">
	import { destinationsData, tunnelsData } from '$lib/api';
	import { formatRate } from '$lib/format';
	import Badge from '$lib/components/Badge.svelte';
	import Identifier from '$lib/components/Identifier.svelte';
	import InlineError from '$lib/components/InlineError.svelte';

	const tunnelCount = (name: string) => ($tunnelsData?.tunnels ?? []).filter((tunnel) => tunnel.destination_name === name).length;
</script>

<div class="page">
	<div class="page-head">
		<h1>Destinations</h1>
		{#if $destinationsData}<span class="muted">{$destinationsData.destinations.length} registered</span>{/if}
	</div>
	<InlineError resource="destinations" />
	{#if $destinationsData}
		{#if $destinationsData.destinations.length === 0}
			<p class="empty">No local destinations are registered. Proxies and SAM sessions create them on demand.</p>
		{:else}
			<section class="panel">
				<div class="table-scroll">
					<table class="data">
						<thead><tr><th>Name</th><th>Address</th><th class="num">Client tunnels</th><th class="num">Bandwidth cap</th></tr></thead>
						<tbody>
							{#each $destinationsData.destinations as destination (destination.name)}
								<tr>
									<td>
										<a href={`/destinations/${encodeURIComponent(destination.name)}/`}>{destination.name}</a>
										{#if destination.default}<Badge tone="info">Default</Badge>{/if}
									</td>
									<td><Identifier value={destination.address} label={`${destination.name} address`} head={16} tail={10} /></td>
									<td class="num">{tunnelCount(destination.name)}</td>
									<td class="num">{destination.bandwidth ? formatRate(destination.bandwidth.rate_bytes_per_second) : 'Unlimited'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}
	{:else}
		<p class="empty">Waiting for destinations.</p>
	{/if}
</div>

<style>
	td a {
		margin-right: var(--space-2);
		font-weight: 700;
		text-underline-offset: 0.2em;
	}
</style>
