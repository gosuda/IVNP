<script lang="ts">
	import { page } from '$app/state';
	import { destinationsData, routerStatus, tunnelsData } from '$lib/api';
	import { formatBytes, formatDuration, formatRate, tunnelLabel } from '$lib/format';
	import Badge from '$lib/components/Badge.svelte';
	import Identifier from '$lib/components/Identifier.svelte';
	import InlineError from '$lib/components/InlineError.svelte';

	const name = $derived(decodeURIComponent(page.params.name ?? ''));
	const destination = $derived($destinationsData?.destinations.find((item) => item.name === name) ?? null);
	const tunnels = $derived(($tunnelsData?.tunnels ?? []).filter((tunnel) => tunnel.destination_name === name));
	const inbound = $derived(tunnels.filter((tunnel) => tunnel.direction === 'inbound').length);
	const outbound = $derived(tunnels.length - inbound);
	const proxies = $derived(
		destination?.default && $routerStatus
			? [
					{ name: 'HTTP proxy', service: $routerStatus.services.http_proxy },
					{ name: 'SOCKS5 proxy', service: $routerStatus.services.socks5 }
				].filter((entry) => entry.service.enabled)
			: []
	);
</script>

<div class="page">
	<nav class="crumbs" aria-label="Breadcrumb"><a href="/destinations/">Destinations</a><span aria-hidden="true">/</span><span>{name}</span></nav>
	<InlineError resource="destinations" />

	{#if destination}
		<div class="page-head">
			<h1>{destination.name}</h1>
			<div class="badges">
				{#if destination.default}<Badge tone="info">Default</Badge>{/if}
				<Badge tone={inbound > 0 && outbound > 0 ? 'ok' : 'warn'}>{inbound} in · {outbound} out</Badge>
			</div>
		</div>

		<section class="panel" aria-labelledby="props-title">
			<div class="panel-head"><h2 id="props-title">Properties</h2></div>
			<dl class="props">
				<div class="wide"><dt>Address</dt><dd><Identifier value={destination.address} label="destination address" full /></dd></div>
				{#if destination.bandwidth}
					<div><dt>Bandwidth cap</dt><dd>{formatRate(destination.bandwidth.rate_bytes_per_second)}</dd></div>
					<div><dt>Burst</dt><dd>{formatBytes(destination.bandwidth.burst_bytes)}</dd></div>
					<div><dt>Tokens available</dt><dd>{formatBytes(destination.bandwidth.available_bytes)}</dd></div>
					<div><dt>Accepted</dt><dd>{formatBytes(destination.bandwidth.accepted_bytes)}</dd></div>
					<div><dt>Held by backpressure</dt><dd>{formatBytes(destination.bandwidth.backpressured_bytes)}</dd></div>
					<div><dt>Waiting senders</dt><dd>{destination.bandwidth.waiters}</dd></div>
				{:else}
					<div><dt>Bandwidth cap</dt><dd>Unlimited</dd></div>
				{/if}
			</dl>
		</section>

		{#if proxies.length > 0}
			<section class="panel" aria-labelledby="proxies-title">
				<div class="panel-head"><h2 id="proxies-title">Served through</h2></div>
				<ul class="proxies">
					{#each proxies as proxy (proxy.name)}
						<li><strong>{proxy.name}</strong> <span class="mono">{proxy.service.address}</span></li>
					{/each}
				</ul>
			</section>
		{/if}

		<section class="panel" aria-labelledby="tunnels-title">
			<div class="panel-head">
				<h2 id="tunnels-title">Client tunnels</h2>
				<a href={`/tunnels/?kind=client&q=${encodeURIComponent(name)}`}>Open in Tunnels</a>
			</div>
			{#if tunnels.length === 0}
				<p class="empty">No live client tunnels. LeaseSet publication waits for at least one inbound tunnel.</p>
			{:else}
				<div class="table-scroll">
					<table class="data">
						<thead><tr><th>Tunnel</th><th>Direction</th><th class="num">Hops</th><th class="num">Expires in</th><th>State</th></tr></thead>
						<tbody>
							{#each tunnels as tunnel (tunnel.id)}
								<tr>
									<td><a class="mono" href={`/tunnels/${tunnel.id}/`}>{tunnelLabel(tunnel.id)}</a></td>
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
	{:else if $destinationsData}
		<div class="page-head"><h1>Destination not found</h1></div>
		<p class="empty">No local destination is named “{name}”. <a href="/destinations/">Back to destinations</a></p>
	{:else}
		<p class="empty">Loading destination.</p>
	{/if}
</div>

<style>
	.badges {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}

	.wide {
		grid-column: 1 / -1;
	}

	.proxies {
		display: grid;
		gap: var(--space-2);
		padding: 0;
		list-style: none;
		font-size: var(--text-sm);
	}

	td a,
	.empty a {
		font-weight: 600;
		text-underline-offset: 0.2em;
	}
</style>
