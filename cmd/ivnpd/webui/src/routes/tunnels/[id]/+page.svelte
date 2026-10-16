<script lang="ts">
	import { page } from '$app/state';
	import { errorMessage, fetchPeers, tunnelsData } from '$lib/api';
	import { formatDuration, formatTimestamp, tunnelLabel } from '$lib/format';
	import type { PeerItem } from '$lib/types';
	import Badge from '$lib/components/Badge.svelte';
	import Identifier from '$lib/components/Identifier.svelte';
	import InlineError from '$lib/components/InlineError.svelte';
	import TunnelPath from '$lib/components/TunnelPath.svelte';

	const id = $derived(Number(page.params.id));
	const tunnel = $derived($tunnelsData?.tunnels.find((item) => item.id === id) ?? null);
	let peers = $state(new Map<string, PeerItem | null>());
	let peerError = $state('');
	let lastKey = '';

	$effect(() => {
		const addresses = tunnel?.hops ?? [];
		const key = addresses.join(',');
		if (!key || key === lastKey) return;
		lastKey = key;
		fetchPeers(addresses)
			.then((result) => {
				peers = result;
				peerError = '';
			})
			.catch((error) => (peerError = errorMessage(error)));
	});
</script>

<div class="page">
	<nav class="crumbs" aria-label="Breadcrumb"><a href="/tunnels/">Tunnels</a><span aria-hidden="true">/</span><span>{Number.isFinite(id) ? tunnelLabel(id) : page.params.id}</span></nav>
	<InlineError resource="tunnels" />

	{#if tunnel}
		<div class="page-head">
			<h1 class="mono">{tunnelLabel(tunnel.id)}</h1>
			<Badge tone={tunnel.state === 'expiring' ? 'warn' : 'ok'}>{tunnel.state === 'expiring' ? 'Renewing' : 'Established'}</Badge>
		</div>

		<section class="panel" aria-labelledby="props-title">
			<div class="panel-head"><h2 id="props-title">Properties</h2></div>
			<dl class="props">
				<div><dt>Tunnel ID</dt><dd class="mono">{tunnel.id} ({tunnelLabel(tunnel.id)})</dd></div>
				<div><dt>Kind</dt><dd>{tunnel.kind === 'client' ? 'Client' : 'Exploratory'}</dd></div>
				<div><dt>Direction</dt><dd>{tunnel.direction === 'inbound' ? 'Inbound' : 'Outbound'}</dd></div>
				<div>
					<dt>Owner</dt>
					<dd>
						{#if tunnel.destination_name}
							<a href={`/destinations/${encodeURIComponent(tunnel.destination_name)}/`}>{tunnel.destination_name}</a>
						{:else}Router (exploratory){/if}
					</dd>
				</div>
				{#if tunnel.owner}<div><dt>Owner destination</dt><dd><Identifier value={tunnel.owner} label="owner destination" /></dd></div>{/if}
				<div><dt>Hops</dt><dd>{tunnel.hop_count}</dd></div>
				<div><dt>Expires</dt><dd>{formatDuration(tunnel.remaining_seconds)} <span class="muted">({formatTimestamp(tunnel.expires_at)})</span></dd></div>
				{#if tunnel.gateway}
					<div><dt>Inbound gateway</dt><dd><Identifier value={tunnel.gateway} href={`/peers/${tunnel.gateway}/`} label="gateway B32" /></dd></div>
				{/if}
				{#if tunnel.gateway_tunnel_id}<div><dt>Gateway tunnel ID</dt><dd class="mono">{tunnel.gateway_tunnel_id}</dd></div>{/if}
			</dl>
		</section>

		<section class="panel" aria-labelledby="path-title">
			<div class="panel-head"><h2 id="path-title">Path</h2></div>
			{#if peerError}<p class="notice" data-tone="crit" role="alert">Peer details unavailable: {peerError}</p>{/if}
			<TunnelPath {tunnel} {peers} />
		</section>

		{#if (tunnel.hops ?? []).length > 0}
			<section class="panel" aria-labelledby="peers-title">
				<div class="panel-head"><h2 id="peers-title">Hop peers</h2></div>
				<div class="table-scroll">
					<table class="data">
						<thead><tr><th>Position</th><th>Peer</th><th>Caps</th><th>Version</th><th class="num">Profile</th><th class="num">Latency</th></tr></thead>
						<tbody>
							{#each tunnel.hops ?? [] as hop, index (`${index}-${hop}`)}
								{@const peer = peers.get(hop)}
								<tr>
									<td>Hop {index + 1}</td>
									<td><Identifier value={hop} href={`/peers/${hop}/`} label="peer B32" copy={false} /></td>
									<td class="mono">{peer?.caps || '—'}</td>
									<td>{peer?.version || '—'}</td>
									<td class="num">{peer?.profile ? `${peer.profile.successes} ok / ${peer.profile.failures} failed` : peer === null ? 'Not in NetDB' : '—'}</td>
									<td class="num">{peer?.profile ? `${peer.profile.mean_latency_ms} ms` : '—'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}
	{:else if $tunnelsData}
		<div class="page-head"><h1>Tunnel not found</h1></div>
		<p class="empty">Tunnel {page.params.id} is not live. Tunnels expire after about ten minutes and are replaced. <a href="/tunnels/">Back to tunnels</a></p>
	{:else}
		<p class="empty">Loading tunnel.</p>
	{/if}
</div>

<style>
	dd a,
	.empty a {
		font-weight: 600;
		text-underline-offset: 0.2em;
	}
</style>
