<script lang="ts">
	import { page } from '$app/state';
	import { APIError, errorMessage, fetchPeers, routerStatus, tunnelsData } from '$lib/api';
	import { b32Label, decodeCaps, formatAgoSeconds, formatTimestamp, tunnelLabel } from '$lib/format';
	import type { PeerItem } from '$lib/types';
	import Badge from '$lib/components/Badge.svelte';
	import Identifier from '$lib/components/Identifier.svelte';

	const address = $derived(page.params.b32 ?? '');
	let peer = $state<PeerItem | null | undefined>(undefined);
	let loadError = $state('');
	let hidden = $state(false);

	$effect(() => {
		const wanted = address;
		peer = undefined;
		loadError = '';
		hidden = false;
		fetchPeers([wanted])
			.then((result) => {
				if (wanted === address) peer = result.get(wanted) ?? null;
			})
			.catch((error) => {
				if (error instanceof APIError && error.status === 403) hidden = true;
				else loadError = errorMessage(error);
			});
	});

	const usedBy = $derived(
		($tunnelsData?.tunnels ?? [])
			.map((tunnel) => ({ tunnel, position: (tunnel.hops ?? []).indexOf(address) }))
			.filter(({ tunnel, position }) => position >= 0 || tunnel.gateway === address)
	);
	const successRate = $derived(peer?.profile && peer.profile.samples > 0 ? Math.round((peer.profile.successes / peer.profile.samples) * 100) : null);
</script>

<div class="page">
	<nav class="crumbs" aria-label="Breadcrumb"><a href="/network/">Network</a><span aria-hidden="true">/</span><span class="mono">{b32Label(address, 10, 6)}</span></nav>

	{#if hidden || $routerStatus?.capabilities.peer_identities === false}
		<div class="page-head"><h1>Peer details hidden</h1></div>
		<p class="notice" data-tone="info">Peer identities are hidden because this console is reachable from other hosts. Start ivnpd with <code class="mono">-webui-show-peers</code> to show them.</p>
	{:else if loadError}
		<div class="page-head"><h1>Peer</h1></div>
		<p class="notice" data-tone="crit" role="alert">{loadError}</p>
	{:else if peer === undefined}
		<p class="empty">Loading peer.</p>
	{:else if peer === null}
		<div class="page-head"><h1 class="mono">{b32Label(address, 12, 8)}</h1><Badge tone="warn">Not in local NetDB</Badge></div>
		<p class="empty">This router has no RouterInfo for the address. It may have expired from the network database.</p>
	{:else}
		<div class="page-head">
			<h1 class="mono">{b32Label(peer.b32, 12, 8)}</h1>
			<div class="badges">
				{#if peer.floodfill}<Badge tone="info">Floodfill</Badge>{/if}
				{#if usedBy.length > 0}<Badge tone="ok">In {usedBy.length} live tunnel{usedBy.length === 1 ? '' : 's'}</Badge>{/if}
			</div>
		</div>

		<section class="panel" aria-labelledby="identity-title">
			<div class="panel-head"><h2 id="identity-title">RouterInfo</h2></div>
			<dl class="props">
				<div><dt>B32</dt><dd><Identifier value={peer.b32} label="peer B32" full /></dd></div>
				<div><dt>Router hash</dt><dd><Identifier value={peer.hash} label="router hash" /></dd></div>
				<div><dt>Version</dt><dd>{peer.version || 'Not reported'}</dd></div>
				<div><dt>Published</dt><dd>{formatTimestamp(peer.published)}</dd></div>
				<div><dt>Last seen locally</dt><dd>{formatAgoSeconds(peer.last_seen_ago_seconds)}</dd></div>
				<div><dt>Transports</dt><dd>{peer.transports?.join(', ') || 'None published'}</dd></div>
			</dl>
			<h3 class="sub">Capabilities</h3>
			{#if peer.caps}
				<ul class="caps">
					{#each decodeCaps(peer.caps) as flag (flag.code)}
						<li><Badge tone={flag.tone}><span class="mono">{flag.code}</span> {flag.label}</Badge></li>
					{/each}
				</ul>
			{:else}
				<p class="muted">No capabilities published.</p>
			{/if}
			<h3 class="sub">Published addresses</h3>
			{#if peer.addresses?.length}
				<ul class="addresses">
					{#each peer.addresses as entry (entry)}<li class="mono">{entry}</li>{/each}
				</ul>
			{:else}
				<p class="muted">No direct addresses. The peer is reachable only through introducers or is hidden.</p>
			{/if}
		</section>

		<section class="panel" aria-labelledby="profile-title">
			<div class="panel-head"><h2 id="profile-title">Local profile</h2></div>
			{#if peer.profile}
				<dl class="props">
					<div><dt>Successful observations</dt><dd>{peer.profile.successes}</dd></div>
					<div><dt>Failed observations</dt><dd>{peer.profile.failures}</dd></div>
					<div><dt>Success rate</dt><dd>{successRate === null ? '—' : `${successRate}%`}</dd></div>
					<div><dt>Mean latency</dt><dd>{peer.profile.mean_latency_ms} ms</dd></div>
					<div><dt>Samples in window</dt><dd>{peer.profile.samples}</dd></div>
				</dl>
			{:else}
				<p class="empty">No build or delivery observations recorded for this peer yet.</p>
			{/if}
		</section>

		<section class="panel" aria-labelledby="used-title">
			<div class="panel-head"><h2 id="used-title">Used by live tunnels</h2></div>
			{#if usedBy.length === 0}
				<p class="empty">No live tunnel created by this router passes through this peer.</p>
			{:else}
				<div class="table-scroll">
					<table class="data">
						<thead><tr><th>Tunnel</th><th>Kind</th><th>Direction</th><th>Position</th></tr></thead>
						<tbody>
							{#each usedBy as { tunnel, position } (tunnel.id)}
								<tr>
									<td><a class="mono" href={`/tunnels/${tunnel.id}/`}>{tunnelLabel(tunnel.id)}</a></td>
									<td>{tunnel.kind}{tunnel.destination_name ? ` · ${tunnel.destination_name}` : ''}</td>
									<td>{tunnel.direction}</td>
									<td>{position >= 0 ? `Hop ${position + 1} of ${tunnel.hop_count}` : 'Gateway'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>
	{/if}
</div>

<style>
	.badges {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}

	.sub {
		margin: var(--space-5) 0 var(--space-2);
		font-size: var(--text-sm);
	}

	.caps,
	.addresses {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		padding: 0;
		list-style: none;
	}

	.addresses {
		display: grid;
		font-size: var(--text-sm);
	}

	td a {
		font-weight: 600;
		text-underline-offset: 0.2em;
	}
</style>
