<script lang="ts">
	import { b32Label } from '$lib/format';
	import type { PeerItem, RouterTunnelItem } from '$lib/types';

	let { tunnel, peers = new Map() }: { tunnel: RouterTunnelItem; peers?: Map<string, PeerItem | null> } = $props();

	interface Node {
		key: string;
		role: string;
		b32?: string;
	}

	// Hops are stored in path order from the first hop. Outbound traffic leaves
	// this router into hop 1; inbound traffic enters at hop 1 (the gateway) and
	// ends at this router.
	const nodes = $derived.by((): Node[] => {
		const hops = tunnel.hops ?? [];
		const local: Node = { key: 'local', role: tunnel.direction === 'outbound' ? 'This router (gateway)' : 'This router (endpoint)' };
		const remote = hops.map((b32, index): Node => {
			let role = `Hop ${index + 1}`;
			if (tunnel.direction === 'inbound' && index === 0) role = 'Inbound gateway';
			if (tunnel.direction === 'outbound' && index === hops.length - 1) role = 'Outbound endpoint';
			return { key: `${index}-${b32}`, role, b32 };
		});
		return tunnel.direction === 'outbound' ? [local, ...remote] : [...remote, local];
	});
</script>

{#if (tunnel.hops ?? []).length === 0}
	<p class="empty">
		{tunnel.hop_count === 0 ? 'Zero-hop tunnel: traffic does not leave this router.' : `${tunnel.hop_count} hops; peer identities are hidden on this console.`}
	</p>
{:else}
	<ol class="path" aria-label={`${tunnel.direction} tunnel path, ${tunnel.hop_count} hops`}>
		{#each nodes as node, index (node.key)}
			<li class:local={!node.b32}>
				<span class="role">{node.role}</span>
				{#if node.b32}
					{@const peer = peers.get(node.b32)}
					<a class="mono" href={`/peers/${node.b32}/`} title={node.b32}>{b32Label(node.b32)}</a>
					<span class="meta">
						{#if peer === undefined}
							Resolving
						{:else if peer === null}
							Not in local NetDB
						{:else}
							{peer.caps || 'no caps'}{peer.profile ? ` · ${peer.profile.successes}/${peer.profile.samples} ok` : ''}
						{/if}
					</span>
				{:else}
					<span class="mono">local</span>
				{/if}
			</li>
			{#if index < nodes.length - 1}<li class="arrow" aria-hidden="true">→</li>{/if}
		{/each}
	</ol>
{/if}

<style>
	.path {
		display: flex;
		flex-wrap: wrap;
		align-items: stretch;
		gap: var(--space-2);
		padding: 0;
		list-style: none;
	}

	li:not(.arrow) {
		display: grid;
		align-content: start;
		gap: var(--space-1);
		min-width: 9.5rem;
		padding: var(--space-3);
		border: var(--rule-thin) solid var(--color-rule-strong);
		background: var(--color-paper);
	}

	li.local {
		border-color: var(--color-accent);
		background: var(--color-accent-soft);
	}

	.arrow {
		align-self: center;
		color: var(--color-muted);
		font-size: var(--text-lg);
	}

	.role {
		color: var(--color-muted);
		font-size: var(--text-xs);
		font-weight: 650;
	}

	a {
		font-size: var(--text-sm);
		font-weight: 650;
		text-underline-offset: 0.2em;
	}

	a:hover {
		color: var(--color-accent);
	}

	.meta {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}
</style>
