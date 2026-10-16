<script lang="ts">
	import { goto } from '$app/navigation';
	import { configData, destinationsData, routerStatus, searchNetDB, tunnelsData } from '$lib/api';
	import { b32Label, tunnelLabel } from '$lib/format';
	import { paletteOpen } from '$lib/ui';

	interface Item {
		id: string;
		group: string;
		label: string;
		sub: string;
		href: string;
		keywords: string;
	}

	let dialog = $state<HTMLDialogElement | null>(null);
	let input = $state<HTMLInputElement | null>(null);
	let query = $state('');
	let activeIndex = $state(0);
	let remote = $state<Item[]>([]);
	let remoteTimer: number | undefined;

	const pages: Item[] = [
		{ id: 'page-overview', group: 'Pages', label: 'Overview', sub: 'Readiness, throughput, services', href: '/', keywords: 'home dashboard status' },
		{ id: 'page-tunnels', group: 'Pages', label: 'Tunnels', sub: 'Pools, builds, and live tunnels', href: '/tunnels/', keywords: 'pool build hop' },
		{ id: 'page-network', group: 'Pages', label: 'Network database', sub: 'Known routers and search', href: '/network/', keywords: 'netdb routers floodfill reseed' },
		{ id: 'page-destinations', group: 'Pages', label: 'Destinations', sub: 'Local I2P destinations', href: '/destinations/', keywords: 'b32 leaseset' },
		{ id: 'page-settings', group: 'Pages', label: 'Settings', sub: 'Features and configuration', href: '/settings/', keywords: 'config features toggle restart' }
	];

	const local = $derived.by((): Item[] => {
		const items: Item[] = [...pages];
		for (const tunnel of $tunnelsData?.tunnels ?? []) {
			items.push({
				id: `tunnel-${tunnel.id}`,
				group: 'Tunnels',
				label: tunnelLabel(tunnel.id),
				sub: [tunnel.kind, tunnel.direction, tunnel.destination_name].filter(Boolean).join(' · '),
				href: `/tunnels/${tunnel.id}/`,
				keywords: `${tunnel.id} ${tunnel.gateway ?? ''} ${(tunnel.hops ?? []).join(' ')}`
			});
		}
		for (const destination of $destinationsData?.destinations ?? []) {
			items.push({
				id: `destination-${destination.name}`,
				group: 'Destinations',
				label: destination.name,
				sub: b32Label(destination.address, 12, 6),
				href: `/destinations/${encodeURIComponent(destination.name)}/`,
				keywords: destination.address
			});
		}
		if ($routerStatus?.capabilities.peer_identities) {
			const peers = new Set<string>();
			for (const tunnel of $tunnelsData?.tunnels ?? []) for (const hop of tunnel.hops ?? []) peers.add(hop);
			for (const peer of peers) {
				items.push({ id: `peer-${peer}`, group: 'Tunnel peers', label: b32Label(peer, 12, 6), sub: 'Hop in a live tunnel', href: `/peers/${peer}/`, keywords: peer });
			}
		}
		for (const field of $configData?.fields ?? []) {
			items.push({
				id: `field-${field.key}`,
				group: 'Settings',
				label: field.label,
				sub: field.key,
				href: `/settings/?focus=${encodeURIComponent(field.key)}`,
				keywords: `${field.key} ${field.description} ${field.group}`
			});
		}
		return items;
	});

	const results = $derived.by((): Item[] => {
		const needle = query.trim().toLowerCase();
		const matched = needle
			? local.filter((item) => `${item.label} ${item.sub} ${item.keywords}`.toLowerCase().includes(needle))
			: local.filter((item) => item.group === 'Pages');
		const seen = new Set(matched.map((item) => item.href));
		return [...matched.slice(0, 40), ...remote.filter((item) => !seen.has(item.href))];
	});

	$effect(() => {
		if (!dialog) return;
		if ($paletteOpen && !dialog.open) {
			query = '';
			remote = [];
			activeIndex = 0;
			dialog.showModal();
			queueMicrotask(() => input?.focus());
		} else if (!$paletteOpen && dialog.open) {
			dialog.close();
		}
	});

	function onInput(): void {
		activeIndex = 0;
		window.clearTimeout(remoteTimer);
		const needle = query.trim();
		if (needle.length < 3 || !$routerStatus?.capabilities.peer_identities) {
			remote = [];
			return;
		}
		remoteTimer = window.setTimeout(async () => {
			try {
				const response = await searchNetDB(needle, 8);
				if (query.trim() !== needle) return;
				remote = response.routers.map((router) => ({
					id: `netdb-${router.b32}`,
					group: `NetDB (${response.matched.toLocaleString()} matches)`,
					label: b32Label(router.b32, 12, 6),
					sub: [router.floodfill ? 'floodfill' : '', router.caps, router.version].filter(Boolean).join(' · '),
					href: `/peers/${router.b32}/`,
					keywords: router.b32
				}));
			} catch {
				remote = [];
			}
		}, 250);
	}

	function choose(item: Item | undefined): void {
		if (!item) return;
		paletteOpen.set(false);
		void goto(item.href);
	}

	function onKeydown(event: KeyboardEvent): void {
		if (event.key === 'ArrowDown') {
			event.preventDefault();
			activeIndex = Math.min(activeIndex + 1, results.length - 1);
		} else if (event.key === 'ArrowUp') {
			event.preventDefault();
			activeIndex = Math.max(activeIndex - 1, 0);
		} else if (event.key === 'Enter') {
			event.preventDefault();
			choose(results[activeIndex]);
		}
	}

	$effect(() => {
		document.getElementById(`palette-${results[activeIndex]?.id}`)?.scrollIntoView({ block: 'nearest' });
	});
</script>

<dialog
	class="modal palette"
	bind:this={dialog}
	aria-label="Search the console"
	onclose={() => paletteOpen.set(false)}
	onclick={(event) => event.target === dialog && paletteOpen.set(false)}
>
	<div class="field">
		<input
			bind:this={input}
			bind:value={query}
			oninput={onInput}
			onkeydown={onKeydown}
			class="input"
			type="search"
			role="combobox"
			aria-expanded="true"
			aria-controls="palette-results"
			aria-activedescendant={results[activeIndex] ? `palette-${results[activeIndex].id}` : undefined}
			aria-autocomplete="list"
			placeholder="Tunnel ID, B32, router hash, setting, or page"
			autocomplete="off"
			spellcheck="false"
		/>
	</div>
	<ul id="palette-results" role="listbox" aria-label="Results">
		{#each results as item, index (item.id)}
			{#if index === 0 || results[index - 1].group !== item.group}
				<li class="group" role="presentation">{item.group}</li>
			{/if}
			<li
				id={`palette-${item.id}`}
				role="option"
				aria-selected={index === activeIndex}
				onclick={() => choose(item)}
				onkeydown={() => {}}
				onpointermove={() => (activeIndex = index)}
			>
				<span class="item-label">{item.label}</span>
				<span class="item-sub">{item.sub}</span>
			</li>
		{:else}
			<li class="none" role="presentation">No matches for “{query}”.</li>
		{/each}
	</ul>
	<p class="hint"><kbd>↑</kbd><kbd>↓</kbd> move · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close</p>
</dialog>

<style>
	.palette {
		width: min(40rem, calc(100vw - var(--space-6)));
		margin-top: 12vh;
	}

	.field {
		padding: var(--space-3);
		border-bottom: var(--rule-thin) solid var(--color-rule);
	}

	ul {
		max-height: min(26rem, 55vh);
		margin: 0;
		padding: var(--space-2) 0;
		overflow-y: auto;
		list-style: none;
	}

	.group {
		padding: var(--space-2) var(--space-4) var(--space-1);
		color: var(--color-muted);
		font-size: var(--text-xs);
		font-weight: 650;
		letter-spacing: 0.05em;
		text-transform: uppercase;
	}

	[role='option'] {
		display: flex;
		justify-content: space-between;
		gap: var(--space-4);
		padding: var(--space-2) var(--space-4);
		cursor: pointer;
	}

	[role='option'][aria-selected='true'] {
		background: var(--color-accent-soft);
		box-shadow: inset 3px 0 var(--color-accent);
	}

	.item-label {
		min-width: 0;
		font-size: var(--text-sm);
		font-weight: 650;
		overflow-wrap: anywhere;
	}

	.item-sub {
		flex: 0 1 auto;
		min-width: 0;
		color: var(--color-muted);
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		text-align: right;
		overflow-wrap: anywhere;
	}

	.none {
		padding: var(--space-5) var(--space-4);
		color: var(--color-muted);
		font-size: var(--text-sm);
	}

	.hint {
		padding: var(--space-2) var(--space-4);
		border-top: var(--rule-thin) solid var(--color-rule);
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	kbd {
		margin-right: 2px;
		padding: 0 0.3rem;
		border: var(--rule-thin) solid var(--color-rule);
		font-family: var(--font-mono);
	}
</style>
