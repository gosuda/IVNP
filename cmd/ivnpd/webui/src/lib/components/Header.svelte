<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { collection, refreshAll, restarting, routerStatus, streamState } from '$lib/api';
	import { formatAgoSeconds } from '$lib/format';
	import { paletteOpen } from '$lib/ui';
	import type { Tone } from '$lib/types';

	const links = [
		{ href: '/', label: 'Overview' },
		{ href: '/tunnels/', label: 'Tunnels' },
		{ href: '/network/', label: 'Network' },
		{ href: '/destinations/', label: 'Destinations' },
		{ href: '/settings/', label: 'Settings' }
	];

	let now = $state(Date.now());
	let refreshing = $state(false);
	const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

	onMount(() => {
		const timer = window.setInterval(() => (now = Date.now()), 1000);
		return () => window.clearInterval(timer);
	});

	const freshness = $derived.by((): { tone: Tone; text: string; detail: string } => {
		if ($restarting) return { tone: 'info', text: 'Restarting', detail: 'The router is restarting' };
		const last = $collection.status.lastSuccess;
		if (last === null) return $collection.status.error ? { tone: 'crit', text: 'Offline', detail: $collection.status.error } : { tone: 'neutral', text: 'Connecting', detail: '' };
		const age = (now - last) / 1000;
		if (age < 12 && $streamState === 'live') return { tone: 'ok', text: 'Live', detail: `Updated ${formatAgoSeconds(age)}` };
		if (age < 30) return { tone: 'warn', text: 'Delayed', detail: `Updated ${formatAgoSeconds(age)}` };
		return { tone: 'crit', text: 'Stale', detail: `Updated ${formatAgoSeconds(age)}` };
	});

	function active(href: string): boolean {
		return href === '/' ? page.url.pathname === '/' : page.url.pathname.startsWith(href);
	}

	async function refresh(): Promise<void> {
		if (refreshing) return;
		refreshing = true;
		await refreshAll();
		refreshing = false;
	}
</script>

<header class="header">
	<a class="wordmark" href="/" aria-label="IVNP router console, overview">
		<span class="mark" aria-hidden="true"></span>
		<span>IVNP</span>
		{#if $routerStatus?.version}<span class="version">{$routerStatus.version}</span>{/if}
	</a>

	<nav aria-label="Console sections">
		{#each links as link (link.href)}
			<a href={link.href} aria-current={active(link.href) ? 'page' : undefined}>{link.label}</a>
		{/each}
	</nav>

	<div class="tools">
		<button class="search" type="button" onclick={() => paletteOpen.set(true)} aria-keyshortcuts={isMac ? 'Meta+K' : 'Control+K'}>
			<span>Search</span><kbd>{isMac ? '⌘K' : 'Ctrl K'}</kbd>
		</button>
		<span class="freshness" data-tone={freshness.tone} title={freshness.detail}>
			<span class="dot" aria-hidden="true"></span>
			<span>{freshness.text}</span>
			{#if freshness.detail && freshness.tone !== 'ok'}<span class="detail">{freshness.detail}</span>{/if}
		</span>
		<button class="button button--quiet" type="button" onclick={refresh} disabled={refreshing} aria-busy={refreshing}>
			{refreshing ? 'Refreshing' : 'Refresh'}
		</button>
	</div>
</header>

<style>
	.header {
		position: sticky;
		top: 0;
		z-index: 10;
		display: grid;
		grid-template-columns: auto minmax(0, 1fr) auto;
		align-items: center;
		gap: var(--space-3) var(--space-6);
		padding: var(--space-3) clamp(var(--space-3), 2.4vw, var(--space-8));
		border-bottom: var(--rule-heavy) solid var(--color-ink);
		background: var(--color-paper);
	}

	.wordmark {
		display: inline-flex;
		align-items: baseline;
		gap: var(--space-2);
		font-family: var(--font-display);
		font-size: 1.15rem;
		font-weight: 800;
		letter-spacing: -0.03em;
		text-decoration: none;
	}

	.mark {
		align-self: center;
		width: 1rem;
		height: 1rem;
		background: var(--color-accent);
	}

	.version {
		color: var(--color-muted);
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		font-weight: 500;
		letter-spacing: 0;
	}

	nav {
		display: flex;
		gap: var(--space-1);
		min-width: 0;
		overflow-x: auto;
		scrollbar-width: none;
	}

	nav a {
		padding: var(--space-2) var(--space-3);
		border-bottom: 3px solid transparent;
		color: var(--color-ink-2);
		font-size: var(--text-sm);
		font-weight: 650;
		text-decoration: none;
		white-space: nowrap;
	}

	nav a:hover {
		color: var(--color-accent);
	}

	nav a[aria-current='page'] {
		border-bottom-color: var(--color-accent);
		color: var(--color-ink);
	}

	.tools {
		display: flex;
		align-items: center;
		gap: var(--space-3);
	}

	.search {
		display: inline-flex;
		align-items: center;
		gap: var(--space-3);
		min-height: 2rem;
		padding: 0.3rem 0.4rem 0.3rem 0.7rem;
		border: var(--rule-thin) solid var(--color-rule-strong);
		border-radius: var(--radius-control);
		background: var(--color-paper-2);
		color: var(--color-muted);
		font-size: var(--text-sm);
		cursor: pointer;
	}

	.search:hover {
		border-color: var(--color-accent);
		color: var(--color-ink);
	}

	kbd {
		padding: 0.05rem 0.35rem;
		border: var(--rule-thin) solid var(--color-rule);
		background: var(--color-paper);
		font-family: var(--font-mono);
		font-size: var(--text-xs);
	}

	.freshness {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		color: var(--color-ink-2);
		font-size: var(--text-xs);
		font-weight: 650;
		white-space: nowrap;
	}

	.freshness .dot {
		width: 0.55rem;
		height: 0.55rem;
		border-radius: 50%;
		background: var(--color-rule-strong);
	}

	.freshness[data-tone='ok'] .dot {
		background: var(--color-ok);
	}

	.freshness[data-tone='warn'] .dot {
		background: var(--color-warn-mark);
	}

	.freshness[data-tone='crit'] {
		color: var(--color-crit);
	}

	.freshness[data-tone='crit'] .dot {
		background: var(--color-crit);
	}

	.freshness[data-tone='info'] .dot {
		background: var(--color-accent);
	}

	.detail {
		color: var(--color-muted);
		font-weight: 500;
	}

	@media (max-width: 960px) {
		.header {
			grid-template-columns: auto auto;
		}

		nav {
			grid-column: 1 / -1;
			grid-row: 2;
		}

		.tools {
			justify-content: end;
		}

		.detail {
			display: none;
		}
	}

	@media (max-width: 560px) {
		.search span {
			display: none;
		}
	}
</style>
