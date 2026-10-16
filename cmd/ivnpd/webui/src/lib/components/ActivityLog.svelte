<script lang="ts">
	import { onMount } from 'svelte';
	import { actionLog } from '$lib/api';
	import { formatAgo, formatTimestamp } from '$lib/format';
	import Badge from './Badge.svelte';

	let { limit = 8 }: { limit?: number } = $props();
	let now = $state(Date.now());
	onMount(() => {
		const timer = window.setInterval(() => (now = Date.now()), 15_000);
		return () => window.clearInterval(timer);
	});

	const names = { reseed: 'Reseed', probe: 'Tunnel probe', restart: 'Restart', config: 'Settings saved', rollback: 'Settings rolled back' };
</script>

{#if $actionLog.length === 0}
	<p class="empty">No operations have run since ivnpd started.</p>
{:else}
	<ol class="log">
		{#each $actionLog.slice(0, limit) as entry (`${entry.at}-${entry.action}`)}
			<li>
				<Badge tone={entry.outcome === 'ok' ? 'ok' : 'crit'}>{entry.outcome === 'ok' ? 'Done' : 'Failed'}</Badge>
				<span class="what"><strong>{names[entry.action]}</strong> <span class="muted">{entry.detail}</span></span>
				<time datetime={new Date(entry.at).toISOString()} title={formatTimestamp(entry.at)}>{formatAgo(entry.at, now)}</time>
			</li>
		{/each}
	</ol>
{/if}

<style>
	.log {
		display: grid;
		padding: 0;
		list-style: none;
	}

	li {
		display: grid;
		grid-template-columns: auto minmax(0, 1fr) auto;
		align-items: center;
		gap: var(--space-3);
		padding-block: var(--space-2);
		border-top: var(--rule-thin) solid var(--color-rule);
		font-size: var(--text-sm);
	}

	li:first-child {
		border-top: 0;
	}

	.what {
		min-width: 0;
		overflow-wrap: anywhere;
	}

	time {
		color: var(--color-muted);
		font-size: var(--text-xs);
		white-space: nowrap;
	}
</style>
