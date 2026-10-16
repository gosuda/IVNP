<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { Tone } from '$lib/types';

	let {
		label,
		value,
		sub,
		tone = 'neutral',
		href,
		children
	}: { label: string; value: string; sub?: string; tone?: Tone; href?: string; children?: Snippet } = $props();
</script>

<div class="metric" data-tone={tone}>
	<span class="label">{label}</span>
	{#if href}
		<a class="value" {href}>{value}</a>
	{:else}
		<strong class="value">{value}</strong>
	{/if}
	{#if sub}<span class="sub">{sub}</span>{/if}
	{@render children?.()}
</div>

<style>
	.metric {
		display: grid;
		align-content: start;
		gap: var(--space-1);
		min-width: 0;
		padding: var(--space-4);
		border-left: 3px solid var(--color-rule);
		background: var(--color-paper);
	}

	.metric[data-tone='ok'] {
		border-left-color: var(--color-ok);
	}

	.metric[data-tone='warn'] {
		border-left-color: var(--color-warn-mark);
	}

	.metric[data-tone='crit'] {
		border-left-color: var(--color-crit);
	}

	.value {
		font-family: var(--font-display);
		font-size: var(--text-metric);
		font-weight: 700;
		letter-spacing: -0.03em;
		line-height: 1.05;
		text-decoration: none;
		overflow-wrap: anywhere;
	}

	a.value:hover {
		color: var(--color-accent);
	}

	.sub {
		color: var(--color-muted);
		font-size: var(--text-xs);
		overflow-wrap: anywhere;
	}
</style>
