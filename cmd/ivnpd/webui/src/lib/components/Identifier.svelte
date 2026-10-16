<script lang="ts">
	import { copyText } from '$lib/api';
	import { middle } from '$lib/format';

	let {
		value,
		href,
		label = 'Identifier',
		head = 10,
		tail = 8,
		full = false,
		copy = true
	}: { value: string; href?: string; label?: string; head?: number; tail?: number; full?: boolean; copy?: boolean } = $props();

	const shown = $derived(full ? value : middle(value, head, tail));
</script>

<span class="identifier">
	{#if !value}
		<span class="muted">Not reported</span>
	{:else if href}
		<a class="mono" {href} title={value}>{shown}</a>
	{:else}
		<span class="mono" title={value}>{shown}</span>
	{/if}
	{#if copy && value}
		<button class="copy" type="button" aria-label={`Copy ${label}`} onclick={() => copyText(value, label)}>Copy</button>
	{/if}
</span>

<style>
	.identifier {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		min-width: 0;
		max-width: 100%;
	}

	.identifier > :first-child {
		min-width: 0;
		overflow-wrap: anywhere;
	}

	a {
		text-decoration-color: var(--color-rule-strong);
		text-underline-offset: 0.2em;
	}

	a:hover {
		color: var(--color-accent);
		text-decoration-color: currentColor;
	}

	.copy {
		flex: 0 0 auto;
		padding: 0.15rem 0.45rem;
		border: var(--rule-thin) solid var(--color-rule-strong);
		border-radius: var(--radius-control);
		background: transparent;
		color: var(--color-ink-2);
		font-size: var(--text-xs);
		font-weight: 600;
		cursor: pointer;
	}

	.copy:hover {
		border-color: var(--color-accent);
		color: var(--color-accent);
	}

	.copy:active {
		transform: translateY(1px);
	}
</style>
