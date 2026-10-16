<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { Tone } from '$lib/types';

	let { tone = 'neutral', title, children }: { tone?: Tone; title?: string; children: Snippet } = $props();
</script>

<span class="badge" data-tone={tone} {title}><span class="dot" aria-hidden="true"></span>{@render children()}</span>

<style>
	.badge {
		display: inline-flex;
		align-items: center;
		gap: 0.4em;
		min-height: 1.6rem;
		padding: 0.15rem 0.55rem;
		border: var(--rule-thin) solid var(--color-rule-strong);
		background: var(--color-paper);
		color: var(--color-ink-2);
		font-size: var(--text-xs);
		font-weight: 650;
		line-height: 1.2;
		white-space: nowrap;
	}

	.dot {
		width: 0.5rem;
		height: 0.5rem;
		flex: 0 0 auto;
		border-radius: 50%;
		background: var(--color-rule-strong);
	}

	.badge[data-tone='ok'] {
		border-color: var(--color-ok);
		background: var(--color-ok-soft);
		color: var(--color-ok);
	}

	.badge[data-tone='ok'] .dot {
		background: var(--color-ok);
	}

	.badge[data-tone='warn'] {
		border-color: var(--color-warn-mark);
		background: var(--color-warn-soft);
		color: var(--color-warn);
	}

	.badge[data-tone='warn'] .dot {
		background: var(--color-warn-mark);
	}

	.badge[data-tone='crit'] {
		border-color: var(--color-crit);
		background: var(--color-crit-soft);
		color: var(--color-crit);
	}

	.badge[data-tone='crit'] .dot {
		background: var(--color-crit);
	}

	.badge[data-tone='info'] {
		border-color: var(--color-accent);
		background: var(--color-accent-soft);
		color: var(--color-accent);
	}

	.badge[data-tone='info'] .dot {
		background: var(--color-accent);
	}
</style>
