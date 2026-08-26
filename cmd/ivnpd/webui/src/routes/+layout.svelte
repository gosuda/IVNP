<script lang="ts">
	import '@fontsource-variable/archivo';
	import '../../tokens.css';
	import ToastContainer from '$lib/components/ToastContainer.svelte';
	import ConfigEditorModal from '$lib/components/ConfigEditorModal.svelte';
	import { isConfigModalOpen } from '$lib/api';
</script>

<div class="app-shell">
	<slot />
	<ToastContainer />
	{#if $isConfigModalOpen}
		<ConfigEditorModal />
	{/if}
</div>

<style>
	:global(*) {
		box-sizing: border-box;
	}

	:global(html),
	:global(body) {
		margin: 0;
		min-width: 320px;
		min-height: 100%;
		overflow-x: clip;
		background: var(--color-paper);
		color: var(--color-ink);
		font-family: var(--font-body);
		font-size: 16px;
		font-variant-numeric: tabular-nums;
		line-height: 1.45;
		-webkit-font-smoothing: antialiased;
	}

	:global(body) {
		min-height: 100vh;
	}

	:global(button),
	:global(input),
	:global(select),
	:global(textarea) {
		font: inherit;
	}

	:global(button),
	:global(a),
	:global(select),
	:global(input[type='checkbox']) {
		touch-action: manipulation;
	}

	:global(a) {
		color: inherit;
	}

	:global(::selection) {
		background: var(--color-accent);
		color: var(--color-accent-ink);
	}

	:global(.cell) {
		min-width: 0;
		background: color-mix(in oklab, var(--color-paper) 94%, transparent);
		border: var(--rule-thin) solid var(--color-rule);
		padding: var(--space-5);
	}

	:global(.cell-head) {
		display: flex;
		align-items: start;
		justify-content: space-between;
		gap: var(--space-4);
		margin-bottom: var(--space-5);
	}

	:global(.cell-title) {
		margin: 0;
		font-family: var(--font-display);
		font-size: var(--text-lg);
		font-weight: 700;
		letter-spacing: -0.02em;
		line-height: 1.1;
	}

	:global(.cell-note),
	:global(.label) {
		font-family: var(--font-label);
		font-size: var(--text-xs);
		font-weight: 600;
		letter-spacing: 0.085em;
		line-height: 1.25;
		text-transform: uppercase;
	}

	:global(.cell-note) {
		color: var(--color-muted);
	}

	:global(.button) {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-2);
		min-height: 2.5rem;
		padding: 0.62rem 0.9rem;
		border: var(--rule-thin) solid var(--color-ink);
		border-radius: var(--radius-control);
		background: var(--color-paper);
		color: var(--color-ink);
		font-weight: 650;
		line-height: 1;
		white-space: nowrap;
		cursor: pointer;
		transition:
			background-color var(--dur-base) var(--ease-out),
			border-color var(--dur-base) var(--ease-out),
			color var(--dur-base) var(--ease-out),
			transform var(--dur-fast) var(--ease-out);
	}

	:global(.button:hover),
	:global(.button.is-hover) {
		border-color: var(--color-accent);
		background: var(--color-accent-soft);
	}

	:global(.button:focus-visible),
	:global(.button.is-focus) {
		outline: 3px solid var(--color-focus);
		outline-offset: 2px;
	}

	:global(.button:active),
	:global(.button.is-active) {
		transform: translateY(1px);
	}

	:global(.button:disabled),
	:global(.button[aria-busy='true']) {
		cursor: not-allowed;
		opacity: 0.48;
		transform: none;
	}

	:global(.button[data-state='error']) {
		border-style: double;
	}

	:global(.button[data-state='success']) {
		background: var(--color-accent);
		color: var(--color-accent-ink);
	}

	:global(.button--primary) {
		border-color: var(--color-accent);
		background: var(--color-accent);
		color: var(--color-accent-ink);
	}

	:global(.button--primary:hover) {
		border-color: var(--color-ink);
		background: var(--color-ink);
	}

	:global(.field) {
		display: grid;
		gap: var(--space-2);
		min-width: 0;
	}

	:global(.field label) {
		font-size: var(--text-sm);
		font-weight: 650;
	}

	:global(.input),
	:global(.select),
	:global(.textarea) {
		width: 100%;
		min-height: 2.65rem;
		border: var(--rule-thin) solid var(--color-rule-strong);
		border-radius: var(--radius-control);
		background: var(--color-paper);
		color: var(--color-ink);
		padding: 0.62rem 0.72rem;
		transition:
			border-color var(--dur-base) var(--ease-out),
			background-color var(--dur-base) var(--ease-out);
	}

	:global(.textarea) {
		min-height: 6.5rem;
		resize: vertical;
	}

	:global(.input:hover),
	:global(.select:hover),
	:global(.textarea:hover) {
		border-color: var(--color-ink);
	}

	:global(.input:focus-visible),
	:global(.select:focus-visible),
	:global(.textarea:focus-visible) {
		border-color: var(--color-accent);
		outline: 3px solid var(--color-focus);
		outline-offset: 1px;
	}

	:global(.input:disabled),
	:global(.select:disabled),
	:global(.textarea:disabled) {
		background: var(--color-paper-2);
		color: var(--color-muted);
		cursor: not-allowed;
	}

	:global(.empty) {
		display: grid;
		place-items: center;
		min-height: 8rem;
		border: var(--rule-thin) dashed var(--color-rule-strong);
		color: var(--color-muted);
		font-size: var(--text-sm);
		text-align: center;
	}

	.app-shell {
		min-height: 100vh;
	}

	@media (prefers-reduced-motion: reduce) {
		:global(*) {
			scroll-behavior: auto !important;
			animation: none !important;
			transition-duration: 0.01ms !important;
		}
	}
</style>
