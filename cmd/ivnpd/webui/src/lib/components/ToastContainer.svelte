<script lang="ts">
	import { removeToast, toasts } from '../api';
</script>

<div class="toast-region" aria-live="polite" aria-relevant="additions removals">
	{#each $toasts as toast (toast.id)}
		<article class:error={toast.type === 'error'} class:success={toast.type === 'success'}>
			<span class="indicator" aria-hidden="true"></span>
			<div>
				<strong>{toast.title}</strong>
				{#if toast.description}<p>{toast.description}</p>{/if}
			</div>
			<button type="button" on:click={() => removeToast(toast.id)} aria-label={`Dismiss ${toast.title}`}>×</button>
		</article>
	{/each}
</div>

<style>
	.toast-region {
		position: fixed;
		right: var(--space-4);
		bottom: var(--space-4);
		z-index: 40;
		display: grid;
		gap: var(--space-2);
		width: min(26rem, calc(100vw - var(--space-8)));
		pointer-events: none;
	}

	article {
		display: grid;
		grid-template-columns: auto minmax(0, 1fr) auto;
		gap: var(--space-3);
		align-items: start;
		padding: var(--space-3);
		border: var(--rule-heavy) solid var(--color-ink);
		background: var(--color-paper);
		box-shadow: 6px 6px 0 var(--color-shadow);
		pointer-events: auto;
		animation: enter var(--dur-dialog) var(--ease-out);
	}

	.indicator {
		width: 0.65rem;
		height: 0.65rem;
		margin-top: 0.25rem;
		background: var(--color-ink);
	}

	.success .indicator {
		background: var(--color-accent);
	}

	.error .indicator {
		background: var(--color-danger);
	}

	strong {
		font-size: var(--text-sm);
	}

	p {
		margin: var(--space-1) 0 0;
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	button {
		width: 1.75rem;
		height: 1.75rem;
		border: 0;
		background: transparent;
		color: var(--color-ink);
		font-size: 1.25rem;
		line-height: 1;
		cursor: pointer;
	}

	button:hover {
		background: var(--color-accent-soft);
	}

	button:focus-visible {
		outline: 3px solid var(--color-focus);
		outline-offset: 1px;
	}

	@keyframes enter {
		from {
			opacity: 0;
			transform: translateY(8px);
		}
		to {
			opacity: 1;
			transform: none;
		}
	}

	@media (max-width: 480px) {
		.toast-region {
			right: var(--space-2);
			bottom: var(--space-2);
			width: calc(100vw - var(--space-4));
		}
	}
</style>
