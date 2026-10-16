<script lang="ts">
	import { removeToast, toasts } from '$lib/api';

	const errors = $derived($toasts.filter((toast) => toast.type === 'error'));
	const notes = $derived($toasts.filter((toast) => toast.type !== 'error'));
</script>

<div class="toast-stack">
	<div role="alert" aria-live="assertive">
		{#each errors as toast (toast.id)}
			<article data-type="error">
				<span class="mark" aria-hidden="true"></span>
				<div>
					<strong>{toast.title}</strong>
					{#if toast.description}<p>{toast.description}</p>{/if}
				</div>
				<button type="button" onclick={() => removeToast(toast.id)} aria-label={`Dismiss ${toast.title}`}>×</button>
			</article>
		{/each}
	</div>
	<div aria-live="polite">
		{#each notes as toast (toast.id)}
			<article data-type={toast.type}>
				<span class="mark" aria-hidden="true"></span>
				<div>
					<strong>{toast.title}</strong>
					{#if toast.description}<p>{toast.description}</p>{/if}
				</div>
				<button type="button" onclick={() => removeToast(toast.id)} aria-label={`Dismiss ${toast.title}`}>×</button>
			</article>
		{/each}
	</div>
</div>

<style>
	.toast-stack {
		position: fixed;
		right: var(--space-4);
		bottom: var(--space-4);
		z-index: 40;
		display: grid;
		gap: var(--space-2);
		width: min(26rem, calc(100vw - var(--space-8)));
		pointer-events: none;
	}

	.toast-stack > div {
		display: grid;
		gap: var(--space-2);
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

	article[data-type='error'] {
		border-color: var(--color-crit);
	}

	.mark {
		width: 0.65rem;
		height: 0.65rem;
		margin-top: 0.3rem;
		background: var(--color-ok);
	}

	article[data-type='info'] .mark {
		background: var(--color-accent);
	}

	article[data-type='error'] .mark {
		background: var(--color-crit);
	}

	strong {
		font-size: var(--text-sm);
	}

	p {
		margin-top: var(--space-1);
		color: var(--color-ink-2);
		font-size: var(--text-xs);
		overflow-wrap: anywhere;
	}

	button {
		width: 1.75rem;
		height: 1.75rem;
		border: 0;
		background: transparent;
		font-size: 1.25rem;
		line-height: 1;
		cursor: pointer;
	}

	button:hover {
		background: var(--color-accent-soft);
	}

	@keyframes enter {
		from {
			opacity: 0;
			transform: translateY(8px);
		}
	}

	@media (max-width: 480px) {
		.toast-stack {
			right: var(--space-2);
			bottom: var(--space-2);
			width: calc(100vw - var(--space-4));
		}
	}
</style>
