<script lang="ts">
	let {
		title,
		body,
		confirmLabel,
		danger = false
	}: { title: string; body: string; confirmLabel: string; danger?: boolean } = $props();

	let dialog = $state<HTMLDialogElement | null>(null);
	let resolver: ((confirmed: boolean) => void) | null = null;

	/** Opens the dialog and resolves with the operator's decision. */
	export function ask(): Promise<boolean> {
		dialog?.showModal();
		return new Promise((resolve) => (resolver = resolve));
	}

	function settle(confirmed: boolean): void {
		resolver?.(confirmed);
		resolver = null;
		if (dialog?.open) dialog.close();
	}
</script>

<dialog class="modal" bind:this={dialog} aria-labelledby="confirm-title" onclose={() => settle(false)}>
	<form method="dialog" class="confirm" onsubmit={(event) => { event.preventDefault(); settle(true); }}>
		<h2 id="confirm-title">{title}</h2>
		<p>{body}</p>
		<div class="actions">
			<button class="button" type="button" onclick={() => settle(false)}>Cancel</button>
			<button class={danger ? 'button button--danger' : 'button button--primary'} type="submit">{confirmLabel}</button>
		</div>
	</form>
</dialog>

<style>
	.confirm {
		display: grid;
		gap: var(--space-4);
		padding: var(--space-5);
	}

	h2 {
		font-size: var(--text-lg);
	}

	p {
		color: var(--color-ink-2);
		font-size: var(--text-sm);
	}

	.actions {
		display: flex;
		justify-content: end;
		gap: var(--space-2);
	}
</style>
