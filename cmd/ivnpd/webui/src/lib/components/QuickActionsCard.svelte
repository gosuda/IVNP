<script lang="ts">
	import {
		addToast,
		isConfigModalOpen,
		routerStatus,
		triggerReseed,
		triggerTunnelProbe
	} from '../api';

	type ActionName = 'reseed' | 'probe';
	let activeAction: ActionName | null = null;
	let actionState: 'idle' | 'success' | 'error' = 'idle';

	async function runAction(name: ActionName): Promise<void> {
		if (activeAction) return;
		activeAction = name;
		actionState = 'idle';
		try {
			const result = name === 'reseed' ? await triggerReseed() : await triggerTunnelProbe();
			actionState = 'success';
			addToast({ type: 'success', title: result });
		} catch (error) {
			actionState = 'error';
			addToast({ type: 'error', title: name === 'reseed' ? 'Reseed not started' : 'Probe not sent', description: error instanceof Error ? error.message : 'Request failed' });
		} finally {
			activeAction = null;
		}
	}
</script>

<section class="cell operations-cell" aria-labelledby="operations-title">
	<div class="cell-head">
		<div>
			<p class="cell-note">Bounded commands</p>
			<h2 class="cell-title" id="operations-title">Operations</h2>
		</div>
		<span class="label">No destructive actions</span>
	</div>

	<div class="operation-list">
		<article>
			<div>
				<strong>Reseed network database</strong>
				<p>Start one configured HTTPS reseed attempt.</p>
			</div>
			<button
				class="button"
				type="button"
				on:click={() => runAction('reseed')}
				disabled={activeAction !== null || !$routerStatus?.reseed.enabled}
				aria-busy={activeAction === 'reseed'}
				data-state={activeAction === null ? actionState : undefined}
			>
				{activeAction === 'reseed' ? 'Starting' : 'Start reseed'}
			</button>
		</article>
		<article>
			<div>
				<strong>Probe exploratory pair</strong>
				<p>Send a DeliveryStatus round trip through the active pair.</p>
			</div>
			<button
				class="button"
				type="button"
				on:click={() => runAction('probe')}
				disabled={activeAction !== null || !$routerStatus?.ready}
				aria-busy={activeAction === 'probe'}
				data-state={activeAction === null ? actionState : undefined}
			>
				{activeAction === 'probe' ? 'Sending' : 'Send probe'}
			</button>
		</article>
		<article>
			<div>
				<strong>Update operating configuration</strong>
				<p>Log level applies immediately. Runtime topology changes are saved for restart.</p>
			</div>
			<button class="button button--primary" type="button" on:click={() => isConfigModalOpen.set(true)}>Open settings</button>
		</article>
	</div>

	<div class="reseed-readout">
		<div><span>Attempts</span><strong>{$routerStatus?.reseed.attempts ?? 0}</strong></div>
		<div><span>Successes</span><strong>{$routerStatus?.reseed.successes ?? 0}</strong></div>
		<div><span>Failures</span><strong>{$routerStatus?.reseed.failures ?? 0}</strong></div>
		<div><span>Sources</span><strong>{$routerStatus?.reseed.endpoints ?? 0}</strong></div>
	</div>
</section>

<style>
	.operations-cell {
		display: grid;
		align-content: start;
		gap: var(--space-4);
	}

	.operation-list {
		display: grid;
	}

	article {
		display: grid;
		grid-template-columns: minmax(0, 1fr) auto;
		align-items: center;
		gap: var(--space-4);
		padding: var(--space-4) 0;
		border-top: var(--rule-thin) solid var(--color-rule);
	}

	article:first-child {
		border-top: var(--rule-heavy) solid var(--color-ink);
	}

	article strong {
		font-size: var(--text-sm);
	}

	article p {
		margin: var(--space-1) 0 0;
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.reseed-readout {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		border-block: var(--rule-heavy) solid var(--color-ink);
	}

	.reseed-readout > div {
		display: grid;
		gap: var(--space-1);
		padding: var(--space-3);
		border-left: var(--rule-thin) solid var(--color-rule);
	}

	.reseed-readout > div:first-child {
		border-left: 0;
	}

	.reseed-readout span {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.reseed-readout strong {
		font-size: var(--text-xl);
		line-height: 1;
	}

	@media (max-width: 560px) {
		.cell-head {
			display: grid;
		}

		article {
			grid-template-columns: 1fr;
		}

		article .button {
			width: 100%;
		}

		.reseed-readout {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.reseed-readout > div:nth-child(3) {
			border-left: 0;
		}
	}
</style>
