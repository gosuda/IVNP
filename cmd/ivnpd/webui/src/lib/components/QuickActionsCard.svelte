<script lang="ts">
	import DataStatus from './DataStatus.svelte';
	import { routerStatus, triggerReseed, triggerTunnelProbe } from '../api';

	export let action: 'reseed' | 'probe';

	let actionState: 'idle' | 'running' | 'success' | 'error' = 'idle';
	let result = '';
	$: busy = actionState === 'running';
	$: available = $routerStatus !== null && (action === 'reseed'
		? $routerStatus.reseed.enabled
		: $routerStatus.readiness.exploratory_inbound_tunnels > 0 && $routerStatus.readiness.exploratory_outbound_tunnels > 0);
	$: unavailableReason = !$routerStatus
		? 'Waiting for router status before this operation is available.'
		: action === 'reseed' ? 'Reseeding is disabled in configuration.' : 'An exploratory inbound and outbound tunnel are needed to send a probe.';

	async function runAction(): Promise<void> {
		if (actionState === 'running' || !available) return;
		actionState = 'running';
		result = '';
		try {
			result = action === 'reseed' ? await triggerReseed() : await triggerTunnelProbe();
			actionState = 'success';
		} catch (error) {
			actionState = 'error';
			result = error instanceof Error ? error.message : 'Request failed';
		}
	}
</script>

<div class="operation">
	<div class="operation-control">
		<div>
			<h3>{action === 'reseed' ? 'Reseed network database' : 'Probe exploratory pair'}</h3>
			<p>{action === 'reseed' ? 'Start one configured HTTPS reseed attempt.' : 'Send a DeliveryStatus round trip through the active pair.'}</p>
		</div>
		<button class="button" type="button" on:click={runAction} disabled={busy || !available} aria-busy={busy} data-state={actionState}>
			{action === 'reseed' ? (busy ? 'Starting' : 'Start reseed') : (busy ? 'Sending' : 'Send probe')}
		</button>
	</div>
	{#if !available}<p class="availability">{unavailableReason}</p>{/if}
	{#if result}
		<p class="result" class:error={actionState === 'error'} role={actionState === 'error' ? 'alert' : 'status'}>{result}</p>
	{/if}
	{#if action === 'reseed'}
		<details><summary>Reseed counters & sources</summary>
		<div class="reseed-readout">
			<div><span>Attempts</span><strong>{$routerStatus?.reseed.attempts ?? '—'}</strong></div>
			<div><span>Successes</span><strong>{$routerStatus?.reseed.successes ?? '—'}</strong></div>
			<div><span>Failures</span><strong>{$routerStatus?.reseed.failures ?? '—'}</strong></div>
			<div><span>Sources</span><strong>{$routerStatus?.reseed.endpoints ?? '—'}</strong></div>
		</div>
		</details>
	{/if}
	<DataStatus resource="status" />
</div>

<style>
	.operation {
		display: grid;
		gap: var(--space-3);
		padding-top: var(--space-4);
		border-top: var(--rule-thin) solid var(--color-rule);
	}

	.operation-control {
		display: grid;
		grid-template-columns: minmax(0, 1fr) auto;
		align-items: center;
		gap: var(--space-4);
	}

	h3 {
		margin: 0;
		font-size: var(--text-sm);
	}

	p {
		margin: var(--space-1) 0 0;
		color: var(--color-muted);
		font-size: var(--text-xs);
		overflow-wrap: anywhere;
	}

	.result {
		padding: var(--space-3);
		border-left: var(--rule-heavy) solid var(--color-accent);
		background: var(--color-accent-soft);
		color: var(--color-ink);
	}

	.result.error {
		border-color: var(--color-ink);
		background: var(--color-paper-2);
		color: var(--color-ink);
	}

	.reseed-readout {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
	}

	.reseed-readout > div {
		display: grid;
		gap: var(--space-1);
		padding: var(--space-2);
		border-left: var(--rule-thin) solid var(--color-rule);
	}

	.reseed-readout > div:first-child { border-left: 0; }
	.reseed-readout span { color: var(--color-muted); font-size: var(--text-xs); }
	.reseed-readout strong { font-size: var(--text-lg); line-height: 1; }

	@media (max-width: 560px) {
		.operation-control { grid-template-columns: minmax(0, 1fr); }
		.button { width: 100%; }
		.reseed-readout { grid-template-columns: repeat(2, minmax(0, 1fr)); }
		.reseed-readout > div:nth-child(3) { border-left: 0; }
	}
</style>
