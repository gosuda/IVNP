<script lang="ts">
	import { addToast, errorMessage, restarting, routerStatus, triggerReseed, triggerRestart, triggerTunnelProbe } from '$lib/api';
	import ConfirmDialog from './ConfirmDialog.svelte';

	type Operation = 'reseed' | 'probe' | 'restart';
	let { operations }: { operations: Operation[] } = $props();

	let running = $state<Operation | null>(null);
	let results = $state<Partial<Record<Operation, { ok: boolean; text: string }>>>({});
	let confirmRestart = $state<ConfirmDialog | null>(null);

	const spec = {
		reseed: { title: 'Reseed network database', detail: 'Fetch RouterInfos from one configured HTTPS reseed source.', verb: 'Start reseed', busy: 'Starting' },
		probe: { title: 'Probe exploratory tunnels', detail: 'Send a DeliveryStatus round trip through the active exploratory pair.', verb: 'Send probe', busy: 'Sending' },
		restart: { title: 'Restart router', detail: 'Stop the router and start it again from the saved configuration file.', verb: 'Restart', busy: 'Restarting' }
	} satisfies Record<Operation, { title: string; detail: string; verb: string; busy: string }>;

	function blocked(operation: Operation): string {
		const status = $routerStatus;
		if ($restarting) return 'Unavailable while the router restarts.';
		if (!status) return 'Waiting for router status.';
		if (operation === 'reseed' && !status.reseed.enabled) return 'Reseeding is turned off in Settings.';
		if (operation === 'probe' && (status.readiness.exploratory_inbound_tunnels === 0 || status.readiness.exploratory_outbound_tunnels === 0)) {
			return 'Needs one exploratory inbound and one outbound tunnel.';
		}
		if (operation === 'restart' && !status.capabilities.restart) return 'Restart is unavailable in memory mode.';
		if (operation === 'restart' && !status.capabilities.config_writable) return status.capabilities.config_write_reason;
		return '';
	}

	async function run(operation: Operation): Promise<void> {
		if (running || blocked(operation)) return;
		if (operation === 'restart' && !(await confirmRestart?.ask())) return;
		running = operation;
		try {
			const call = { reseed: triggerReseed, probe: triggerTunnelProbe, restart: triggerRestart }[operation];
			results[operation] = { ok: true, text: await call() };
		} catch (error) {
			results[operation] = { ok: false, text: errorMessage(error) };
			addToast({ type: 'error', title: `${spec[operation].title} failed`, description: errorMessage(error) });
		} finally {
			running = null;
		}
	}
</script>

<ul class="operations">
	{#each operations as operation (operation)}
		{@const reason = blocked(operation)}
		{@const result = results[operation]}
		<li>
			<div>
				<h3>{spec[operation].title}</h3>
				<p>{reason || spec[operation].detail}</p>
				{#if result}
					<p class="result" data-ok={result.ok} role={result.ok ? 'status' : 'alert'}>{result.text}</p>
				{/if}
			</div>
			<button
				class={operation === 'restart' ? 'button button--danger' : 'button'}
				type="button"
				disabled={Boolean(reason) || running !== null}
				aria-busy={running === operation}
				onclick={() => run(operation)}
			>
				{running === operation ? spec[operation].busy : spec[operation].verb}
			</button>
		</li>
	{/each}
</ul>

{#if operations.includes('restart')}
	<ConfirmDialog
		bind:this={confirmRestart}
		title="Restart the router now?"
		body="Tunnels, transport sessions, and proxy connections drop and rebuild. The console stays available and reconnects when the new router starts."
		confirmLabel="Restart router"
		danger
	/>
{/if}

<style>
	.operations {
		display: grid;
		gap: 0;
		padding: 0;
		list-style: none;
	}

	li {
		display: grid;
		grid-template-columns: minmax(0, 1fr) auto;
		align-items: center;
		gap: var(--space-4);
		padding-block: var(--space-3);
		border-top: var(--rule-thin) solid var(--color-rule);
	}

	li:first-child {
		border-top: 0;
		padding-top: 0;
	}

	h3 {
		font-size: var(--text-sm);
		font-weight: 700;
	}

	p {
		margin-top: var(--space-1);
		color: var(--color-muted);
		font-size: var(--text-xs);
		overflow-wrap: anywhere;
	}

	.result {
		color: var(--color-ok);
		font-weight: 600;
	}

	.result[data-ok='false'] {
		color: var(--color-crit);
	}

	@media (max-width: 520px) {
		li {
			grid-template-columns: minmax(0, 1fr);
		}
	}
</style>
