<script lang="ts">
	import {
		addToast,
		isConfigModalOpen,
		isConnected,
		lastUpdated,
		refreshDashboard,
		routerStatus
	} from '../api';

	let refreshing = false;

	async function refresh(): Promise<void> {
		if (refreshing) return;
		refreshing = true;
		await refreshDashboard();
		refreshing = false;
		addToast({ type: 'info', title: 'Router data refreshed' });
	}
</script>

<header class="header">
	<div class="identity">
		<span class="period" aria-hidden="true"></span>
		<div>
			<a class="wordmark" href="#top" aria-label="IVNP router dashboard">ivnp router</a>
			<p>embedded i2p runtime</p>
		</div>
	</div>

	<div class="readout" aria-live="polite">
		<span class:online={$isConnected} class="connection-mark" aria-hidden="true"></span>
		<span>{$isConnected ? 'live' : 'disconnected'}</span>
		{#if $routerStatus}
			<span class="separator">/</span>
			<span>{$routerStatus.reachability}</span>
			<span class="separator">/</span>
			<span>net {$routerStatus.network_id}</span>
		{/if}
		{#if $lastUpdated}
			<span class="separator">/</span>
			<time datetime={$lastUpdated.toISOString()}>{$lastUpdated.toLocaleTimeString()}</time>
		{/if}
	</div>

	<div class="actions">
		<button class="button" type="button" on:click={refresh} aria-busy={refreshing} disabled={refreshing}>
			{refreshing ? 'Refreshing' : 'Refresh'}
		</button>
		<button class="button button--primary" type="button" on:click={() => isConfigModalOpen.set(true)}>
			Settings
		</button>
	</div>
</header>

<style>
	.header {
		display: grid;
		grid-template-columns: minmax(12rem, 1fr) auto auto;
		align-items: center;
		gap: var(--space-6);
		min-height: 5.25rem;
		padding: var(--space-4) clamp(var(--space-4), 3vw, var(--space-8));
		border-bottom: var(--rule-heavy) solid var(--color-ink);
		background: var(--color-paper);
	}

	.identity {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		min-width: 0;
	}

	.period {
		width: 1.25rem;
		height: 1.25rem;
		flex: 0 0 auto;
		background: var(--color-accent);
	}

	.wordmark {
		display: block;
		width: fit-content;
		font-family: var(--font-display);
		font-size: 1.18rem;
		font-weight: 800;
		letter-spacing: -0.035em;
		line-height: 1;
		text-decoration: none;
		white-space: nowrap;
	}

	.wordmark:hover {
		text-decoration: underline;
		text-decoration-color: var(--color-accent);
		text-underline-offset: 0.2em;
	}

	.identity p {
		margin: var(--space-1) 0 0;
		color: var(--color-muted);
		font-size: var(--text-xs);
		letter-spacing: 0.055em;
		text-transform: uppercase;
	}

	.readout {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		color: var(--color-ink-2);
		font-family: var(--font-label);
		font-size: var(--text-xs);
		font-weight: 600;
		letter-spacing: 0.07em;
		text-transform: uppercase;
		white-space: nowrap;
	}

	.connection-mark {
		width: 0.55rem;
		height: 0.55rem;
		border: var(--rule-thin) solid var(--color-ink);
		background: transparent;
	}

	.connection-mark.online {
		border-color: var(--color-accent);
		background: var(--color-accent);
	}

	.separator {
		color: var(--color-rule-strong);
	}

	.actions {
		display: flex;
		gap: var(--space-2);
	}

	@media (max-width: 860px) {
		.header {
			grid-template-columns: 1fr auto;
		}

		.readout {
			grid-column: 1 / -1;
			grid-row: 2;
			justify-content: flex-start;
			overflow-x: auto;
			padding-bottom: var(--space-1);
		}
	}

	@media (max-width: 520px) {
		.header {
			grid-template-columns: 1fr;
			gap: var(--space-3);
		}

		.actions {
			grid-row: 2;
		}

		.readout {
			grid-row: 3;
		}

		.actions .button {
			flex: 1;
		}
	}
</style>
