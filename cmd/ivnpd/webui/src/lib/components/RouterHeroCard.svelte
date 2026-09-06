<script lang="ts">
	import { copyText, formatDuration, routerStatus } from '../api';
	import DataStatus from './DataStatus.svelte';

	$: readiness = $routerStatus?.readiness;
	// Mirrors dataPlaneReady in controlplane/internal/runtime/controller.go; lifecycle remains authoritative in ready.
	$: unmetConditions = readiness
		? [
				readiness.netdb_routers < 50 ? 'NetDB ≥ 50 routers' : null,
				readiness.router_info_publications === 0 ? 'RouterInfo publication' : null,
				readiness.lease_set2_publications === 0 ? 'LeaseSet2 publication' : null,
				readiness.exploratory_inbound_tunnels === 0 ? 'exploratory inbound' : null,
				readiness.exploratory_outbound_tunnels === 0 ? 'exploratory outbound' : null,
				readiness.client_inbound_tunnels === 0 ? 'client inbound' : null,
				readiness.client_outbound_tunnels === 0 ? 'client outbound' : null,
				readiness.floodfill_configured && !readiness.floodfill_advertised ? 'floodfill advertisement' : null
			].filter(Boolean)
		: [];
</script>

<section class="cell router-cell" aria-labelledby="router-title">
	<div class="cell-head">
		<h1 class="cell-title" id="router-title">Router readiness</h1>
		{#if $routerStatus}
			<strong class="readiness-state" class:ready={$routerStatus.ready}>{$routerStatus.ready ? 'Ready' : 'Not ready'}</strong>
		{/if}
	</div>
	<DataStatus resource="status" />

	{#if $routerStatus && readiness}
		<dl class="facts">
			<div><dt>Reachability</dt><dd>{$routerStatus.reachability}</dd></div>
			<div><dt>Bootstrap stage</dt><dd>{readiness.bootstrap_stage}</dd></div>
			<div><dt>Exploratory tunnels</dt><dd>{readiness.exploratory_inbound_tunnels} in / {readiness.exploratory_outbound_tunnels} out</dd></div>
			<div><dt>Successful publications</dt><dd>{readiness.router_info_publications} <small>RouterInfo</small> / {readiness.lease_set2_publications} <small>LeaseSet2</small></dd></div>
		</dl>
		<p class="floodfill">Floodfill: <strong>{$routerStatus.floodfill_configured ? 'configured' : 'not configured'}</strong> · <strong>{$routerStatus.floodfill_advertised ? 'advertised' : 'not advertised'}</strong></p>
		{#if !$routerStatus.ready}
			<p class="readiness-note">
				{#if unmetConditions.length > 0}
				Waiting for: {unmetConditions.join('; ')}.
				{:else}
					Data-plane conditions are met; the runtime has not reported ready.
				{/if}
			</p>
		{/if}

		<details>
			<summary>Router identification & transport details</summary>
		<p class="note">Readiness does not require public reachability. Bootstrap stage records progress, not current readiness.</p>
			<div class="identity-lines">
				<div>
					<span>B32</span>
					<code>{$routerStatus.router_b32 || 'Not reported'}</code>
					<button class="text-action" type="button" disabled={!$routerStatus.router_b32} aria-label="Copy router B32 address" on:click={() => copyText($routerStatus?.router_b32 ?? '', 'B32 address copied')}>Copy</button>
				</div>
				<div>
					<span>Router hash</span>
					<code>{$routerStatus.router_hash || 'Not reported'}</code>
					<button class="text-action" type="button" disabled={!$routerStatus.router_hash} aria-label="Copy router hash" on:click={() => copyText($routerStatus?.router_hash ?? '', 'Router hash copied')}>Copy</button>
				</div>
			</div>
			<dl class="identity-facts">
				<div><dt>Version</dt><dd>{$routerStatus.version || 'Not configured'}</dd></div>
				<div><dt>Family</dt><dd>{$routerStatus.family || 'Not configured'}</dd></div>
				<div><dt>Network ID</dt><dd>{$routerStatus.network_id}</dd></div>
			<div><dt>Lifecycle</dt><dd>{$routerStatus.state}</dd></div>
			<div><dt>Uptime</dt><dd>{formatDuration($routerStatus.uptime_seconds)}</dd></div>
			<div><dt>NetDB routers</dt><dd>{readiness.netdb_routers} <small>/ 50 required</small></dd></div>
			<div><dt>Client tunnels</dt><dd>{readiness.client_inbound_tunnels} in / {readiness.client_outbound_tunnels} out</dd></div>
			</dl>
			<div class="transports">
				{#each Object.entries($routerStatus.transports) as [name, transport]}
					<div class="transport">
						<h2>{name.toUpperCase()} <span>{transport.enabled ? 'Enabled in config' : 'Disabled in config'}</span></h2>
						<dl>
							<div><dt>Sessions / limit</dt><dd>{transport.active_sessions} / {transport.max_sessions}</dd></div>
							<div><dt>Configured bind</dt><dd><code>{transport.bind_address || 'Not configured'}</code></dd></div>
							<div><dt>Configured advertisement</dt><dd><code>{transport.advertised_address || 'Not configured'}</code></dd></div>
						</dl>
					</div>
				{/each}
			</div>
		</details>
	{/if}
</section>

<style>
	.router-cell {
		display: grid;
		align-content: start;
		gap: var(--space-3);
	}

	.cell-head {
		align-items: center;
		flex-wrap: wrap;
		margin-bottom: 0;
		flex-direction: row;
	}

	.readiness-state {
		padding: var(--space-2) var(--space-3);
		border: var(--rule-thin) solid var(--color-rule-strong);
		font-size: var(--text-sm);
		white-space: nowrap;
	}

	.readiness-state.ready {
		border-color: var(--color-accent);
		color: var(--color-accent);
	}

	dl, p {
		margin: 0;
	}

	.facts, .identity-facts {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		gap: var(--space-4);
	}

	dt, .note, small {
		color: var(--color-muted);
		font-size: var(--text-xs);
		font-weight: 400;
	}

	dd {
		margin: var(--space-1) 0 0;
		font-size: var(--text-sm);
		font-weight: 600;
		overflow-wrap: anywhere;
	}

	.floodfill, .readiness-note {
		font-size: var(--text-sm);
		overflow-wrap: anywhere;
	}

	.readiness-note {
		border-left: var(--rule-heavy) solid var(--color-accent);
		padding-left: var(--space-3);
	}

	details {
		min-width: 0;
		border-top: var(--rule-thin) solid var(--color-rule);
	}

	summary {
		padding-block: var(--space-3);
		font-size: var(--text-sm);
		font-weight: 600;
		cursor: pointer;
		overflow-wrap: anywhere;
	}

	summary:hover, .text-action:hover {
		color: var(--color-accent);
	}

	summary:focus-visible, .text-action:focus-visible {
		outline: 3px solid var(--color-focus);
		outline-offset: 2px;
	}

	.identity-lines {
		display: grid;
		gap: var(--space-3);
	}

	.identity-lines > div {
		display: grid;
		grid-template-columns: 6rem minmax(0, 1fr) auto;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
	}

	code {
		min-width: 0;
		color: var(--color-ink-2);
		font-family: var(--font-body);
		font-size: var(--text-sm);
		overflow-wrap: anywhere;
	}

	.text-action {
		padding: var(--space-2);
		border: var(--rule-thin) solid var(--color-rule-strong);
		background: transparent;
		color: var(--color-ink);
		font-size: var(--text-xs);
		font-weight: 650;
		cursor: pointer;
		white-space: nowrap;
	}

	.text-action:active {
		transform: translateY(1px);
	}

	.text-action:disabled {
		color: var(--color-muted);
		cursor: not-allowed;
	}

	.identity-facts {
		grid-template-columns: repeat(3, minmax(0, 1fr));
		margin-top: var(--space-4);
	}

	.transports {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: var(--space-4);
		margin-top: var(--space-4);
	}

	.transport {
		min-width: 0;
		padding-top: var(--space-3);
		border-top: var(--rule-thin) solid var(--color-rule);
	}

	.transport h2 {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin: 0 0 var(--space-3);
		font-size: var(--text-sm);
	}

	.transport h2 span {
		color: var(--color-muted);
		font-size: var(--text-xs);
		font-weight: 400;
	}

	.transport dl {
		display: grid;
		gap: var(--space-2);
	}

	@media (max-width: 700px) {
		.facts {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
	}

	@media (max-width: 480px) {
		.transports, .identity-facts {
			grid-template-columns: minmax(0, 1fr);
		}

		.identity-lines > div {
			grid-template-columns: minmax(0, 1fr) auto;
		}

		.identity-lines > div > span {
			grid-column: 1 / -1;
		}
	}
</style>
