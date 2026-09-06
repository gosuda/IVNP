<script lang="ts">
	import { copyText, destinationsData, formatBytes, formatRate, routerStatus } from '../api';
	import DataStatus from './DataStatus.svelte';

	$: services = $routerStatus
		? [
				{ name: 'HTTP proxy', ...$routerStatus.services.http_proxy },
				{ name: 'SOCKS5', ...$routerStatus.services.socks5 },
				{ name: 'SAM', ...$routerStatus.services.sam }
			]
		: [];
</script>

<section class="cell destination-cell" aria-labelledby="destination-title">
	<h2 class="cell-title" id="destination-title">Local services</h2>
	<DataStatus resource="status" />
	{#if $routerStatus}
		<div class="service-grid">
			{#each services as service}
				<div class="service">
					<div class="service-heading">
						<h3>{service.name}</h3>
						<span>{service.enabled ? 'Enabled in config' : 'Disabled in config'}</span>
					</div>
					<div class="address-line">
						<code>{service.address || 'No configured address'}</code>
						<button class="text-action" type="button" disabled={!service.address} aria-label={`Copy ${service.name} configured address`} on:click={() => copyText(service.address, `${service.name} address copied`)}>Copy</button>
					</div>
				</div>
			{/each}
		</div>
		<p class="note">Configuration only. Listener availability and end-to-end connectivity are not observed.</p>
		<details>
			<summary>Address book & metrics configuration</summary>
			<div class="secondary-services">
				<div class="service">
					<div class="service-heading">
						<h3>Address book</h3>
						<span>{$routerStatus.services.addressbook.enabled ? 'Enabled in config' : 'Disabled in config'}</span>
					</div>
					<p>{$routerStatus.services.addressbook.subscriptions} configured subscriptions</p>
				</div>
				<div class="service">
					<div class="service-heading">
						<h3>Metrics</h3>
						<span>{$routerStatus.services.metrics.enabled ? 'Enabled in config' : 'Disabled in config'}</span>
					</div>
					<div class="address-line">
						<code>{$routerStatus.services.metrics.address || 'No configured address'}</code>
						<button class="text-action" type="button" disabled={!$routerStatus.services.metrics.address} aria-label="Copy metrics configured address" on:click={() => copyText($routerStatus?.services.metrics.address ?? '', 'Metrics address copied')}>Copy</button>
					</div>
				</div>
			</div>
		</details>
	{/if}

	<div class="destinations">
		<DataStatus resource="destinations" />
		{#if $destinationsData}
			{#if $destinationsData.destinations.length > 0}
				<details>
					<summary>Local destinations ({$destinationsData.destinations.length})</summary>
					<div class="destination-list">
						{#each $destinationsData.destinations as destination (destination.name)}
							<article>
								<div class="destination-name">
									<h3>{destination.name}</h3>
									{#if destination.default}<span>Default</span>{/if}
								</div>
								<div class="address-line">
									<code>{destination.address || 'No address reported'}</code>
									<button class="text-action" type="button" disabled={!destination.address} aria-label={`Copy ${destination.name} destination address`} on:click={() => copyText(destination.address, `${destination.name} address copied`)}>Copy</button>
								</div>
								{#if destination.bandwidth}
									<dl class="bandwidth">
										<div><dt>Bandwidth cap</dt><dd>{formatRate(destination.bandwidth.rate_bytes_per_second)}</dd></div>
										<div><dt>Accepted</dt><dd>{formatBytes(destination.bandwidth.accepted_bytes)}</dd></div>
										<div><dt>Backpressure</dt><dd>{formatBytes(destination.bandwidth.backpressured_bytes)}</dd></div>
										<div><dt>Waiters</dt><dd>{destination.bandwidth.waiters}</dd></div>
									</dl>
								{/if}
							</article>
						{/each}
					</div>
				</details>
			{:else}
				<p class="note">No local destinations were registered in the last collection.</p>
			{/if}
		{/if}
	</div>
</section>

<style>
	.destination-cell {
		display: grid;
		align-content: start;
		gap: var(--space-3);
	}

	.service-grid, .secondary-services {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: var(--space-4);
	}

	.service {
		display: grid;
		align-content: start;
		gap: var(--space-3);
		min-width: 0;
		padding-block: var(--space-3);
		border-top: var(--rule-heavy) solid var(--color-ink);
	}

	.service-heading, .destination-name {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		justify-content: space-between;
		gap: var(--space-2);
		min-width: 0;
	}

	h3 {
		min-width: 0;
		margin: 0;
		font-size: var(--text-sm);
		overflow-wrap: anywhere;
	}

	.service-heading span, .note, dt {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	p {
		margin: 0;
		font-size: var(--text-sm);
	}

	.address-line {
		display: grid;
		grid-template-columns: minmax(0, 1fr) auto;
		align-items: center;
		gap: var(--space-2);
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

	.text-action:hover, summary:hover {
		color: var(--color-accent);
	}

	.text-action:active {
		transform: translateY(1px);
	}

	.text-action:disabled {
		color: var(--color-muted);
		cursor: not-allowed;
	}

	.text-action:focus-visible, summary:focus-visible {
		outline: 3px solid var(--color-focus);
		outline-offset: 2px;
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

	.secondary-services {
		grid-template-columns: repeat(2, minmax(0, 1fr));
	}

	.secondary-services .service {
		border-top: 0;
		padding-top: 0;
	}

	.destinations, .destination-list {
		display: grid;
		gap: var(--space-3);
		min-width: 0;
	}

	article {
		display: grid;
		gap: var(--space-3);
		min-width: 0;
		padding-bottom: var(--space-3);
		border-bottom: var(--rule-thin) solid var(--color-rule);
	}

	.destination-name {
		justify-content: start;
	}

	.destination-name span {
		color: var(--color-accent);
		font-size: var(--text-xs);
		font-weight: 600;
	}

	.bandwidth {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		gap: var(--space-3);
		margin: 0;
	}

	dd {
		margin: var(--space-1) 0 0;
		font-size: var(--text-sm);
		font-weight: 600;
		overflow-wrap: anywhere;
	}

	@media (max-width: 700px) {
		.service-grid, .secondary-services {
			grid-template-columns: minmax(0, 1fr);
		}

		.bandwidth {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
	}
</style>
