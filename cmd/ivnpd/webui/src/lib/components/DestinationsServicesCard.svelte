<script lang="ts">
	import { copyText, destinationsData, formatBytes, formatRate, routerStatus, shortHash } from '../api';

	$: services = $routerStatus
		? [
				{ name: 'HTTP proxy', ...$routerStatus.services.http_proxy },
				{ name: 'SOCKS5', ...$routerStatus.services.socks5 },
				{ name: 'SAM', ...$routerStatus.services.sam },
				{ name: 'Metrics', ...$routerStatus.services.metrics }
			]
		: [];
</script>

<section class="cell destination-cell" aria-labelledby="destination-title">
	<div class="cell-head">
		<div>
			<p class="cell-note">Local edges</p>
			<h2 class="cell-title" id="destination-title">Destinations & services</h2>
		</div>
		<strong>{$destinationsData?.destinations.length ?? 0} identities</strong>
	</div>

	<div class="service-grid">
		{#each services as service}
			<div class:enabled={service.enabled}>
				<span class="service-mark" aria-hidden="true"></span>
				<strong>{service.name}</strong>
				<span>{service.enabled ? service.address : 'disabled'}</span>
			</div>
		{/each}
		<div class:enabled={$routerStatus?.services.addressbook.enabled}>
			<span class="service-mark" aria-hidden="true"></span>
			<strong>Address book</strong>
			<span>{$routerStatus?.services.addressbook.enabled ? `${$routerStatus.services.addressbook.subscriptions} subscriptions` : 'disabled'}</span>
		</div>
	</div>

	<div class="destination-list">
		{#if ($destinationsData?.destinations.length ?? 0) > 0}
			{#each $destinationsData?.destinations ?? [] as destination (destination.name)}
				<article>
					<div class="destination-name">
						<strong>{destination.name}</strong>
						{#if destination.default}<span>default</span>{/if}
					</div>
					<button class="address" type="button" title={destination.address} on:click={() => copyText(destination.address, `${destination.name} address copied`)}>
						{shortHash(destination.address, 20, 9)}
					</button>
					{#if destination.bandwidth}
						<div class="bandwidth">
							<span>Cap <strong>{formatRate(destination.bandwidth.rate_bytes_per_second)}</strong></span>
							<span>Accepted <strong>{formatBytes(destination.bandwidth.accepted_bytes)}</strong></span>
							<span>Backpressure <strong>{formatBytes(destination.bandwidth.backpressured_bytes)}</strong></span>
							<span>Waiters <strong>{destination.bandwidth.waiters}</strong></span>
						</div>
					{/if}
				</article>
			{/each}
		{:else}
			<div class="empty">No local destinations are registered</div>
		{/if}
	</div>
</section>

<style>
	.destination-cell {
		display: grid;
		align-content: start;
		gap: var(--space-5);
	}

	.cell-head > strong {
		font-size: var(--text-sm);
		white-space: nowrap;
	}

	.service-grid {
		display: grid;
		grid-template-columns: repeat(5, minmax(0, 1fr));
		border-block: var(--rule-heavy) solid var(--color-ink);
	}

	.service-grid > div {
		display: grid;
		grid-template-columns: auto minmax(0, 1fr);
		gap: var(--space-1) var(--space-2);
		min-width: 0;
		padding: var(--space-3);
		border-left: var(--rule-thin) solid var(--color-rule);
	}

	.service-grid > div:first-child {
		border-left: 0;
	}

	.service-mark {
		width: 0.55rem;
		height: 0.55rem;
		margin-top: 0.25rem;
		border: var(--rule-thin) solid var(--color-ink);
	}

	.service-grid .enabled .service-mark {
		border-color: var(--color-accent);
		background: var(--color-accent);
	}

	.service-grid strong {
		min-width: 0;
		font-size: var(--text-xs);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.service-grid div > span:last-child {
		grid-column: 1 / -1;
		min-width: 0;
		color: var(--color-muted);
		font-size: 0.68rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.destination-list {
		display: grid;
		gap: var(--space-3);
	}

	article {
		display: grid;
		grid-template-columns: minmax(8rem, 0.7fr) minmax(12rem, 1.3fr);
		gap: var(--space-3) var(--space-5);
		align-items: center;
		padding-bottom: var(--space-3);
		border-bottom: var(--rule-thin) solid var(--color-rule);
	}

	.destination-name {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-width: 0;
	}

	.destination-name strong {
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.destination-name span {
		padding: 0.12rem 0.3rem;
		border: var(--rule-thin) solid var(--color-accent);
		color: var(--color-accent);
		font-size: 0.62rem;
		font-weight: 700;
		text-transform: uppercase;
	}

	.address {
		min-width: 0;
		padding: var(--space-1) 0;
		border: 0;
		border-bottom: var(--rule-thin) solid var(--color-rule-strong);
		background: transparent;
		color: var(--color-ink-2);
		font-size: var(--text-sm);
		text-align: left;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		cursor: pointer;
	}

	.address:hover {
		border-color: var(--color-accent);
		color: var(--color-accent);
	}

	.address:focus-visible {
		outline: 3px solid var(--color-focus);
		outline-offset: 2px;
	}

	.bandwidth {
		grid-column: 1 / -1;
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		gap: var(--space-3);
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.bandwidth strong {
		color: var(--color-ink);
	}

	@media (max-width: 800px) {
		.service-grid {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.service-grid > div:nth-child(odd) {
			border-left: 0;
		}
	}

	@media (max-width: 560px) {
		article {
			grid-template-columns: 1fr;
		}

		.bandwidth {
			grid-column: 1;
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
	}
</style>
