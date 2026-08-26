<script lang="ts">
	import { onMount } from 'svelte';
	import {
		addToast,
		fetchConfig,
		isConfigModalOpen,
		updateConfig
	} from '../api';
	import type { RouterConfigData, RouterConfigUpdate } from '../types';

	type Tab = 'router' | 'tunnels' | 'services' | 'sources';
	let activeTab: Tab = 'router';
	let config: RouterConfigData | null = null;
	let draft: RouterConfigData | null = null;
	let endpointsText = '';
	let subscriptionsText = '';
	let loading = true;
	let saving = false;
	let saveState: 'idle' | 'success' | 'error' = 'idle';
	let loadError = '';
	let closeButton: HTMLButtonElement;
	let dialogElement: HTMLDivElement;

	onMount(async () => {
		try {
			config = await fetchConfig();
			draft = structuredClone(config);
			endpointsText = config.reseed.endpoints.join('\n');
			subscriptionsText = config.addressbook.subscriptions.join('\n');
		} catch (error) {
			loadError = error instanceof Error ? error.message : 'Configuration could not be loaded';
		} finally {
			loading = false;
			closeButton?.focus();
		}
	});

	function close(): void {
		if (!saving) isConfigModalOpen.set(false);
	}

	function handleKeydown(event: KeyboardEvent): void {
		if (event.key === 'Escape') {
			close();
			return;
		}
		if (event.key !== 'Tab' || !dialogElement) return;
		const focusable = Array.from(
			dialogElement.querySelectorAll<HTMLElement>(
				'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])'
			)
		);
		if (focusable.length === 0) return;
		const first = focusable[0];
		const last = focusable[focusable.length - 1];
		if (event.shiftKey && document.activeElement === first) {
			event.preventDefault();
			last.focus();
		} else if (!event.shiftKey && document.activeElement === last) {
			event.preventDefault();
			first.focus();
		}
	}

	function handleBackdrop(event: MouseEvent): void {
		if (event.target === event.currentTarget) close();
	}

	function lines(value: string): string[] {
		return value
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter(Boolean);
	}

	function buildUpdate(value: RouterConfigData): RouterConfigUpdate {
		return {
			router: { floodfill: value.router.floodfill, family: value.router.family },
			tunnel: structuredClone(value.tunnel),
			ntcp2: { enabled: value.ntcp2.enabled, max_sessions: value.ntcp2.max_sessions },
			ssu2: { enabled: value.ssu2.enabled, max_sessions: value.ssu2.max_sessions },
			reseed: {
				enabled: value.reseed.enabled,
				required: value.reseed.enabled && value.reseed.required,
				endpoints: value.reseed.enabled ? lines(endpointsText) : []
			},
			addressbook: {
				enabled: value.addressbook.enabled,
				subscriptions: lines(subscriptionsText),
				refresh_interval_hours: value.addressbook.refresh_interval_hours
			},
			services: {
				http_proxy_enabled: value.services.http_proxy_enabled,
				http_proxy_port: value.services.http_proxy_port,
				socks5_enabled: value.services.socks5_enabled,
				socks5_port: value.services.socks5_port,
				sam_enabled: value.services.sam_enabled,
				sam_port: value.services.sam_port,
				metrics_enabled: value.services.metrics_enabled,
				metrics_port: value.services.metrics_port
			},
			log: { level: value.log.level }
		};
	}

	async function save(): Promise<void> {
		if (!draft || saving) return;
		saving = true;
		saveState = 'idle';
		try {
			const result = await updateConfig(buildUpdate(draft));
			saveState = 'success';
			const applied = result.applied.length > 0 ? `${result.applied.join(', ')} applied now.` : '';
			const restart = result.restart_required.length > 0 ? `${result.restart_required.length} changes require restart.` : '';
			addToast({
				type: 'success',
				title: result.status === 'unchanged' ? 'Configuration unchanged' : 'Configuration saved',
				description: [applied, restart].filter(Boolean).join(' ')
			});
			config = await fetchConfig();
			draft = structuredClone(config);
		} catch (error) {
			saveState = 'error';
			addToast({ type: 'error', title: 'Configuration rejected', description: error instanceof Error ? error.message : 'Save failed' });
		} finally {
			saving = false;
		}
	}
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="backdrop" role="presentation" on:mousedown={handleBackdrop}>
	<div class="dialog" role="dialog" aria-modal="true" aria-labelledby="config-title" bind:this={dialogElement}>
		<header>
			<div>
				<p class="cell-note">Operating configuration</p>
				<h2 id="config-title">Router settings</h2>
			</div>
			<button class="close" type="button" bind:this={closeButton} on:click={close} aria-label="Close settings">×</button>
		</header>

		<nav class="tabs" aria-label="Configuration sections">
			{#each [
				['router', 'Router'],
				['tunnels', 'Tunnels'],
				['services', 'Services'],
				['sources', 'Sources']
			] as tab}
				<button
					type="button"
					class:active={activeTab === tab[0]}
					on:click={() => (activeTab = tab[0] as Tab)}
					aria-pressed={activeTab === tab[0]}
				>
					{tab[1]}
				</button>
			{/each}
		</nav>

		<div class="dialog-body">
			{#if loading}
				<div class="empty">Loading configuration</div>
			{:else if loadError}
				<div class="empty">{loadError}</div>
			{:else if draft}
				{#if draft.restart_required}
					<p class="restart-banner">Saved configuration differs from the running router. Restart ivnpd to apply topology changes.</p>
				{/if}

				{#if activeTab === 'router'}
					<div class="form-grid">
						<div class="read-only"><span>Network</span><strong>{draft.network.id}</strong></div>
						<div class="read-only"><span>IP families</span><strong>{draft.network.ipv4 ? 'IPv4' : ''}{draft.network.ipv4 && draft.network.ipv6 ? ' + ' : ''}{draft.network.ipv6 ? 'IPv6' : ''}</strong></div>
						<div class="read-only"><span>Router version</span><strong>{draft.router.version}</strong></div>
						<div class="field">
							<label for="log-level">Live log level</label>
							<select class="select" id="log-level" bind:value={draft.log.level}>
								<option value="debug">Debug</option>
								<option value="info">Info</option>
								<option value="warn">Warn</option>
								<option value="error">Error</option>
							</select>
						</div>
						<div class="field wide">
							<label for="family">Router family</label>
							<input class="input" id="family" maxlength="64" bind:value={draft.router.family} />
						</div>
						<label class="toggle wide">
							<input type="checkbox" bind:checked={draft.router.floodfill} />
							<span><strong>Floodfill participant</strong><small>Advertised after restart when runtime readiness permits.</small></span>
						</label>
					</div>
				{:else if activeTab === 'tunnels'}
					<div class="form-grid">
						<label class="toggle wide">
							<input type="checkbox" bind:checked={draft.tunnel.enabled} />
							<span><strong>Enable tunnels</strong><small>Required by local proxy services.</small></span>
						</label>
						<div class="field"><label for="hops">Hops</label><input class="input" id="hops" type="number" min="1" max="7" bind:value={draft.tunnel.hops} /></div>
						<div class="field"><label for="bandwidth-rate">Rate bytes/s</label><input class="input" id="bandwidth-rate" type="number" min="1024" bind:value={draft.tunnel.bandwidth_rate_bytes_per_second} /></div>
						<div class="field"><label for="bandwidth-burst">Burst bytes</label><input class="input" id="bandwidth-burst" type="number" min="1024" bind:value={draft.tunnel.bandwidth_burst_bytes} /></div>
						<div class="field"><label for="exploratory-in">Exploratory inbound target</label><input class="input" id="exploratory-in" type="number" min="1" max="16" bind:value={draft.tunnel.exploratory_inbound_target} /></div>
						<div class="field"><label for="exploratory-out">Exploratory outbound target</label><input class="input" id="exploratory-out" type="number" min="1" max="16" bind:value={draft.tunnel.exploratory_outbound_target} /></div>
						<div class="field"><label for="exploratory-capacity">Exploratory capacity</label><input class="input" id="exploratory-capacity" type="number" min="2" max="64" bind:value={draft.tunnel.exploratory_pool_capacity} /></div>
						<div class="field"><label for="client-in">Client inbound target</label><input class="input" id="client-in" type="number" min="1" max="16" bind:value={draft.tunnel.client_inbound_target} /></div>
						<div class="field"><label for="client-out">Client outbound target</label><input class="input" id="client-out" type="number" min="1" max="16" bind:value={draft.tunnel.client_outbound_target} /></div>
						<div class="field"><label for="client-capacity">Client capacity</label><input class="input" id="client-capacity" type="number" min="2" max="64" bind:value={draft.tunnel.client_pool_capacity} /></div>
					</div>
					<p class="form-note">Each pool capacity must be at least twice its largest live target.</p>
				{:else if activeTab === 'services'}
					<div class="service-settings">
						{#each [
							{ key: 'http', label: 'HTTP proxy', address: draft.services.http_proxy_address },
							{ key: 'socks', label: 'SOCKS5 proxy', address: draft.services.socks5_address },
							{ key: 'sam', label: 'SAM bridge', address: draft.services.sam_address },
							{ key: 'metrics', label: 'Prometheus metrics', address: draft.services.metrics_address }
						] as service}
							<div class="service-setting">
								<label class="toggle">
									{#if service.key === 'http'}<input type="checkbox" bind:checked={draft.services.http_proxy_enabled} />
									{:else if service.key === 'socks'}<input type="checkbox" bind:checked={draft.services.socks5_enabled} />
									{:else if service.key === 'sam'}<input type="checkbox" bind:checked={draft.services.sam_enabled} />
									{:else}<input type="checkbox" bind:checked={draft.services.metrics_enabled} />{/if}
									<span><strong>{service.label}</strong><small>Listener host: {service.address}</small></span>
								</label>
								<div class="field">
									<label for={`${service.key}-port`}>Port</label>
									{#if service.key === 'http'}<input class="input" id={`${service.key}-port`} type="number" min="1" max="65535" bind:value={draft.services.http_proxy_port} />
									{:else if service.key === 'socks'}<input class="input" id={`${service.key}-port`} type="number" min="1" max="65535" bind:value={draft.services.socks5_port} />
									{:else if service.key === 'sam'}<input class="input" id={`${service.key}-port`} type="number" min="1" max="65535" bind:value={draft.services.sam_port} />
									{:else}<input class="input" id={`${service.key}-port`} type="number" min="1" max="65535" bind:value={draft.services.metrics_port} />{/if}
								</div>
							</div>
						{/each}
						<div class="transport-settings">
							<label class="toggle"><input type="checkbox" bind:checked={draft.ntcp2.enabled} /><span><strong>NTCP2</strong><small>{draft.ntcp2.bind_address || 'Unbound'}</small></span></label>
							<div class="field"><label for="ntcp2-sessions">Max sessions</label><input class="input" id="ntcp2-sessions" type="number" min="1" max="65536" bind:value={draft.ntcp2.max_sessions} /></div>
							<label class="toggle"><input type="checkbox" bind:checked={draft.ssu2.enabled} /><span><strong>SSU2</strong><small>{draft.ssu2.bind_address || 'Unbound'}</small></span></label>
							<div class="field"><label for="ssu2-sessions">Max sessions</label><input class="input" id="ssu2-sessions" type="number" min="1" max="65536" bind:value={draft.ssu2.max_sessions} /></div>
						</div>
					</div>
				{:else}
					<div class="source-settings">
						<div class="source-block">
							<label class="toggle"><input type="checkbox" bind:checked={draft.reseed.enabled} /><span><strong>HTTPS reseed</strong><small>Disabling also clears persisted endpoints.</small></span></label>
							<label class="toggle"><input type="checkbox" bind:checked={draft.reseed.required} disabled={!draft.reseed.enabled} /><span><strong>Require reseed</strong><small>Startup fails if bootstrap cannot complete.</small></span></label>
							<div class="field"><label for="reseed-endpoints">Reseed endpoints, one per line</label><textarea class="textarea" id="reseed-endpoints" bind:value={endpointsText} disabled={!draft.reseed.enabled}></textarea></div>
						</div>
						<div class="source-block">
							<label class="toggle"><input type="checkbox" bind:checked={draft.addressbook.enabled} /><span><strong>Address book</strong><small>Resolve local and subscribed I2P host names.</small></span></label>
							<div class="field"><label for="refresh-hours">Refresh interval, hours</label><input class="input" id="refresh-hours" type="number" min="1" max="168" bind:value={draft.addressbook.refresh_interval_hours} /></div>
							<div class="field"><label for="subscriptions">Subscriptions, one per line</label><textarea class="textarea" id="subscriptions" bind:value={subscriptionsText}></textarea></div>
						</div>
					</div>
				{/if}
			{/if}
		</div>

		<footer>
			<span>Only log level applies without restart.</span>
			<div>
				<button class="button" type="button" on:click={close} disabled={saving}>Cancel</button>
				<button class="button button--primary" type="button" on:click={save} disabled={!draft || saving} aria-busy={saving} data-state={saveState}>
					{saving ? 'Saving' : 'Save configuration'}
				</button>
			</div>
		</footer>
	</div>
</div>

<style>
	.backdrop {
		position: fixed;
		inset: 0;
		z-index: 20;
		display: grid;
		place-items: center;
		padding: var(--space-4);
		background: var(--color-scrim);
	}

	.dialog {
		display: grid;
		grid-template-rows: auto auto minmax(0, 1fr) auto;
		width: min(64rem, 100%);
		max-height: min(54rem, calc(100vh - var(--space-8)));
		border: var(--rule-heavy) solid var(--color-ink);
		background: var(--color-paper);
		animation: enter var(--dur-dialog) var(--ease-out);
	}

	.dialog > header,
	.dialog > footer {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-4);
		padding: var(--space-4) var(--space-5);
	}

	.dialog > header {
		border-bottom: var(--rule-heavy) solid var(--color-ink);
	}

	header p,
	header h2 {
		margin: 0;
	}

	header h2 {
		font-size: var(--text-xl);
		letter-spacing: -0.03em;
	}

	.close {
		display: grid;
		place-items: center;
		width: 2.5rem;
		height: 2.5rem;
		border: var(--rule-thin) solid var(--color-ink);
		background: var(--color-paper);
		color: var(--color-ink);
		font-size: 1.55rem;
		line-height: 1;
		cursor: pointer;
	}

	.close:hover {
		border-color: var(--color-accent);
		background: var(--color-accent-soft);
	}

	.close:focus-visible {
		outline: 3px solid var(--color-focus);
		outline-offset: 2px;
	}

	.tabs {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		border-bottom: var(--rule-thin) solid var(--color-rule-strong);
	}

	.tabs button {
		min-height: 2.8rem;
		border: 0;
		border-left: var(--rule-thin) solid var(--color-rule);
		background: var(--color-paper);
		color: var(--color-muted);
		font-size: var(--text-sm);
		font-weight: 650;
		white-space: nowrap;
		cursor: pointer;
	}

	.tabs button:first-child {
		border-left: 0;
	}

	.tabs button:hover,
	.tabs button.active {
		background: var(--color-accent-soft);
		color: var(--color-ink);
	}

	.tabs button.active {
		box-shadow: inset 0 -3px var(--color-accent);
	}

	.tabs button:focus-visible {
		position: relative;
		z-index: 1;
		outline: 3px solid var(--color-focus);
		outline-offset: -3px;
	}

	.dialog-body {
		overflow-y: auto;
		padding: var(--space-5);
	}

	.restart-banner,
	.form-note {
		margin: 0 0 var(--space-5);
		padding: var(--space-3);
		border-left: 3px solid var(--color-accent);
		background: var(--color-accent-soft);
		font-size: var(--text-sm);
	}

	.form-grid {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: var(--space-4);
	}

	.wide {
		grid-column: span 2;
	}

	.read-only {
		display: grid;
		gap: var(--space-1);
		padding: var(--space-3);
		border-block: var(--rule-thin) solid var(--color-rule);
		background: var(--color-paper-2);
	}

	.read-only span,
	.form-note,
	.dialog > footer > span {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.toggle {
		display: flex;
		align-items: start;
		gap: var(--space-3);
		min-width: 0;
		padding: var(--space-3);
		border: var(--rule-thin) solid var(--color-rule);
		cursor: pointer;
	}

	.toggle:hover {
		border-color: var(--color-accent);
		background: var(--color-accent-soft);
	}

	.toggle input {
		width: 1.1rem;
		height: 1.1rem;
		margin: 0.12rem 0 0;
		accent-color: var(--color-accent);
	}

	.toggle input:focus-visible {
		outline: 3px solid var(--color-focus);
		outline-offset: 2px;
	}

	.toggle span {
		display: grid;
		min-width: 0;
	}

	.toggle small {
		color: var(--color-muted);
		overflow-wrap: anywhere;
	}

	.service-settings,
	.source-settings {
		display: grid;
		gap: var(--space-4);
	}

	.service-setting,
	.transport-settings,
	.source-block {
		display: grid;
		grid-template-columns: minmax(0, 1fr) minmax(9rem, 0.35fr);
		gap: var(--space-4);
		padding-bottom: var(--space-4);
		border-bottom: var(--rule-thin) solid var(--color-rule);
	}

	.transport-settings {
		grid-template-columns: minmax(0, 1fr) minmax(9rem, 0.35fr) minmax(0, 1fr) minmax(9rem, 0.35fr);
		border-bottom: 0;
	}

	.source-settings {
		grid-template-columns: repeat(2, minmax(0, 1fr));
	}

	.source-block {
		grid-template-columns: 1fr;
		align-content: start;
		padding: var(--space-4);
		border: var(--rule-thin) solid var(--color-rule-strong);
	}

	.dialog > footer {
		border-top: var(--rule-heavy) solid var(--color-ink);
	}

	.dialog > footer div {
		display: flex;
		gap: var(--space-2);
	}

	@keyframes enter {
		from {
			opacity: 0;
			transform: translateY(10px);
		}
		to {
			opacity: 1;
			transform: none;
		}
	}

	@media (max-width: 760px) {
		.form-grid {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.transport-settings,
		.source-settings {
			grid-template-columns: 1fr;
		}

		.dialog > footer {
			align-items: stretch;
			flex-direction: column;
		}
	}

	@media (max-width: 480px) {
		.backdrop {
			padding: 0;
		}

		.dialog {
			width: 100%;
			height: 100dvh;
			max-height: none;
			border: 0;
		}

		.dialog > header,
		.dialog-body,
		.dialog > footer {
			padding-inline: var(--space-4);
		}

		.form-grid {
			grid-template-columns: 1fr;
		}

		.wide {
			grid-column: 1;
		}

		.dialog > footer div {
			display: grid;
			grid-template-columns: 1fr 1fr;
		}
	}
</style>
