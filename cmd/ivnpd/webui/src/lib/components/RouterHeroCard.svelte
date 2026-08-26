<script lang="ts">
	import { copyText, formatDuration, routerStatus, shortHash } from '../api';
</script>

<section class="cell router-cell" aria-labelledby="router-title">
	{#if $routerStatus}
		<div class="cell-head">
			<div>
				<p class="cell-note">Router identity</p>
				<h1 class="router-state" id="router-title">{$routerStatus.state}<span class="period" aria-hidden="true"></span></h1>
			</div>
			<div class:ready={$routerStatus.ready} class="state-stamp">
				{$routerStatus.ready ? 'data plane ready' : 'initializing'}
			</div>
		</div>

		<div class="identity-lines">
			<div>
				<span class="label">B32</span>
				<code title={$routerStatus.router_b32}>{shortHash($routerStatus.router_b32, 20, 10)}</code>
				<button class="text-action" type="button" on:click={() => copyText($routerStatus?.router_b32 ?? '', 'B32 address copied')}>Copy</button>
			</div>
			<div>
				<span class="label">Router hash</span>
				<code title={$routerStatus.router_hash}>{shortHash($routerStatus.router_hash, 20, 10)}</code>
				<button class="text-action" type="button" on:click={() => copyText($routerStatus?.router_hash ?? '', 'Router hash copied')}>Copy</button>
			</div>
		</div>

		<div class="facts">
			<div><span>Reachability</span><strong>{$routerStatus.reachability}</strong></div>
			<div><span>Uptime</span><strong>{formatDuration($routerStatus.uptime_seconds)}</strong></div>
			<div><span>Version</span><strong>{$routerStatus.version || '—'}</strong></div>
			<div><span>Family</span><strong>{$routerStatus.family || '—'}</strong></div>
		</div>

		<div class="transports">
			{#each Object.entries($routerStatus.transports) as [name, transport]}
				<div class="transport">
					<div>
						<span class="label">{name}</span>
						<strong>{transport.enabled ? `${transport.active_sessions} / ${transport.max_sessions}` : 'disabled'}</strong>
					</div>
					<p>{transport.enabled ? transport.bind_address : 'Listener disabled'}</p>
				</div>
			{/each}
		</div>
	{:else}
		<div class="empty">Waiting for router status</div>
	{/if}
</section>

<style>
	.router-cell {
		position: relative;
		display: flex;
		flex-direction: column;
		min-height: 27rem;
		overflow: clip;
	}

	.router-cell::after {
		content: '';
		position: absolute;
		width: 8rem;
		height: 8rem;
		right: -4rem;
		bottom: -4rem;
		border-radius: 50%;
		background: var(--color-accent);
	}

	.cell-note {
		margin: 0 0 var(--space-2);
	}

	.router-state {
		margin: 0;
		min-width: 0;
		font-family: var(--font-display);
		font-size: clamp(3.2rem, 7vw, 6.8rem);
		font-weight: 800;
		letter-spacing: -0.055em;
		line-height: 0.84;
		text-transform: lowercase;
		overflow-wrap: anywhere;
	}

	.period {
		display: inline-block;
		width: 0.28em;
		height: 0.28em;
		margin-left: 0.06em;
		background: var(--color-accent);
	}

	.state-stamp {
		padding: var(--space-2) var(--space-3);
		border: var(--rule-thin) dashed var(--color-ink);
		font-size: var(--text-xs);
		font-weight: 650;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		white-space: nowrap;
	}

	.state-stamp.ready {
		border-style: solid;
		border-color: var(--color-accent);
		background: var(--color-accent);
		color: var(--color-accent-ink);
	}

	.identity-lines {
		display: grid;
		gap: var(--space-3);
		margin-top: var(--space-6);
	}

	.identity-lines > div {
		display: grid;
		grid-template-columns: 5.5rem minmax(0, 1fr) auto;
		align-items: center;
		gap: var(--space-3);
		padding-bottom: var(--space-2);
		border-bottom: var(--rule-thin) solid var(--color-rule);
	}

	code {
		min-width: 0;
		overflow: hidden;
		color: var(--color-ink-2);
		font-family: var(--font-body);
		font-size: var(--text-sm);
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.text-action {
		padding: var(--space-1) 0;
		border: 0;
		border-bottom: var(--rule-thin) solid var(--color-ink);
		background: transparent;
		color: var(--color-ink);
		font-size: var(--text-xs);
		font-weight: 650;
		cursor: pointer;
		white-space: nowrap;
	}

	.text-action:hover {
		border-color: var(--color-accent);
		color: var(--color-accent);
	}

	.text-action:active {
		transform: translateY(1px);
	}

	.text-action:disabled {
		color: var(--color-muted);
		cursor: not-allowed;
		opacity: 0.55;
	}

	.text-action:focus-visible {
		outline: 3px solid var(--color-focus);
		outline-offset: 2px;
	}

	.facts {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		margin-top: auto;
		padding-top: var(--space-8);
	}

	.facts div {
		display: grid;
		gap: var(--space-1);
		padding-inline: var(--space-3);
		border-left: var(--rule-thin) solid var(--color-rule);
	}

	.facts div:first-child {
		padding-left: 0;
		border-left: 0;
	}

	.facts span,
	.transport p {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.facts strong {
		font-size: var(--text-body);
		text-transform: capitalize;
	}

	.transports {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: var(--space-4);
		margin-top: var(--space-5);
		padding-top: var(--space-4);
		border-top: var(--rule-heavy) solid var(--color-ink);
	}

	.transport > div {
		display: flex;
		justify-content: space-between;
		gap: var(--space-3);
	}

	.transport p {
		margin: var(--space-1) 0 0;
		overflow-wrap: anywhere;
	}

	@media (max-width: 620px) {
		.cell-head {
			display: grid;
		}

		.state-stamp {
			width: fit-content;
		}

		.identity-lines > div {
			grid-template-columns: 1fr auto;
		}

		.identity-lines .label {
			grid-column: 1 / -1;
		}

		.facts {
			grid-template-columns: repeat(2, minmax(0, 1fr));
			gap: var(--space-4) 0;
		}

		.facts div:nth-child(3) {
			padding-left: 0;
			border-left: 0;
		}

		.transports {
			grid-template-columns: 1fr;
		}
	}
</style>
