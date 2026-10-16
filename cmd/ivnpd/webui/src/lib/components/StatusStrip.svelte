<script lang="ts">
	import { collection, configData, restarting, routerStatus, tunnelsData } from '$lib/api';
	import { deriveHealth } from '$lib/health';

	const health = $derived(
		deriveHealth({
			status: $routerStatus,
			statusError: $collection.status.error,
			tunnels: $tunnelsData,
			config: $configData,
			restarting: $restarting
		})
	);
</script>

<section class="strip" data-tone={health.tone} aria-labelledby="health-title">
	<div class="verdict">
		<span class="mark" aria-hidden="true"></span>
		<h1 id="health-title">{health.headline}</h1>
	</div>
	{#if health.blockers.length > 0}
		<ul>
			{#each health.blockers.slice(0, 5) as blocker (blocker.title)}
				<li data-tone={blocker.tone}>
					{#if blocker.href}<a href={blocker.href}>{blocker.title}</a>{:else}{blocker.title}{/if}
				</li>
			{/each}
			{#if health.blockers.length > 5}<li class="more">{health.blockers.length - 5} more</li>{/if}
		</ul>
	{:else if health.tone === 'ok'}
		<p>All readiness conditions are met and every enabled service is listening.</p>
	{/if}
</section>

<style>
	.strip {
		display: grid;
		grid-template-columns: minmax(12rem, auto) minmax(0, 1fr);
		align-items: center;
		gap: var(--space-3) var(--space-8);
		padding: var(--space-4) var(--space-5);
		border: var(--rule-thin) solid var(--color-rule);
		border-left: 6px solid var(--color-rule-strong);
		background: var(--color-paper);
	}

	.strip[data-tone='ok'] {
		border-left-color: var(--color-ok);
	}

	.strip[data-tone='warn'] {
		border-left-color: var(--color-warn-mark);
		background: var(--color-warn-soft);
	}

	.strip[data-tone='crit'] {
		border-left-color: var(--color-crit);
		background: var(--color-crit-soft);
	}

	.strip[data-tone='info'] {
		border-left-color: var(--color-accent);
		background: var(--color-accent-soft);
	}

	.verdict {
		display: flex;
		align-items: center;
		gap: var(--space-3);
	}

	.mark {
		width: 0.9rem;
		height: 0.9rem;
		border-radius: 50%;
		background: var(--color-rule-strong);
	}

	[data-tone='ok'] .mark {
		background: var(--color-ok);
	}

	[data-tone='warn'] .mark {
		background: var(--color-warn-mark);
	}

	[data-tone='crit'] .mark {
		background: var(--color-crit);
	}

	[data-tone='info'] .mark {
		background: var(--color-accent);
	}

	h1 {
		font-size: var(--text-xl);
		font-weight: 750;
	}

	ul {
		display: grid;
		gap: var(--space-1);
		padding: 0;
		list-style: none;
		font-size: var(--text-sm);
	}

	li {
		position: relative;
		padding-left: var(--space-4);
		overflow-wrap: anywhere;
	}

	li::before {
		content: '';
		position: absolute;
		top: 0.5em;
		left: 0;
		width: 0.45rem;
		height: 0.45rem;
		background: var(--color-rule-strong);
	}

	li[data-tone='crit']::before {
		background: var(--color-crit);
	}

	li[data-tone='warn']::before {
		background: var(--color-warn-mark);
	}

	li[data-tone='info']::before {
		background: var(--color-accent);
	}

	li a {
		font-weight: 600;
		text-underline-offset: 0.2em;
	}

	li a:hover {
		color: var(--color-accent);
	}

	.more {
		color: var(--color-muted);
	}

	p {
		color: var(--color-ink-2);
		font-size: var(--text-sm);
	}

	@media (max-width: 720px) {
		.strip {
			grid-template-columns: minmax(0, 1fr);
		}
	}
</style>
