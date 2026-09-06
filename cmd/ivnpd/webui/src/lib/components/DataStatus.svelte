<script lang="ts">
	import { collectionState, resourceLabels, retryResource } from '../api';
	import type { DataResource } from '../api';

	export let resource: DataResource;
	$: state = $collectionState[resource];
</script>

<div class="data-status" class:interrupted={state.error !== null} role="status">
	<span>
		<span>{resourceLabels[resource]} · </span>
		{#if state.error}
			<strong>{state.lastSuccess === null ? 'Collection failed' : 'Updates interrupted'}</strong>
			<span class="reason">{state.error}</span>
		{:else if state.lastSuccess === null}
			— · Waiting for data
		{/if}
		{#if state.lastSuccess !== null}
			<span>Last collected <time datetime={new Date(state.lastSuccess).toISOString()} title={new Date(state.lastSuccess).toLocaleString()}>{new Date(state.lastSuccess).toLocaleTimeString()}</time></span>
		{/if}
	</span>
	{#if state.error}
		<button class="button" type="button" disabled={state.loading} aria-busy={state.loading} aria-label={`Retry ${resourceLabels[resource]}`} on:click={() => retryResource(resource)}>{state.loading ? 'Retrying' : 'Retry'}</button>
	{/if}
</div>

<style>
	.data-status { display: flex; align-items: center; justify-content: space-between; gap: var(--space-3); margin-block: var(--space-3); color: var(--color-muted); font-size: var(--text-sm); }
	.data-status > span { min-width: 0; overflow-wrap: anywhere; }
	.interrupted { padding: var(--space-3); border-left: var(--rule-heavy) solid var(--color-ink); background: var(--color-paper-2); color: var(--color-ink); }
	.reason { display: block; }
	.button { flex-shrink: 0; font-size: var(--text-sm); }
	@media (max-width: 520px) { .data-status { align-items: flex-start; flex-direction: column; } }
</style>
