<script lang="ts">
	import { collection, resourceLabels, retry } from '$lib/api';
	import type { Resource } from '$lib/api';
	import { formatAgo } from '$lib/format';

	let { resource }: { resource: Resource } = $props();
	const entry = $derived($collection[resource]);
</script>

{#if entry.error}
	<div class="notice" data-tone="crit" role="alert">
		<span>
			<strong>{resourceLabels[resource]} {entry.lastSuccess === null ? 'unavailable' : 'not updating'}.</strong>
			{entry.error}
			{#if entry.lastSuccess !== null}<span class="muted">Showing data from {formatAgo(entry.lastSuccess)}.</span>{/if}
		</span>
		<button class="button button--quiet" type="button" disabled={entry.loading} aria-busy={entry.loading} onclick={() => retry(resource)}>
			{entry.loading ? 'Retrying' : 'Retry'}
		</button>
	</div>
{/if}
