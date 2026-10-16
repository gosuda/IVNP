<script lang="ts">
	import { onMount, tick } from 'svelte';
	import { beforeNavigate, goto } from '$app/navigation';
	import { page } from '$app/state';
	import { APIError, addToast, configData, errorMessage, fetchConfig, patchConfig, rollbackConfig } from '$lib/api';
	import type { ConfigField, ConfigGroup, ConfigValue } from '$lib/types';
	import Badge from '$lib/components/Badge.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import InlineError from '$lib/components/InlineError.svelte';
	import Operations from '$lib/components/Operations.svelte';
	import SettingField from '$lib/components/SettingField.svelte';

	const groups: Array<{ id: ConfigGroup; label: string }> = [
		{ id: 'features', label: 'Features' },
		{ id: 'router', label: 'Router' },
		{ id: 'tunnels', label: 'Tunnels' },
		{ id: 'transports', label: 'Transports' },
		{ id: 'services', label: 'Services' },
		{ id: 'sources', label: 'Sources' },
		{ id: 'logging', label: 'Logging' }
	];

	let draft = $state<Record<string, ConfigValue>>({});
	let errors = $state<Record<string, string>>({});
	let saving = $state(false);
	let conflict = $state(false);
	let showDiff = $state(false);
	let confirmRollback = $state<ConfirmDialog | null>(null);
	let tabButtons: HTMLButtonElement[] = $state([]);

	const config = $derived($configData);
	const fields = $derived(config?.fields ?? []);
	const byKey = $derived(new Map(fields.map((field) => [field.key, field])));
	const focusKey = $derived(page.url.searchParams.get('focus') ?? '');
	const activeGroup = $derived.by((): ConfigGroup => {
		const requested = page.url.searchParams.get('group') as ConfigGroup | null;
		if (requested && groups.some((group) => group.id === requested)) return requested;
		return byKey.get(focusKey)?.group ?? 'features';
	});
	const visible = $derived(fields.filter((field) => field.group === activeGroup));
	const dirtyKeys = $derived(Object.keys(draft).filter((key) => byKey.has(key) && !same(draft[key], byKey.get(key)!.value)));
	const pending = $derived(fields.filter((field) => field.pending));
	const writable = $derived(Boolean(config?.writable));

	function same(left: ConfigValue | null | undefined, right: ConfigValue | null | undefined): boolean {
		return JSON.stringify(left) === JSON.stringify(right);
	}

	function effective(key: string): ConfigValue | undefined {
		return key in draft ? draft[key] : byKey.get(key)?.value;
	}

	function blockedBy(field: ConfigField): string {
		const missing = field.requires.filter((key) => effective(key) !== true);
		return missing.map((key) => byKey.get(key)?.label ?? key).join(' and ');
	}

	function display(value: ConfigValue | null | undefined): string {
		if (value === null || value === undefined) return '—';
		if (typeof value === 'boolean') return value ? 'On' : 'Off';
		if (Array.isArray(value)) return value.length ? value.join(', ') : 'None';
		return String(value) || 'Empty';
	}

	function set(field: ConfigField, value: ConfigValue): void {
		const next = { ...draft };
		if (same(value, field.value)) delete next[field.key];
		else next[field.key] = value;
		draft = next;
		if (errors[field.key]) errors = Object.fromEntries(Object.entries(errors).filter(([key]) => key !== field.key));
	}

	function selectGroup(group: ConfigGroup): void {
		const url = new URL(page.url);
		url.searchParams.set('group', group);
		url.searchParams.delete('focus');
		void goto(url, { replaceState: true, noScroll: true, keepFocus: true });
	}

	function tabKeydown(event: KeyboardEvent, index: number): void {
		const delta = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
		if (!delta) return;
		event.preventDefault();
		const next = (index + delta + groups.length) % groups.length;
		selectGroup(groups[next].id);
		tabButtons[next]?.focus();
	}

	async function focusField(key: string): Promise<void> {
		await tick();
		const element = document.querySelector<HTMLElement>(`[data-key="${CSS.escape(key)}"]`);
		element?.scrollIntoView({ block: 'center' });
		element?.querySelector<HTMLElement>('input, select, textarea')?.focus();
	}

	$effect(() => {
		if (focusKey && byKey.has(focusKey)) void focusField(focusKey);
	});

	async function save(): Promise<void> {
		if (!config || saving || dirtyKeys.length === 0) return;
		saving = true;
		const changes = Object.fromEntries(dirtyKeys.map((key) => [key, draft[key]]));
		try {
			const result = await patchConfig(config.revision, changes);
			draft = {};
			errors = {};
			conflict = false;
			showDiff = false;
			const parts = [
				result.applied.length ? `${result.applied.length} applied now.` : '',
				result.restart_required.length ? `${result.restart_required.length} apply after restart.` : ''
			].filter(Boolean);
			addToast({ type: 'success', title: result.status === 'unchanged' ? 'Nothing changed' : 'Settings saved', description: parts.join(' ') });
			await fetchConfig();
		} catch (error) {
			if (error instanceof APIError && error.status === 409 && typeof error.body.revision === 'string') {
				conflict = true;
			} else if (error instanceof APIError && error.status === 400 && typeof error.body.key === 'string' && error.body.key) {
				const key = error.body.key;
				errors = { ...errors, [key]: error.message };
				const field = byKey.get(key);
				if (field && field.group !== activeGroup) selectGroup(field.group);
				void focusField(key);
			} else {
				addToast({ type: 'error', title: 'Settings not saved', description: errorMessage(error) });
			}
		} finally {
			saving = false;
		}
	}

	async function reloadKeepingEdits(): Promise<void> {
		await fetchConfig();
		const latest = new Map(($configData?.fields ?? []).map((field) => [field.key, field.value]));
		draft = Object.fromEntries(Object.entries(draft).filter(([key, value]) => latest.has(key) && !same(value, latest.get(key))));
		conflict = false;
	}

	async function rollback(): Promise<void> {
		if (!config || !(await confirmRollback?.ask())) return;
		try {
			const result = await rollbackConfig(config.revision);
			draft = {};
			addToast({ type: 'success', title: 'Previous configuration restored', description: result.restart_required.length ? `${result.restart_required.length} settings apply after restart.` : undefined });
			await fetchConfig();
		} catch (error) {
			if (error instanceof APIError && error.status === 409) conflict = true;
			else addToast({ type: 'error', title: 'Rollback failed', description: errorMessage(error) });
		}
	}

	beforeNavigate((navigation) => {
		const leavingSettings = navigation.to?.url.pathname !== page.url.pathname;
		if (leavingSettings && dirtyKeys.length > 0 && !confirm(`Discard ${dirtyKeys.length} unsaved change${dirtyKeys.length === 1 ? '' : 's'}?`)) navigation.cancel();
	});

	onMount(() => {
		void fetchConfig();
		const guard = (event: BeforeUnloadEvent) => {
			if (dirtyKeys.length > 0) event.preventDefault();
		};
		window.addEventListener('beforeunload', guard);
		return () => window.removeEventListener('beforeunload', guard);
	});
</script>

<div class="page">
	<div class="page-head">
		<h1>Settings</h1>
		{#if config}
			<span class="muted">
				{#if config.revision}Revision <code class="mono">{config.revision.slice(0, 10)}</code>{:else}Memory mode{/if}
			</span>
		{/if}
	</div>
	<InlineError resource="config" />

	{#if config}
		{#if !writable}
			<p class="notice" data-tone="warn">{config.write_blocked_reason || 'Configuration is read-only for this session.'}</p>
		{/if}
		{#if config.file_error}
			<p class="notice" data-tone="crit" role="alert">The configuration file could not be parsed: {config.file_error}. Values shown come from the running router.</p>
		{/if}
		{#if conflict}
			<div class="notice" data-tone="crit" role="alert">
				<span><strong>The configuration file changed after this page loaded.</strong> Reload to see the current values; your unsaved edits are kept where they still differ.</span>
				<span class="row">
					<button class="button button--quiet" type="button" onclick={reloadKeepingEdits}>Reload and keep edits</button>
					<button class="button button--quiet" type="button" onclick={() => { draft = {}; conflict = false; void fetchConfig(); }}>Discard edits</button>
				</span>
			</div>
		{/if}

		{#if pending.length > 0}
			<section class="panel pending" aria-labelledby="pending-title">
				<div class="panel-head">
					<h2 id="pending-title">Waiting for restart</h2>
					<span class="muted">{pending.length} saved setting{pending.length === 1 ? '' : 's'} differ from the running router</span>
				</div>
				<div class="table-scroll">
					<table class="data">
						<thead><tr><th>Setting</th><th>Running</th><th>Saved</th></tr></thead>
						<tbody>
							{#each pending as field (field.key)}
								<tr>
									<td><a href={`/settings/?focus=${encodeURIComponent(field.key)}`}>{field.label}</a> <code class="mono muted">{field.key}</code></td>
									<td>{display(field.running)}</td>
									<td><strong>{display(field.value)}</strong></td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
				<div class="restart"><Operations operations={['restart']} /></div>
			</section>
		{/if}

		<div class="layout">
			<div class="tabs" role="tablist" aria-label="Setting groups" aria-orientation="horizontal">
				{#each groups as group, index (group.id)}
					{@const count = fields.filter((field) => field.group === group.id && dirtyKeys.includes(field.key)).length}
					<button
						bind:this={tabButtons[index]}
						type="button"
						role="tab"
						id={`tab-${group.id}`}
						aria-selected={activeGroup === group.id}
						aria-controls="settings-panel"
						tabindex={activeGroup === group.id ? 0 : -1}
						onclick={() => selectGroup(group.id)}
						onkeydown={(event) => tabKeydown(event, index)}
					>
						{group.label}{#if count > 0}<span class="count">{count}</span>{/if}
					</button>
				{/each}
			</div>

			<div id="settings-panel" role="tabpanel" aria-labelledby={`tab-${activeGroup}`} class="fields" class:features={activeGroup === 'features'}>
				{#each visible as field (field.key)}
					<SettingField
						{field}
						value={effective(field.key) ?? field.value}
						disabled={!writable || saving}
						blockedBy={blockedBy(field)}
						error={errors[field.key] ?? ''}
						dirty={dirtyKeys.includes(field.key)}
						onchange={(value) => set(field, value)}
					/>
				{:else}
					<p class="empty">No settings in this group.</p>
				{/each}
			</div>
		</div>

		{#if config.backup_available && writable}
			<section class="panel" aria-labelledby="backup-title">
				<div class="panel-head"><h2 id="backup-title">Backup</h2></div>
				<div class="row between">
					<p class="muted">Every save keeps the previous file as <code class="mono">ivnp.conf.bak</code>. Restoring swaps the two, so a restore can itself be undone.</p>
					<button class="button" type="button" onclick={rollback}>Restore previous file</button>
				</div>
			</section>
		{/if}

		{#if dirtyKeys.length > 0}
			<div class="savebar" role="region" aria-label="Unsaved changes">
				<div class="savebar-inner">
					<div>
						<strong>{dirtyKeys.length} unsaved change{dirtyKeys.length === 1 ? '' : 's'}</strong>
						<button class="link" type="button" aria-expanded={showDiff} onclick={() => (showDiff = !showDiff)}>{showDiff ? 'Hide' : 'Review'}</button>
					</div>
					<div class="row">
						<button class="button" type="button" onclick={() => (draft = {})} disabled={saving}>Discard</button>
						<button class="button button--primary" type="button" onclick={save} disabled={saving || !writable} aria-busy={saving}>{saving ? 'Saving' : 'Save changes'}</button>
					</div>
				</div>
				{#if showDiff}
					<ul class="diff">
						{#each dirtyKeys as key (key)}
							{@const field = byKey.get(key)}
							<li>
								<span>{field?.label ?? key}</span>
								<span class="muted">{display(field?.value)}</span>
								<span aria-hidden="true">→</span>
								<strong>{display(draft[key])}</strong>
								<Badge tone={field?.apply === 'live' ? 'ok' : 'neutral'}>{field?.apply === 'live' ? 'Now' : 'On restart'}</Badge>
							</li>
						{/each}
					</ul>
				{/if}
			</div>
		{/if}
	{:else}
		<p class="empty">Loading configuration.</p>
	{/if}
</div>

<ConfirmDialog
	bind:this={confirmRollback}
	title="Restore the previous configuration file?"
	body="The file saved before the last change replaces the current one. Restart-only settings take effect after the next restart."
	confirmLabel="Restore file"
/>

<style>
	.row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
	}

	.between {
		justify-content: space-between;
		gap: var(--space-4);
	}

	.pending {
		border-left: 4px solid var(--color-warn-mark);
	}

	.pending a {
		font-weight: 600;
		text-underline-offset: 0.2em;
	}

	.restart {
		margin-top: var(--space-4);
		padding-top: var(--space-4);
		border-top: var(--rule-thin) solid var(--color-rule);
	}

	.layout {
		display: grid;
		gap: var(--space-4);
	}

	.tabs {
		display: flex;
		gap: 0;
		overflow-x: auto;
		border-bottom: var(--rule-thin) solid var(--color-rule-strong);
		scrollbar-width: none;
	}

	[role='tab'] {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-3) var(--space-4);
		border: 0;
		border-bottom: 3px solid transparent;
		background: transparent;
		color: var(--color-ink-2);
		font-size: var(--text-sm);
		font-weight: 650;
		white-space: nowrap;
		cursor: pointer;
	}

	[role='tab']:hover {
		color: var(--color-accent);
	}

	[role='tab'][aria-selected='true'] {
		border-bottom-color: var(--color-accent);
		color: var(--color-ink);
	}

	.count {
		min-width: 1.25rem;
		padding: 0 0.3rem;
		border-radius: 999px;
		background: var(--color-accent);
		color: var(--color-accent-ink);
		font-size: var(--text-xs);
		text-align: center;
	}

	.fields {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(min(100%, 22rem), 1fr));
		gap: var(--space-3);
		padding-bottom: 6rem;
	}

	.savebar {
		position: sticky;
		bottom: var(--space-3);
		z-index: 5;
		display: grid;
		gap: var(--space-3);
		padding: var(--space-3) var(--space-4);
		border: var(--rule-heavy) solid var(--color-ink);
		background: var(--color-paper);
		box-shadow: 6px 6px 0 var(--color-shadow);
	}

	.savebar-inner {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
	}

	.link {
		margin-left: var(--space-2);
		padding: 0;
		border: 0;
		background: none;
		color: var(--color-accent);
		font-size: var(--text-sm);
		font-weight: 650;
		text-decoration: underline;
		text-underline-offset: 0.2em;
		cursor: pointer;
	}

	.diff {
		display: grid;
		gap: var(--space-2);
		max-height: 14rem;
		padding: var(--space-3) 0 0;
		overflow-y: auto;
		border-top: var(--rule-thin) solid var(--color-rule);
		list-style: none;
		font-size: var(--text-sm);
	}

	.diff li {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		overflow-wrap: anywhere;
	}
</style>
