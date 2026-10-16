<script lang="ts">
	import type { ConfigField, ConfigValue } from '$lib/types';
	import Badge from './Badge.svelte';

	let {
		field,
		value,
		disabled = false,
		blockedBy = '',
		error = '',
		dirty = false,
		onchange
	}: {
		field: ConfigField;
		value: ConfigValue;
		disabled?: boolean;
		blockedBy?: string;
		error?: string;
		dirty?: boolean;
		onchange: (value: ConfigValue) => void;
	} = $props();

	const id = $derived(`field-${field.key.replace(/\W/g, '-')}`);
	const describedBy = $derived(`${id}-help${error ? ` ${id}-error` : ''}`);
	const inactive = $derived(disabled || Boolean(blockedBy));

	function listText(input: ConfigValue): string {
		return Array.isArray(input) ? input.join('\n') : String(input ?? '');
	}

	function parseList(text: string): string[] {
		return text
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter(Boolean);
	}
</script>

<div class="setting" class:toggle={field.type === 'bool'} class:dirty data-key={field.key}>
	{#if field.type === 'bool'}
		<label class="switch-row" for={id}>
			<span class="text">
				<span class="name">{field.label}</span>
				<span class="help" id={`${id}-help`}>{blockedBy ? `Requires ${blockedBy}.` : field.description}</span>
			</span>
			<input
				{id}
				type="checkbox"
				role="switch"
				checked={Boolean(value)}
				disabled={inactive}
				aria-describedby={describedBy}
				aria-invalid={error ? 'true' : undefined}
				onchange={(event) => onchange(event.currentTarget.checked)}
			/>
		</label>
	{:else}
		<label class="name" for={id}>{field.label}{#if field.unit}<span class="muted"> ({field.unit})</span>{/if}</label>
		<span class="help" id={`${id}-help`}>
			{blockedBy ? `Requires ${blockedBy}.` : field.description}
			{#if field.type === 'int' && field.min !== null && field.max !== null}<span class="muted"> Range {field.min.toLocaleString()} to {field.max.toLocaleString()}.</span>{/if}
			{#if field.type === 'duration'}<span class="muted"> Use a number with ms, s, m, or h, for example 90s or 6h.</span>{/if}
			{#if field.type === 'list'}<span class="muted"> One entry per line.</span>{/if}
		</span>
		{#if field.type === 'enum'}
			<select {id} class="select" value={String(value)} disabled={inactive} aria-describedby={describedBy} onchange={(event) => onchange(event.currentTarget.value)}>
				{#each field.options ?? [] as option (option)}<option value={option}>{option}</option>{/each}
			</select>
		{:else if field.type === 'int'}
			<input
				{id}
				class="input"
				type="number"
				inputmode="numeric"
				step="1"
				min={field.min ?? undefined}
				max={field.max ?? undefined}
				value={Number(value)}
				disabled={inactive}
				aria-describedby={describedBy}
				aria-invalid={error ? 'true' : undefined}
				onchange={(event) => onchange(event.currentTarget.valueAsNumber)}
			/>
		{:else if field.type === 'list'}
			<textarea
				{id}
				class="textarea"
				value={listText(value)}
				disabled={inactive}
				aria-describedby={describedBy}
				aria-invalid={error ? 'true' : undefined}
				spellcheck="false"
				onchange={(event) => onchange(parseList(event.currentTarget.value))}
			></textarea>
		{:else}
			<input
				{id}
				class="input"
				type="text"
				value={String(value ?? '')}
				disabled={inactive}
				aria-describedby={describedBy}
				aria-invalid={error ? 'true' : undefined}
				spellcheck="false"
				autocomplete="off"
				onchange={(event) => onchange(event.currentTarget.value.trim())}
			/>
		{/if}
	{/if}
	<div class="meta">
		<Badge tone={field.apply === 'live' ? 'ok' : 'neutral'}>{field.apply === 'live' ? 'Applies now' : 'Applies on restart'}</Badge>
		{#if dirty}<Badge tone="info">Unsaved</Badge>{:else if field.pending}<Badge tone="warn">Waiting for restart</Badge>{/if}
		<code class="mono key">{field.key}</code>
	</div>
	{#if error}<p class="error" id={`${id}-error`} role="alert">{error}</p>{/if}
</div>

<style>
	.setting {
		display: grid;
		align-content: start;
		gap: var(--space-2);
		min-width: 0;
		padding: var(--space-4);
		border: var(--rule-thin) solid var(--color-rule);
		background: var(--color-paper);
		scroll-margin-top: 7rem;
	}

	.setting.dirty {
		border-color: var(--color-accent);
		box-shadow: inset 3px 0 var(--color-accent);
	}

	.switch-row {
		display: flex;
		align-items: start;
		justify-content: space-between;
		gap: var(--space-4);
		cursor: pointer;
	}

	.text {
		display: grid;
		gap: var(--space-1);
	}

	.name {
		font-size: var(--text-sm);
		font-weight: 700;
	}

	.help {
		color: var(--color-ink-2);
		font-size: var(--text-xs);
		line-height: 1.5;
	}

	input[role='switch'] {
		position: relative;
		flex: 0 0 auto;
		width: 2.6rem;
		height: 1.45rem;
		margin: 0;
		border: var(--rule-thin) solid var(--color-rule-strong);
		border-radius: 999px;
		background: var(--color-paper-3);
		appearance: none;
		cursor: pointer;
		transition: background-color var(--dur-base) var(--ease-out);
	}

	input[role='switch']::after {
		content: '';
		position: absolute;
		top: 2px;
		left: 2px;
		width: calc(1.45rem - 6px);
		height: calc(1.45rem - 6px);
		border-radius: 50%;
		background: var(--color-paper);
		box-shadow: 0 1px 2px var(--color-shadow);
		transition: transform var(--dur-base) var(--ease-out);
	}

	input[role='switch']:checked {
		border-color: var(--color-accent);
		background: var(--color-accent);
	}

	input[role='switch']:checked::after {
		transform: translateX(1.15rem);
	}

	input[role='switch']:disabled {
		cursor: not-allowed;
		opacity: 0.5;
	}

	.meta {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		margin-top: var(--space-1);
	}

	.key {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.error {
		color: var(--color-crit);
		font-size: var(--text-xs);
		font-weight: 600;
	}
</style>
