<script lang="ts">
	import '@fontsource-variable/archivo';
	import '../../tokens.css';
	import '$lib/styles/global.css';
	import { onMount, type Snippet } from 'svelte';
	import { page } from '$app/state';
	import { authRequired, configData, fetchStatus, refreshAll, restarting, routerStatus, setAccessToken } from '$lib/api';
	import { startLiveUpdates } from '$lib/live';
	import { paletteOpen } from '$lib/ui';
	import Header from '$lib/components/Header.svelte';
	import Toasts from '$lib/components/Toasts.svelte';
	import CommandPalette from '$lib/components/CommandPalette.svelte';

	let { children }: { children: Snippet } = $props();

	let token = $state('');
	let authenticating = $state(false);
	let authError = $state('');

	onMount(() => startLiveUpdates());

	function onKeydown(event: KeyboardEvent): void {
		const target = event.target as HTMLElement | null;
		const typing = target?.closest('input, textarea, select, [contenteditable="true"]');
		if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
			event.preventDefault();
			paletteOpen.set(true);
		} else if (event.key === '/' && !typing) {
			event.preventDefault();
			paletteOpen.set(true);
		}
	}

	async function authenticate(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		if (token.trim().length < 16 || authenticating) return;
		authenticating = true;
		authError = '';
		setAccessToken(token);
		const status = await fetchStatus();
		if (!status) {
			authError = $authRequired ? 'The token was rejected.' : 'ivnpd did not answer. Check that the router is running and retry.';
		} else {
			token = '';
			await refreshAll();
		}
		authenticating = false;
	}
</script>

<svelte:window onkeydown={onKeydown} />
<svelte:head>
	<title>{page.url.pathname === '/' ? 'IVNP router console' : `${page.url.pathname.split('/')[1]} · IVNP`}</title>
	<meta name="description" content="Local operations console for the IVNP I2P router" />
</svelte:head>

<a class="skip" href="#main">Skip to content</a>
<Header />

{#if $authRequired}
	<main id="main" class="access">
		<section class="access-panel" aria-labelledby="access-title">
			<h1 id="access-title">Access token required</h1>
			<p>This console listens on a non-loopback address. Enter the token from <code class="mono">IVNPD_WEBUI_TOKEN</code> or the ivnpd startup log. It stays in this browser tab only.</p>
			<form onsubmit={authenticate}>
				<label for="access-token">Access token</label>
				<input class="input" id="access-token" type="password" bind:value={token} autocomplete="current-password" required minlength="16" />
				{#if authError}<p class="notice" data-tone="crit" role="alert">{authError}</p>{/if}
				<button class="button button--primary" type="submit" disabled={authenticating || token.trim().length < 16} aria-busy={authenticating}>
					{authenticating ? 'Checking token' : 'Open console'}
				</button>
			</form>
		</section>
	</main>
{:else}
	{#if $restarting}
		<div class="banner notice" data-tone="info" role="status">Router restarting. Tunnels and sessions rebuild; this page reconnects automatically.</div>
	{:else if $configData?.restart_required && !page.url.pathname.startsWith('/settings')}
		<div class="banner notice" data-tone="info" role="status">
			<span>Saved settings differ from the running router and apply after a restart.</span>
			<a class="button button--quiet" href="/settings/">Review changes</a>
		</div>
	{/if}
	<main id="main">
		{@render children()}
	</main>
{/if}

<footer class="footer">
	<span>IVNP {$routerStatus?.version ?? ''}</span>
	<span>Network {$routerStatus?.network_id ?? '—'}</span>
</footer>

<Toasts />
<CommandPalette />

<style>
	.skip {
		position: absolute;
		left: var(--space-3);
		top: -3rem;
		z-index: 50;
		padding: var(--space-2) var(--space-3);
		background: var(--color-ink);
		color: var(--color-paper);
	}

	.skip:focus {
		top: var(--space-3);
	}

	main {
		min-height: calc(100vh - 9rem);
	}

	.banner {
		max-width: var(--page-max);
		margin: var(--space-3) auto 0;
		width: calc(100% - 2 * clamp(var(--space-3), 2.4vw, var(--space-8)));
	}

	.access {
		display: grid;
		place-items: center;
		padding: var(--space-8) var(--space-4);
	}

	.access-panel {
		display: grid;
		gap: var(--space-4);
		width: min(34rem, 100%);
		padding: clamp(var(--space-5), 5vw, var(--space-8));
		border: var(--rule-heavy) solid var(--color-ink);
		box-shadow: 10px 10px 0 var(--color-shadow);
	}

	.access-panel h1 {
		font-size: clamp(1.8rem, 6vw, 2.6rem);
		letter-spacing: -0.04em;
	}

	.access-panel p {
		color: var(--color-ink-2);
	}

	.access-panel form {
		display: grid;
		gap: var(--space-3);
	}

	.access-panel label {
		font-size: var(--text-sm);
		font-weight: 700;
	}

	.footer {
		display: flex;
		justify-content: space-between;
		gap: var(--space-4);
		padding: var(--space-4) clamp(var(--space-3), 2.4vw, var(--space-8));
		border-top: var(--rule-thin) solid var(--color-rule);
		color: var(--color-muted);
		font-size: var(--text-xs);
	}
</style>
