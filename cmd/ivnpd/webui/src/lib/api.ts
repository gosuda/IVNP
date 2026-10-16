import { browser } from '$app/environment';
import { get, writable } from 'svelte/store';
import type {
	ActionLogEntry,
	ActionLogResponse,
	ConfigResponse,
	ConfigUpdateResult,
	ConfigValue,
	DestinationsResponse,
	HistoryResponse,
	HistorySample,
	NetDBResponse,
	ObservabilityMetricsResponse,
	PeerItem,
	PeersResponse,
	RouterStatusResponse,
	RouterTunnelsResponse,
	ToastMessage
} from './types';

const accessTokenKey = 'ivnp-webui-token';
const historyLimit = 720;
const historyIntervalMs = 5_000;

export type Resource = 'status' | 'metrics' | 'tunnels' | 'destinations' | 'history' | 'config' | 'actions';
export interface CollectionState {
	loading: boolean;
	error: string | null;
	lastSuccess: number | null;
}

export const resourceLabels: Record<Resource, string> = {
	status: 'Router status',
	metrics: 'Live metrics',
	tunnels: 'Tunnels',
	destinations: 'Destinations',
	history: 'History',
	config: 'Configuration',
	actions: 'Activity'
};

const idle = (): CollectionState => ({ loading: false, error: null, lastSuccess: null });

export const routerStatus = writable<RouterStatusResponse | null>(null);
export const metrics = writable<ObservabilityMetricsResponse | null>(null);
export const tunnelsData = writable<RouterTunnelsResponse | null>(null);
export const destinationsData = writable<DestinationsResponse | null>(null);
export const history = writable<HistorySample[]>([]);
export const configData = writable<ConfigResponse | null>(null);
export const actionLog = writable<ActionLogEntry[]>([]);
export const collection = writable<Record<Resource, CollectionState>>({
	status: idle(),
	metrics: idle(),
	tunnels: idle(),
	destinations: idle(),
	history: idle(),
	config: idle(),
	actions: idle()
});
export const streamState = writable<'connecting' | 'live' | 'reconnecting' | 'offline'>('offline');
export const restarting = writable(false);
export const authRequired = writable(false);
export const toasts = writable<ToastMessage[]>([]);

const sequence: Record<Resource, number> = { status: 0, metrics: 0, tunnels: 0, destinations: 0, history: 0, config: 0, actions: 0 };
const recoveryListeners = new Set<() => void>();
let toastSequence = 0;

/** Registers a callback that runs once the router answers again after a restart. */
export function onRecovered(listener: () => void): () => void {
	recoveryListeners.add(listener);
	return () => recoveryListeners.delete(listener);
}

export class APIError extends Error {
	constructor(
		public readonly status: number,
		message: string,
		public readonly body: Record<string, unknown> = {}
	) {
		super(message);
	}
}

export function getAccessToken(): string {
	return browser ? (sessionStorage.getItem(accessTokenKey) ?? '') : '';
}

export function setAccessToken(token: string): void {
	if (!browser) return;
	const value = token.trim();
	if (value) sessionStorage.setItem(accessTokenKey, value);
	else sessionStorage.removeItem(accessTokenKey);
	authRequired.set(false);
}

export function addToast(message: Omit<ToastMessage, 'id'>): void {
	const toast = { ...message, id: ++toastSequence };
	toasts.update((items) => [...items.slice(-4), toast]);
	// Errors stay until dismissed so the reason can be read and acted on.
	if (browser && toast.type !== 'error') window.setTimeout(() => removeToast(toast.id), 5000);
}

export function removeToast(id: number): void {
	toasts.update((items) => items.filter((item) => item.id !== id));
}

function markRecovered(): void {
	if (!get(restarting)) return;
	restarting.set(false);
	for (const listener of recoveryListeners) listener();
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
	const headers = new Headers(init.headers);
	headers.set('Accept', 'application/json');
	const token = getAccessToken();
	if (token) headers.set('Authorization', `Bearer ${token}`);
	const response = await fetch(path, { ...init, headers });
	if (!response.ok) {
		let body: Record<string, unknown> = {};
		let message = `${response.status} ${response.statusText}`;
		try {
			body = (await response.json()) as Record<string, unknown>;
			if (typeof body.error === 'string') message = body.error;
		} catch {
			// Plain-text middleware errors keep the status line as the message.
		}
		if (response.status === 401) authRequired.set(true);
		if (response.status === 503 && body.restarting === true) restarting.set(true);
		throw new APIError(response.status, message, body);
	}
	const answersDuringRestart =
		path === '/api/history' || path === '/api/actions/log' || (path === '/api/config' && (init.method ?? 'GET') === 'GET');
	if (!answersDuringRestart) markRecovered();
	return (await response.json()) as T;
}

function update(resource: Resource, patch: Partial<CollectionState>): void {
	collection.update((states) => ({ ...states, [resource]: { ...states[resource], ...patch } }));
}

async function collect<T>(resource: Resource, path: string, accept: (value: T) => void): Promise<T | null> {
	const current = ++sequence[resource];
	update(resource, { loading: true });
	try {
		const value = await request<T>(path, { signal: AbortSignal.timeout(10_000) });
		if (current !== sequence[resource]) return null;
		accept(value);
		update(resource, { loading: false, error: null, lastSuccess: Date.now() });
		return value;
	} catch (error) {
		if (current === sequence[resource]) {
			const restartingNow = error instanceof APIError && error.body.restarting === true;
			update(resource, { loading: false, error: restartingNow ? null : errorMessage(error) });
		}
		return null;
	}
}

export function errorMessage(error: unknown): string {
	if (error instanceof DOMException && error.name === 'TimeoutError') return 'The router did not answer within 10 seconds.';
	if (error instanceof TypeError) return 'The console cannot reach ivnpd.';
	return error instanceof Error ? error.message : 'Request failed';
}

export const fetchStatus = () => collect<RouterStatusResponse>('status', '/api/status', (value) => routerStatus.set(value));
export const fetchTunnels = () => collect<RouterTunnelsResponse>('tunnels', '/api/tunnels', (value) => tunnelsData.set(value));
export const fetchDestinations = () => collect<DestinationsResponse>('destinations', '/api/destinations', (value) => destinationsData.set(value));
export const fetchConfig = () => collect<ConfigResponse>('config', '/api/config', (value) => configData.set(value));
export const fetchActionLog = () => collect<ActionLogResponse>('actions', '/api/actions/log', (value) => actionLog.set(value.entries));
export const fetchHistory = () => collect<HistoryResponse>('history', '/api/history', (value) => history.set(value.samples.slice(-historyLimit)));
export const fetchMetrics = () => collect<ObservabilityMetricsResponse>('metrics', '/api/metrics', applyMetrics);

/** Accepts one live metrics sample and extends the server history at its 5 s cadence. */
export function applyMetrics(value: ObservabilityMetricsResponse): void {
	if (!Number.isFinite(value.sampled_at)) throw new Error('Invalid metrics timestamp');
	const previous = get(metrics);
	if (previous && value.sampled_at < previous.sampled_at) return;
	metrics.set(value);
	update('metrics', { loading: false, error: null, lastSuccess: Date.now() });
	history.update((samples) => {
		const last = samples.at(-1);
		if (last && value.sampled_at - last.t < historyIntervalMs) return samples;
		const sample: HistorySample = {
			t: value.sampled_at,
			in_rate_bps: value.bandwidth.in_rate_bps,
			out_rate_bps: value.bandwidth.out_rate_bps,
			active_tunnels: value.tunnels.active,
			build_successes: value.tunnels.build_successes,
			build_failures: value.tunnels.build_failures,
			netdb_routers: value.netdb.routers,
			floodfills: value.netdb.floodfills,
			goroutines: value.process.goroutines,
			heap_inuse_bytes: value.process.heap_inuse_bytes
		};
		return [...samples.slice(-(historyLimit - 1)), sample];
	});
}

export function metricsEventURL(): string {
	const token = getAccessToken();
	return token ? `/api/events?token=${encodeURIComponent(token)}` : '/api/events';
}

export async function refreshAll(): Promise<void> {
	await Promise.all([fetchStatus(), fetchMetrics(), fetchTunnels(), fetchDestinations(), fetchConfig(), fetchActionLog()]);
}

export function retry(resource: Resource): Promise<unknown> {
	const calls: Record<Resource, () => Promise<unknown>> = {
		status: fetchStatus,
		metrics: fetchMetrics,
		tunnels: fetchTunnels,
		destinations: fetchDestinations,
		history: fetchHistory,
		config: fetchConfig,
		actions: fetchActionLog
	};
	return calls[resource]();
}

export async function searchNetDB(query: string, limit = 50): Promise<NetDBResponse> {
	const params = new URLSearchParams({ limit: String(limit) });
	if (query.trim()) params.set('q', query.trim());
	return request<NetDBResponse>(`/api/netdb?${params}`, { signal: AbortSignal.timeout(10_000) });
}

const peerCache = new Map<string, { at: number; peer: PeerItem | null }>();

/** Resolves peers by B32 with a 15 s cache; unknown addresses map to null. */
export async function fetchPeers(addresses: string[]): Promise<Map<string, PeerItem | null>> {
	const now = Date.now();
	const result = new Map<string, PeerItem | null>();
	const wanted = Array.from(new Set(addresses.filter(Boolean)));
	const stale = wanted.filter((address) => {
		const cached = peerCache.get(address);
		if (cached && now - cached.at < 15_000) {
			result.set(address, cached.peer);
			return false;
		}
		return true;
	});
	for (let offset = 0; offset < stale.length; offset += 64) {
		const batch = stale.slice(offset, offset + 64);
		const response = await request<PeersResponse>(`/api/peers?b32=${encodeURIComponent(batch.join(','))}`);
		for (const peer of response.peers) {
			peerCache.set(peer.b32, { at: now, peer });
			result.set(peer.b32, peer);
		}
		for (const address of response.missing) {
			peerCache.set(address, { at: now, peer: null });
			result.set(address, null);
		}
	}
	return result;
}

async function action(path: string): Promise<string> {
	try {
		const response = await request<{ result: string }>(path, { method: 'POST' });
		return response.result;
	} finally {
		void fetchActionLog();
	}
}

export const triggerReseed = () => action('/api/actions/reseed');
export const triggerTunnelProbe = () => action('/api/actions/tunnel-probe');

export async function triggerRestart(): Promise<string> {
	const result = await action('/api/actions/restart');
	restarting.set(true);
	return result;
}

export async function patchConfig(revision: string, changes: Record<string, ConfigValue>): Promise<ConfigUpdateResult> {
	try {
		return await request<ConfigUpdateResult>('/api/config', {
			method: 'PATCH',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ revision, changes })
		});
	} finally {
		void fetchActionLog();
	}
}

export async function rollbackConfig(revision: string): Promise<ConfigUpdateResult> {
	try {
		return await request<ConfigUpdateResult>('/api/config/rollback', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ revision })
		});
	} finally {
		void fetchActionLog();
	}
}

export async function copyText(value: string, label: string): Promise<void> {
	try {
		await navigator.clipboard.writeText(value);
		addToast({ type: 'success', title: `${label} copied` });
	} catch {
		addToast({ type: 'error', title: 'Clipboard unavailable', description: 'The browser blocked clipboard access for this page.' });
	}
}
