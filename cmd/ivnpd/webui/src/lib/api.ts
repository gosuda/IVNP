import { browser } from '$app/environment';
import { get, writable } from 'svelte/store';
import type {
	ConfigUpdateResult,
	DestinationsResponse,
	NetDBResponse,
	ObservabilityMetricsResponse,
	RouterConfigData,
	RouterConfigUpdate,
	RouterStatusResponse,
	RouterTunnelsResponse,
	TelemetryPoint,
	ToastMessage
} from './types';

const accessTokenKey = 'ivnp-webui-token';
const historyWindowMs = 120_000;
let toastSequence = 0;

export const routerStatus = writable<RouterStatusResponse | null>(null);
export const metrics = writable<ObservabilityMetricsResponse | null>(null);
export const tunnelsData = writable<RouterTunnelsResponse | null>(null);
export const netdbData = writable<NetDBResponse | null>(null);
export const destinationsData = writable<DestinationsResponse | null>(null);
export const telemetryHistory = writable<TelemetryPoint[]>([]);
export const metricsStreamState = writable<'connecting' | 'open' | 'error' | 'closed'>('closed');
export const netdbQuery = writable('');
export type DataResource = 'status' | 'metrics' | 'tunnels' | 'netdb' | 'destinations';
type CollectionState = { loading: boolean; error: string | null; lastSuccess: number | null };
export const resourceLabels: Record<DataResource, string> = {
	status: 'Router status', metrics: 'Metrics', tunnels: 'Tunnels', netdb: 'NetDB', destinations: 'Destinations'
};
export const collectionState = writable<Record<DataResource, CollectionState>>({
	status: { loading: false, error: null, lastSuccess: null },
	metrics: { loading: false, error: null, lastSuccess: null },
	tunnels: { loading: false, error: null, lastSuccess: null },
	netdb: { loading: false, error: null, lastSuccess: null },
	destinations: { loading: false, error: null, lastSuccess: null }
});
const requestSequence: Record<DataResource, number> = { status: 0, metrics: 0, tunnels: 0, netdb: 0, destinations: 0 };
let netdbLimit = 50;
export const authRequired = writable(false);
export const lastUpdated = writable<Date | null>(null);
export const isConfigModalOpen = writable(false);
export const toasts = writable<ToastMessage[]>([]);

export class APIError extends Error {
	constructor(
		public readonly status: number,
		message: string
	) {
		super(message);
	}
}

export function getAccessToken(): string {
	return browser ? sessionStorage.getItem(accessTokenKey) ?? '' : '';
}

export function setAccessToken(token: string): void {
	if (!browser) return;
	const value = token.trim();
	if (value) sessionStorage.setItem(accessTokenKey, value);
	else sessionStorage.removeItem(accessTokenKey);
	authRequired.set(false);
}

export function clearAccessToken(): void {
	if (browser) sessionStorage.removeItem(accessTokenKey);
	authRequired.set(true);
	metricsStreamState.set('closed');
}

export function addToast(message: Omit<ToastMessage, 'id'>): void {
	const toast = { ...message, id: ++toastSequence };
	toasts.update((items) => [...items, toast]);
	if (browser) {
		window.setTimeout(() => removeToast(toast.id), 4200);
	}
}

export function removeToast(id: number): void {
	toasts.update((items) => items.filter((item) => item.id !== id));
}

async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
	const headers = new Headers(init.headers);
	headers.set('Accept', 'application/json');
	const token = getAccessToken();
	if (token) headers.set('Authorization', `Bearer ${token}`);
	const response = await fetch(path, { ...init, headers });
	if (!response.ok) {
		let message = `${response.status} ${response.statusText}`;
		try {
			const payload = (await response.json()) as { error?: string };
			if (payload.error) message = payload.error;
		} catch {
			// The status text remains the useful fallback.
		}
		if (response.status === 401) authRequired.set(true);
		throw new APIError(response.status, message);
	}
	return (await response.json()) as T;
}

function updateCollection(resource: DataResource, update: Partial<CollectionState>): void {
	collectionState.update((states) => ({ ...states, [resource]: { ...states[resource], ...update } }));
}

export function markMetricsInterrupted(message: string): void {
	updateCollection('metrics', { error: message });
}

async function collect<T>(resource: DataResource, path: string, accept: (response: T) => void): Promise<T | null> {
	const sequence = ++requestSequence[resource];
	updateCollection(resource, { loading: true });
	try {
		const response = await apiRequest<T>(path, { signal: AbortSignal.timeout(10_000) });
		if (sequence !== requestSequence[resource]) return null;
		accept(response);
		updateCollection(resource, { loading: false, error: null, lastSuccess: Date.now() });
		return response;
	} catch (error) {
		if (sequence === requestSequence[resource]) {
			updateCollection(resource, { loading: false, error: error instanceof Error ? error.message : 'Collection failed' });
		}
		return null;
	}
}

export async function fetchStatus(): Promise<RouterStatusResponse | null> {
	return collect<RouterStatusResponse>('status', '/api/status', (response) => {
		routerStatus.set(response);
		authRequired.set(false);
	});
}

export function applyMetrics(response: ObservabilityMetricsResponse): void {
	if (!Number.isFinite(response.sampled_at)) throw new Error('Invalid metrics timestamp');
	const previous = get(metrics);
	if (previous && response.sampled_at < previous.sampled_at) return;
	const builds = response.tunnels.build_successes + response.tunnels.build_failures;
	const buildSuccessRate = builds > 0 ? (response.tunnels.build_successes / builds) * 100 : null;
	const point: TelemetryPoint = {
		timestamp: response.sampled_at,
		inRate: response.bandwidth.in_rate_bps,
		outRate: response.bandwidth.out_rate_bps,
		activeTunnels: response.tunnels.active,
		buildSuccessRate,
		routers: response.netdb.routers,
		floodfills: response.netdb.floodfills,
		goroutines: response.process.goroutines,
		heapBytes: response.process.heap_inuse_bytes
	};
	requestSequence.metrics++;
	metrics.set(response);
	updateCollection('metrics', { loading: false, error: null, lastSuccess: Date.now() });
	telemetryHistory.update((points) => [
		...points.filter((existing) => existing.timestamp > point.timestamp - historyWindowMs && existing.timestamp < point.timestamp),
		point
	]);
}

export async function fetchMetrics(): Promise<ObservabilityMetricsResponse | null> {
	return collect<ObservabilityMetricsResponse>('metrics', '/api/metrics', applyMetrics);
}

export async function fetchTunnels(): Promise<RouterTunnelsResponse | null> {
	return collect<RouterTunnelsResponse>('tunnels', '/api/tunnels', tunnelsData.set);
}

export async function fetchNetDB(query = get(netdbQuery), limit = netdbLimit): Promise<NetDBResponse | null> {
	const appliedQuery = query.trim();
	if (appliedQuery !== get(netdbQuery) || limit !== netdbLimit) {
		netdbData.set(null);
		updateCollection('netdb', { lastSuccess: null, error: null });
	}
	netdbQuery.set(appliedQuery);
	netdbLimit = limit;
	const params = new URLSearchParams({ limit: String(limit) });
	if (appliedQuery) params.set('q', appliedQuery);
	return collect<NetDBResponse>('netdb', `/api/netdb?${params}`, netdbData.set);
}

export async function fetchDestinations(): Promise<DestinationsResponse | null> {
	return collect<DestinationsResponse>('destinations', '/api/destinations', destinationsData.set);
}

export async function fetchConfig(): Promise<RouterConfigData> {
	return apiRequest<RouterConfigData>('/api/config');
}

export async function updateConfig(update: RouterConfigUpdate): Promise<ConfigUpdateResult> {
	return apiRequest<ConfigUpdateResult>('/api/config', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(update)
	});
}

export async function triggerReseed(): Promise<string> {
	const response = await apiRequest<{ result: string }>('/api/actions/reseed', { method: 'POST' });
	return response.result;
}

export async function triggerTunnelProbe(): Promise<string> {
	const response = await apiRequest<{ result: string }>('/api/actions/tunnel-probe', { method: 'POST' });
	return response.result;
}

export function metricsEventURL(): string {
	const token = getAccessToken();
	if (!token) return '/api/events';
	return `/api/events?token=${encodeURIComponent(token)}`;
}

export async function refreshDashboard(): Promise<{ failed: DataResource[] }> {
	const resources: DataResource[] = ['status', 'metrics', 'tunnels', 'netdb', 'destinations'];
	const responses = await Promise.all([fetchStatus(), fetchMetrics(), fetchTunnels(), fetchNetDB(), fetchDestinations()]);
	const failed = resources.filter((_, index) => responses[index] === null);
	if (failed.length === 0) lastUpdated.set(new Date());
	return { failed };
}

export async function retryResource(resource: DataResource): Promise<unknown> {
	const requests = { status: fetchStatus, metrics: fetchMetrics, tunnels: fetchTunnels, netdb: fetchNetDB, destinations: fetchDestinations };
	return requests[resource]();
}

export function formatBytes(value: number, decimals = 1): string {
	if (!Number.isFinite(value) || value <= 0) return '0 B';
	const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
	const index = Math.max(0, Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1));
	return `${(value / 1024 ** index).toFixed(index === 0 && Number.isInteger(value) ? 0 : decimals)} ${units[index]}`;
}

export function formatRate(value: number, decimals = 1): string {
	return `${formatBytes(value, decimals)}/s`;
}

export function formatDuration(seconds: number): string {
	if (!Number.isFinite(seconds) || seconds < 0) return '—';
	const days = Math.floor(seconds / 86400);
	const hours = Math.floor((seconds % 86400) / 3600);
	const minutes = Math.floor((seconds % 3600) / 60);
	if (days > 0) return `${days}d ${hours}h`;
	if (hours > 0) return `${hours}h ${minutes}m`;
	return `${minutes}m ${Math.floor(seconds % 60)}s`;
}

export function shortHash(value: string, head = 10, tail = 6): string {
	if (!value) return '—';
	if (value.length <= head + tail + 1) return value;
	return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export async function copyText(value: string, label: string): Promise<void> {
	try {
		await navigator.clipboard.writeText(value);
		addToast({ type: 'success', title: label });
	} catch {
		addToast({ type: 'error', title: 'Clipboard unavailable' });
	}
}
