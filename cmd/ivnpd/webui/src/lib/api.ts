import { browser } from '$app/environment';
import { writable } from 'svelte/store';
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
const maxHistoryPoints = 120;
let toastSequence = 0;

export const routerStatus = writable<RouterStatusResponse | null>(null);
export const metrics = writable<ObservabilityMetricsResponse | null>(null);
export const tunnelsData = writable<RouterTunnelsResponse | null>(null);
export const netdbData = writable<NetDBResponse | null>(null);
export const destinationsData = writable<DestinationsResponse | null>(null);
export const telemetryHistory = writable<TelemetryPoint[]>([]);
export const isConnected = writable(false);
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
	isConnected.set(false);
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

export async function fetchStatus(): Promise<RouterStatusResponse | null> {
	try {
		const response = await apiRequest<RouterStatusResponse>('/api/status');
		routerStatus.set(response);
		isConnected.set(true);
		authRequired.set(false);
		lastUpdated.set(new Date());
		return response;
	} catch {
		isConnected.set(false);
		return null;
	}
}

export function applyMetrics(response: ObservabilityMetricsResponse): void {
	metrics.set(response);
	const builds = response.tunnels.build_successes + response.tunnels.build_failures;
	const buildSuccessRate = builds > 0 ? (response.tunnels.build_successes / builds) * 100 : 0;
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
	telemetryHistory.update((points) => [...points, point].slice(-maxHistoryPoints));
	isConnected.set(true);
	lastUpdated.set(new Date(response.sampled_at));
}

export async function fetchMetrics(): Promise<ObservabilityMetricsResponse | null> {
	try {
		const response = await apiRequest<ObservabilityMetricsResponse>('/api/metrics');
		applyMetrics(response);
		return response;
	} catch {
		return null;
	}
}

export async function fetchTunnels(): Promise<RouterTunnelsResponse | null> {
	try {
		const response = await apiRequest<RouterTunnelsResponse>('/api/tunnels');
		tunnelsData.set(response);
		return response;
	} catch {
		return null;
	}
}

export async function fetchNetDB(query = '', limit = 50): Promise<NetDBResponse | null> {
	try {
		const params = new URLSearchParams({ limit: String(limit) });
		if (query.trim()) params.set('q', query.trim());
		const response = await apiRequest<NetDBResponse>(`/api/netdb?${params}`);
		netdbData.set(response);
		return response;
	} catch {
		return null;
	}
}

export async function fetchDestinations(): Promise<DestinationsResponse | null> {
	try {
		const response = await apiRequest<DestinationsResponse>('/api/destinations');
		destinationsData.set(response);
		return response;
	} catch {
		return null;
	}
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

export async function refreshDashboard(): Promise<void> {
	await Promise.all([fetchStatus(), fetchMetrics(), fetchTunnels(), fetchNetDB(), fetchDestinations()]);
}

export function formatBytes(value: number, decimals = 1): string {
	if (!Number.isFinite(value) || value <= 0) return '0 B';
	const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
	const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
	return `${(value / 1024 ** index).toFixed(index === 0 ? 0 : decimals)} ${units[index]}`;
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
