import { get } from 'svelte/store';
import {
	applyMetrics,
	collection,
	fetchActionLog,
	fetchConfig,
	fetchDestinations,
	fetchHistory,
	fetchMetrics,
	fetchStatus,
	fetchTunnels,
	metricsEventURL,
	onRecovered,
	refreshAll,
	restarting,
	streamState
} from './api';
import type { Resource } from './api';
import type { ObservabilityMetricsResponse } from './types';

/**
 * Owns every timer and the metrics stream for the whole console so pages only
 * read stores. Returns a stop function for the root layout to call on unmount.
 */
export function startLiveUpdates(): () => void {
	let stopped = false;
	let source: EventSource | null = null;
	let lastSample = 0;
	const timers: number[] = [];

	const idle = (resource: Resource) => !get(collection)[resource].loading;

	function connect(): void {
		source?.close();
		streamState.set(get(streamState) === 'offline' ? 'connecting' : 'reconnecting');
		source = new EventSource(metricsEventURL());
		source.addEventListener('metrics', (event) => {
			try {
				const envelope = JSON.parse((event as MessageEvent<string>).data) as { metrics: ObservabilityMetricsResponse };
				applyMetrics(envelope.metrics);
				lastSample = Date.now();
				streamState.set('live');
			} catch {
				streamState.set('reconnecting');
			}
		});
		source.addEventListener('error', () => {
			if (!stopped) streamState.set('reconnecting');
		});
	}

	function every(intervalMs: number, task: () => void): void {
		timers.push(window.setInterval(() => !stopped && task(), intervalMs));
	}

	const unsubscribe = onRecovered(() => {
		void fetchHistory();
		void refreshAll();
		connect();
	});

	void (async () => {
		await Promise.all([refreshAll(), fetchHistory()]);
		if (stopped) return;
		lastSample = Date.now();
		connect();
	})();

	every(5_000, () => {
		if (idle('status')) void fetchStatus();
		if (get(restarting)) return;
		if (idle('tunnels')) void fetchTunnels();
		if (idle('destinations')) void fetchDestinations();
		// The stream delivers one sample per second; poll only when it has gone quiet.
		if (Date.now() - lastSample > 4_000 && idle('metrics')) {
			streamState.set('reconnecting');
			void fetchMetrics();
		}
	});
	every(15_000, () => idle('actions') && void fetchActionLog());
	every(30_000, () => idle('config') && void fetchConfig());
	every(60_000, () => {
		if (get(streamState) !== 'live' && !get(restarting)) connect();
	});

	return () => {
		stopped = true;
		unsubscribe();
		source?.close();
		streamState.set('offline');
		for (const timer of timers) window.clearInterval(timer);
	};
}
