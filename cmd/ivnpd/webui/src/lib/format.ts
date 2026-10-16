// Display formatting shared by every view. Pure functions only.

export function formatBytes(value: number, decimals = 1): string {
	if (!Number.isFinite(value) || value <= 0) return '0 B';
	const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
	const index = Math.max(0, Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1));
	return `${(value / 1024 ** index).toFixed(index === 0 && Number.isInteger(value) ? 0 : decimals)} ${units[index]}`;
}

export function formatRate(value: number, decimals = 1): string {
	return `${formatBytes(value, decimals)}/s`;
}

export function formatCount(value: number): string {
	return Number.isFinite(value) ? value.toLocaleString() : '—';
}

export function formatPercent(numerator: number, denominator: number): string {
	if (!denominator) return '—';
	return `${Math.round((numerator / denominator) * 100)}%`;
}

export function formatDuration(seconds: number): string {
	if (!Number.isFinite(seconds) || seconds < 0) return '—';
	const days = Math.floor(seconds / 86400);
	const hours = Math.floor((seconds % 86400) / 3600);
	const minutes = Math.floor((seconds % 3600) / 60);
	if (days > 0) return `${days}d ${hours}h`;
	if (hours > 0) return `${hours}h ${minutes}m`;
	if (minutes > 0) return `${minutes}m ${Math.floor(seconds % 60)}s`;
	return `${Math.floor(seconds)}s`;
}

/** Relative age such as "12s ago" or "3h ago" for an elapsed number of seconds. */
export function formatAgoSeconds(seconds: number): string {
	if (!Number.isFinite(seconds) || seconds < 0) return '—';
	if (seconds < 5) return 'just now';
	if (seconds < 60) return `${Math.floor(seconds)}s ago`;
	if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
	if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
	return `${Math.floor(seconds / 86400)}d ago`;
}

export function formatAgo(timestampMs: number, now = Date.now()): string {
	return formatAgoSeconds((now - timestampMs) / 1000);
}

export function formatTimestamp(timestampMs: number): string {
	return timestampMs > 0 ? new Date(timestampMs).toLocaleString() : '—';
}

/** Middle truncation that keeps both ends of an identifier comparable. */
export function middle(value: string, head = 8, tail = 6): string {
	if (!value) return '—';
	if (value.length <= head + tail + 1) return value;
	return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/** Short label for a B32 address without the .b32.i2p suffix. */
export function b32Label(value: string, head = 8, tail = 4): string {
	return middle(value.replace(/\.b32\.i2p$/, ''), head, tail);
}

export function tunnelLabel(id: number): string {
	return `0x${id.toString(16).padStart(8, '0')}`;
}

export interface CapabilityFlag {
	code: string;
	label: string;
	tone: 'neutral' | 'ok' | 'warn' | 'crit';
}

const capabilityLabels: Record<string, Omit<CapabilityFlag, 'code'>> = {
	K: { label: 'Bandwidth < 12 KB/s', tone: 'neutral' },
	L: { label: 'Bandwidth 12-48 KB/s', tone: 'neutral' },
	M: { label: 'Bandwidth 48-64 KB/s', tone: 'neutral' },
	N: { label: 'Bandwidth 64-128 KB/s', tone: 'neutral' },
	O: { label: 'Bandwidth 128-256 KB/s', tone: 'neutral' },
	P: { label: 'Bandwidth 256-2000 KB/s', tone: 'neutral' },
	X: { label: 'Bandwidth > 2000 KB/s', tone: 'neutral' },
	f: { label: 'Floodfill', tone: 'ok' },
	R: { label: 'Reachable', tone: 'ok' },
	U: { label: 'Unreachable', tone: 'warn' },
	H: { label: 'Hidden', tone: 'neutral' },
	D: { label: 'Moderate congestion', tone: 'warn' },
	E: { label: 'High congestion', tone: 'warn' },
	G: { label: 'Rejecting tunnels', tone: 'crit' }
};

/** Decodes a RouterInfo caps string into labelled flags; unknown letters pass through. */
export function decodeCaps(caps: string): CapabilityFlag[] {
	return Array.from(new Set(caps.split(''))).map((code) => ({
		code,
		...(capabilityLabels[code] ?? { label: `Capability ${code}`, tone: 'neutral' as const })
	}));
}
