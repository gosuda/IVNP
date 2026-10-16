// Wire types for the ivnpd WebUI API (contract v2). Keys mirror the Go JSON tags.

export interface ReadinessDetails {
	bootstrap_stage: number;
	netdb_routers: number;
	router_info_publications: number;
	lease_set2_publications: number;
	exploratory_inbound_tunnels: number;
	exploratory_outbound_tunnels: number;
	client_inbound_tunnels: number;
	client_outbound_tunnels: number;
	floodfill_configured: boolean;
	floodfill_advertised: boolean;
	router_reachable: boolean;
	ssu2_vector_io: boolean;
	ssu2_kernel_drop_accounting: boolean;
	process_goroutines: number;
	process_heap_inuse_bytes: number;
	process_heap_objects: number;
}

export type UnmetConditionKey =
	| 'netdb_routers'
	| 'router_info_publication'
	| 'lease_set2_publication'
	| 'exploratory_inbound'
	| 'exploratory_outbound'
	| 'client_inbound'
	| 'client_outbound'
	| 'floodfill_advertisement';

export interface UnmetCondition {
	key: UnmetConditionKey;
	current: number | null;
	required: number | null;
}

export interface TransportStatus {
	enabled: boolean;
	bind_address: string;
	advertised_address: string;
	active_sessions: number;
	max_sessions: number;
}

export interface ServiceStatus {
	enabled: boolean;
	address: string;
	listening: boolean | null;
}

export interface Capabilities {
	config_writable: boolean;
	config_write_reason: string;
	restart: boolean;
	peer_identities: boolean;
}

export interface RouterStatusResponse {
	ready: boolean;
	state: string;
	router_hash: string;
	router_b32: string;
	network_id: number;
	version: string;
	family: string;
	uptime_seconds: number;
	reachability: 'reachable' | 'testing' | 'firewalled' | 'disabled';
	floodfill_configured: boolean;
	floodfill_advertised: boolean;
	transit_configured: boolean;
	readiness: ReadinessDetails;
	unmet_conditions: UnmetCondition[];
	capabilities: Capabilities;
	transports: { ntcp2: TransportStatus; ssu2: TransportStatus };
	reseed: {
		enabled: boolean;
		required: boolean;
		endpoints: number;
		attempts: number;
		successes: number;
		failures: number;
	};
	services: {
		http_proxy: ServiceStatus;
		socks5: ServiceStatus;
		sam: ServiceStatus;
		metrics: ServiceStatus;
		control: ServiceStatus;
		addressbook: { enabled: boolean; subscriptions: number };
	};
}

export interface ObservabilityMetricsResponse {
	sampled_at: number;
	bandwidth: {
		in_rate_bps: number;
		out_rate_bps: number;
		in_total_bytes: number;
		out_total_bytes: number;
		peak_rate_bps: number;
		rate_limit_bps: number;
	};
	tunnels: {
		active: number;
		exploratory_in: number;
		exploratory_out: number;
		client_in: number;
		client_out: number;
		builds_total: number;
		build_successes: number;
		build_failures: number;
		forwarded_messages: number;
	};
	netdb: {
		routers: number;
		floodfills: number;
		lookups: number;
		lookup_failures: number;
		stores: number;
		store_failures: number;
	};
	transport: {
		sessions: number;
		connections: number;
		disconnections: number;
		handshake_failures: number;
	};
	proxy: { requests: number; failures: number; active: number };
	process: {
		goroutines: number;
		heap_inuse_bytes: number;
		heap_objects: number;
		allocated_bytes_total: number;
		gc_cycles: number;
		gc_pause_ns: number;
	};
}

export interface HistorySample {
	t: number;
	in_rate_bps: number;
	out_rate_bps: number;
	active_tunnels: number;
	build_successes: number;
	build_failures: number;
	netdb_routers: number;
	floodfills: number;
	goroutines: number;
	heap_inuse_bytes: number;
}

export interface HistoryResponse {
	interval_seconds: number;
	samples: HistorySample[];
}

export interface RouterTunnelItem {
	id: number;
	direction: 'inbound' | 'outbound';
	kind: 'exploratory' | 'client';
	destination_name?: string;
	owner?: string;
	gateway?: string;
	gateway_tunnel_id?: number;
	hop_count: number;
	hops?: string[];
	expires_at: number;
	remaining_seconds: number;
	state: 'established' | 'expiring';
}

export interface RouterTunnelsResponse {
	exploratory_inbound_active: number;
	exploratory_inbound_target: number;
	exploratory_outbound_active: number;
	exploratory_outbound_target: number;
	exploratory_pool_capacity: number;
	client_inbound_active: number;
	client_inbound_target: number;
	client_outbound_active: number;
	client_outbound_target: number;
	client_pool_capacity: number;
	builds_total: number;
	build_successes: number;
	build_failures: number;
	forwarded_messages: number;
	peer_identities: boolean;
	recent_window_seconds: number;
	recent_build_successes: number;
	recent_build_failures: number;
	tunnels: RouterTunnelItem[];
}

export interface NetDBRouterItem {
	hash: string;
	b32: string;
	floodfill: boolean;
	transports: string[] | null;
	addresses: string[] | null;
	published: number;
	version: string;
	caps: string;
	last_seen_ago_seconds: number;
}

export interface NetDBResponse {
	total_routers: number;
	floodfill_routers: number;
	lookups_total: number;
	lookups_failed: number;
	matched: number;
	routers: NetDBRouterItem[];
}

export interface PeerProfile {
	successes: number;
	failures: number;
	mean_latency_ms: number;
	samples: number;
}

export interface PeerItem extends NetDBRouterItem {
	profile: PeerProfile | null;
}

export interface PeersResponse {
	peers: PeerItem[];
	missing: string[];
}

export interface LocalDestinationItem {
	name: string;
	address: string;
	default: boolean;
	bandwidth?: {
		rate_bytes_per_second: number;
		burst_bytes: number;
		available_bytes: number;
		accepted_bytes: number;
		backpressured_bytes: number;
		waiters: number;
	};
}

export interface DestinationsResponse {
	destinations: LocalDestinationItem[];
}

export type ConfigFieldType = 'bool' | 'int' | 'string' | 'enum' | 'list' | 'duration';
export type ConfigGroup = 'features' | 'router' | 'tunnels' | 'transports' | 'services' | 'sources' | 'logging';
export type ConfigValue = boolean | number | string | string[];

export interface ConfigField {
	key: string;
	group: ConfigGroup;
	label: string;
	description: string;
	type: ConfigFieldType;
	value: ConfigValue;
	running: ConfigValue | null;
	min: number | null;
	max: number | null;
	options: string[] | null;
	unit: string;
	apply: 'live' | 'restart';
	requires: string[];
	pending: boolean;
}

export interface ConfigResponse {
	revision: string;
	writable: boolean;
	write_blocked_reason: string;
	restart_required: boolean;
	backup_available: boolean;
	file_error: string;
	fields: ConfigField[];
}

export interface ConfigUpdateResult {
	status: 'saved' | 'unchanged';
	revision: string;
	applied: string[];
	restart_required: string[];
}

export type ActionName = 'reseed' | 'probe' | 'restart' | 'config' | 'rollback';

export interface ActionLogEntry {
	at: number;
	action: ActionName;
	outcome: 'ok' | 'error';
	detail: string;
}

export interface ActionLogResponse {
	entries: ActionLogEntry[];
}

export type Tone = 'ok' | 'warn' | 'crit' | 'info' | 'neutral';

export interface ToastMessage {
	id: number;
	type: 'success' | 'error' | 'info';
	title: string;
	description?: string;
}
