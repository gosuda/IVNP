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
	readiness: ReadinessDetails;
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

export interface TelemetryPoint {
	timestamp: number;
	inRate: number;
	outRate: number;
	activeTunnels: number;
	buildSuccessRate: number;
	routers: number;
	floodfills: number;
	goroutines: number;
	heapBytes: number;
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
	tunnels: RouterTunnelItem[];
}

export interface NetDBRouterItem {
	hash: string;
	b32: string;
	floodfill: boolean;
	transports: string[];
	addresses: string[];
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
	routers: NetDBRouterItem[];
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

export interface RouterConfigData {
	network: { id: number; ipv4: boolean; ipv6: boolean };
	router: { floodfill: boolean; family: string; version: string };
	tunnel: {
		enabled: boolean;
		hops: number;
		exploratory_inbound_target: number;
		exploratory_outbound_target: number;
		exploratory_pool_capacity: number;
		client_inbound_target: number;
		client_outbound_target: number;
		client_pool_capacity: number;
		bandwidth_rate_bytes_per_second: number;
		bandwidth_burst_bytes: number;
	};
	ntcp2: { enabled: boolean; bind_address: string; advertised_address: string; max_sessions: number };
	ssu2: { enabled: boolean; bind_address: string; advertised_address: string; max_sessions: number };
	reseed: { enabled: boolean; required: boolean; endpoints: string[] };
	addressbook: { enabled: boolean; subscriptions: string[]; refresh_interval_hours: number };
	services: {
		http_proxy_enabled: boolean;
		http_proxy_address: string;
		http_proxy_port: number;
		socks5_enabled: boolean;
		socks5_address: string;
		socks5_port: number;
		sam_enabled: boolean;
		sam_address: string;
		sam_port: number;
		metrics_enabled: boolean;
		metrics_address: string;
		metrics_port: number;
	};
	log: { level: 'debug' | 'info' | 'warn' | 'error'; format: 'text' | 'json' };
	restart_required: boolean;
}

export interface RouterConfigUpdate {
	router: Pick<RouterConfigData['router'], 'floodfill' | 'family'>;
	tunnel: RouterConfigData['tunnel'];
	ntcp2: Pick<RouterConfigData['ntcp2'], 'enabled' | 'max_sessions'>;
	ssu2: Pick<RouterConfigData['ssu2'], 'enabled' | 'max_sessions'>;
	reseed: RouterConfigData['reseed'];
	addressbook: RouterConfigData['addressbook'];
	services: Pick<
		RouterConfigData['services'],
		| 'http_proxy_enabled'
		| 'http_proxy_port'
		| 'socks5_enabled'
		| 'socks5_port'
		| 'sam_enabled'
		| 'sam_port'
		| 'metrics_enabled'
		| 'metrics_port'
	>;
	log: Pick<RouterConfigData['log'], 'level'>;
}

export interface ConfigUpdateResult {
	status: 'saved' | 'unchanged';
	applied: string[];
	restart_required: string[];
}

export interface ToastMessage {
	id: number;
	type: 'success' | 'error' | 'info';
	title: string;
	description?: string;
}
