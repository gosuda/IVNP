import type { ConfigResponse, RouterStatusResponse, RouterTunnelsResponse, ServiceStatus, Tone, UnmetCondition } from './types';

export interface Blocker {
	tone: Tone;
	title: string;
	href?: string;
}

export interface Health {
	tone: Tone;
	headline: string;
	blockers: Blocker[];
}

const conditionText: Record<UnmetCondition['key'], (condition: UnmetCondition) => Blocker> = {
	netdb_routers: (c) => ({ tone: 'warn', title: `NetDB knows ${c.current ?? 0} of ${c.required ?? 50} required routers`, href: '/network/' }),
	router_info_publication: () => ({ tone: 'warn', title: 'RouterInfo has not been published yet', href: '/network/' }),
	lease_set2_publication: () => ({ tone: 'warn', title: 'No LeaseSet2 has been published for a local destination', href: '/destinations/' }),
	exploratory_inbound: () => ({ tone: 'warn', title: 'No exploratory inbound tunnel', href: '/tunnels/?kind=exploratory' }),
	exploratory_outbound: () => ({ tone: 'warn', title: 'No exploratory outbound tunnel', href: '/tunnels/?kind=exploratory' }),
	client_inbound: () => ({ tone: 'warn', title: 'No client inbound tunnel', href: '/tunnels/?kind=client' }),
	client_outbound: () => ({ tone: 'warn', title: 'No client outbound tunnel', href: '/tunnels/?kind=client' }),
	floodfill_advertisement: () => ({ tone: 'warn', title: 'Floodfill is configured but not advertised', href: '/settings/?focus=router.floodfill' })
};

export const serviceNames: Record<string, string> = {
	http_proxy: 'HTTP proxy',
	socks5: 'SOCKS5 proxy',
	sam: 'SAM bridge',
	control: 'Control API',
	metrics: 'Prometheus metrics'
};

export function listedServices(status: RouterStatusResponse): Array<{ key: string; name: string; service: ServiceStatus }> {
	return (['http_proxy', 'socks5', 'sam', 'control', 'metrics'] as const)
		.filter((key) => status.services[key])
		.map((key) => ({ key, name: serviceNames[key], service: status.services[key] }));
}

export function serviceTone(service: ServiceStatus): Tone {
	if (!service.enabled) return 'neutral';
	if (service.listening === false) return 'crit';
	return service.listening ? 'ok' : 'neutral';
}

export function serviceState(service: ServiceStatus): string {
	if (!service.enabled) return 'Off';
	if (service.listening === null) return 'Starting';
	return service.listening ? 'Listening' : 'Not listening';
}

/** Derives one operational verdict plus ordered, linkable reasons. */
export function deriveHealth(input: {
	status: RouterStatusResponse | null;
	statusError: string | null;
	tunnels: RouterTunnelsResponse | null;
	config: ConfigResponse | null;
	restarting: boolean;
}): Health {
	const { status, statusError, tunnels, config, restarting } = input;
	if (restarting) {
		return { tone: 'info', headline: 'Router restarting', blockers: [{ tone: 'info', title: 'The console stays available; data resumes when the new router starts.' }] };
	}
	if (!status) {
		return statusError
			? { tone: 'crit', headline: 'Router unreachable', blockers: [{ tone: 'crit', title: statusError }] }
			: { tone: 'neutral', headline: 'Connecting to router', blockers: [] };
	}

	const blockers: Blocker[] = [];
	if (statusError) blockers.push({ tone: 'crit', title: `Status updates failing: ${statusError}` });
	if (status.state !== 'running') blockers.push({ tone: 'crit', title: `Router lifecycle is ${status.state}` });
	for (const { name, service } of listedServices(status)) {
		if (service.enabled && service.listening === false) {
			blockers.push({ tone: 'crit', title: `${name} is enabled but not listening on ${service.address || 'its configured port'}` });
		}
	}
	if (!status.ready) {
		for (const condition of status.unmet_conditions ?? []) blockers.push(conditionText[condition.key](condition));
		if ((status.unmet_conditions ?? []).length === 0) blockers.push({ tone: 'warn', title: 'Data-plane conditions are met; waiting for the runtime to report ready' });
	}
	if (tunnels && tunnels.recent_build_successes + tunnels.recent_build_failures >= 10) {
		const rate = tunnels.recent_build_successes / (tunnels.recent_build_successes + tunnels.recent_build_failures);
		if (rate < 0.3) blockers.push({ tone: 'warn', title: `Only ${Math.round(rate * 100)}% of recent tunnel builds succeeded`, href: '/tunnels/' });
	}
	if (status.reachability === 'firewalled') blockers.push({ tone: 'info', title: 'Firewalled: peers reach this router through introducers' });
	if (config?.restart_required) {
		const pending = config.fields.filter((field) => field.pending).length;
		blockers.push({ tone: 'info', title: `${pending || 'Some'} saved setting${pending === 1 ? '' : 's'} apply after restart`, href: '/settings/' });
	}

	const worst: Tone = blockers.some((b) => b.tone === 'crit') ? 'crit' : status.ready ? 'ok' : 'warn';
	const headline = worst === 'crit' ? 'Needs attention' : status.ready ? 'Ready' : 'Starting up';
	return { tone: worst, headline, blockers };
}
