package noderuntime

import (
	"gosuda.org/ivnp/networking"

	"cmp"

	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	natRequestedLifetime = 2 * time.Minute
	natRetryInterval     = 30 * time.Second
	natRequestTimeout    = 5 * time.Second
	natPMPProbeTimeout   = 500 * time.Millisecond
)

var errUPnPDiscoveryUnavailable = errors.New("daemon: no UPnP Internet Gateway Device found")

type natPMPClient interface {
	PublicAddress(context.Context) (networking.NetworkAddressTranslationPortMappingPublicAddress, error)
	Map(context.Context, networking.NetworkAddressTranslationPortMappingMappingRequest) (networking.NetworkAddressTranslationPortMappingMapping, error)
	Unmap(context.Context, networking.NetworkAddressTranslationPortMappingMapping) error
}

type upnpClient interface {
	Discover(context.Context) ([]networking.UniversalPlugAndPlayDiscoveryResponse, error)
	Describe(context.Context, *url.URL) (networking.UniversalPlugAndPlayGateway, error)
	ExternalAddress(context.Context, networking.UniversalPlugAndPlayGateway) (netip.Addr, error)
	AddPortMapping(context.Context, networking.UniversalPlugAndPlayGateway, networking.UniversalPlugAndPlayPortMapping) error
	DeletePortMapping(context.Context, networking.UniversalPlugAndPlayGateway, string, uint16, string) error
}

type natMappingSpec struct {
	addressIndex int
	transport    string
	protocol     string
	internalPort uint16
	boundAddress netip.Addr
	publicHint   netip.Addr
}

type activeNATMapping struct {
	spec         natMappingSpec
	method       string
	public       netip.Addr
	externalPort uint16
	lifetime     time.Duration
	expiresAt    time.Time
	natClient    natPMPClient
	natMapping   networking.NetworkAddressTranslationPortMappingMapping
	upnpClient   upnpClient
	upnpGateway  networking.UniversalPlugAndPlayGateway
	internalIP   netip.Addr
}

type natMappingPublisher struct {
	base      []networking.RouterPublishedAddress
	config    configTransports
	localInfo *networking.RouterLocalRouterInfo
	logger    *slog.Logger

	newNATPMP      func(netip.AddrPort) natPMPClient
	upnp           upnpClient
	prefixes       func() ([]netip.Prefix, error)
	now            func() time.Time
	route          func(context.Context, string, uint16) (netip.Addr, error)
	natPMPEndpoint netip.AddrPort
	upnpLocation   *url.URL
	retryInterval  time.Duration
	wait           func(context.Context, time.Duration) bool

	mu              sync.Mutex
	started         bool
	closed          bool
	ctx             context.Context
	cancel          context.CancelFunc
	active          map[int]*activeNATMapping
	cachedNAT       natPMPClient
	cachedNATIP     netip.Addr
	cachedPublic    netip.Addr
	cachedUPnP      networking.UniversalPlugAndPlayGateway
	upnpUnavailable bool
	wg              sync.WaitGroup
}

type configTransports struct {
	ntcp2 autoTransportConfig
	ssu2  autoTransportConfig
}

type autoTransportConfig struct {
	enabled    bool
	automatic  bool
	publicHint netip.Addr
}

func newNATMappingPublisher(base staticAddressPublisher, ntcp2, ssu2 autoTransportConfig, natPMPEndpoint netip.AddrPort, upnpEndpoint string, localInfo *networking.RouterLocalRouterInfo, logger *slog.Logger) networking.RouterAddressPublisher {
	if !ntcp2.automatic && !ssu2.automatic {
		return base
	}
	publisher := &natMappingPublisher{
		base:           append([]networking.RouterPublishedAddress(nil), base...),
		config:         configTransports{ntcp2: ntcp2, ssu2: ssu2},
		localInfo:      localInfo,
		logger:         logger,
		upnp:           new(networking.UniversalPlugAndPlayClient),
		prefixes:       interfacePrefixes,
		now:            time.Now,
		active:         make(map[int]*activeNATMapping, 2),
		route:          routedLocalIPv4Host,
		natPMPEndpoint: natPMPEndpoint,
		retryInterval:  natRetryInterval,
		wait:           waitFor,
	}
	if upnpEndpoint != "" {
		publisher.upnpLocation, _ = url.Parse(upnpEndpoint)
	}
	publisher.newNATPMP = func(endpoint netip.AddrPort) natPMPClient {
		client := networking.NetworkAddressTranslationPortMappingNewClient(endpoint.Addr())
		client.Port = endpoint.Port()
		client.Timeout = natPMPProbeTimeout
		return client
	}
	return publisher
}

func (p *natMappingPublisher) Addresses(context.Context) ([]networking.RouterPublishedAddress, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addressesLocked(), nil
}

func (p *natMappingPublisher) AddressesForSockets(ctx context.Context, ntcp2 net.Listener, ssu2 net.PacketConn) ([]networking.RouterPublishedAddress, error) {
	p.mu.Lock()
	if p.started || p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	p.started = true
	p.ctx, p.cancel = context.WithCancel(ctx)
	workerCtx := p.ctx
	p.mu.Unlock()

	specs := make([]natMappingSpec, 0, 2)
	if p.config.ntcp2.enabled && p.config.ntcp2.automatic && ntcp2 != nil {
		if spec, err := p.specForSocket("NTCP2", "TCP", ntcp2.Addr(), p.config.ntcp2.publicHint); err == nil {
			specs = append(specs, spec)
		} else {
			p.logger.Warn("automatic NTCP2 mapping disabled", "error", err)
		}
	}
	if p.config.ssu2.enabled && p.config.ssu2.automatic && ssu2 != nil {
		if spec, err := p.specForSocket("SSU", "UDP", ssu2.LocalAddr(), p.config.ssu2.publicHint); err == nil {
			specs = append(specs, spec)
		} else {
			p.logger.Warn("automatic SSU2 mapping disabled", "error", err)
		}
	}

	for i := range specs {
		mapping, err := p.attempt(workerCtx, specs[i], 0)
		if err != nil {
			p.logger.Warn("automatic port mapping unavailable", "transport", specs[i].transport, "error", err)
		} else {
			p.mu.Lock()
			p.active[specs[i].addressIndex] = mapping
			p.mu.Unlock()
			p.logger.Info("automatic port mapping established", "transport", specs[i].transport, "method", mapping.method, "public", mapping.public.String(), "port", mapping.externalPort, "lease", mapping.lifetime)
		}
		p.wg.Add(1)
		go p.maintain(workerCtx, specs[i], mapping)
	}

	p.mu.Lock()
	addresses := p.addressesLocked()
	reachable := p.reachableLocked()
	p.mu.Unlock()
	if reachable {
		p.localInfo.SetReachability(networking.RouterReachabilityReachable)
	} else {
		p.localInfo.SetReachability(networking.RouterReachabilityFirewalled)
	}
	return addresses, nil
}

func (p *natMappingPublisher) specForSocket(transport, protocol string, address net.Addr, publicHint netip.Addr) (natMappingSpec, error) {
	bound, port, err := socketEndpoint(address)
	if err != nil {
		return natMappingSpec{}, err
	}
	if bound.IsLoopback() {
		return natMappingSpec{}, errors.New("daemon: automatic mapping requires a non-loopback transport listener")
	}
	index := -1
	for i := range p.base {
		if p.base[i].Transport == transport {
			index = i
			break
		}
	}
	if index < 0 {
		return natMappingSpec{}, fmt.Errorf("daemon: missing %s publication", transport)
	}
	return natMappingSpec{addressIndex: index, transport: transport, protocol: protocol, internalPort: port, boundAddress: bound, publicHint: publicHint}, nil
}

func socketEndpoint(address net.Addr) (netip.Addr, uint16, error) {
	if address == nil {
		return netip.Addr{}, 0, errors.New("daemon: mapping socket is unavailable")
	}
	host, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("daemon: invalid mapping socket: %w", err)
	}
	parsedHost, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("daemon: invalid mapping address: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.Addr{}, 0, errors.New("daemon: mapping socket has no assigned port")
	}
	return parsedHost.Unmap(), uint16(port), nil
}

func (p *natMappingPublisher) attempt(ctx context.Context, spec natMappingSpec, externalPort uint16) (*activeNATMapping, error) {
	natCtx, cancel := context.WithTimeout(ctx, natRequestTimeout)
	mapping, natErr := p.attemptNATPMP(natCtx, spec, externalPort)
	cancel()
	if natErr == nil {
		return mapping, nil
	}
	upnpCtx, cancel := context.WithTimeout(ctx, natRequestTimeout)
	mapping, upnpErr := p.attemptUPnP(upnpCtx, spec, externalPort)
	cancel()
	if upnpErr == nil {
		return mapping, nil
	}
	return nil, errors.Join(natErr, upnpErr)
}

func (p *natMappingPublisher) attemptNATPMP(ctx context.Context, spec natMappingSpec, externalPort uint16) (*activeNATMapping, error) {
	p.mu.Lock()
	cachedClient, cachedGateway, cachedPublic := p.cachedNAT, p.cachedNATIP, p.cachedPublic
	p.mu.Unlock()
	if cachedClient != nil {
		if mapping, err := p.mapNATPMP(ctx, cachedClient, cachedGateway, cachedPublic, spec, externalPort); err == nil {
			return mapping, nil
		}
	}
	var candidates []netip.AddrPort
	if p.natPMPEndpoint.IsValid() {
		candidates = []netip.AddrPort{p.natPMPEndpoint}
	} else {
		prefixes, err := p.prefixes()
		if err != nil {
			return nil, err
		}
		gateways := gatewayCandidates(prefixes)
		candidates = make([]netip.AddrPort, len(gateways))
		for i := range gateways {
			candidates[i] = netip.AddrPortFrom(gateways[i], networking.NetworkAddressTranslationPortMappingDefaultPort)
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("daemon: no NAT-PMP gateway candidates")
	}
	var result error
	for _, endpoint := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		gateway := endpoint.Addr()
		local, routeErr := p.route(ctx, gateway.String(), endpoint.Port())
		if routeErr != nil || !boundAccepts(spec.boundAddress, local) {
			continue
		}
		client := p.newNATPMP(endpoint)
		public := spec.publicHint
		observed, publicErr := client.PublicAddress(ctx)
		if publicErr == nil && validPublicIPv4(observed.Address) {
			public = observed.Address.Unmap()
		}
		if !validPublicIPv4(public) {
			result = errors.Join(result, publicErr)
			continue
		}
		mapping, mapErr := p.mapNATPMP(ctx, client, gateway, public, spec, externalPort)
		if mapErr != nil {
			result = errors.Join(result, mapErr)
			continue
		}
		p.mu.Lock()
		p.cachedNAT, p.cachedNATIP, p.cachedPublic = client, gateway, public
		p.mu.Unlock()
		return mapping, nil
	}
	if result ==
		nil {
		result = errors.New("daemon: NAT-PMP gateway did not respond")
	}

	return nil, result
}

func (p *natMappingPublisher) mapNATPMP(ctx context.Context, client natPMPClient, gateway, public netip.Addr, spec natMappingSpec, externalPort uint16) (*activeNATMapping, error) {
	protocol := networking.NetworkAddressTranslationPortMappingTCP
	if spec.protocol == "UDP" {
		protocol = networking.NetworkAddressTranslationPortMappingUDP
	}
	mapping, err := client.Map(ctx, networking.NetworkAddressTranslationPortMappingMappingRequest{Protocol: protocol, InternalPort: spec.internalPort, ExternalPort: externalPort, Lifetime: natRequestedLifetime})
	if err != nil {
		return nil, err
	}
	if mapping.ExternalPort == 0 || mapping.Lifetime <= 0 {
		return nil, errors.New("daemon: NAT-PMP returned an empty mapping")
	}
	now := p.now()
	return &activeNATMapping{spec: spec, method: "natpmp", public: public, externalPort: mapping.ExternalPort, lifetime: mapping.Lifetime, expiresAt: now.Add(mapping.Lifetime), natClient: client, natMapping: mapping}, nil
}

func (p *natMappingPublisher) attemptUPnP(ctx context.Context, spec natMappingSpec, externalPort uint16) (*activeNATMapping, error) {
	gateway, err := p.upnpGateway(ctx)
	if err != nil {
		return nil, err
	}
	public := spec.publicHint
	observed, err := p.upnp.ExternalAddress(ctx, gateway)
	if err == nil && validPublicIPv4(observed) {
		public = observed.Unmap()
	}
	if !validPublicIPv4(public) {
		return nil, errors.New("daemon: UPnP gateway did not report a public IPv4 address")
	}
	internalIP, err := p.route(ctx, gateway.ControlURL.Hostname(), 80)
	if err != nil {
		return nil, err
	}
	if !boundAccepts(spec.boundAddress, internalIP) {
		return nil, errors.New("daemon: transport listener does not accept the UPnP internal address")
	}

	externalPort = cmp.Or(externalPort, spec.internalPort)

	mapping := networking.UniversalPlugAndPlayPortMapping{ExternalPort: externalPort, Protocol: spec.protocol, InternalPort: spec.internalPort, InternalClient: internalIP.String(), Enabled: true, Description: "ivnp " + strings.ToLower(spec.transport), LeaseDuration: uint32(natRequestedLifetime / time.Second)}
	if err = p.upnp.AddPortMapping(ctx, gateway, mapping); err != nil {
		return nil, err
	}
	now := p.now()
	return &activeNATMapping{spec: spec, method: "upnp", public: public, externalPort: externalPort, lifetime: natRequestedLifetime, expiresAt: now.Add(natRequestedLifetime), upnpClient: p.upnp, upnpGateway: gateway, internalIP: internalIP}, nil
}

func (p *natMappingPublisher) upnpGateway(ctx context.Context) (networking.UniversalPlugAndPlayGateway, error) {
	p.mu.Lock()
	cached := p.cachedUPnP
	p.mu.Unlock()
	if cached.ControlURL != nil {
		return cached, nil
	}
	if p.upnpLocation != nil {
		gateway, err := p.upnp.Describe(ctx, p.upnpLocation)
		if err != nil {
			return networking.UniversalPlugAndPlayGateway{}, err
		}
		p.mu.Lock()
		p.cachedUPnP = gateway
		p.mu.Unlock()
		return gateway, nil
	}
	p.mu.Lock()
	unavailable := p.upnpUnavailable
	p.mu.Unlock()
	if unavailable {
		return networking.UniversalPlugAndPlayGateway{}, errUPnPDiscoveryUnavailable
	}
	responses, err := p.upnp.Discover(ctx)
	if err != nil {
		return networking.UniversalPlugAndPlayGateway{}, err
	}
	var result error
	for _, response := range responses {
		gateway, describeErr := p.upnp.Describe(ctx, response.Location)
		if describeErr != nil {
			result = errors.Join(result, describeErr)
			continue
		}
		p.mu.Lock()
		p.cachedUPnP = gateway
		p.mu.Unlock()
		return gateway, nil
	}
	if result == nil {
		p.mu.Lock()
		p.upnpUnavailable = true
		p.mu.Unlock()
		result = errUPnPDiscoveryUnavailable
	}
	return networking.UniversalPlugAndPlayGateway{}, result
}

func (p *natMappingPublisher) maintain(ctx context.Context, spec natMappingSpec, current *activeNATMapping) {
	defer p.wg.Done()
	defer func() {
		if current != nil {
			p.remove(current)
		}
	}()
	for {
		if current == nil {
			if !p.wait(ctx, p.retryInterval) {
				return
			}
			mapping, err := p.attempt(ctx, spec, 0)
			if err != nil {
				if errors.Is(err, errUPnPDiscoveryUnavailable) {
					p.logger.Debug("automatic port mapping retry skipped unavailable UPnP discovery", "transport", spec.transport, "error", err)
				} else {
					p.logger.Warn("automatic port mapping retry failed", "transport", spec.transport, "error", err)
				}
				continue
			}
			current = mapping
			p.setActive(ctx, mapping)
			continue
		}

		if !p.wait(ctx, adaptiveRenewDelay(current.lifetime)) {
			return
		}
		for current != nil {
			renewed, err := p.renew(ctx, current)
			if err == nil {
				old := current
				current = renewed
				p.setActive(ctx, renewed)
				p.logger.Debug("automatic port mapping renewed", "transport", spec.transport, "method", renewed.method, "port", renewed.externalPort, "lease", renewed.lifetime)
				if old.externalPort != renewed.externalPort || old.method != renewed.method {
					p.remove(old)
				}
				break
			}
			p.logger.Warn("automatic port mapping renewal failed", "transport", spec.transport, "method", current.method, "error", err)
			remaining := current.expiresAt.Sub(p.now())
			if remaining <= 0 {
				p.clearActive(ctx, spec.addressIndex, current)
				current = nil
				break
			}
			retry := min(remaining/2, 5*time.Second)
			if retry <= 0 || !p.wait(ctx, retry) {
				return
			}
		}
	}
}

func (p *natMappingPublisher) renew(ctx context.Context, current *activeNATMapping) (*activeNATMapping, error) {
	if current.method == "natpmp" {
		return p.mapNATPMP(ctx, current.natClient, current.natMapping.Gateway, current.public, current.spec, current.externalPort)
	}
	mapping := networking.UniversalPlugAndPlayPortMapping{ExternalPort: current.externalPort, Protocol: current.spec.protocol, InternalPort: current.spec.internalPort, InternalClient: current.internalIP.String(), Enabled: true, Description: "ivnp " + strings.ToLower(current.spec.transport), LeaseDuration: uint32(natRequestedLifetime / time.Second)}
	if err := current.upnpClient.AddPortMapping(ctx, current.upnpGateway, mapping); err != nil {
		return nil, err
	}
	now := p.now()
	copy := *current
	copy.lifetime = natRequestedLifetime
	copy.expiresAt = now.Add(natRequestedLifetime)
	return &copy, nil
}

func adaptiveRenewDelay(granted time.Duration) time.Duration {
	if granted <= 0 {
		return natRetryInterval
	}
	delay := granted * 2 / 3
	if delay < time.Second {
		return granted / 2
	}
	return delay
}

func (p *natMappingPublisher) setActive(ctx context.Context, mapping *activeNATMapping) {
	p.mu.Lock()
	old := p.active[mapping.spec.addressIndex]
	p.active[mapping.spec.addressIndex] = mapping
	changed := old == nil || old.public != mapping.public || old.externalPort != mapping.externalPort
	p.mu.Unlock()
	if changed {
		p.publish(ctx)
	}
}

func (p *natMappingPublisher) clearActive(ctx context.Context, index int, expected *activeNATMapping) {
	p.mu.Lock()
	if p.active[index] != expected {
		p.mu.Unlock()
		return
	}
	delete(p.active, index)
	p.mu.Unlock()
	p.publish(ctx)
}

func (p *natMappingPublisher) publish(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	p.mu.Lock()
	addresses := p.addressesLocked()
	reachable := p.reachableLocked()
	p.mu.Unlock()
	if err := p.localInfo.ReplaceAddresses(addresses); err != nil {
		p.logger.Error("automatic mapping address update failed", "error", err)
		return
	}
	if reachable {
		p.localInfo.SetReachability(networking.RouterReachabilityReachable)
	} else {
		p.localInfo.SetReachability(networking.RouterReachabilityFirewalled)
	}
	if err := p.localInfo.Publish(ctx); err != nil && ctx.Err() == nil {
		p.logger.Error("automatic mapping RouterInfo publication failed", "error", err)
	}
}

func (p *natMappingPublisher) addressesLocked() []networking.RouterPublishedAddress {
	addresses := make([]networking.RouterPublishedAddress, len(p.base))
	for i := range p.base {
		addresses[i] = p.base[i]
		addresses[i].Options = append([]networking.RouterMappingOption(nil), p.base[i].Options...)
		if mapping := p.active[i]; mapping != nil {
			addresses[i].Options = append(addresses[i].Options,
				networking.RouterMappingOption{Key: "host", Value: mapping.public.String()},
				networking.RouterMappingOption{Key: "port", Value: strconv.Itoa(int(mapping.externalPort))},
			)
		}
	}
	return addresses
}

func (p *natMappingPublisher) reachableLocked() bool {
	if len(p.active) != 0 {
		return true
	}
	for i := range p.base {
		for _, option := range p.base[i].Options {
			if option.Key == "host" && option.Value != "" {
				return true
			}
		}
	}
	return false
}

func (p *natMappingPublisher) remove(mapping *activeNATMapping) {
	ctx, cancel := context.WithTimeout(context.Background(), natRequestTimeout)
	defer cancel()
	var err error
	if mapping.method == "natpmp" {
		err = mapping.natClient.Unmap(ctx, mapping.natMapping)
	} else {
		err = mapping.upnpClient.DeletePortMapping(ctx, mapping.upnpGateway, "", mapping.externalPort, mapping.spec.protocol)
	}
	if err != nil {
		p.logger.Warn("automatic port mapping removal failed", "transport", mapping.spec.transport, "method", mapping.method, "error", err)
	}
	if err == nil {
		p.logger.Debug("automatic port mapping removed", "transport", mapping.spec.transport, "method", mapping.method, "port", mapping.externalPort)
	}
}

func (p *natMappingPublisher) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	cancel := p.cancel
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	p.wg.Wait()
	return nil
}

func waitFor(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func interfacePrefixes() ([]netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Is4() {
				prefixes = append(prefixes, prefix)
			}
		}
	}
	return prefixes, nil
}

func gatewayCandidates(prefixes []netip.Prefix) []netip.Addr {
	type candidate struct {
		address netip.Addr
		score   int
	}
	seen := make(map[netip.Addr]struct{})
	items := make([]candidate, 0, len(prefixes)*2)
	add := func(address netip.Addr, score int) {
		address = address.Unmap()
		if !address.Is4() || address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() {
			return
		}
		if _, exists := seen[address]; exists {
			return
		}
		seen[address] = struct{}{}
		items = append(items, candidate{address: address, score: score})
	}
	for _, prefix := range prefixes {
		address := prefix.Addr().Unmap()
		if !address.Is4() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			continue
		}
		value := binary.BigEndian.Uint32(address.AsSlice())
		if value > 1 {
			score := 10
			if prefix.Bits() >= 30 {
				score = 100
			}
			add(ipv4FromUint32(value-1), score)
		}
		if prefix.Bits() <= 30 {
			network := prefix.Masked().Addr()
			raw := binary.BigEndian.Uint32(network.AsSlice()) + 1
			add(ipv4FromUint32(raw), 50)
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].score > items[j].score })
	if len(items) > 8 {
		items = items[:8]
	}
	result := make([]netip.Addr, len(items))
	for i := range items {
		result[i] = items[i].address
	}
	return result
}

func ipv4FromUint32(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func routedLocalIPv4Host(ctx context.Context, host string, port uint16) (netip.Addr, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "udp4", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return netip.Addr{}, err
	}
	defer connection.Close()
	udp, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("daemon: cannot determine mapping interface")
	}
	address, ok := netip.AddrFromSlice(udp.IP)
	if !ok || !address.Is4() {
		return netip.Addr{}, errors.New("daemon: mapping interface is not IPv4")
	}
	return address.Unmap(), nil
}

func boundAccepts(bound, internal netip.Addr) bool {
	if !bound.IsValid() || !internal.IsValid() {
		return false
	}
	bound, internal = bound.Unmap(), internal.Unmap()
	return bound.IsUnspecified() || bound == internal || bound.IsLoopback() && internal.IsLoopback()
}

func validPublicIPv4(address netip.Addr) bool {
	address = address.Unmap()
	return address.Is4() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}

var _ networking.RouterSocketAddressPublisher = (*natMappingPublisher)(nil)
var _ networking.RouterAddressPublisherCloser = (*natMappingPublisher)(nil)
