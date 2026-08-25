package observability

import (
	"runtime"
	"sync/atomic"
)

// Registry holds the process-wide, label-free operational metrics. A daemon
// owns exactly one Registry and passes that handle to every producer.
type Registry struct{ state *registryState }

var zeroRegistryState registryState

type registryState struct {
	lifecycle   lifecycleMetrics
	reseed      reseedMetrics
	transport   transportMetrics
	netdb       netdbMetrics
	tunnel      tunnelMetrics
	admission   admissionMetrics
	proxy       proxyMetrics
	control     controlMetrics
	bootstrap   bootstrapMetrics
	publication publicationMetrics
	sam         samMetrics
	garlic      garlicMetrics
	ssu2        ssu2Metrics
}

type lifecycleMetrics struct{ starts, stops, failures, running, ingressPanics atomic.Uint64 }
type reseedMetrics struct{ attempts, successes, failures, bytes, sources atomic.Uint64 }
type transportMetrics struct{ connections, disconnections, handshakeFailures, receivedBytes, sentBytes, sessions atomic.Uint64 }
type netdbMetrics struct{ lookups, lookupFailures, stores, storeFailures, routers atomic.Uint64 }
type tunnelMetrics struct {
	builds, buildSuccesses, buildFailures, active atomic.Uint64
	exploratoryInbound, exploratoryOutbound       atomic.Uint64
	clientInbound, clientOutbound                 atomic.Uint64
	participatingForwarded                        atomic.Uint64
}
type admissionMetrics struct{ allowed, rejected, inFlight atomic.Uint64 }
type proxyMetrics struct{ requests, failures, active atomic.Uint64 }
type controlMetrics struct{ requests, failures, active atomic.Uint64 }
type bootstrapMetrics struct{ stage, routerReachable atomic.Uint64 }
type samMetrics struct{ udpInvalid, udpBackpressure, protocolFailures atomic.Uint64 }
type publicationMetrics struct {
	routerInfoSuccesses, leaseSet2Successes atomic.Uint64
	attempts, sendFailures, timeouts        atomic.Uint64
}
type garlicMetrics struct {
	newSessionSent, newSessionReceived           atomic.Uint64
	existingSessionSent, existingSessionReceived atomic.Uint64
	dhStepsSent, dhStepsReceived                 atomic.Uint64
	tunnelClovesForwarded                        atomic.Uint64
}
type ssu2Metrics struct {
	vectorIOEnabled, kernelDropAccounting                         atomic.Uint64
	received, enqueued, processed, receiveQueueDrops, kernelDrops atomic.Uint64
	sendEnqueued, sent, sendFailed, sendQueueDrops                atomic.Uint64
	receiveMultiBatches, sendMultiBatches                         atomic.Uint64
	ingressQueueDepth, egressQueueDepth                           atomic.Uint64
}

// Snapshot is an immutable copy of Registry values. Process values are sampled
// directly from the Go runtime at scrape time rather than maintained by a
// second polling owner.
type Snapshot struct {
	Lifecycle   LifecycleSnapshot
	Reseed      ReseedSnapshot
	Transport   TransportSnapshot
	NetDB       NetDBSnapshot
	Tunnel      TunnelSnapshot
	Admission   AdmissionSnapshot
	Proxy       ProxySnapshot
	Control     ControlSnapshot
	Bootstrap   BootstrapSnapshot
	Publication PublicationSnapshot
	Garlic      GarlicSnapshot
	SAM         SAMSnapshot
	SSU2        SSU2Snapshot
	Process     ProcessSnapshot
}

type LifecycleSnapshot struct{ Starts, Stops, Failures, Running, IngressRecoveredPanics uint64 }
type ReseedSnapshot struct{ Attempts, Successes, Failures, Bytes, Sources uint64 }
type TransportSnapshot struct{ Connections, Disconnections, HandshakeFailures, ReceivedBytes, SentBytes, Sessions uint64 }
type NetDBSnapshot struct{ Lookups, LookupFailures, Stores, StoreFailures, Routers uint64 }
type TunnelSnapshot struct {
	Builds, BuildSuccesses, BuildFailures, Active       uint64
	ExploratoryInboundActive, ExploratoryOutboundActive uint64
	ClientInboundActive, ClientOutboundActive           uint64
	ParticipatingForwarded                              uint64
}
type AdmissionSnapshot struct{ Allowed, Rejected, InFlight uint64 }
type ProxySnapshot struct{ Requests, Failures, Active uint64 }
type ControlSnapshot struct{ Requests, Failures, Active uint64 }
type BootstrapSnapshot struct{ Stage, RouterReachable uint64 }
type PublicationSnapshot struct {
	RouterInfoSuccesses, LeaseSet2Successes uint64
	Attempts, SendFailures, Timeouts        uint64
}
type SAMSnapshot struct{ UDPInvalid, UDPBackpressureRejections, ProtocolFailures uint64 }
type GarlicSnapshot struct {
	NewSessionSent, NewSessionReceived           uint64
	ExistingSessionSent, ExistingSessionReceived uint64
	DHStepsSent, DHStepsReceived                 uint64
	TunnelClovesForwarded                        uint64
}
type SSU2Snapshot struct {
	VectorIOEnabled, KernelDropAccounting                                     uint64
	ReceivedDatagrams, EnqueuedDatagrams, ProcessedDatagrams                  uint64
	ReceiveQueueDrops, KernelDrops                                            uint64
	SendEnqueuedDatagrams, SentDatagrams, SendFailedDatagrams, SendQueueDrops uint64
	ReceiveMultiBatches, SendMultiBatches                                     uint64
	IngressQueueDepth, EgressQueueDepth                                       uint64
}
type ProcessSnapshot struct {
	Goroutines, HeapInuseBytes, HeapObjects uint64
	AllocatedBytesTotal, MallocsTotal       uint64
	GCCyclesTotal, GCPauseNanosecondsTotal  uint64
}

func NewRegistry() *Registry { return &Registry{state: &registryState{}} }
func (r *Registry) metrics() *registryState {
	if r != nil && r.state != nil {
		return r.state
	}
	return &zeroRegistryState
}

func (r *Registry) Snapshot() Snapshot {
	if r == nil {
		return Snapshot{}
	}
	s := r.metrics()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return Snapshot{
		Lifecycle:   LifecycleSnapshot{s.lifecycle.starts.Load(), s.lifecycle.stops.Load(), s.lifecycle.failures.Load(), s.lifecycle.running.Load(), s.lifecycle.ingressPanics.Load()},
		Reseed:      ReseedSnapshot{s.reseed.attempts.Load(), s.reseed.successes.Load(), s.reseed.failures.Load(), s.reseed.bytes.Load(), s.reseed.sources.Load()},
		Transport:   TransportSnapshot{s.transport.connections.Load(), s.transport.disconnections.Load(), s.transport.handshakeFailures.Load(), s.transport.receivedBytes.Load(), s.transport.sentBytes.Load(), s.transport.sessions.Load()},
		NetDB:       NetDBSnapshot{s.netdb.lookups.Load(), s.netdb.lookupFailures.Load(), s.netdb.stores.Load(), s.netdb.storeFailures.Load(), s.netdb.routers.Load()},
		Tunnel:      TunnelSnapshot{s.tunnel.builds.Load(), s.tunnel.buildSuccesses.Load(), s.tunnel.buildFailures.Load(), s.tunnel.active.Load(), s.tunnel.exploratoryInbound.Load(), s.tunnel.exploratoryOutbound.Load(), s.tunnel.clientInbound.Load(), s.tunnel.clientOutbound.Load(), s.tunnel.participatingForwarded.Load()},
		Admission:   AdmissionSnapshot{s.admission.allowed.Load(), s.admission.rejected.Load(), s.admission.inFlight.Load()},
		Proxy:       ProxySnapshot{s.proxy.requests.Load(), s.proxy.failures.Load(), s.proxy.active.Load()},
		Control:     ControlSnapshot{s.control.requests.Load(), s.control.failures.Load(), s.control.active.Load()},
		Bootstrap:   BootstrapSnapshot{s.bootstrap.stage.Load(), s.bootstrap.routerReachable.Load()},
		Publication: PublicationSnapshot{s.publication.routerInfoSuccesses.Load(), s.publication.leaseSet2Successes.Load(), s.publication.attempts.Load(), s.publication.sendFailures.Load(), s.publication.timeouts.Load()},
		SAM:         SAMSnapshot{s.sam.udpInvalid.Load(), s.sam.udpBackpressure.Load(), s.sam.protocolFailures.Load()},
		Garlic:      GarlicSnapshot{s.garlic.newSessionSent.Load(), s.garlic.newSessionReceived.Load(), s.garlic.existingSessionSent.Load(), s.garlic.existingSessionReceived.Load(), s.garlic.dhStepsSent.Load(), s.garlic.dhStepsReceived.Load(), s.garlic.tunnelClovesForwarded.Load()},
		SSU2:        SSU2Snapshot{s.ssu2.vectorIOEnabled.Load(), s.ssu2.kernelDropAccounting.Load(), s.ssu2.received.Load(), s.ssu2.enqueued.Load(), s.ssu2.processed.Load(), s.ssu2.receiveQueueDrops.Load(), s.ssu2.kernelDrops.Load(), s.ssu2.sendEnqueued.Load(), s.ssu2.sent.Load(), s.ssu2.sendFailed.Load(), s.ssu2.sendQueueDrops.Load(), s.ssu2.receiveMultiBatches.Load(), s.ssu2.sendMultiBatches.Load(), s.ssu2.ingressQueueDepth.Load(), s.ssu2.egressQueueDepth.Load()},
		Process: ProcessSnapshot{
			Goroutines: uint64(runtime.NumGoroutine()), HeapInuseBytes: memory.HeapInuse, HeapObjects: memory.HeapObjects,
			AllocatedBytesTotal: memory.TotalAlloc, MallocsTotal: memory.Mallocs,
			GCCyclesTotal: uint64(memory.NumGC), GCPauseNanosecondsTotal: memory.PauseTotalNs,
		},
	}
}

func (r *Registry) IncLifecycleStarts()                { r.metrics().lifecycle.starts.Add(1) }
func (r *Registry) IncLifecycleStops()                 { r.metrics().lifecycle.stops.Add(1) }
func (r *Registry) IncLifecycleFailures()              { r.metrics().lifecycle.failures.Add(1) }
func (r *Registry) SetLifecycleRunning(v uint64)       { r.metrics().lifecycle.running.Store(v) }
func (r *Registry) IncIngressRecoveredPanics()         { r.metrics().lifecycle.ingressPanics.Add(1) }
func (r *Registry) IncReseedAttempts()                 { r.metrics().reseed.attempts.Add(1) }
func (r *Registry) IncReseedSuccesses()                { r.metrics().reseed.successes.Add(1) }
func (r *Registry) IncReseedFailures()                 { r.metrics().reseed.failures.Add(1) }
func (r *Registry) AddReseedBytes(v uint64)            { r.metrics().reseed.bytes.Add(v) }
func (r *Registry) SetReseedSources(v uint64)          { r.metrics().reseed.sources.Store(v) }
func (r *Registry) IncTransportConnections()           { r.metrics().transport.connections.Add(1) }
func (r *Registry) IncTransportDisconnections()        { r.metrics().transport.disconnections.Add(1) }
func (r *Registry) IncTransportHandshakeFailures()     { r.metrics().transport.handshakeFailures.Add(1) }
func (r *Registry) AddTransportReceivedBytes(v uint64) { r.metrics().transport.receivedBytes.Add(v) }
func (r *Registry) AddTransportSentBytes(v uint64)     { r.metrics().transport.sentBytes.Add(v) }
func (r *Registry) SetTransportSessions(v uint64)      { r.metrics().transport.sessions.Store(v) }
func (r *Registry) IncNetDBLookups()                   { r.metrics().netdb.lookups.Add(1) }
func (r *Registry) IncNetDBLookupFailures()            { r.metrics().netdb.lookupFailures.Add(1) }
func (r *Registry) IncNetDBStores()                    { r.metrics().netdb.stores.Add(1) }
func (r *Registry) IncNetDBStoreFailures()             { r.metrics().netdb.storeFailures.Add(1) }
func (r *Registry) SetNetDBRouters(v uint64)           { r.metrics().netdb.routers.Store(v) }
func (r *Registry) IncTunnelBuilds()                   { r.metrics().tunnel.builds.Add(1) }
func (r *Registry) IncTunnelBuildSuccesses()           { r.metrics().tunnel.buildSuccesses.Add(1) }
func (r *Registry) IncTunnelBuildFailures()            { r.metrics().tunnel.buildFailures.Add(1) }
func (r *Registry) SetTunnelActive(v uint64)           { r.metrics().tunnel.active.Store(v) }
func (r *Registry) SetTunnelExploratoryInboundActive(v uint64) {
	r.metrics().tunnel.exploratoryInbound.Store(v)
}
func (r *Registry) SetTunnelExploratoryOutboundActive(v uint64) {
	r.metrics().tunnel.exploratoryOutbound.Store(v)
}
func (r *Registry) SetTunnelClientInboundActive(v uint64) { r.metrics().tunnel.clientInbound.Store(v) }
func (r *Registry) SetTunnelClientOutboundActive(v uint64) {
	r.metrics().tunnel.clientOutbound.Store(v)
}
func (r *Registry) IncTunnelParticipatingForwarded() {
	r.metrics().tunnel.participatingForwarded.Add(1)
}
func (r *Registry) IncAdmissionAllowed()          { r.metrics().admission.allowed.Add(1) }
func (r *Registry) IncAdmissionRejected()         { r.metrics().admission.rejected.Add(1) }
func (r *Registry) SetAdmissionInFlight(v uint64) { r.metrics().admission.inFlight.Store(v) }
func (r *Registry) IncProxyRequests()             { r.metrics().proxy.requests.Add(1) }
func (r *Registry) IncProxyFailures()             { r.metrics().proxy.failures.Add(1) }
func (r *Registry) SetProxyActive(v uint64)       { r.metrics().proxy.active.Store(v) }
func (r *Registry) IncControlRequests()           { r.metrics().control.requests.Add(1) }
func (r *Registry) IncControlFailures()           { r.metrics().control.failures.Add(1) }
func (r *Registry) SetControlActive(v uint64)     { r.metrics().control.active.Store(v) }
func (r *Registry) SetBootstrapStage(v uint64)    { r.metrics().bootstrap.stage.Store(v) }
func (r *Registry) SetRouterReachable(v uint64)   { r.metrics().bootstrap.routerReachable.Store(v) }
func (r *Registry) IncPublicationRouterInfoSuccesses() {
	r.metrics().publication.routerInfoSuccesses.Add(1)
}
func (r *Registry) IncPublicationLeaseSet2Successes() {
	r.metrics().publication.leaseSet2Successes.Add(1)
}
func (r *Registry) IncSAMUDPInvalid()                  { r.metrics().sam.udpInvalid.Add(1) }
func (r *Registry) IncSAMUDPBackpressureRejected()     { r.metrics().sam.udpBackpressure.Add(1) }
func (r *Registry) IncSAMProtocolFailures()            { r.metrics().sam.protocolFailures.Add(1) }
func (r *Registry) IncPublicationAttempts()            { r.metrics().publication.attempts.Add(1) }
func (r *Registry) IncPublicationSendFailures()        { r.metrics().publication.sendFailures.Add(1) }
func (r *Registry) IncPublicationTimeouts()            { r.metrics().publication.timeouts.Add(1) }
func (r *Registry) IncGarlicECIESNewSessionSent()      { r.metrics().garlic.newSessionSent.Add(1) }
func (r *Registry) IncGarlicECIESNewSessionReceived()  { r.metrics().garlic.newSessionReceived.Add(1) }
func (r *Registry) IncGarlicECIESExistingSessionSent() { r.metrics().garlic.existingSessionSent.Add(1) }
func (r *Registry) IncGarlicECIESExistingSessionReceived() {
	r.metrics().garlic.existingSessionReceived.Add(1)
}
func (r *Registry) IncGarlicECIESDHStepsSent()      { r.metrics().garlic.dhStepsSent.Add(1) }
func (r *Registry) IncGarlicECIESDHStepsReceived()  { r.metrics().garlic.dhStepsReceived.Add(1) }
func (r *Registry) IncGarlicTunnelClovesForwarded() { r.metrics().garlic.tunnelClovesForwarded.Add(1) }
func (r *Registry) SetSSU2VectorIOEnabled(v uint64) { r.metrics().ssu2.vectorIOEnabled.Store(v) }
func (r *Registry) SetSSU2KernelDropAccounting(v uint64) {
	r.metrics().ssu2.kernelDropAccounting.Store(v)
}
func (r *Registry) AddSSU2ReceivedDatagrams(v uint64)     { r.metrics().ssu2.received.Add(v) }
func (r *Registry) AddSSU2EnqueuedDatagrams(v uint64)     { r.metrics().ssu2.enqueued.Add(v) }
func (r *Registry) AddSSU2ProcessedDatagrams(v uint64)    { r.metrics().ssu2.processed.Add(v) }
func (r *Registry) AddSSU2ReceiveQueueDrops(v uint64)     { r.metrics().ssu2.receiveQueueDrops.Add(v) }
func (r *Registry) AddSSU2KernelDrops(v uint64)           { r.metrics().ssu2.kernelDrops.Add(v) }
func (r *Registry) AddSSU2SendEnqueuedDatagrams(v uint64) { r.metrics().ssu2.sendEnqueued.Add(v) }
func (r *Registry) AddSSU2SentDatagrams(v uint64)         { r.metrics().ssu2.sent.Add(v) }
func (r *Registry) AddSSU2SendFailedDatagrams(v uint64)   { r.metrics().ssu2.sendFailed.Add(v) }
func (r *Registry) AddSSU2SendQueueDrops(v uint64)        { r.metrics().ssu2.sendQueueDrops.Add(v) }
func (r *Registry) IncSSU2ReceiveMultiBatches()           { r.metrics().ssu2.receiveMultiBatches.Add(1) }
func (r *Registry) IncSSU2SendMultiBatches()              { r.metrics().ssu2.sendMultiBatches.Add(1) }
func (r *Registry) SetSSU2IngressQueueDepth(v uint64)     { r.metrics().ssu2.ingressQueueDepth.Store(v) }
func (r *Registry) SetSSU2EgressQueueDepth(v uint64)      { r.metrics().ssu2.egressQueueDepth.Store(v) }
func (r *Registry) IncSSU2IngressQueueDepth()             { r.metrics().ssu2.ingressQueueDepth.Add(1) }
func (r *Registry) DecSSU2IngressQueueDepth()             { r.metrics().ssu2.ingressQueueDepth.Add(^uint64(0)) }
func (r *Registry) IncSSU2EgressQueueDepth()              { r.metrics().ssu2.egressQueueDepth.Add(1) }
func (r *Registry) DecSSU2EgressQueueDepth()              { r.metrics().ssu2.egressQueueDepth.Add(^uint64(0)) }
