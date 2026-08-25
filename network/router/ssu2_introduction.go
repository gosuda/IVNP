package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/network/transport/ssu2"
	"gosuda.org/ivnp/protocol/i2np"
	"gosuda.org/ivnp/protocol/netdb"
)

const (
	ssu2RelayRejectTagNotFound    = 5
	ssu2RelayRejectLimit          = 3
	ssu2RelayRejectSignature      = 67
	ssu2RelayRejectUnsupported    = 65
	ssu2RelayRejectAliceUnknown   = 70
	ssu2RelayRejectGeneralFailure = 64
)

func (m *SSU2Manager) finishRelayRequestLocked(nonce uint32, relay *ssu2RelayRequest, err error) {
	if relay == nil || relay.completed || m.relayRequests[nonce] != relay {
		return
	}
	relay.completed = true
	relay.err = err
	if relay.timer != nil {
		relay.timer.Stop()
	}
	delete(m.relayRequests, nonce)
	close(relay.ready)
}

func (m *SSU2Manager) expireIntroductions(now time.Time) {
	m.mu.Lock()
	for nonce, relay := range m.relayRequests {
		if !now.Before(relay.expires) {
			m.finishRelayRequestLocked(nonce, relay, ErrSSU2Introduction)
		}
	}
	for nonce, forward := range m.relayForwards {
		if !now.Before(forward.expires) {
			delete(m.relayForwards, nonce)
		}
	}
	for nonce, deferred := range m.deferredRelayIntros {
		if !now.Before(deferred.expires) {
			delete(m.deferredRelayIntros, nonce)
		}
	}
	m.mu.Unlock()
}

func (m *SSU2Manager) ssu2KeysForPeer(peer ivnp.Hash) (ssu2PeerAddress, error) {
	if m.database == nil {
		return ssu2PeerAddress{}, ErrSSU2Peer
	}
	ref, ok := m.database.Routers().Get(peer)
	if !ok {
		return ssu2PeerAddress{}, ErrSSU2Peer
	}
	return selectSSU2Keys(ref.Info)
}

func (m *SSU2Manager) routerInfo(peer ivnp.Hash) (netdb.RouterInfo, bool) {
	if m.database == nil {
		return netdb.RouterInfo{}, false
	}
	ref, ok := m.database.Routers().Get(peer)
	if !ok {
		return netdb.RouterInfo{}, false
	}
	return ref.Info, true
}

type ssu2ControlSigner interface {
	Sign([]byte) []byte
}

func (m *SSU2Manager) signSSU2Control(message []byte) ([]byte, error) {
	m.mu.RLock()
	sign := m.signControl
	local := m.bindings.LocalInfo
	m.mu.RUnlock()
	if sign != nil {
		return sign(message)
	}
	signer, ok := local.(ssu2ControlSigner)
	if !ok {
		return nil, ErrSSU2Introduction
	}
	return signer.Sign(message), nil
}

func (m *SSU2Manager) localSSU2Endpoint() (netip.AddrPort, error) {
	m.mu.RLock()
	source := m.introductionEndpoint
	m.mu.RUnlock()
	if source != nil {
		endpoint, err := source()
		if err != nil || !validSSU2Endpoint(endpoint) {
			return netip.AddrPort{}, ErrSSU2Introduction
		}
		return endpoint, nil
	}
	bindings := m.currentBindings()
	if bindings.LocalInfo == nil {
		return netip.AddrPort{}, ErrSSU2Introduction
	}
	address, err := selectSSU2Address(bindings.LocalInfo.Snapshot())
	if err != nil {
		return netip.AddrPort{}, ErrSSU2Introduction
	}
	ip, err := netip.ParseAddr(address.host)
	if err != nil || !ip.IsValid() {
		return netip.AddrPort{}, ErrSSU2Introduction
	}
	endpoint := netip.AddrPortFrom(ip, address.port)
	if !validSSU2Endpoint(endpoint) {
		return netip.AddrPort{}, ErrSSU2Introduction
	}
	return endpoint, nil
}

func (m *SSU2Manager) relayTimestampValid(timestamp uint32) bool {
	delta := m.now().Unix() - int64(timestamp)
	if delta < 0 {
		delta = -delta
	}
	return time.Duration(delta)*time.Second <= m.maxClockSkew
}

func (m *SSU2Manager) handleRelayRequest(alice *ssu2TransportSession, request ssu2.RelayRequest) {
	m.mu.RLock()
	charliePeer, found := m.introducers[request.RelayTag]
	charlie := m.sessionsByPeer[charliePeer]
	bindings := m.bindings
	m.mu.RUnlock()
	if bindings.LocalInfo == nil {
		return
	}
	localHash := bindings.LocalInfo.Hash()
	if !found || charlie == nil || !m.sessionActive(charlie) {
		m.sendRelayResponse(alice, localHash, ssu2.RelayResponse{Code: ssu2RelayRejectTagNotFound, Nonce: request.Nonce, Timestamp: uint32(m.now().Unix())})
		return
	}
	aliceInfo, known := m.routerInfo(alice.peer)
	input, err := ssu2.RelayRequestSignatureInput(nil, localHash[:], charliePeer[:], request)
	if err != nil || !known || !m.relayTimestampValid(request.Timestamp) {
		m.sendRelayResponse(alice, localHash, ssu2.RelayResponse{Code: ssu2RelayRejectSignature, Nonce: request.Nonce, Timestamp: uint32(m.now().Unix())})
		return
	}
	valid, verifyErr := aliceInfo.Identity.Verify(input, request.Signature)
	clear(input)
	if verifyErr != nil || !valid {
		m.sendRelayResponse(alice, localHash, ssu2.RelayResponse{Code: ssu2RelayRejectSignature, Nonce: request.Nonce, Timestamp: uint32(m.now().Unix())})
		return
	}
	m.mu.Lock()
	if _, exists := m.relayForwards[request.Nonce]; exists {
		m.mu.Unlock()
		return
	}
	if len(m.relayForwards) >= m.maxPending {
		m.mu.Unlock()
		m.sendRelayResponse(alice, localHash, ssu2.RelayResponse{Code: ssu2RelayRejectLimit, Nonce: request.Nonce, Timestamp: uint32(m.now().Unix())})
		return
	}
	jobs, ctx := m.relayStoreJobs, m.ctx
	if jobs == nil || ctx == nil || !m.runningLocked() {
		m.mu.Unlock()
		m.sendRelayResponse(alice, localHash, ssu2.RelayResponse{Code: ssu2RelayRejectGeneralFailure, Nonce: request.Nonce, Timestamp: uint32(m.now().Unix())})
		return
	}
	m.relayForwards[request.Nonce] = ssu2RelayForward{alice: alice, charlie: charlie, expires: m.nowLocked().Add(m.timeout)}
	m.mu.Unlock()

	job := ssu2RelayStoreJob{nonce: request.Nonce, request: request, alice: alice, charlie: charlie, aliceInfo: aliceInfo, localHash: localHash}
	select {
	case jobs <- job:
	case <-ctx.Done():
		m.failRelayForward(job)
	default:
		m.failRelayForward(job)
	}
}

// relayStoreLoop drains bounded relay jobs. Multiple workers may compress
// independent RouterInfos concurrently; the shared cache is separately locked.
func (m *SSU2Manager) relayStoreLoop() {
	defer m.wg.Done()
	m.mu.RLock()
	ctx, jobs := m.ctx, m.relayStoreJobs
	m.mu.RUnlock()
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-jobs:
			m.forwardRelayStore(job)
		}
	}
}

func (m *SSU2Manager) forwardRelayStore(job ssu2RelayStoreJob) {
	m.mu.RLock()
	forward, active := m.relayForwards[job.nonce]
	m.mu.RUnlock()
	if !active || forward.alice != job.alice || forward.charlie != job.charlie {
		return
	}
	store, err := m.cachedSSU2RouterInfoStore(job.aliceInfo, m.now())
	if err == nil {
		job.charlie.frameMu.Lock()
		err = forEachSSU2I2NPFragment(job.charlie.frame[:], store, func(fragment []byte) error {
			return m.sendData(job.charlie, fragment)
		})
		job.charlie.frameMu.Unlock()
	}
	if err == nil {
		var intro []byte
		intro, err = ssu2.MarshalRelayIntroBlock(nil, ssu2.RelayIntro{AliceHash: [32]byte(job.alice.peer), Request: job.request})
		if err == nil {
			err = m.sendData(job.charlie, intro)
		}

	}
	if err != nil {
		m.failRelayForward(job)
	}
}

func (m *SSU2Manager) failRelayForward(job ssu2RelayStoreJob) {
	m.mu.Lock()
	forward, active := m.relayForwards[job.nonce]
	active = active && forward.alice == job.alice && forward.charlie == job.charlie
	if active {
		delete(m.relayForwards, job.nonce)
	}
	m.mu.Unlock()
	if active {
		m.sendRelayResponse(job.alice, job.localHash, ssu2.RelayResponse{Code: ssu2RelayRejectGeneralFailure, Nonce: job.request.Nonce, Timestamp: uint32(m.now().Unix())})
	}
}

func (m *SSU2Manager) handleRelayIntro(bob *ssu2TransportSession, intro ssu2.RelayIntro) {
	m.handleRelayIntroAttempt(bob, intro, 0)
}

func (m *SSU2Manager) handleRelayIntroAttempt(bob *ssu2TransportSession, intro ssu2.RelayIntro, attempt uint8) {
	bindings := m.currentBindings()
	if bindings.LocalInfo == nil {
		return
	}
	localHash := bindings.LocalInfo.Hash()
	response := ssu2.RelayResponse{Code: ssu2RelayRejectAliceUnknown, Nonce: intro.Request.Nonce, Timestamp: uint32(m.now().Unix())}
	alice := ivnp.Hash(intro.AliceHash)
	aliceInfo, known := m.routerInfo(alice)
	if !known && attempt < 3 && m.deferRelayIntro(bob, intro, attempt) {
		return
	}
	if known && m.relayTimestampValid(intro.Request.Timestamp) {
		response, delivered := m.processRelayIntro(bob, intro, localHash, aliceInfo)
		if delivered {
			return
		}
		m.sendRelayResponse(bob, bob.peer, response)
		return
	}
	m.sendRelayResponse(bob, bob.peer, response)
}

func (m *SSU2Manager) processRelayIntro(bob *ssu2TransportSession, intro ssu2.RelayIntro, localHash ivnp.Hash, aliceInfo netdb.RouterInfo) (ssu2.RelayResponse, bool) {
	response := ssu2.RelayResponse{Code: ssu2RelayRejectSignature, Nonce: intro.Request.Nonce, Timestamp: uint32(m.now().Unix())}
	input, err := ssu2.RelayRequestSignatureInput(nil, bob.peer[:], localHash[:], intro.Request)
	if err != nil {
		return response, false
	}
	valid, verifyErr := aliceInfo.Identity.Verify(input, intro.Request.Signature)
	clear(input)
	if verifyErr != nil || !valid {
		return response, false
	}
	endpoint, err := m.localSSU2Endpoint()
	if err != nil {
		response.Code = ssu2RelayRejectUnsupported
		return response, false
	}
	aliceAddress, err := selectSSU2Keys(aliceInfo)
	if err != nil {
		response.Code = ssu2RelayRejectAliceUnknown
		return response, false
	}
	destinationID, sourceID := ssu2.RelayConnectionIDs(intro.Request.Nonce)
	remote := udpAddressFromAddrPort(intro.Request.Endpoint)
	m.mu.Lock()
	token, err := m.newTokenLocked(remote, destinationID, sourceID)
	m.mu.Unlock()
	if err != nil {
		response.Code = ssu2RelayRejectGeneralFailure
		return response, false
	}
	response = ssu2.RelayResponse{
		Nonce:     intro.Request.Nonce,
		Timestamp: uint32(m.now().Unix()),
		Endpoint:  endpoint,
		Token:     token,
		HasToken:  true,
	}
	if !m.signRelayResponse(bob.peer, &response) {
		return response, true
	}
	block, err := ssu2.MarshalRelayResponseBlock(nil, response)
	if err != nil || m.sendData(bob, block) != nil {
		return response, true
	}
	m.sendHolePunch(aliceAddress, intro.Request.Endpoint, response)
	return response, true
}

func (m *SSU2Manager) deferRelayIntro(bob *ssu2TransportSession, intro ssu2.RelayIntro, attempt uint8) bool {
	m.mu.Lock()
	if !m.runningLocked() || len(m.deferredRelayIntros) >= m.maxPending {
		m.mu.Unlock()
		return false
	}
	if _, exists := m.deferredRelayIntros[intro.Request.Nonce]; exists {
		m.mu.Unlock()
		return true
	}
	m.deferredRelayIntros[intro.Request.Nonce] = ssu2DeferredRelayIntro{
		bob:     bob,
		intro:   intro,
		attempt: attempt,
		expires: m.nowLocked().Add(m.timeout),
	}
	m.mu.Unlock()
	time.AfterFunc(20*time.Millisecond, func() {
		m.mu.Lock()
		deferred, exists := m.deferredRelayIntros[intro.Request.Nonce]
		if exists {
			delete(m.deferredRelayIntros, intro.Request.Nonce)
		}
		m.mu.Unlock()
		if exists {
			m.handleRelayIntroAttempt(deferred.bob, deferred.intro, deferred.attempt+1)
		}
	})
	return true
}

func (m *SSU2Manager) handleRelayResponse(from *ssu2TransportSession, response ssu2.RelayResponse) {
	m.mu.RLock()
	relay := m.relayRequests[response.Nonce]
	m.mu.RUnlock()
	if relay == nil || from == nil || from.peer != relay.introducer {
		return
	}
	m.acceptRelayResponse(response, relay)
}

func (m *SSU2Manager) forwardRelayResponse(from *ssu2TransportSession, response ssu2.RelayResponse, data []byte) {
	m.mu.Lock()
	forward, ok := m.relayForwards[response.Nonce]
	if ok && forward.charlie == from {
		delete(m.relayForwards, response.Nonce)
	} else {
		ok = false
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	payload, err := ssu2.MarshalBlock(nil, ssu2.BlockRelayResponse, data)
	if err == nil {
		_ = m.sendData(forward.alice, payload)
	}
}

func (m *SSU2Manager) acceptRelayResponse(response ssu2.RelayResponse, relay *ssu2RelayRequest) {
	if response.Code != 0 {
		m.mu.Lock()
		m.finishRelayRequestLocked(response.Nonce, relay, ErrSSU2Introduction)
		m.mu.Unlock()
		return
	}
	if !m.relayTimestampValid(response.Timestamp) {
		m.mu.Lock()
		m.finishRelayRequestLocked(response.Nonce, relay, ErrSSU2Introduction)
		m.mu.Unlock()
		return
	}
	targetInfo, known := m.routerInfo(relay.target)
	input, err := ssu2.RelayResponseSignatureInput(nil, relay.introducer[:], response)
	valid, verifyErr := false, err
	if err == nil && known {
		valid, verifyErr = targetInfo.Identity.Verify(input, response.Signature)
		clear(input)
	}
	if verifyErr != nil || !valid {
		m.mu.Lock()
		m.finishRelayRequestLocked(response.Nonce, relay, ErrSSU2Introduction)
		m.mu.Unlock()
		return
	}
	m.startIntroducedOutbound(response, relay)
}

func (m *SSU2Manager) startIntroducedOutbound(response ssu2.RelayResponse, relay *ssu2RelayRequest) {
	destinationID, sourceID := ssu2.RelayConnectionIDs(response.Nonce)
	m.mu.Lock()
	if relay.completed || m.relayRequests[response.Nonce] != relay {
		m.mu.Unlock()
		return
	}
	if session := m.sessionsByPeer[relay.target]; session != nil && !session.idle(m.nowLocked(), m.idleTimeout) {
		m.finishRelayRequestLocked(response.Nonce, relay, nil)
		m.mu.Unlock()
		return
	}
	pending, err := m.newIntroducedOutboundLocked(relay.target, relay.address, response.Endpoint, destinationID, sourceID)
	if err != nil {
		m.finishRelayRequestLocked(response.Nonce, relay, ErrSSU2Introduction)
		m.mu.Unlock()
		return
	}
	pending.tokenSent = true
	relay.started = true
	m.finishRelayRequestLocked(response.Nonce, relay, nil)
	m.mu.Unlock()
	m.sendSessionRequest(pending, response.Token)
}

func (m *SSU2Manager) sendRelayResponse(session *ssu2TransportSession, bobHash ivnp.Hash, response ssu2.RelayResponse) {
	if !m.signRelayResponse(bobHash, &response) {
		return
	}
	payload, err := ssu2.MarshalRelayResponseBlock(nil, response)
	if err == nil {
		_ = m.sendData(session, payload)
	}
}

func (m *SSU2Manager) signRelayResponse(bobHash ivnp.Hash, response *ssu2.RelayResponse) bool {
	input, err := ssu2.RelayResponseSignatureInput(nil, bobHash[:], *response)
	if err != nil {
		return false
	}
	response.Signature, err = m.signSSU2Control(input)
	clear(input)
	return err == nil && len(response.Signature) != 0
}

func (m *SSU2Manager) sendHolePunch(aliceAddress ssu2PeerAddress, remote netip.AddrPort, response ssu2.RelayResponse) {
	if !validSSU2Endpoint(remote) {
		return
	}
	payload, err := m.holePunchPayload(response)
	if err != nil {
		return
	}
	destinationID, sourceID := ssu2.RelayConnectionIDs(response.Nonce)
	packetNumber, err := randomPacketNumber()
	if err != nil {
		return
	}
	packet, err := ssu2.BuildHolePunch(make([]byte, ssu2.MaxIPv4PacketLen), aliceAddress.intro[:], destinationID, sourceID, 0, packetNumber, payload)
	if err == nil {
		_ = m.writeRelayTo(packet, udpAddressFromAddrPort(remote), uint64(response.Nonce))
	}
}

func (m *SSU2Manager) holePunchPayload(response ssu2.RelayResponse) ([]byte, error) {
	payload, err := ssu2DateTimeBlock(m.now())
	if err != nil {
		return nil, err
	}
	endpoint := response.Endpoint
	data, err := ssu2EndpointData(endpoint)
	if err != nil {
		return nil, err
	}
	payload, err = ssu2.MarshalBlock(payload, ssu2.BlockAddress, data)
	if err != nil {
		return nil, err
	}
	return ssu2.MarshalRelayResponseBlock(payload, response)
}

func (m *SSU2Manager) handleHolePunch(header ssu2.LongHeader, payload []byte, _ net.Addr) {
	iterator := ssu2.NewBlockIterator(payload)
	var response ssu2.RelayResponse
	for {
		block, ok, err := iterator.Next()
		if err != nil || !ok {
			return
		}
		if block.Type != ssu2.BlockRelayResponse {
			continue
		}
		response, err = ssu2.ParseRelayResponseBlock(block.Data)
		if err != nil {
			return
		}
		break
	}
	destinationID, sourceID := ssu2.RelayConnectionIDs(response.Nonce)
	if header.DestinationID != destinationID || header.SourceID != sourceID {
		return
	}
	m.mu.RLock()
	relay := m.relayRequests[response.Nonce]
	m.mu.RUnlock()
	if relay != nil {
		m.acceptRelayResponse(response, relay)
	}
}

// ssu2RouterInfoStore constructs a one-off deterministic store. Relay
// forwarding uses cachedSSU2RouterInfoStore from its control-plane worker.
func ssu2RouterInfoStore(info netdb.RouterInfo, now time.Time) (i2np.Message, error) {
	snapshot, err := newSSU2RouterInfoStoreSnapshot(info)
	if err != nil {
		return i2np.Message{}, err
	}
	return snapshot.message(now)
}

// cachedSSU2RouterInfoStore refreshes an entry when the immutable RouterInfo
// bytes change. Compression runs outside the cache lock.
func (m *SSU2Manager) cachedSSU2RouterInfoStore(info netdb.RouterInfo, now time.Time) (i2np.Message, error) {
	hash := info.Hash()
	raw := info.Bytes()
	m.routerInfoStoresMu.RLock()
	cached, ok := m.routerInfoStores[hash]
	m.routerInfoStoresMu.RUnlock()
	if ok && bytes.Equal(cached.raw, raw) {
		return cached.message(now)
	}
	snapshot, err := newSSU2RouterInfoStoreSnapshot(info)
	if err != nil {
		return i2np.Message{}, err
	}
	m.routerInfoStoresMu.Lock()
	if m.routerInfoStores == nil {
		m.routerInfoStores = make(map[ivnp.Hash]ssu2RouterInfoStoreSnapshot)
	}
	if current, exists := m.routerInfoStores[hash]; exists && bytes.Equal(current.raw, raw) {
		snapshot = current
	} else {
		m.routerInfoStores[hash] = snapshot
	}
	m.routerInfoStoresMu.Unlock()
	return snapshot.message(now)
}

func newSSU2RouterInfoStoreSnapshot(info netdb.RouterInfo) (ssu2RouterInfoStoreSnapshot, error) {
	raw := info.Bytes()
	if len(raw) == 0 || len(raw) > netdb.MaxRouterInfoBytes {
		return ssu2RouterInfoStoreSnapshot{}, ErrSSU2Peer
	}
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return ssu2RouterInfoStoreSnapshot{}, err
	}
	writer.Header.ModTime = time.Unix(0, 0)
	writer.Header.OS = 255
	if _, err = writer.Write(raw); err == nil {
		err = writer.Close()
	}
	if err != nil {
		return ssu2RouterInfoStoreSnapshot{}, err
	}
	if compressed.Len() == 0 || compressed.Len() > netdb.MaxRouterInfoBytes || compressed.Len() > 0xffff {
		return ssu2RouterInfoStoreSnapshot{}, ErrSSU2Peer
	}
	return ssu2RouterInfoStoreSnapshot{
		raw:        append([]byte(nil), raw...),
		compressed: append([]byte(nil), compressed.Bytes()...),
		hash:       info.Hash(),
	}, nil
}

func (snapshot ssu2RouterInfoStoreSnapshot) message(now time.Time) (i2np.Message, error) {
	payload := make([]byte, 39+len(snapshot.compressed))
	copy(payload[:32], snapshot.hash[:])
	payload[32] = byte(i2np.StoreRouterInfo)
	binary.BigEndian.PutUint16(payload[37:39], uint16(len(snapshot.compressed)))
	copy(payload[39:], snapshot.compressed)
	if _, err := i2np.ParseDatabaseStore(payload); err != nil {
		return i2np.Message{}, err
	}
	id, err := randomPacketNumber()
	if err != nil {
		return i2np.Message{}, err
	}
	return i2np.Message{Header: i2np.Header{Type: i2np.DatabaseStore, ID: id, Expiration: uint64(now.Add(time.Minute).UnixMilli())}, Payload: payload}, nil
}

func selectSSU2Keys(info netdb.RouterInfo) (ssu2PeerAddress, error) {
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil {
			return ssu2PeerAddress{}, err
		}
		if !ok {
			return ssu2PeerAddress{}, ErrSSU2Peer
		}
		if !bytes.Equal(address.TransportStyle, []byte("SSU")) && !bytes.Equal(address.TransportStyle, []byte("SSU2")) {
			continue
		}
		var static, intro, version string
		options := address.Options.Iterator()
		for {
			name, value, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			switch string(name) {
			case "s":
				static = string(value)
			case "i":
				intro = string(value)
			case "v":
				version = string(value)
			}
		}
		staticKey, staticErr := ivnp.DecodeI2PBase64([]byte(static))
		introKey, introErr := ivnp.DecodeI2PBase64([]byte(intro))
		if staticErr != nil || introErr != nil || len(staticKey) != 32 || len(introKey) != 32 || !supportsSSU2Version(version) {
			continue
		}
		var selected ssu2PeerAddress
		copy(selected.static[:], staticKey)
		copy(selected.intro[:], introKey)
		return selected, nil
	}
}

type ssu2IntroducerCandidate struct {
	peer     ivnp.Hash
	relayTag uint32
}

func (m *SSU2Manager) introduceFromRouterInfo(ctx context.Context, target ivnp.Hash) error {
	endpoint, err := m.localSSU2Endpoint()
	if err != nil {
		return err
	}
	info, known := m.routerInfo(target)
	if !known {
		return ErrSSU2Peer
	}
	candidates := selectSSU2Introducers(info, uint64(m.now().Unix()))
	if len(candidates) == 0 {
		return ErrSSU2Peer
	}
	lastErr := ErrSSU2Introduction
	for _, candidate := range candidates {
		if err = m.Introduce(ctx, candidate.peer, target, candidate.relayTag, endpoint); err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

func selectSSU2Introducers(info netdb.RouterInfo, now uint64) []ssu2IntroducerCandidate {
	addresses := info.Addresses()
	var candidates []ssu2IntroducerCandidate
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			return candidates
		}
		if !bytes.Equal(address.TransportStyle, []byte("SSU")) && !bytes.Equal(address.TransportStyle, []byte("SSU2")) {
			continue
		}
		var peers [3]ivnp.Hash
		var tags, expirations [3]uint32
		var hasPeer, hasTag [3]bool
		options := address.Options.Iterator()
		for {
			name, value, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			switch {
			case len(name) == 3 && bytes.Equal(name[:2], []byte("ih")) && name[2] >= '0' && name[2] <= '2':
				index := int(name[2] - '0')
				decoded, err := ivnp.DecodeI2PBase64(value)
				if err == nil && len(decoded) == len(peers[index]) {
					copy(peers[index][:], decoded)
					hasPeer[index] = true
				}
			case len(name) == 5 && bytes.Equal(name[:4], []byte("itag")) && name[4] >= '0' && name[4] <= '2':
				index := int(name[4] - '0')
				tag, err := strconv.ParseUint(string(value), 10, 32)
				if err == nil && tag != 0 {
					tags[index] = uint32(tag)
					hasTag[index] = true
				}
			case len(name) == 5 && bytes.Equal(name[:4], []byte("iexp")) && name[4] >= '0' && name[4] <= '2':
				index := int(name[4] - '0')
				expiration, err := strconv.ParseUint(string(value), 10, 32)
				if err == nil {
					expirations[index] = uint32(expiration)
				}
			}
		}
		for index := range peers {
			selectSSU2IntroducersSelected := hasPeer[index] && hasTag[index]
			if selectSSU2IntroducersSelected {
				selectSSU2IntroducersSelected = (expirations[index] == 0 || uint64(expirations[index]) >= now)
			}
			if selectSSU2IntroducersSelected {
				candidates = append(candidates, ssu2IntroducerCandidate{peer: peers[index], relayTag: tags[index]})
			}
		}
	}
}

func validSSU2Endpoint(endpoint netip.AddrPort) bool {
	address := endpoint.Addr()
	return endpoint.IsValid() && endpoint.Port() != 0 && !address.IsUnspecified() && !address.Is4In6() && (address.Is4() || address.Is6())
}

func udpAddressFromAddrPort(endpoint netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{IP: endpoint.Addr().AsSlice(), Port: int(endpoint.Port())}
}

func ssu2EndpointData(endpoint netip.AddrPort) ([]byte, error) {
	if !validSSU2Endpoint(endpoint) {
		return nil, ErrSSU2Introduction
	}
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, endpoint.Port())
	if endpoint.Addr().Is4() {
		v4 := endpoint.Addr().As4()
		return append(data, v4[:]...), nil
	}
	v6 := endpoint.Addr().As16()
	return append(data, v6[:]...), nil
}

func randomRelayNonce() (uint32, error) {
	for {
		nonce, err := randomPacketNumber()
		if err != nil {
			return 0, err
		}
		if nonce != 0 {
			return nonce, nil
		}
	}
}
