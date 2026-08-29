package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
)

// StartVariableOutbound creates a historical 528-byte VariableTunnelBuild.
// It is deliberately separate from StartOutbound: current peers should use the
// smaller short ECIES format unless a mixed compatibility path is required.
func (m *BuildManager) StartVariableOutbound(ctx context.Context, build VariableOutboundBuild) (uint32, error) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.isReleased() {
		return 0, ErrBuildConfig
	}
	if ctx ==
		nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := m.now()
	startVariableOutboundRejected := build.CircuitID == 0 || len(build.Hops) == 0 || len(build.Hops) > legacyBuildMaxRecords || build.ReplyRouter == (foundation.Hash{}) || build.ReplyTunnelID == 0 || build.ExpiresAt <= now
	if !startVariableOutboundRejected {
		startVariableOutboundRejected = !validVariableHops(build.Hops)
	}
	if startVariableOutboundRejected {
		return 0, ErrBuildConfig
	}
	ids := make([]uint32, len(build.Hops)+1)
	for index := range ids {
		id, err := m.uniqueMessageID(ids[:index])
		if err != nil {
			return 0, err
		}
		ids[index] = id
	}
	recordCount := legacyBuildMinRecords
	if len(build.Hops) > recordCount {
		recordCount = legacyBuildMaxRecords
	}
	positions, err := m.randomPositions(len(build.Hops), recordCount)
	if err != nil {
		return 0, err
	}
	payload := make([]byte, 1+recordCount*VariableBuildRecordSize)
	payload[0] = byte(recordCount)
	if _, err = io.ReadFull(m.random, payload[1:]); err != nil {
		return 0, err
	}
	keys := make([]VariableBuildKeys, len(build.Hops))
	for index, hop := range build.Hops {
		nextRouter, nextTunnel := build.ReplyRouter, build.ReplyTunnelID
		if index+1 < len(build.Hops) {
			nextRouter, nextTunnel = build.Hops[index+1].Router, build.Hops[index+1].ReceiveTunnelID
		}
		request := VariableBuildRequest{ReceiveTunnelID: hop.ReceiveTunnelID, NextTunnelID: nextTunnel, NextRouter: nextRouter, Endpoint: index+1 == len(build.Hops), RequestHours: uint32(now / 3_600_000), RequestMinutes: uint32(now / 60_000), LifetimeSeconds: legacyBuildLifetimeSeconds, NextMessageID: ids[index+1]}
		if err = fillVariableRequest(payload[1+int(positions[index])*VariableBuildRecordSize:1+(int(positions[index])+1)*VariableBuildRecordSize], hop, request, m.local, m.random, &keys[index]); err != nil {
			clearVariableBuildKeys(keys)
			return 0, err
		}
	}
	if err = PreprocessVariableBuildRecords(payload[1:], keys, positions); err != nil {
		clearVariableBuildKeys(keys)
		return 0, err
	}
	messageDeadline, err := randomizedBuildMessageDeadline(now, m.random)
	if err != nil {
		clearVariableBuildKeys(keys)
		return 0, err
	}
	replyID := ids[len(ids)-1]
	pending := &pendingVariableBuild{build: cloneVariableOutboundBuild(build), keys: keys, positions: positions, replyID: replyID, recordCount: uint8(recordCount), deadline: build.ExpiresAt}
	m.mu.Lock()
	if len(m.pending)+len(m.pendingInbound)+len(m.pendingVariable) >= m.maxPending || m.replyIDInUseLocked(replyID) {
		m.mu.Unlock()
		cancelBuildDeadline(pending.cancelDeadline)
		clearVariableBuildKeys(keys)
		return 0, ErrBuildPending
	}
	m.pendingVariable[replyID] = pending
	m.mu.Unlock()
	message := i2np.Message{Header: i2np.Header{Type: i2np.VariableTunnelBuild, ID: ids[0], Expiration: messageDeadline}, Payload: payload}
	if err = m.sender.Send(ctx, build.Hops[0].Router, message); err != nil {
		m.removeVariablePending(replyID)
		return 0, err
	}
	m.armVariableDeadline(replyID)
	return replyID, nil
}

func (m *BuildManager) armVariableDeadline(replyID uint32) {
	now := m.now()
	m.mu.Lock()
	pending := m.pendingVariable[replyID]
	if pending != nil {
		pending.deadline = min(pending.build.ExpiresAt, saturatingDeadline(now, buildRequestTimeout()))
		pending.cancelDeadline = m.scheduleBuildDeadline(now, pending.deadline)
	}
	m.mu.Unlock()
}

func fillVariableRequest(record []byte, hop VariableBuildHop, request VariableBuildRequest, local foundation.Hash, random io.Reader, keys *VariableBuildKeys) error {
	var err error
	switch hop.Kind {
	case VariableBuildElGamal:
		var plaintext [LegacyBuildRequestPlainSize]byte
		if err = MarshalElGamalBuildRequest(plaintext[:], request, local, random); err == nil {
			err = EncryptElGamalBuildRequest(record, hop.Router, hop.ElGamalKey, plaintext[:])
		}
		clear(plaintext[:])
		keys.Kind, keys.LayerKey, keys.IVKey, keys.ReplyKey, keys.ReplyIV = hop.Kind, request.LayerKey, request.IVKey, request.ReplyKey, request.ReplyIV
		return err
	case VariableBuildLongECIES:
		var plaintext [LongBuildRequestPlainSize]byte
		if err = MarshalLongECIESBuildRequest(plaintext[:], request); err == nil {
			*keys, err = encryptLongECIESBuildRequest(record, hop.Router, hop.StaticKey[:], plaintext[:], random)
		}
		clear(plaintext[:])
		return err
	default:
		return ErrBuildConfig
	}
}

func (m *BuildManager) handleVariableTransit(message i2np.Message) error {
	if m.local == (foundation.Hash{}) {
		return ErrBuildConfig
	}
	records, err := i2np.ParseBuildRecords(i2np.VariableTunnelBuild, message.Payload)
	if err != nil {
		return err
	}
	now := m.now()
	if !m.reserveTransit(message.Header.ID, sha256.Sum256(message.Payload), now) {
		return ErrBuildTransit
	}
	kind := VariableBuildLongECIES
	if m.legacyEnabled {
		kind = VariableBuildElGamal
	} else if m.staticPrivateKey == nil {
		return ErrBuildConfig
	}
	var staticPrivate []byte
	if m.staticPrivateKey != nil {
		staticPrivate = m.staticPrivateKey.Bytes()
	}
	var plaintext [LongBuildRequestPlainSize]byte
	request, keys, slot, err := ProcessVariableBuildRecords(records.Records, plaintext[:], m.local, kind, staticPrivate, m.legacyPrivate, false, m.random)
	clear(plaintext[:])
	if err != nil {
		return err
	}
	defer clearVariableBuildKey(&keys)
	accept := m.validVariableTransitRequest(request, kind, now)
	if accept && m.admit != nil {
		accept = m.admit(shortRequestFromVariable(request))
	}
	if accept {
		accept = m.installVariableTransitCircuit(request, now) == nil
	}
	if accept {
		record := records.Records[int(slot)*VariableBuildRecordSize : (int(slot)+1)*VariableBuildRecordSize]
		if err = sealVariableBuildReply(record, keys, m.random, 0); err != nil {
			return err
		}
	}
	if request.Endpoint {
		if request.NextRouter == (foundation.Hash{}) || request.NextRouter == m.local || request.NextTunnelID == 0 {
			if accept {
				m.runtime.RemoveCircuit(request.ReceiveTunnelID)
			}
			return ErrBuildRejected
		}
		if err = m.sendVariableReply(request, message.Payload, now); err != nil {
			if accept {
				m.runtime.RemoveCircuit(request.ReceiveTunnelID)
			}
			return err
		}
		if !accept {
			return ErrBuildRejected
		}
		return nil
	}
	forward := i2np.Message{Header: i2np.Header{Type: i2np.VariableTunnelBuild, ID: request.NextMessageID, Expiration: saturatingDeadline(now, nextHopSendTimeout)}, Payload: message.Payload}
	if err = m.sender.Send(m.ctx, request.NextRouter, forward); err != nil {
		if accept {
			m.runtime.RemoveCircuit(request.ReceiveTunnelID)
		}
		return err
	}
	if !accept {
		return ErrBuildRejected
	}
	return nil
}

func (m *BuildManager) sendVariableReply(request VariableBuildRequest, records []byte, now uint64) error {
	reply := i2np.Message{Header: i2np.Header{Type: i2np.VariableTunnelBuildReply, ID: request.NextMessageID, Expiration: saturatingDeadline(now, nextHopSendTimeout)}, Payload: records}
	frame := make([]byte, reply.EncodedLen())
	if _, err := reply.MarshalTo(frame); err != nil {
		return err
	}
	payload := make([]byte, i2np.TunnelGatewayHeaderLen+len(frame))
	binary.BigEndian.PutUint32(payload[:4], request.NextTunnelID)
	binary.BigEndian.PutUint16(payload[4:6], uint16(len(frame)))
	copy(payload[6:], frame)
	gateway := i2np.Message{Header: i2np.Header{Type: i2np.TunnelGateway, ID: request.NextMessageID, Expiration: saturatingDeadline(now, nextHopSendTimeout)}, Payload: payload}
	return m.sender.Send(m.ctx, request.NextRouter, gateway)
}

// HandleVariableReply validates a returned VariableTunnelBuildReply and
// installs the creator's outbound circuit only when every hop accepted it.
func (m *BuildManager) HandleVariableReply(message i2np.Message) error {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.isReleased() {
		return ErrBuildPending
	}
	if message.Header.Type != i2np.VariableTunnelBuildReply {
		return ErrBuildConfig
	}
	pending := m.takeVariablePending(message.Header.ID)
	if pending == nil {
		return ErrBuildPending
	}
	defer m.notifyBuildEvent()
	defer clearVariableBuildKeys(pending.keys)
	records, err := i2np.ParseBuildRecords(i2np.VariableTunnelBuildReply, message.Payload)
	if err != nil {
		return err
	}
	now := m.now()
	if pending.deadline <= now || records.Count != pending.recordCount {
		return ErrBuildPending
	}
	replies := make([]byte, len(pending.keys)*LongBuildResponsePlainSize)
	defer clear(replies)
	if err = OpenVariableBuildReplies(records.Records, pending.keys, pending.positions, replies); err != nil {
		return err
	}
	for hop, key := range pending.keys {
		if key.Kind == VariableBuildElGamal {
			slot := pending.positions[hop]
			var record [VariableBuildRecordSize]byte
			copy(record[:], records.Records[int(slot)*VariableBuildRecordSize:(int(slot)+1)*VariableBuildRecordSize])
			for later := hop + 1; later < len(pending.keys); later++ {
				cbcVariableDecrypt(record[:], record[:], pending.keys[later].ReplyKey, pending.keys[later].ReplyIV)
			}
			cbcVariableDecrypt(record[:], record[:], key.ReplyKey, key.ReplyIV)
			if record[VariableBuildRecordSize-1] != 0 {
				return ErrBuildRejected
			}
		} else if replies[(hop+1)*LongBuildResponsePlainSize-1] != 0 {
			return ErrBuildRejected
		}
	}
	transforms := make([]LayerCipher, len(pending.keys))
	for hop := range pending.keys {
		key := pending.keys[len(pending.keys)-1-hop]
		if transforms[hop], err = NewLayerEncryptor(key.LayerKey[:], key.IVKey[:]); err != nil {
			return err
		}
	}
	circuit := OutboundCircuit{ID: pending.build.CircuitID, FirstHop: pending.build.Hops[0].Router, NextTunnelID: pending.build.Hops[0].ReceiveTunnelID, Transforms: transforms, ExpiresAt: pending.build.ExpiresAt}
	entry := Entry{ID: circuit.ID, Direction: Outbound, Expires: circuit.ExpiresAt}
	var retired Entry
	var replaced bool
	if m.pool != nil {
		retired, replaced, err = m.pool.Replace(entry, pending.build.retireID, now)
		if err != nil {
			return err
		}
	}
	if err = m.runtime.RegisterOutbound(circuit); err != nil {
		if m.pool != nil {
			m.pool.RollbackReplace(entry, retired, replaced, m.now())
		}
		return err
	}
	if replaced {
		m.runtime.RemoveCircuit(retired.ID)
	}
	return nil
}

func (m *BuildManager) validVariableTransitRequest(request VariableBuildRequest, kind VariableBuildKind, now uint64) bool {
	if !validVariableRequest(request) || request.NextRouter == m.local {
		return false
	}
	if kind == VariableBuildElGamal {
		time := uint64(request.RequestHours) * 3_600_000
		return time <= now+3_600_000 && now <= time+7_200_000
	}
	time := uint64(request.RequestMinutes) * 60_000
	return request.LifetimeSeconds == legacyBuildLifetimeSeconds && time <= now+60_000 && now <= time+60_000
}
func (m *BuildManager) installVariableTransitCircuit(request VariableBuildRequest, now uint64) error {
	decryptor, err := NewLayerDecryptor(request.LayerKey[:], request.IVKey[:])
	if err != nil {
		return err
	}
	circuit := InboundCircuit{ID: request.ReceiveTunnelID, Transforms: []LayerCipher{decryptor}, ExpiresAt: now + 660_000}
	if request.Endpoint {
		circuit.Endpoint, circuit.Local = NewEndpoint(128, 0), m.localDelivery
	} else {
		circuit.Forward = &Forward{Peer: request.NextRouter, TunnelID: request.NextTunnelID}
	}
	return m.runtime.RegisterInbound(circuit)
}
func shortRequestFromVariable(request VariableBuildRequest) ShortBuildRequest {
	return ShortBuildRequest{ReceiveTunnelID: request.ReceiveTunnelID, NextTunnelID: request.NextTunnelID, NextRouter: request.NextRouter, Gateway: request.Gateway, Endpoint: request.Endpoint, RequestMinutes: request.RequestMinutes, LifetimeSeconds: request.LifetimeSeconds, NextMessageID: request.NextMessageID}
}
func validVariableHops(hops []VariableBuildHop) bool {
	for index, hop := range hops {
		validVariableHopsRejected := hop.Router == (foundation.Hash{}) || hop.ReceiveTunnelID == 0 || hop.Kind != VariableBuildElGamal && hop.Kind != VariableBuildLongECIES || hop.Kind == VariableBuildElGamal && hop.ElGamalKey == (cryptography.ElGamalPublicKey{})
		if !validVariableHopsRejected {
			validVariableHopsRejected = hop.Kind == VariableBuildLongECIES && hop.StaticKey == ([32]byte{})
		}
		if validVariableHopsRejected {
			return false
		}
		for previous := range index {
			if hops[previous].Router == hop.Router || hops[previous].ReceiveTunnelID == hop.ReceiveTunnelID {
				return false
			}
		}
	}
	return true
}
func cloneVariableOutboundBuild(build VariableOutboundBuild) VariableOutboundBuild {
	build.Hops = append([]VariableBuildHop(nil), build.Hops...)
	return build
}
func clearVariableBuildKeys(keys []VariableBuildKeys) { clear(keys) }
func clearVariableBuildKey(key *VariableBuildKeys)    { *key = VariableBuildKeys{} }
func (m *BuildManager) takeVariablePending(id uint32) *pendingVariableBuild {
	m.mu.Lock()
	pending := m.pendingVariable[id]
	delete(m.pendingVariable, id)
	if pending == nil {
		if recent, ok := m.recent[id]; ok && recent.variable != nil {
			pending = recent.variable
			delete(m.recent, id)
		}
	}
	m.mu.Unlock()
	if pending != nil {
		cancelBuildDeadline(pending.cancelDeadline)
	}
	return pending
}
func (m *BuildManager) removeVariablePending(id uint32) {
	m.mu.Lock()
	pending := m.pendingVariable[id]
	delete(m.pendingVariable, id)
	m.mu.Unlock()
	if pending != nil {
		clearVariableBuildKeys(pending.keys)
	}
}
