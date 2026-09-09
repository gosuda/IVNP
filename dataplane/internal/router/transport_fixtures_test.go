package router

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
)

var (
	errTestFutureRouterInfo     = errors.New("future test RouterInfo")
	errTestStaleRouterInfo      = errors.New("stale test RouterInfo")
	errTestPeerSignatureInvalid = errors.New("test peer signature invalid")
)

type transportTestOption struct{ Key, Value string }
type transportTestAddress struct {
	Transport string
	Cost      uint8
	Options   []transportTestOption
}
type transportTestLocalConfig struct {
	Local         foundation.LocalIdentityOwner
	RouterVersion string
	Options       []transportTestOption
}
type transportTestReachability uint8

const (
	transportTestUnknown transportTestReachability = iota
	transportTestReachable
	transportTestFirewalled
)

type transportTestLocal struct {
	mu           sync.Mutex
	owner        foundation.LocalIdentityOwner
	identity     []byte
	private      ed25519.PrivateKey
	addresses    []transportTestAddress
	version      string
	options      []transportTestOption
	reachability transportTestReachability
	snapshot     foundation.NetworkDatabaseRouterInfo
}

func newTransportTestLocal(config transportTestLocalConfig) (*transportTestLocal, error) {
	identity, err := config.Local.Identity()
	if err != nil {
		return nil, err
	}
	_, private := config.Local.SigningKeyPair()
	return &transportTestLocal{owner: config.Local, identity: append([]byte(nil), identity.Bytes()...), private: private, version: config.RouterVersion, options: append([]transportTestOption(nil), config.Options...)}, nil
}
func (l *transportTestLocal) Hash() foundation.Hash      { return l.owner.IdentityHash() }
func (l *transportTestLocal) Sign(message []byte) []byte { return ed25519.Sign(l.private, message) }
func (l *transportTestLocal) Snapshot() foundation.NetworkDatabaseRouterInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snapshot
}
func (l *transportTestLocal) ReplaceAddresses(addresses []transportTestAddress) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addresses = make([]transportTestAddress, len(addresses))
	for i, address := range addresses {
		l.addresses[i] = address
		l.addresses[i].Options = append([]transportTestOption(nil), address.Options...)
	}
	return nil
}
func (l *transportTestLocal) SetReachability(value transportTestReachability) {
	l.mu.Lock()
	l.reachability = value
	l.mu.Unlock()
}
func (l *transportTestLocal) Publish(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := l.PublishAt(uint64(time.Now().UnixMilli()))
	return err
}
func (l *transportTestLocal) PublishAt(now uint64) (foundation.NetworkDatabaseRouterInfo, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.publishLocked(now)
}
func (l *transportTestLocal) publishLocked(now uint64) (foundation.NetworkDatabaseRouterInfo, error) {
	raw := append([]byte(nil), l.identity...)
	raw = binary.BigEndian.AppendUint64(raw, now)
	raw = append(raw, byte(len(l.addresses)))
	for _, address := range l.addresses {
		raw = append(raw, address.Cost)
		raw = binary.BigEndian.AppendUint64(raw, 0)
		raw = append(raw, byte(len(address.Transport)))
		raw = append(raw, address.Transport...)
		var err error
		raw, err = appendTransportTestMapping(raw, address.Options)
		if err != nil {
			return foundation.NetworkDatabaseRouterInfo{}, err
		}
	}
	raw = append(raw, 0)
	caps := "L"
	if l.reachability == transportTestReachable {
		caps += "R"
	}
	if l.reachability == transportTestFirewalled {
		caps += "U"
	}
	options := []transportTestOption{{Key: "caps", Value: caps}, {Key: "netId", Value: "2"}}
	if l.version != "" {
		options = append(options, transportTestOption{Key: "router.version", Value: l.version})
	}
	options = append(options, l.options...)
	raw, err := appendTransportTestMapping(raw, options)
	if err != nil {
		return foundation.NetworkDatabaseRouterInfo{}, err
	}
	raw = append(raw, ed25519.Sign(l.private, raw)...)
	info, err := foundation.NetworkDatabaseParseRouterInfo(raw)
	if err == nil {
		l.snapshot = info
	}
	return info, err
}
func appendTransportTestMapping(raw []byte, options []transportTestOption) ([]byte, error) {
	entries := make([]foundation.MappingEntry, len(options))
	for i, option := range options {
		entries[i] = foundation.MappingEntry{Key: []byte(option.Key), Value: []byte(option.Value)}
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].Key, entries[j].Key) < 0 })
	n, err := foundation.MappingEncodedLen(entries)
	if err != nil {
		return nil, err
	}
	offset := len(raw)
	raw = append(raw, make([]byte, n)...)
	_, err = foundation.MarshalMappingTo(raw[offset:], entries)
	return raw, err
}
func (l *transportTestLocal) UpdateSSU2Introducers(ctx context.Context, leases []SSU2Introducer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.addresses {
		address := &l.addresses[i]
		if address.Transport != "SSU" && address.Transport != "SSU2" {
			continue
		}
		options := make([]transportTestOption, 0, len(address.Options)+len(leases)*3)
		for _, option := range address.Options {
			if strings.HasPrefix(option.Key, "ih") || strings.HasPrefix(option.Key, "itag") || strings.HasPrefix(option.Key, "iexp") {
				continue
			}
			options = append(options, option)
		}
		for slot, lease := range leases {
			index := strconv.Itoa(slot)
			options = append(options, transportTestOption{Key: "ih" + index, Value: foundation.EncodeI2PBase64(lease.Peer[:])}, transportTestOption{Key: "itag" + index, Value: strconv.FormatUint(uint64(lease.RelayTag), 10)}, transportTestOption{Key: "iexp" + index, Value: strconv.FormatInt(lease.Expiration.Unix(), 10)})
		}
		address.Options = options
	}
	_, err := l.publishLocked(uint64(time.Now().UnixMilli()))
	return err
}

type transportTestPeerRef struct {
	Hash foundation.Hash
	Info foundation.NetworkDatabaseRouterInfo
}
type transportTestPeers struct {
	mu    sync.RWMutex
	infos map[foundation.Hash]foundation.NetworkDatabaseRouterInfo
}

func newTransportTestPeers() *transportTestPeers {
	return &transportTestPeers{infos: make(map[foundation.Hash]foundation.NetworkDatabaseRouterInfo)}
}
func (p *transportTestPeers) RouterInfo(peer foundation.Hash) (foundation.NetworkDatabaseRouterInfo, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	info, ok := p.infos[peer]
	return info, ok
}
func (p *transportTestPeers) DialRouterInfo(peer foundation.Hash, now uint64) (foundation.NetworkDatabaseRouterInfo, error) {
	info, ok := p.RouterInfo(peer)
	if !ok {
		return foundation.NetworkDatabaseRouterInfo{}, ErrSessionUnavailable
	}
	if err := transportTestFresh(info, now, 24*time.Hour); err != nil {
		return foundation.NetworkDatabaseRouterInfo{}, err
	}
	return info, nil
}
func transportTestFresh(info foundation.NetworkDatabaseRouterInfo, now uint64, maximumAge time.Duration) error {
	if info.Published > now {
		if info.Published-now > uint64(2*time.Minute/time.Millisecond) {
			return errTestFutureRouterInfo
		}
	} else if now-info.Published > uint64(maximumAge/time.Millisecond) {
		return errTestStaleRouterInfo
	}
	return nil
}
func (p *transportTestPeers) Get(peer foundation.Hash) (transportTestPeerRef, bool) {
	info, ok := p.RouterInfo(peer)
	return transportTestPeerRef{Hash: peer, Info: info}, ok
}
func (p *transportTestPeers) AdmitRouterInfo(info foundation.NetworkDatabaseRouterInfo, now uint64) error {
	valid, err := info.Verify()
	if err != nil {
		return err
	}
	if !valid {
		return errTestPeerSignatureInvalid
	}
	if err := transportTestFresh(info, now, 90*time.Minute); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if current, ok := p.infos[info.Hash()]; !ok || current.Published <= info.Published {
		p.infos[info.Hash()] = info
	}
	return nil
}
func (p *transportTestPeers) PeerAtEndpoint(endpoint netip.AddrPort) (foundation.Hash, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var matched foundation.Hash
	found := false
	for peer, info := range p.infos {
		if !SSU2PeerEndpointMatches(info, endpoint) {
			continue
		}
		if found {
			return foundation.Hash{}, false
		}
		matched, found = peer, true
	}
	return matched, found
}
func (p *transportTestPeers) Store(message foundation.I2NPMessage, now uint64) error {
	store, err := foundation.I2NPParseDatabaseStore(message.Payload)
	if err != nil {
		return err
	}
	raw, err := inflateSSU2RouterInfo(store.Data)
	if err != nil {
		return err
	}
	info, err := foundation.NetworkDatabaseParseRouterInfo(raw)
	if err != nil {
		return err
	}
	return p.AdmitRouterInfo(info, now)
}

type transportTestClock struct{ now time.Time }

func (c transportTestClock) Now() time.Time { return c.now }
