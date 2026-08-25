package router

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/netdb"
	"gosuda.org/ivnp/observability"
)

const defaultNetworkID = 2

var ErrLocalRouterInfoOptions = errors.New("router: invalid local RouterInfo options")

// SSU2Introducer is a currently valid relay lease advertised in the local
// SSU2 address.  LocalRouterInfo alone translates leases into RouterInfo
// options and signs the replacement snapshot.
type SSU2Introducer struct {
	Peer       foundation.Hash
	RelayTag   uint32
	Expiration time.Time
}

// LocalRouterInfoConfig configures the concrete LocalInfo implementation used
// by an embedded router. Local may own either a modern RouterIdentity or a
// legacy Destination. NetworkID defaults to the public I2P network (2).
// Options extend the generated netId and optional router.version properties;
// callers must not supply duplicate property keys.
type LocalRouterInfoConfig struct {
	Local         foundation.LocalIdentityOwner
	Database      *netdb.Database
	Clock         Clock
	NetworkID     uint32
	RouterVersion string
	Peers         []foundation.Hash
	Options       []MappingOption
	Metrics       *observability.Registry
}

// LocalRouterInfo is a concrete local RouterInfo owner. It atomically turns
// published transport addresses and reachability into signed RouterInfo bytes,
// retains an immutable snapshot, and admits each successful publication into
// the supplied local netdb.
type LocalRouterInfo struct {
	info     *netdb.LocalRouterInfo
	database *netdb.Database
	clock    Clock
	metrics  *observability.Registry

	mu           sync.Mutex
	addresses    []PublishedAddress
	peers        []foundation.Hash
	baseOptions  []foundation.MappingEntry
	reachability Reachability
}

// NewLocalRouterInfo constructs a local RouterInfo owner without publishing or
// performing network I/O. Database may be nil for callers that only need
// signed snapshots; an embedded router should pass its active netdb.Database.
func NewLocalRouterInfo(config LocalRouterInfoConfig) (*LocalRouterInfo, error) {
	if config.Clock == nil {
		config.Clock = WallClock{}
	}
	if config.NetworkID == 0 {
		config.NetworkID = defaultNetworkID
	}
	baseOptions, err := localRouterBaseOptions(config.NetworkID, config.RouterVersion, config.Options)
	if err != nil {
		return nil, err
	}
	contacts := netdb.RouterInfoContacts{
		Peers:   append([]foundation.Hash(nil), config.Peers...),
		Options: baseOptions,
	}
	info, err := netdb.NewLocalRouterInfo(netdb.LocalRouterInfoConfig{
		Local:    config.Local,
		Contacts: contacts,
	})
	if err != nil {
		return nil, err
	}
	return &LocalRouterInfo{
		info:        info,
		database:    config.Database,
		clock:       config.Clock,
		metrics:     config.Metrics,
		peers:       append([]foundation.Hash(nil), config.Peers...),
		baseOptions: cloneI2PMappingEntries(baseOptions),
	}, nil
}

// Hash returns the immutable local RouterIdentity hash.
func (l *LocalRouterInfo) Hash() foundation.Hash { return l.info.Hash() }

// Sign returns an authenticated signature for a native router transport
// control message using this local RouterInfo's immutable signing key.
func (l *LocalRouterInfo) Sign(message []byte) []byte {
	return l.info.Sign(message)
}

// Snapshot returns the last signed RouterInfo, or its zero value before the
// first successful publication or after contact data changes.
func (l *LocalRouterInfo) Snapshot() netdb.RouterInfo {
	info, ok := l.info.Snapshot()
	if !ok {
		return netdb.RouterInfo{}
	}
	return info
}

// ReplaceAddresses atomically replaces locally advertised transport addresses.
// It does not infer reachability from a listener bind; callers must report it
// separately through SetReachability before Publish.
func (l *LocalRouterInfo) ReplaceAddresses(addresses []PublishedAddress) error {
	owned := clonePublishedAddresses(addresses)
	l.mu.Lock()
	defer l.mu.Unlock()
	contacts, err := l.contactsLocked(owned, l.reachability)
	if err != nil {
		return err
	}
	if err = l.info.ReplaceContacts(contacts); err != nil {
		return err
	}
	l.addresses = owned
	return nil
}

// SetReachability changes only the advertised RouterInfo capability. A later
// Publish signs the new state; socket binding by itself never calls this method.
func (l *LocalRouterInfo) SetReachability(reachability Reachability) {
	l.mu.Lock()
	defer l.mu.Unlock()
	contacts, err := l.contactsLocked(l.addresses, reachability)
	if err != nil {
		return
	}
	if l.info.ReplaceContacts(contacts) != nil {
		return
	}
	l.reachability = reachability
	if l.metrics != nil {
		if reachability == ReachabilityReachable {
			l.metrics.SetRouterReachable(1)
		} else {
			l.metrics.SetRouterReachable(0)
		}
	}
}

// Reachability returns the current capability owned by LocalRouterInfo.
func (l *LocalRouterInfo) Reachability() Reachability {
	if l == nil {
		return ReachabilityUnknown
	}
	l.mu.Lock()
	value := l.reachability
	l.mu.Unlock()
	return value
}

// Publish signs the current local RouterInfo and admits it to the configured
// netdb. Its published timestamp is obtained once from the configured Clock.
func (l *LocalRouterInfo) Publish(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	now := uint64(l.clock.Now().UnixMilli())
	info, err := l.info.Publish(now)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if l.database != nil {
		if err = l.database.AdmitRouterInfo(info, false, now); err != nil {
			return err
		}
	}
	return nil
}

// UpdateSSU2Introducers atomically replaces only SSU/SSU2 introducer options
// and publishes the resulting signed RouterInfo. Callers cannot mutate the
// local address snapshot directly, avoiding competing publication owners.
func (l *LocalRouterInfo) UpdateSSU2Introducers(ctx context.Context, leases []SSU2Introducer) error {
	if ctx ==
		nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	owned := append([]SSU2Introducer(nil), leases...)
	if len(owned) > 3 {
		return ErrLocalRouterInfoOptions
	}
	sort.Slice(owned, func(left, right int) bool { return owned[left].RelayTag < owned[right].RelayTag })
	for index, lease := range owned {
		updateSSU2IntroducersRejected := lease.RelayTag == 0 || !lease.Expiration.After(l.clock.Now())
		if !updateSSU2IntroducersRejected {
			updateSSU2IntroducersRejected = (index > 0 && lease.RelayTag == owned[index-1].RelayTag)
		}
		if updateSSU2IntroducersRejected {
			return ErrLocalRouterInfoOptions
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	addresses := clonePublishedAddresses(l.addresses)
	for index := range addresses {
		if addresses[index].Transport != "SSU" && addresses[index].Transport != "SSU2" {
			continue
		}
		options := addresses[index].Options[:0]
		for _, option := range addresses[index].Options {
			if len(option.Key) == 3 && option.Key[:2] == "ih" && option.Key[2] >= '0' && option.Key[2] <= '2' {
				continue
			}
			updateSSU2IntroducersRejected := len(option.Key) == 5 && (option.Key[:4] == "itag" || option.Key[:4] == "iexp") &&
				option.Key[4] >= '0'
			if updateSSU2IntroducersRejected {
				updateSSU2IntroducersRejected = option.Key[4] <= '2'
			}
			if updateSSU2IntroducersRejected {
				continue
			}
			options = append(options, option)
		}
		for leaseIndex, lease := range owned {
			slot := strconv.Itoa(leaseIndex)
			options = append(options,
				MappingOption{Key: "ih" + slot, Value: foundation.EncodeI2PBase64(lease.Peer[:])},
				MappingOption{Key: "itag" + slot, Value: strconv.FormatUint(uint64(lease.RelayTag), 10)},
				MappingOption{Key: "iexp" + slot, Value: strconv.FormatInt(lease.Expiration.Unix(), 10)},
			)
		}
		addresses[index].Options = append([]MappingOption(nil), options...)
	}
	contacts, err := l.contactsLocked(addresses, l.reachability)
	if err != nil {
		return err
	}
	if err = l.info.ReplaceContacts(contacts); err != nil {
		return err
	}
	l.addresses = addresses
	now := uint64(l.clock.Now().UnixMilli())
	info, err := l.info.Publish(now)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if l.database != nil {
		return l.database.AdmitRouterInfo(info, false, now)
	}
	return nil
}

func (l *LocalRouterInfo) contactsLocked(addresses []PublishedAddress, reachability Reachability) (netdb.RouterInfoContacts, error) {
	options, err := localRouterCapabilities(l.baseOptions, reachability)
	if err != nil {
		return netdb.RouterInfoContacts{}, err
	}
	contacts := netdb.RouterInfoContacts{
		Addresses: make([]netdb.LocalRouterAddress, len(addresses)),
		Peers:     append([]foundation.Hash(nil), l.peers...),
		Options:   options,
	}
	for index, address := range addresses {
		options, err := mappingOptions(address.Options)
		if err != nil {
			return netdb.RouterInfoContacts{}, err
		}
		if len(address.Transport) == 0 || len(address.Transport) > 255 {
			return netdb.RouterInfoContacts{}, ErrLocalRouterInfoOptions
		}
		contacts.Addresses[index] = netdb.LocalRouterAddress{
			Cost:           address.Cost,
			TransportStyle: []byte(address.Transport),
			Options:        options,
		}
	}
	return contacts, nil
}

func localRouterBaseOptions(networkID uint32, version string, options []MappingOption) ([]foundation.MappingEntry, error) {
	entries := make([]foundation.MappingEntry, 0, len(options)+2)
	entries = append(entries, foundation.MappingEntry{Key: []byte("netId"), Value: []byte(strconv.FormatUint(uint64(networkID), 10))})
	if version != "" {
		entries = append(entries, foundation.MappingEntry{Key: []byte("router.version"), Value: []byte(version)})
	}
	for _, option := range options {
		if option.Key == "caps" {
			return nil, ErrLocalRouterInfoOptions
		}
		entries = append(entries, foundation.MappingEntry{Key: []byte(option.Key), Value: []byte(option.Value)})
	}
	return canonicalMappingEntries(entries)
}

func localRouterCapabilities(base []foundation.MappingEntry, reachability Reachability) ([]foundation.MappingEntry, error) {
	entries := cloneI2PMappingEntries(base)
	if reachability == ReachabilityUnknown {
		return entries, nil
	}
	capability := byte('R')
	if reachability == ReachabilityFirewalled {
		capability = 'U'
	}
	entries = append(entries, foundation.MappingEntry{Key: []byte("caps"), Value: []byte{capability}})
	return canonicalMappingEntries(entries)
}

func mappingOptions(options []MappingOption) ([]foundation.MappingEntry, error) {
	entries := make([]foundation.MappingEntry, len(options))
	for index, option := range options {
		entries[index] = foundation.MappingEntry{Key: []byte(option.Key), Value: []byte(option.Value)}
	}
	return canonicalMappingEntries(entries)
}

func canonicalMappingEntries(entries []foundation.MappingEntry) ([]foundation.MappingEntry, error) {
	owned := cloneI2PMappingEntries(entries)
	sort.Slice(owned, func(left, right int) bool {
		return bytes.Compare(owned[left].Key, owned[right].Key) < 0
	})
	if _, err := foundation.MappingEncodedLen(owned); err != nil {
		return nil, err
	}
	return owned, nil
}

func cloneI2PMappingEntries(entries []foundation.MappingEntry) []foundation.MappingEntry {
	owned := make([]foundation.MappingEntry, len(entries))
	for index, entry := range entries {
		owned[index] = foundation.MappingEntry{
			Key:   append([]byte(nil), entry.Key...),
			Value: append([]byte(nil), entry.Value...),
		}
	}
	return owned
}

func clonePublishedAddresses(addresses []PublishedAddress) []PublishedAddress {
	owned := make([]PublishedAddress, len(addresses))
	for index, address := range addresses {
		owned[index].Transport = address.Transport
		owned[index].Cost = address.Cost
		owned[index].Options = append([]MappingOption(nil), address.Options...)
	}
	return owned
}
