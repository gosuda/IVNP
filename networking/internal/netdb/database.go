package netdb

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/pool"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/observability"
)

const (
	RouterInfoMaxAgeMillis       = uint64((90 * time.Minute) / time.Millisecond)
	ReseedRouterInfoMaxAgeMillis = uint64((24 * time.Hour) / time.Millisecond)
	RouterInfoMaxFutureMillis    = uint64((2 * time.Minute) / time.Millisecond)
	LeaseSetMaxPastMillis        = uint64((10 * time.Minute) / time.Millisecond)
	LeaseSetClockFudgeMillis     = uint64(time.Minute / time.Millisecond)
	LeaseSetMaxFutureMillis      = uint64((15 * time.Minute) / time.Millisecond)
	MetaLeaseSetMaxFutureMillis  = uint64((65_535 * time.Second) / time.Millisecond)
)

var (
	ErrStoreKeyMismatch   = errors.New("netdb: database store key does not match payload identity")
	ErrStoreUnsupported   = errors.New("netdb: database store type is not supported")
	ErrRouterInfoTooLarge = errors.New("netdb: decompressed RouterInfo exceeds Java I2P 4 KiB limit")
	ErrRouterInfoStale    = errors.New("netdb: RouterInfo publication is stale")
	ErrRouterInfoFuture   = errors.New("netdb: RouterInfo publication is too far in the future")
	ErrLeaseSetExpired    = errors.New("netdb: LeaseSet is expired or too old")
	ErrLeaseSetFuture     = errors.New("netdb: LeaseSet expires too far in the future")
)

type leaseEntry struct {
	legacy    LeaseSet
	v2        LeaseSet2
	meta      MetaLeaseSet
	encrypted EncryptedLeaseSet
	version   uint64
	expires   uint64
	published bool
	typeID    i2np.StoreType
}

type leaseExpiry struct {
	key     foundation.Hash
	expires uint64
}

// Database stores verified RouterInfos and LeaseSets with memory bounds and TTL expiration.
type Database struct {
	routers          *Table
	leasesMu         sync.RWMutex
	leases           map[foundation.Hash]leaseEntry
	leaseExpiries    []leaseExpiry
	leaseExpiryIndex map[foundation.Hash]int
	maxLeases        int
	gzipPool         sync.Pool
	metrics          *observability.Registry
}

func NewDatabase(local foundation.Hash, bucketCapacity int) *Database {
	return &Database{
		routers: NewTable(local, bucketCapacity), leases: make(map[foundation.Hash]leaseEntry),
		leaseExpiryIndex: make(map[foundation.Hash]int), maxLeases: 4096,
	}
}

// SetMetrics sets the observability registry for recording NetDB metrics.
func (d *Database) SetMetrics(metrics *observability.Registry) {
	if d != nil {
		d.metrics = metrics
	}
}

// RoutingKey computes the daily DHT routing key SHA256(hash || YYYYMMDD) in UTC.
func RoutingKey(key foundation.Hash, nowMillis uint64) foundation.Hash {
	date := time.UnixMilli(int64(nowMillis)).UTC()
	year, month, day := date.Date()
	var input [40]byte
	copy(input[:32], key[:])
	input[32] = byte('0' + year/1000%10)
	input[33] = byte('0' + year/100%10)
	input[34] = byte('0' + year/10%10)
	input[35] = byte('0' + year%10)
	input[36] = byte('0' + int(month)/10)
	input[37] = byte('0' + int(month)%10)
	input[38] = byte('0' + day/10)
	input[39] = byte('0' + day%10)
	return foundation.Sum(input[:])
}

// FloodTargetsAt finds floodfill routers closest to the routing key at nowMillis.
func (d *Database) FloodTargetsAt(dst []RouterRef, key foundation.Hash, nowMillis uint64) []RouterRef {
	return d.routers.ClosestFloodfillsInto(dst, RoutingKey(key, nowMillis))
}

// FloodTargets finds the current UTC day's closest floodfill routers.
func (d *Database) FloodTargets(dst []RouterRef, key foundation.Hash) []RouterRef {
	return d.FloodTargetsAt(dst, key, uint64(time.Now().UnixMilli()))
}

func (d *Database) Routers() *Table { return d.routers }

// RouterInfoFresh checks whether a RouterInfo is fresh enough to accept at nowMillis.
func RouterInfoFresh(info RouterInfo, nowMillis uint64) error {
	return routerInfoFresh(info, nowMillis, RouterInfoMaxAgeMillis)
}

// ReseedRouterInfoFresh checks whether a reseed RouterInfo is within the 24-hour window.
func ReseedRouterInfoFresh(info RouterInfo, nowMillis uint64) error {
	return routerInfoFresh(info, nowMillis, ReseedRouterInfoMaxAgeMillis)
}

func routerInfoFresh(info RouterInfo, nowMillis, maxAgeMillis uint64) error {
	if info.Published > nowMillis {
		if info.Published-nowMillis > RouterInfoMaxFutureMillis {
			return ErrRouterInfoFuture
		}
		return nil
	}
	if nowMillis-info.Published > maxAgeMillis {
		return ErrRouterInfoStale
	}
	return nil
}

// AdmitRouterInfo verifies and stores a RouterInfo.
func (d *Database) AdmitRouterInfo(info RouterInfo, _ bool, seenAt uint64) error {
	return d.admitRouterInfo(info, seenAt, RouterInfoMaxAgeMillis)
}

// AdmitReseedRouterInfo verifies and stores a reseed RouterInfo.
func (d *Database) AdmitReseedRouterInfo(info RouterInfo, seenAt uint64) error {
	return d.admitRouterInfo(info, seenAt, ReseedRouterInfoMaxAgeMillis)
}

func (d *Database) admitRouterInfo(info RouterInfo, seenAt, maxAgeMillis uint64) error {
	valid, err := info.Verify()
	floodfill := IsFloodfill(info)
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidSignature
	}
	if err := routerInfoFresh(info, seenAt, maxAgeMillis); err != nil {
		return err
	}
	owned := make([]byte, len(info.Bytes()))
	copy(owned, info.Bytes())
	ownedInfo, err := ParseRouterInfo(owned)
	if err != nil {
		return err
	}
	d.routers.StoreVerified(ownedInfo, floodfill, seenAt)
	if d.metrics != nil {
		d.metrics.SetNetDBRouters(uint64(d.routers.Len()))
	}
	return nil
}

// HandleDatabaseStore verifies and stores a received DatabaseStore message.
func (d *Database) HandleDatabaseStore(store i2np.DatabaseStoreMessage, floodfill bool, seenAt uint64) error {
	return d.HandleDatabaseStoreAsPublished(store, floodfill, seenAt, true)
}

// HandleDatabaseStoreAsPublished stores a DatabaseStore message with the given published state.
func (d *Database) HandleDatabaseStoreAsPublished(store i2np.DatabaseStoreMessage, floodfill bool, seenAt uint64, published bool) error {
	var err error
	switch store.Type {
	case i2np.StoreRouterInfo:
		err = d.storeRouterInfo(store, floodfill, seenAt)
	case i2np.StoreLeaseSet:
		err = d.storeLeaseSet(store, seenAt, published)
	case i2np.StoreLeaseSet2:
		err = d.storeLeaseSet2(store, seenAt, published)
	case i2np.StoreMetaLeaseSet:
		err = d.storeMetaLeaseSet(store, seenAt, published)
	case i2np.StoreEncryptedLeaseSet:
		err = d.storeEncryptedLeaseSet(store, seenAt, published)
	default:
		err = ErrStoreUnsupported
	}
	if d.metrics != nil {
		if err == nil {
			d.metrics.IncNetDBStores()
		} else {
			d.metrics.IncNetDBStoreFailures()
		}
	}
	return err
}

// StoreMatchesCurrent reports whether the store matches the newest version already in the database.
func (d *Database) StoreMatchesCurrent(store i2np.DatabaseStoreMessage) bool {
	if store.Type == i2np.StoreRouterInfo {
		inflated, lease, err := d.inflateRouterInfo(store.Data)
		if err != nil {
			return false
		}
		defer lease.Release()
		incoming, err := ParseRouterInfo(inflated)
		if err != nil {
			return false
		}
		current, ok := d.routers.Get(store.Key)
		return ok && current.Info.Published == incoming.Published && bytes.Equal(current.Info.Bytes(), incoming.Bytes())
	}
	d.leasesMu.RLock()
	entry, ok := d.leases[store.Key]
	if !ok || entry.typeID != store.Type {
		d.leasesMu.RUnlock()
		return false
	}
	var data []byte
	switch entry.typeID {
	case i2np.StoreLeaseSet:
		data = entry.legacy.Bytes()
	case i2np.StoreLeaseSet2:
		data = entry.v2.Bytes()
	case i2np.StoreMetaLeaseSet:
		data = entry.meta.Bytes()
	case i2np.StoreEncryptedLeaseSet:
		data = entry.encrypted.Bytes()
	}
	matches := bytes.Equal(data, store.Data)
	d.leasesMu.RUnlock()
	return matches
}

func (d *Database) storeRouterInfo(store i2np.DatabaseStoreMessage, floodfill bool, seenAt uint64) error {
	inflated, lease, err := d.inflateRouterInfo(store.Data)
	if err != nil {
		return err
	}
	defer lease.Release()
	parsed, err := ParseRouterInfo(inflated)
	if err != nil {
		return err
	}
	if parsed.Hash() != store.Key {
		return ErrStoreKeyMismatch
	}
	return d.AdmitRouterInfo(parsed, floodfill, seenAt)
}

func (d *Database) storeLeaseSet(store i2np.DatabaseStoreMessage, seenAt uint64, published bool) error {
	parsed, err := ParseLeaseSet(store.Data)
	if err != nil {
		return err
	}
	if parsed.Hash() != store.Key {
		return ErrStoreKeyMismatch
	}
	valid, err := parsed.Verify()
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidSignature
	}
	earliest, latest, err := legacyLeaseRange(parsed)
	if err != nil {
		return err
	}
	if err = validateLeaseSetRange(earliest, latest, seenAt, LeaseSetMaxFutureMillis); err != nil {
		return err
	}
	owned := append([]byte(nil), store.Data...)
	parsed, err = ParseLeaseSet(owned)
	if err != nil {
		return err
	}
	d.leasesMu.Lock()
	defer d.leasesMu.Unlock()
	if old, exists := d.leases[store.Key]; exists && old.version >= earliest {
		if published && !old.published {
			old.published = true
			d.leases[store.Key] = old
		}
		return nil
	}
	d.storeLeaseEntry(store.Key, leaseEntry{legacy: parsed, version: earliest, expires: latest, published: published, typeID: store.Type})
	return nil
}

func (d *Database) storeLeaseSet2(store i2np.DatabaseStoreMessage, seenAt uint64, published bool) error {
	parsed, err := ParseLeaseSet2(store.Data)
	if err != nil {
		return err
	}
	if parsed.Hash() != store.Key {
		return ErrStoreKeyMismatch
	}
	valid, err := parsed.Verify()
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidSignature
	}
	earliest, latest, err := leaseSet2Range(parsed)
	if err != nil {
		return err
	}
	if err = validateLeaseSetRange(earliest, latest, seenAt, LeaseSetMaxFutureMillis); err != nil {
		return err
	}
	owned := append([]byte(nil), store.Data...)
	parsed, err = ParseLeaseSet2(owned)
	if err != nil {
		return err
	}
	version := uint64(parsed.Header.Published)
	expires := (uint64(parsed.Header.Published) + uint64(parsed.Header.Expires)) * 1000
	d.leasesMu.Lock()
	defer d.leasesMu.Unlock()
	if old, exists := d.leases[store.Key]; exists && old.version >= version {
		if published && !old.published {
			old.published = true
			d.leases[store.Key] = old
		}
		return nil
	}
	d.storeLeaseEntry(store.Key, leaseEntry{v2: parsed, version: version, expires: expires, published: published, typeID: store.Type})
	return nil
}

func (d *Database) storeMetaLeaseSet(store i2np.DatabaseStoreMessage, seenAt uint64, published bool) error {
	parsed, err := ParseMetaLeaseSet(store.Data)
	if err != nil {
		return err
	}
	if parsed.Hash() != store.Key {
		return ErrStoreKeyMismatch
	}
	valid, err := parsed.Verify()
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidSignature
	}
	earliest, latest, err := metaLeaseSetRange(parsed)
	if err != nil {
		return err
	}
	headerExpires := (uint64(parsed.Header.Published) + uint64(parsed.Header.Expires)) * 1000
	if headerExpires < latest {
		latest = headerExpires
	}
	if err = validateLeaseSetRange(earliest, latest, seenAt, MetaLeaseSetMaxFutureMillis); err != nil {
		return err
	}
	owned := append([]byte(nil), store.Data...)
	parsed, err = ParseMetaLeaseSet(owned)
	if err != nil {
		return err
	}
	version := uint64(parsed.Header.Published)
	d.leasesMu.Lock()
	defer d.leasesMu.Unlock()
	if old, exists := d.leases[store.Key]; exists && old.version >= version {
		if published && !old.published {
			old.published = true
			d.leases[store.Key] = old
		}
		return nil
	}
	d.storeLeaseEntry(store.Key, leaseEntry{meta: parsed, version: version, expires: headerExpires, published: published, typeID: store.Type})
	return nil
}

func (d *Database) storeEncryptedLeaseSet(store i2np.DatabaseStoreMessage, seenAt uint64, published bool) error {
	parsed, err := ParseEncryptedLeaseSet(store.Data)
	if err != nil {
		return err
	}
	earliest := uint64(parsed.Published) * 1000
	latest := (uint64(parsed.Published) + uint64(parsed.Expires)) * 1000
	if err = validateLeaseSetRange(earliest, latest, seenAt, LeaseSetMaxFutureMillis); err != nil {
		return err
	}
	if parsed.Hash() != store.Key {
		return ErrStoreKeyMismatch
	}
	valid, err := parsed.Verify()
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidSignature
	}
	owned := append([]byte(nil), store.Data...)
	parsed, err = ParseEncryptedLeaseSet(owned)
	if err != nil {
		return err
	}
	version := uint64(parsed.Published)
	d.leasesMu.Lock()
	defer d.leasesMu.Unlock()
	if old, exists := d.leases[store.Key]; exists && old.version >= version {
		if published && !old.published {
			old.published = true
			d.leases[store.Key] = old
		}
		return nil
	}
	d.storeLeaseEntry(store.Key, leaseEntry{encrypted: parsed, version: version, expires: latest, published: published, typeID: store.Type})
	return nil
}

func legacyLeaseRange(set LeaseSet) (uint64, uint64, error) {
	leases := set.Leases()
	earliest, latest := ^uint64(0), uint64(0)
	for {
		lease, ok, err := leases.Next()
		if err != nil {
			return 0, 0, err
		}
		if !ok {
			break
		}
		earliest = min(earliest, lease.EndDate)
		latest = max(latest, lease.EndDate)
	}
	if latest == 0 {
		return 0, 0, ErrLeaseSetExpired
	}
	return earliest, latest, nil
}

func leaseSet2Range(set LeaseSet2) (uint64, uint64, error) {
	leases := set.Leases()
	earliest, latest := ^uint64(0), uint64(0)
	for {
		lease, ok, err := leases.Next()
		if err != nil {
			return 0, 0, err
		}
		if !ok {
			break
		}
		end := uint64(lease.EndDate) * 1000
		earliest = min(earliest, end)
		latest = max(latest, end)
	}
	if latest == 0 {
		return 0, 0, ErrLeaseSetExpired
	}
	return earliest, latest, nil
}

func metaLeaseSetRange(set MetaLeaseSet) (uint64, uint64, error) {
	leases := set.Leases()
	earliest, latest := ^uint64(0), uint64(0)
	for {
		lease, ok, err := leases.Next()
		if err != nil {
			return 0, 0, err
		}
		if !ok {
			break
		}
		end := uint64(lease.EndDate) * 1000
		earliest = min(earliest, end)
		latest = max(latest, end)
	}
	if latest == 0 {
		return 0, 0, ErrLeaseSetExpired
	}
	return earliest, latest, nil
}

func validateLeaseSetRange(earliest, latest, now, maxFuture uint64) error {
	oldestAllowed := uint64(0)
	if now > LeaseSetMaxPastMillis {
		oldestAllowed = now - LeaseSetMaxPastMillis
	}
	currentCutoff := uint64(0)
	if now > LeaseSetClockFudgeMillis {
		currentCutoff = now - LeaseSetClockFudgeMillis
	}
	if earliest <= oldestAllowed || latest <= currentCutoff {
		return ErrLeaseSetExpired
	}
	if latest > saturatingAdd(now, LeaseSetClockFudgeMillis+maxFuture) {
		return ErrLeaseSetFuture
	}
	return nil
}

// LeaseSet returns the newest legacy LeaseSet for key, when one is stored.
func (d *Database) LeaseSet(key foundation.Hash) (LeaseSet, bool) {
	d.leasesMu.RLock()
	entry, ok := d.leases[key]
	d.leasesMu.RUnlock()
	return entry.legacy, ok && entry.typeID == i2np.StoreLeaseSet
}

// LeaseSet2 returns the newest LS2 for key, when one is stored.
func (d *Database) LeaseSet2(key foundation.Hash) (LeaseSet2, bool) {
	d.leasesMu.RLock()
	entry, ok := d.leases[key]
	d.leasesMu.RUnlock()
	return entry.v2, ok && entry.typeID == i2np.StoreLeaseSet2
}

// MetaLeaseSet returns the newest meta LeaseSet for key, when one is stored.
func (d *Database) MetaLeaseSet(key foundation.Hash) (MetaLeaseSet, bool) {
	d.leasesMu.RLock()
	entry, ok := d.leases[key]
	d.leasesMu.RUnlock()
	return entry.meta, ok && entry.typeID == i2np.StoreMetaLeaseSet
}

// EncryptedLeaseSet returns the newest encrypted LeaseSet for key.
func (d *Database) EncryptedLeaseSet(key foundation.Hash) (EncryptedLeaseSet, bool) {
	d.leasesMu.RLock()
	entry, ok := d.leases[key]
	d.leasesMu.RUnlock()
	return entry.encrypted, ok && entry.typeID == i2np.StoreEncryptedLeaseSet
}

func (d *Database) storeLeaseEntry(key foundation.Hash, entry leaseEntry) {
	_, exists := d.leases[key]
	if !exists && len(d.leases) >= d.maxLeases {
		if oldest, ok := d.popLeaseExpiryLocked(); ok {
			delete(d.leases, oldest.key)
		}
	}
	d.leases[key] = entry
	d.upsertLeaseExpiryLocked(key, entry.expires)
}

func (d *Database) upsertLeaseExpiryLocked(key foundation.Hash, expires uint64) {
	if index, ok := d.leaseExpiryIndex[key]; ok {
		d.leaseExpiries[index].expires = expires
		d.fixLeaseExpiryLocked(index)
		return
	}
	d.leaseExpiries = append(d.leaseExpiries, leaseExpiry{key: key, expires: expires})
	index := len(d.leaseExpiries) - 1
	d.leaseExpiryIndex[key] = index
	for index > 0 {
		parent := (index - 1) / 2
		if !d.lessLeaseExpiryLocked(index, parent) {
			break
		}
		d.swapLeaseExpiryLocked(index, parent)
		index = parent
	}
}

func (d *Database) popLeaseExpiryLocked() (leaseExpiry, bool) {
	if len(d.leaseExpiries) == 0 {
		return leaseExpiry{}, false
	}
	oldest := d.leaseExpiries[0]
	delete(d.leaseExpiryIndex, oldest.key)
	last := len(d.leaseExpiries) - 1
	if last != 0 {
		d.leaseExpiries[0] = d.leaseExpiries[last]
		d.leaseExpiryIndex[d.leaseExpiries[0].key] = 0
	}
	d.leaseExpiries[last] = leaseExpiry{}
	d.leaseExpiries = d.leaseExpiries[:last]
	if len(d.leaseExpiries) != 0 {
		d.fixLeaseExpiryLocked(0)
	}
	return oldest, true
}

func (d *Database) fixLeaseExpiryLocked(index int) {
	for index > 0 {
		parent := (index - 1) / 2
		if !d.lessLeaseExpiryLocked(index, parent) {
			break
		}
		d.swapLeaseExpiryLocked(index, parent)
		index = parent
	}
	for {
		left := 2*index + 1
		if left >= len(d.leaseExpiries) {
			return
		}
		child := left
		if right := left + 1; right < len(d.leaseExpiries) && d.lessLeaseExpiryLocked(right, left) {
			child = right
		}
		if !d.lessLeaseExpiryLocked(child, index) {
			return
		}
		d.swapLeaseExpiryLocked(index, child)
		index = child
	}
}

func (d *Database) lessLeaseExpiryLocked(left, right int) bool {
	leftExpiry := d.leaseExpiries[left].expires
	rightExpiry := d.leaseExpiries[right].expires
	if leftExpiry == 0 {
		return false
	}
	if rightExpiry == 0 {
		return true
	}
	if leftExpiry == rightExpiry {
		return bytes.Compare(d.leaseExpiries[left].key[:], d.leaseExpiries[right].key[:]) < 0
	}
	return leftExpiry < rightExpiry
}

func (d *Database) swapLeaseExpiryLocked(left, right int) {
	d.leaseExpiries[left], d.leaseExpiries[right] = d.leaseExpiries[right], d.leaseExpiries[left]
	d.leaseExpiryIndex[d.leaseExpiries[left].key] = left
	d.leaseExpiryIndex[d.leaseExpiries[right].key] = right
}

// ExpireLeases removes stored lease entries that have passed their expiration time.
func (d *Database) ExpireLeases(nowMillis uint64) int {
	d.leasesMu.Lock()
	defer d.leasesMu.Unlock()
	removed := 0
	for len(d.leaseExpiries) != 0 {
		oldest := d.leaseExpiries[0]
		if oldest.expires == 0 || oldest.expires >= nowMillis {
			break
		}
		d.popLeaseExpiryLocked()
		delete(d.leases, oldest.key)
		removed++
	}
	return removed
}

func (d *Database) inflateRouterInfo(compressed []byte) ([]byte, *pool.Lease, error) {
	input := bytes.NewReader(compressed)
	value := d.gzipPool.Get()
	var reader *gzip.Reader
	var err error
	if value == nil {
		reader, err = gzip.NewReader(input)
	} else {
		reader = value.(*gzip.Reader)
		err = reader.Reset(input)
	}
	if err != nil {
		return nil, nil, err
	}
	reader.Multistream(false)
	// Read one sentinel byte beyond Java I2P's protocol maximum. This accepts
	// an exact 4 KiB RouterInfo while rejecting a gzip bomb before it can
	// allocate or retain a larger object.
	lease, ok := pool.AcquireLease(MaxRouterInfoBytes + 1)
	if !ok {
		return nil, nil, ErrRouterInfoTooLarge
	}
	output, _ := lease.Bytes(MaxRouterInfoBytes + 1)
	used := 0
	for {
		n, readErr := reader.Read(output[used:])
		used += n
		if used > MaxRouterInfoBytes {
			reader.Close()
			d.gzipPool.Put(reader)
			lease.Release()
			return nil, nil, ErrRouterInfoTooLarge
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			reader.Close()
			d.gzipPool.Put(reader)
			lease.Release()
			return nil, nil, readErr
		}
		if n == 0 {
			reader.Close()
			d.gzipPool.Put(reader)
			lease.Release()
			return nil, nil, io.ErrNoProgress
		}
	}
	if err = reader.Close(); err != nil {
		d.gzipPool.Put(reader)
		lease.Release()
		return nil, nil, err
	}
	d.gzipPool.Put(reader)
	return output[:used], lease, nil
}
