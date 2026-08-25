package netdb

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"io"
	"time"
)

const (
	explorerSteadyMaxInflight    = 4
	explorerBootstrapMaxInflight = 8
	explorerSteadyMinimum        = 8
	explorerBootstrapMinimum     = 12
	explorerBackoffBase          = uint64(30 * 1000)
	explorerBackoffCap           = uint64(10 * 60 * 1000)
	explorerBootstrapBackoffBase = uint64(10 * 1000)
	explorerBootstrapBackoffCap  = uint64(time.Minute / time.Millisecond)
)

var ErrExplorerConfig = errors.New("netdb: invalid explorer configuration")

type explorationPending struct {
	done <-chan LookupResult
}

// ExplorerConfig binds sparse-bucket exploration to the existing bounded
// RequestManager. It owns no goroutines: maintenance drives both launch and
// completion processing.
type ExplorerConfig struct {
	Table      *Table
	Requests   *RequestManager
	Now        func() uint64
	Rand       io.Reader
	Aggressive func() bool
}

// Explorer starts enough type-3 lookups per Maintain call to fill its bounded
// four-request window. Each target belongs to exactly one XOR bucket.
type Explorer struct {
	table    *Table
	requests *RequestManager
	now      func() uint64
	rand     io.Reader
	minimum  uint16

	aggressive func() bool
	nextAt     [BucketCount]uint64
	failures   [BucketCount]uint8
	pending    [BucketCount]explorationPending
	cursor     int
	inflight   int
	closed     bool
}

func NewExplorer(config ExplorerConfig) (*Explorer, error) {
	if config.Table == nil || config.Requests == nil || config.Now == nil {
		return nil, ErrExplorerConfig
	}
	if config.Rand == nil {
		config.Rand = cryptorand.Reader
	}
	minimum := min(explorerSteadyMinimum, config.Table.BucketCapacity())
	if minimum <= 0 {
		return nil, ErrExplorerConfig
	}
	return &Explorer{
		table: config.Table, requests: config.Requests, now: config.Now, rand: config.Rand,
		minimum: uint16(minimum), aggressive: config.Aggressive,
	}, nil
}

// Maintain drains completed lookups and fills the bounded exploration window
// from eligible sparse buckets. Saturated request capacity is treated as a
// short failed attempt, avoiding a retry storm while the shared owner is full.
func (e *Explorer) Maintain(ctx context.Context) error {
	if e.closed {
		return context.Canceled
	}
	if ctx ==
		nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	now := e.now()
	var occupancy [BucketCount]uint16
	e.table.BucketOccupancy(&occupancy)
	e.drain(now, &occupancy)
	maxInflight := explorerSteadyMaxInflight
	minimum := e.minimum
	if e.aggressive != nil && e.aggressive() {
		maxInflight = explorerBootstrapMaxInflight
		minimum = uint16(min(explorerBootstrapMinimum, e.table.BucketCapacity()))
	}
	for scanned := 0; scanned < BucketCount && e.inflight < maxInflight; scanned++ {
		bucket := e.cursor
		e.cursor = (e.cursor + 1) % BucketCount
		if occupancy[bucket] >= minimum || e.pending[bucket].done != nil || e.nextAt[bucket] > now {
			continue
		}
		target, err := explorationTarget(e.table.Local(), bucket, e.rand)
		if err != nil {
			e.deferBucket(bucket, now)
			return err
		}
		done, err := e.requests.Explore(ctx, target)
		if err != nil {
			e.deferBucket(bucket, now)
			if errors.Is(err, ErrRequestManagerFull) || errors.Is(err, ErrNoFloodfill) {
				return nil
			}
			return err
		}
		e.pending[bucket].done = done
		e.inflight++
	}
	return nil
}

func (e *Explorer) drain(now uint64, occupancy *[BucketCount]uint16) {
	for bucket := range e.pending {
		done := e.pending[bucket].done
		if done == nil {
			continue
		}
		select {
		case <-done:
			e.pending[bucket].done = nil
			e.inflight--
			if occupancy[bucket] < e.currentMinimum() {
				e.deferBucket(bucket, now)
			} else {
				e.failures[bucket] = 0
				e.nextAt[bucket] = now
			}
		default:
		}
	}
}

func (e *Explorer) currentMinimum() uint16 {
	if e.aggressive != nil && e.aggressive() {
		return uint16(min(explorerBootstrapMinimum, e.table.BucketCapacity()))
	}
	return e.minimum
}

func (e *Explorer) deferBucket(bucket int, now uint64) {
	if e.failures[bucket] < 7 {
		e.failures[bucket]++
	}
	backoffBase, backoffCap := explorerBackoffBase, explorerBackoffCap
	if e.aggressive != nil && e.aggressive() {
		backoffBase, backoffCap = explorerBootstrapBackoffBase, explorerBootstrapBackoffCap
	}
	shift := e.failures[bucket] - 1
	backoff := backoffBase
	for shift > 0 && backoff < backoffCap {
		backoff *= 2
		shift--
	}
	if backoff > backoffCap {
		backoff = backoffCap
	}
	if ^uint64(0)-now < backoff {
		e.nextAt[bucket] = ^uint64(0)
	} else {
		e.nextAt[bucket] = now + backoff
	}
}

// Close prevents new work and releases completion channels. RequestManager
// owns the shared requests and remains responsible for their bounded expiry.
func (e *Explorer) Close() {
	if e == nil {
		return
	}
	e.closed = true
	for bucket := range e.pending {
		e.pending[bucket].done = nil
	}
	e.inflight = 0
}

// Inflight reports the bounded number of explorer-owned lookup results.
func (e *Explorer) Inflight() int {
	if e == nil {
		return 0
	}
	return e.inflight
}

func explorationTarget(local [32]byte, bucket int, random io.Reader) ([32]byte, error) {
	var noise [32]byte
	if _, err := io.ReadFull(random, noise[:]); err != nil {
		return [32]byte{}, err
	}
	target := local
	for bit := bucket; bit < BucketCount; bit++ {
		byteIndex := bit / 8
		mask := byte(1 << (7 - bit%8))
		if bit == bucket {
			target[byteIndex] ^= mask
			continue
		}
		if noise[byteIndex]&mask != 0 {
			target[byteIndex] |= mask
		} else {
			target[byteIndex] &^= mask
		}
	}
	return target, nil
}
