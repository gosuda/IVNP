package netdb

import (
	"bytes"
	"context"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestExplorationTargetStaysInSelectedBucket(t *testing.T) {
	var local foundation.Hash
	for _, bucket := range []int{0, 7, 8, BucketCount - 1} {
		target, err := explorationTarget(local, bucket, bytes.NewReader(bytes.Repeat([]byte{0xff}, foundation.HashLength)))
		if err != nil {
			t.Fatal(err)
		}
		if got := distanceBucket(local, target); got != bucket {
			t.Fatalf("bucket %d target distance = %d", bucket, got)
		}
		for bit := range bucket {
			byteIndex, mask := bit/8, byte(1<<(7-bit%8))
			if target[byteIndex]&mask != local[byteIndex]&mask {
				t.Fatalf("bucket %d changed prefix bit %d", bucket, bit)
			}
		}
	}
}

func TestExplorerFillsConfiguredWindowInOneMaintenancePass(t *testing.T) {
	for _, test := range []struct {
		name       string
		aggressive bool
		want       int
	}{
		{name: "steady", want: explorerSteadyMaxInflight},
		{name: "bootstrap", aggressive: true, want: explorerBootstrapMaxInflight},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
			addRequestTestFloodfill(database, requestTestHash(0x80))
			sender := new(requestTestSender)
			now := uint64(100)
			requests, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(0x81), tunnel: 7, viaTunnel: true}, RequestManagerConfig{
				Capacity: 16, MaxCandidates: 1, TimeoutMillis: 1000, Now: func() uint64 { return now },
				Rand: bytes.NewReader(bytes.Repeat([]byte{1}, 128)),
			})
			if err != nil {
				t.Fatal(err)
			}
			explorer, err := NewExplorer(ExplorerConfig{
				Table: database.Routers(), Requests: requests, Now: func() uint64 { return now },
				Rand:       bytes.NewReader(bytes.Repeat([]byte{2}, explorerBootstrapMaxInflight*foundation.HashLength)),
				Aggressive: func() bool { return test.aggressive },
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = explorer.Maintain(context.Background()); err != nil {
				t.Fatal(err)
			}
			if explorer.Inflight() != test.want {
				t.Fatalf("inflight = %d, want %d", explorer.Inflight(), test.want)
			}
			if sent := len(sender.snapshot()); sent != test.want {
				t.Fatalf("exploration lookups sent = %d, want %d", sent, test.want)
			}
		})
	}
}
