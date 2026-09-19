package reseed

import (
	"crypto/rand"
	"testing"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/foundation"
)

func BenchmarkOrderByLocalBuckets10K(b *testing.B) {
	slots := make(map[foundation.Hash]*dedupSlot, 10000)
	for i := 0; i < 10000; i++ {
		var h foundation.Hash
		_, _ = rand.Read(h[:])
		slots[h] = &dedupSlot{best: reseedCandidate{}}
	}
	var local foundation.Hash
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = orderByLocalBuckets(slots, local, 20)
	}
}

func BenchmarkRouterInfoVerify(b *testing.B) {
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		b.Fatal(err)
	}
	owner, err := controlplanenetdb.NewLocalRouterInfo(controlplanenetdb.LocalRouterInfoConfig{
		Local: local,
		Contacts: controlplanenetdb.RouterInfoContacts{Options: []foundation.MappingEntry{
			{Key: []byte("netId"), Value: []byte("2")},
		}},
	})
	if err != nil {
		b.Fatal(err)
	}
	info, err := owner.Publish(1000)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := info.Verify(); !ok {
			b.Fatal("verify failed")
		}
	}
}
