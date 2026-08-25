package garlic

import (
	"testing"
)

func TestTagStoreConsumesAndExpiresTags(t *testing.T) {
	store := NewTagStore(1)
	tag, key := make([]byte, 32), make([]byte, 32)
	tag[0], key[0] = 1, 2
	if !store.Put(tag, key, 10) {
		t.Fatal("Put failed")
	}
	got, ok := store.Take(tag, 9)
	if !ok || got != [32]byte{2} {
		t.Fatalf("Take = %x, %t", got, ok)
	}
	if _, ok := store.Take(tag, 9); ok {
		t.Fatal("tag reused")
	}
	store.Put(tag, key, 10)
	if _, ok := store.Take(tag, 11); ok {
		t.Fatal("expired tag accepted")
	}
}

func TestTagStoreClearReleasesBackingMapAndRemainsUsable(t *testing.T) {
	store := NewTagStore(1)
	tag, key := make([]byte, 32), make([]byte, 32)
	tag[0], key[0] = 4, 5
	if !store.Put(tag, key, 10) {
		t.Fatal("Put failed")
	}
	store.Clear()
	if store.tags != nil {
		t.Fatal("Clear retained tag map")
	}
	if _, ok := store.Take(tag, 1); ok {
		t.Fatal("Clear retained tag")
	}
	if !store.Put(tag, key, 10) {
		t.Fatal("Put after Clear failed")
	}
	if got, ok := store.Take(tag, 1); !ok || got != [32]byte{5} {
		t.Fatalf("Take after Clear = %x, %t", got, ok)
	}
}
