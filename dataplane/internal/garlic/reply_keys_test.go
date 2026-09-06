package garlic

import (
	"errors"
	"testing"
)

func TestReplyKeyRegistryConsumesOnceAndExpires(t *testing.T) {
	registry := NewReplyKeyRegistry(1)
	var tag [8]byte
	tag[0] = 1
	key := GarlicReplyKey{Tag: tag, ExpiresAt: 10}
	key.Key[0] = 2
	if err := registry.RegisterGarlicReplyKey(key); err != nil {
		t.Fatal(err)
	}
	if registry.Len() != 1 {
		t.Fatalf("registered keys = %d, want 1", registry.Len())
	}
	got, ok := registry.ConsumeGarlicReplyKey(tag, 9)
	if !ok || got.Key != key.Key || got.Tag != tag {
		t.Fatalf("consumed reply key = %#v, %t", got, ok)
	}
	if _, ok = registry.ConsumeGarlicReplyKey(tag, 9); ok || registry.Len() != 0 {
		t.Fatalf("reply key reused=%t entries=%d", ok, registry.Len())
	}
	if err := registry.RegisterGarlicReplyKey(key); err != nil {
		t.Fatal(err)
	}
	if _, ok = registry.ConsumeGarlicReplyKey(tag, 10); ok {
		t.Fatal("consumed expired reply key")
	}
}

func TestReplyKeyRegistryIsBoundedAndRemovalWipesEntry(t *testing.T) {
	registry := NewReplyKeyRegistry(1)
	var firstTag, secondTag [8]byte
	firstTag[0], secondTag[0] = 1, 2
	first := GarlicReplyKey{Tag: firstTag, ExpiresAt: 10}
	second := GarlicReplyKey{Tag: secondTag, ExpiresAt: 10}
	if err := registry.RegisterGarlicReplyKey(first); err != nil {
		t.Fatal(err)
	}
	if err := registry.RegisterGarlicReplyKey(second); !errors.Is(err, ErrReplyKeyRegistryFull) {
		t.Fatalf("full registry error = %v", err)
	}
	registry.RemoveGarlicReplyKey(firstTag)
	if registry.Len() != 0 {
		t.Fatalf("removed entries = %d, want 0", registry.Len())
	}
	if err := registry.RegisterGarlicReplyKey(second); err != nil {
		t.Fatal(err)
	}
	if removed := registry.Expire(10); removed != 1 || registry.Len() != 0 {
		t.Fatalf("expired=%d entries=%d", removed, registry.Len())
	}
}
