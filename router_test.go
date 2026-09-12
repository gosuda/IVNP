package ivnp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"testing"
)

func isolatedRouterConfig() RouterConfig {
	cfg := DefaultRouterConfig()
	cfg.Bootstrap.ReseedURLs = nil
	cfg.NTCP2.Bind = netip.MustParseAddrPort("127.0.0.1:0")
	cfg.SSU2 = TransportConfig{}
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return cfg
}

func TestInMemoryRouterLeavesNoStateAndDoesNotShareIdentity(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	cfg := isolatedRouterConfig()
	first, err := NewRouter(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})
	second, err := NewRouter(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Error(err)
		}
	})
	if first.Hash() == second.Hash() || first.Hash() == (Hash{}) {
		t.Fatal("independent in-memory routers did not obtain distinct identities")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("in-memory router created data entries: %v", entries)
	}
}

func TestPersistentRouterRetainsIdentityAndReleasesExclusiveState(t *testing.T) {
	cfg := isolatedRouterConfig()
	cfg.Persistence = &PersistenceConfig{Directory: t.TempDir()}
	first, err := NewRouter(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})
	hash := first.Hash()
	conflicting, err := NewRouter(t.Context(), cfg)
	if conflicting != nil {
		_ = conflicting.Close()
		t.Fatal("two routers acquired the same persistent state")
	}
	if err == nil {
		t.Fatal("opening locked state succeeded")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewRouter(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Error(err)
		}
	})
	if second.Hash() != hash {
		t.Fatal("persistent reopen rotated router identity")
	}
}

func TestCanceledRouterConstructionDoesNotCreatePersistentState(t *testing.T) {
	cfg := isolatedRouterConfig()
	directory := t.TempDir()
	cfg.Persistence = &PersistenceConfig{Directory: directory}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	router, err := NewRouter(ctx, cfg)
	if router != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled constructor = %v, %v", router, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("canceled constructor created persistent state: %v", entries)
	}
}

func TestRouterRejectsEmptyPersistenceInsteadOfUsingMemory(t *testing.T) {
	cfg := isolatedRouterConfig()
	cfg.Persistence = &PersistenceConfig{}
	router, err := NewRouter(t.Context(), cfg)
	if router != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty persistence = %v, %v", router, err)
	}
	var detail *ConfigError
	if !errors.As(err, &detail) || detail.Field != "Persistence.Directory" {
		t.Fatalf("missing persistence field diagnostic: %v", err)
	}
}

func TestCorruptPersistentStateDoesNotReplaceMasterKey(t *testing.T) {
	cfg := isolatedRouterConfig()
	cfg.Persistence = &PersistenceConfig{Directory: t.TempDir()}
	router, err := NewRouter(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	settings, _, err := routerSettings(cfg)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(settings.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	if err := os.WriteFile(settings.StatePath, []byte("corrupted state"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewRouter(t.Context(), cfg)
	if reopened != nil {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("corrupted persistent state produced a router")
	}
	if !errors.Is(err, ErrStateConflict) {
		t.Fatalf("corrupted state error = %v", err)
	}
	after, err := os.ReadFile(settings.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(after, original) {
		t.Fatal("failed state load replaced the existing master key")
	}
}

func TestTaintedCopyPersistenceAllowsConcurrentRouters(t *testing.T) {
	dir := t.TempDir()
	cfg := isolatedRouterConfig()
	cfg.Persistence = &PersistenceConfig{Directory: dir}
	first, err := NewRouter(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = first.Close()
	}()

	// Normal second router fails because dir is locked
	_, err = NewRouter(t.Context(), cfg)
	if err == nil {
		t.Fatal("expected locked state conflict, got nil")
	}

	// Tainted copy second router succeeds
	taintedCfg := isolatedRouterConfig()
	taintedCfg.Persistence = &PersistenceConfig{
		Directory:   dir,
		TempDir:     t.TempDir(),
		TaintedCopy: true,
	}
	second, err := NewRouter(t.Context(), taintedCfg)
	if err != nil {
		t.Fatalf("tainted router failed to start: %v", err)
	}
	defer func() {
		_ = second.Close()
	}()

	if second.Hash() != first.Hash() {
		t.Fatalf("expected tainted router to inherit identity %x, got %x", first.Hash(), second.Hash())
	}
}
