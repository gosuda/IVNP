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
	"time"
)

func isolatedRouterConfig() RouterConfig {
	cfg := DefaultRouterConfig()
	cfg.Bootstrap.ReseedURLs = nil
	cfg.Bootstrap.PriorityReseedURLs = nil
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
	cfg.Persistence = &PersistenceConfig{Directory: t.TempDir(), DisableTaintedCopy: true}
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
	cfg.Persistence = DefaultPersistenceConfig(dir)
	first, err := NewRouter(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = first.Close()
	}()

	// Second router with DisableTaintedCopy fails because dir is locked
	exclusiveCfg := isolatedRouterConfig()
	exclusiveCfg.Persistence = &PersistenceConfig{
		Directory:          dir,
		DisableTaintedCopy: true,
	}
	_, err = NewRouter(t.Context(), exclusiveCfg)
	if err == nil {
		t.Fatal("expected locked state conflict, got nil")
	}

	// Concurrent second router with default persistence succeeds via tainted copy
	secondCfg := isolatedRouterConfig()
	secondCfg.Persistence = &PersistenceConfig{Directory: dir}
	second, err := NewRouter(t.Context(), secondCfg)
	if err != nil {
		t.Fatalf("concurrent second router failed to start: %v", err)
	}
	defer func() {
		_ = second.Close()
	}()

	if second.Hash() != first.Hash() {
		t.Fatalf("expected tainted router to inherit identity %x, got %x", first.Hash(), second.Hash())
	}
}

func TestDefaultRouterConfigPriorityReseed(t *testing.T) {
	cfg := DefaultRouterConfig()
	if len(cfg.Bootstrap.PriorityReseedURLs) != 1 || cfg.Bootstrap.PriorityReseedURLs[0] != "https://hotseed.gosuda.org/i2pseeds.su3?netid=2" {
		t.Fatalf("default PriorityReseedURLs = %v", cfg.Bootstrap.PriorityReseedURLs)
	}
	if cfg.Bootstrap.PriorityReseedTimeout != 2*time.Second {
		t.Fatalf("default PriorityReseedTimeout = %v, want 2s", cfg.Bootstrap.PriorityReseedTimeout)
	}
}

func TestRouterConfigPriorityReseedValidation(t *testing.T) {
	cfg := DefaultRouterConfig()
	cfg.Bootstrap.PriorityReseedTimeout = -time.Second
	if _, _, err := routerSettings(cfg); err == nil {
		t.Fatal("negative PriorityReseedTimeout was accepted")
	}

	cfg = DefaultRouterConfig()
	cfg.Bootstrap.PriorityReseedURLs = []string{"http://insecure.example/i2p?netid=2"}
	if _, _, err := routerSettings(cfg); err == nil {
		t.Fatal("insecure HTTP PriorityReseedURL was accepted")
	}

	cfg = DefaultRouterConfig()
	cfg.Bootstrap.PriorityReseedURLs = []string{"https://hotseed.gosuda.org/i2pseeds.su3?netid=999"}
	if _, _, err := routerSettings(cfg); err == nil {
		t.Fatal("PriorityReseedURL with wrong netid was accepted")
	}
}
