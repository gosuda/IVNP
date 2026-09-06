package router

import (
	"context"
	"testing"
)

func TestLifecycleStopsWorkers(t *testing.T) {
	var lifecycle Lifecycle
	if !lifecycle.Start(context.Background()) {
		t.Fatal("Start failed")
	}
	done := make(chan struct{})
	if err := lifecycle.Go(func(ctx context.Context) { <-ctx.Done(); close(done) }); err != nil {
		t.Fatal(err)
	}
	lifecycle.Stop()
	<-done
	if err := lifecycle.Go(func(context.Context) {}); err != ErrStopped {
		t.Fatalf("Go after Stop = %v", err)
	}
}
