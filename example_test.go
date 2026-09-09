package ivnp_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"gosuda.org/ivnp"
)

func ExampleNewRouter() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cfg := ivnp.DefaultRouterConfig()
	router, err := ivnp.NewRouter(ctx, cfg)
	if err != nil {
		panic(err)
	}
	defer router.Close()
	<-ctx.Done()
}

func ExampleNewRouter_persistence() {
	cfg := ivnp.DefaultRouterConfig()
	cfg.Persistence = &ivnp.PersistenceConfig{Directory: "./router-data"}
	router, err := ivnp.NewRouter(context.Background(), cfg)
	if err != nil {
		panic(err)
	}
	defer router.Close()
}

func ExampleRouter_NewDestination() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	router, err := ivnp.NewRouter(ctx, ivnp.DefaultRouterConfig())
	if err != nil {
		panic(err)
	}
	defer router.Close()

	dest, err := router.NewDestination(ctx, ivnp.DefaultDestinationConfig())
	if err != nil {
		panic(err)
	}
	defer dest.Close()

	listener, err := dest.ListenContext(ctx, "i2p", ":8080")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println(net.JoinHostPort(dest.B32(), "8080"))
}
