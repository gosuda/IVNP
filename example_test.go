package ivnp_test

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"syscall"
	"time"

	"gosuda.org/ivnp"
)

func ExampleNode() {
	cfg, err := ivnp.LoadOrCreateConfig("ivnp.conf")
	if err != nil {
		panic(err)
	}

	router, err := ivnp.New(cfg, ivnp.Options{})
	if err != nil {
		panic(err)
	}
	defer router.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err = router.Start(ctx); err != nil {
		panic(err)
	}
	if err = router.Wait(); err != nil {
		panic(err)
	}
}

func ExampleNode_DestinationController() {
	cfg, err := ivnp.LoadOrCreateConfig("ivnp.conf")
	if err != nil {
		panic(err)
	}

	router, err := ivnp.New(cfg, ivnp.Options{})
	if err != nil {
		panic(err)
	}
	defer router.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err = router.Start(ctx); err != nil {
		panic(err)
	}

	endpoint, err := router.DestinationController().CreateDestination(ctx, ivnp.DestinationSpec{})
	if err != nil {
		panic(err)
	}
	defer endpoint.Close()

	ready, ok := endpoint.(ivnp.ReadyDestinationEndpoint)
	if !ok {
		panic("destination endpoint does not report readiness")
	}
	if err = ready.WaitReady(ctx); err != nil {
		panic(err)
	}

	connection, err := endpoint.DialI2P(ctx, "stats.i2p:80")
	if err != nil {
		panic(err)
	}
	defer connection.Close()
	if err = writeHTTPGet(connection); err != nil {
		panic(err)
	}
}

func writeHTTPGet(connection net.Conn) error {
	_, err := fmt.Fprint(connection, "GET / HTTP/1.0\r\nHost: stats.i2p\r\n\r\n")
	return err
}
