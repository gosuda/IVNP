package sam

import (
	"context"
	"net"
	"sync"
	"testing"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
)

func TestSessionStartReceiverCloseConcurrentRace(t *testing.T) {
	for i := 0; i < 200; i++ {
		controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
		server, err := NewServer(ServerConfig{
			Address:              "127.0.0.1:0",
			Controller:           controller,
			MaxSessionQueueBytes: 1024,
			SessionQueue:         16,
			MaxSessions:          16,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := server.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		local, err := foundation.GenerateLegacyLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		endpoint, err := controller.CreateDestination(context.Background(), destination.DestinationSpec{Local: local})
		if err != nil {
			t.Fatal(err)
		}
		pipeA, pipeB := net.Pipe()
		control := &serverConnection{Conn: pipeA}
		session := newRootSession(server, "test", styleDatagram, endpoint, control, 0, 0, 0, 0, 0, false, nil, nil)
		if err := server.addRoot(session); err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = session.startReceiver(destination.DestinationRoute{}, 10)
		}()
		go func() {
			defer wg.Done()
			_ = session.close()
		}()
		wg.Wait()
		pipeA.Close()
		pipeB.Close()
		_ = server.Close()
		local.ReleaseSensitive()
	}
}
