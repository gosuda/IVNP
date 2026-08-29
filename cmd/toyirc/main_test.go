package main

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExchangeIRCCompletesWelcomeAndPong(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	defer serverConnection.Close()
	serverErr := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConnection)
		for _, prefix := range []string{"NICK ivtest", "USER ivtest "} {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverErr <- err
				return
			}
			if !strings.HasPrefix(line, prefix) {
				serverErr <- fmt.Errorf("line %q does not start with %q", line, prefix)
				return
			}
		}
		if _, err := io.WriteString(serverConnection, "PING :nonce\r\n"); err != nil {
			serverErr <- err
			return
		}
		pong, err := reader.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if pong != "PONG :nonce\r\n" {
			serverErr <- fmt.Errorf("pong = %q", pong)
			return
		}
		_, err = io.WriteString(serverConnection, ":irc.example 001 ivtest :welcome\r\n")
		serverErr <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := exchangeIRC(ctx, clientConnection, "ivtest"); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestExchangeIRCRejectsOversizedLine(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	defer serverConnection.Close()
	go func() {
		reader := bufio.NewReader(serverConnection)
		_, _ = reader.ReadString('\n')
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(serverConnection, strings.Repeat("x", 513)+"\n")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := exchangeIRC(ctx, clientConnection, "ivtest"); err == nil || !strings.Contains(err.Error(), "oversized IRC line") {
		t.Fatalf("oversized line error = %v", err)
	}
}

type retrySAMNetwork struct {
	starts int
	dials  int
}

func (n *retrySAMNetwork) Start(context.Context) error {
	n.starts++
	return nil
}

func (n *retrySAMNetwork) DialI2P(context.Context, string) (net.Conn, error) {
	n.dials++
	if n.dials == 1 {
		return nil, errors.New("temporary dial failure")
	}
	clientConnection, serverConnection := net.Pipe()
	go func() {
		defer serverConnection.Close()
		reader := bufio.NewReader(serverConnection)
		for range 2 {
			if _, err := reader.ReadString('\n'); err != nil {
				return
			}
		}
		_, _ = io.WriteString(serverConnection, ":irc.example 001 ivtest :welcome\r\n")
	}()
	return clientConnection, nil
}

func TestRunIRC2PReusesSAMSessionAcrossDialRetries(t *testing.T) {
	network := new(retrySAMNetwork)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	config := ircConfig{samAddress: "127.0.0.1:7656", server: "irc.example.i2p", port: 6667, nick: "ivtest"}
	if err := runIRC2PNetwork(ctx, config, io.Discard, network, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if network.starts != 1 || network.dials != 2 {
		t.Fatalf("SAM lifecycle starts=%d dials=%d, want 1/2", network.starts, network.dials)
	}
}

func TestIRC2PIntegration(t *testing.T) {
	if os.Getenv("IVNP_IRC2P_INTEGRATION") != "1" {
		t.Skip("set IVNP_IRC2P_INTEGRATION=1 to run the live irc2p check")
	}
	samAddress := cmp.Or(os.Getenv("IVNP_IRC2P_SAM"), "127.0.0.1:7656")
	server := cmp.Or(os.Getenv("IVNP_IRC2P_SERVER"), "irc.postman.i2p")
	nick, err := randomNick()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxRunTime-10*time.Second)
	defer cancel()
	if err = runIRC2P(ctx, ircConfig{samAddress: samAddress, server: server, port: 6667, nick: nick}, io.Discard); err != nil {
		t.Fatal(err)
	}
}
