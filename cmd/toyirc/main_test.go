package main

import (
	"bufio"
	"cmp"
	"context"
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
