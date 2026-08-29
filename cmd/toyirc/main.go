package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"gosuda.org/ivnp/client"
	"gosuda.org/ivnp/foundation"
)

const maxRunTime = 5 * time.Minute

type ircConfig struct {
	samAddress string
	server     string
	port       int
	nick       string
}

func main() {
	var timeout time.Duration
	config := ircConfig{}
	flag.StringVar(&config.samAddress, "sam", "127.0.0.1:7656", "SAM bridge address")
	flag.StringVar(&config.server, "server", "irc.postman.i2p", "IRC I2P hostname or destination")
	flag.IntVar(&config.port, "port", 6667, "IRC destination port")
	flag.StringVar(&config.nick, "nick", "", "IRC nickname")
	flag.DurationVar(&timeout, "timeout", maxRunTime, "overall connection timeout")
	flag.Parse()
	if timeout <= 0 || timeout > maxRunTime {
		fmt.Fprintln(os.Stderr, "timeout must be between 1ns and 5m")
		os.Exit(2)
	}
	if config.nick == "" {
		nick, err := randomNick()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		config.nick = nick
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if err := runIRC2P(ctx, config, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runIRC2P(ctx context.Context, config ircConfig, output io.Writer) error {
	if ctx == nil || config.samAddress == "" || config.server == "" {
		return errors.New("toyirc: invalid configuration")
	}
	if config.port < 1 || config.port > 65535 || !validNick(config.nick) {
		return errors.New("toyirc: invalid configuration")
	}
	address := net.JoinHostPort(config.server, strconv.Itoa(config.port))
	var lastErr error
	for {
		attemptContext, cancel := context.WithTimeout(ctx, 90*time.Second)
		lastErr = runIRC2PAttempt(attemptContext, config, address)
		cancel()
		if lastErr == nil {
			_, err := fmt.Fprintf(output, "connected to %s as %s\n", address, config.nick)
			return err
		}
		if ctx.Err() != nil {
			return fmt.Errorf("toyirc: connect %s: %w", address, errors.Join(ctx.Err(), lastErr))
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("toyirc: connect %s: %w", address, errors.Join(ctx.Err(), lastErr))
		case <-timer.C:
		}
	}
}

func runIRC2PAttempt(ctx context.Context, config ircConfig, address string) error {
	network, err := client.SimpleAnonymousMessagingNew(client.SimpleAnonymousMessagingConfig{
		Address: config.samAddress, SignatureType: foundation.SigningEdDSASHA512Ed25519,
		LeaseSetEncTypes: []foundation.CryptoKeyType{foundation.CryptoX25519},
	})
	if err != nil {
		return fmt.Errorf("toyirc: create SAM session: %w", err)
	}
	defer network.Close()
	if err = network.Start(ctx); err != nil {
		return fmt.Errorf("toyirc: start SAM session: %w", err)
	}
	connection, err := network.DialI2P(ctx, address)
	if err != nil {
		return fmt.Errorf("toyirc: connect %s: %w", address, err)
	}
	defer connection.Close()
	return exchangeIRC(ctx, connection, config.nick)
}

func exchangeIRC(ctx context.Context, connection net.Conn, nick string) error {
	if ctx == nil || connection == nil || !validNick(nick) {
		return errors.New("toyirc: invalid IRC connection")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	if err := writeIRC(connection, "NICK "+nick); err != nil {
		return fmt.Errorf("toyirc: send NICK: %w", err)
	}
	if err := writeIRC(connection, "USER "+nick+" 0 * :IVNP integration client"); err != nil {
		return fmt.Errorf("toyirc: send USER: %w", err)
	}
	reader := bufio.NewReaderSize(connection, 1024)
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("toyirc: IRC deadline: %w", ctx.Err())
			}
			return fmt.Errorf("toyirc: read IRC: %w", err)
		}
		if len(line) > 512 {
			return errors.New("toyirc: oversized IRC line")
		}
		message := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if strings.HasPrefix(message, "PING ") {
			if err = writeIRC(connection, "PONG "+strings.TrimPrefix(message, "PING ")); err != nil {
				return fmt.Errorf("toyirc: send PONG: %w", err)
			}
			continue
		}
		command := ircCommand(message)
		switch command {
		case "001":
			_ = writeIRC(connection, "QUIT :integration complete")
			return nil
		case "ERROR":
			return fmt.Errorf("toyirc: IRC server error: %s", message)
		}
	}
}

func writeIRC(writer io.Writer, line string) error {
	if strings.ContainsAny(line, "\r\n") || len(line) > 510 {
		return errors.New("toyirc: invalid IRC line")
	}
	_, err := io.WriteString(writer, line+"\r\n")
	return err
}

func ircCommand(message string) string {
	fields := strings.Fields(message)
	if len(fields) == 0 {
		return ""
	}
	if strings.HasPrefix(fields[0], ":") {
		if len(fields) < 2 {
			return ""
		}
		return strings.ToUpper(fields[1])
	}
	return strings.ToUpper(fields[0])
}

func validNick(nick string) bool {
	if len(nick) < 1 || len(nick) > 16 {
		return false
	}
	for index, character := range nick {
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		if letter || character == '_' || character == '-' {
			continue
		}
		digitAfterFirst := index > 0 && character >= '0' && character <= '9'
		if !digitAfterFirst {
			return false
		}
	}
	return true
}

func randomNick() (string, error) {
	var suffix [3]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("iv%06x", suffix), nil
}
