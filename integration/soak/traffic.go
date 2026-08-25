package main

import (
	"gosuda.org/ivnp/client"

	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"gosuda.org/ivnp"
)

const (
	streamProbePort    = 23191
	maxStreamProbeSize = 64 * 1024
	probeTimeout       = 30 * time.Second
)

var probeSizes = [...]int{32, 1024, 16 * 1024, 64 * 1024}

type trafficEndpoint struct {
	name        string
	address     string
	network     *client.SimpleAnonymousMessagingNetwork
	listener    net.Listener
	eepsiteBody string
	done        chan struct{}
}

type trafficRunner struct {
	runID      string
	endpoints  map[string]*trafficEndpoint
	sequence   map[string]uint64
	udp        *samMessageProbes
	sequenceMu sync.Mutex
}

type direction struct {
	name string
	from string
	to   string
}

var requiredDirections = [...]direction{
	{name: "ivnp-client-to-java", from: "ivnp-client", to: "java"},
	{name: "java-to-ivnp-site", from: "java", to: "ivnp-site"},
	{name: "ivnp-client-to-ivnp-site", from: "ivnp-client", to: "ivnp-site"},
}

func newTrafficRunner(ctx context.Context, runID string, addresses map[string]string, udpAddress string) (*trafficRunner, error) {
	runner := &trafficRunner{runID: runID, endpoints: make(map[string]*trafficEndpoint, 3), sequence: make(map[string]uint64, len(requiredDirections))}
	// Java uses one-hop client tunnels so its LeaseSet is published through a
	// real remote gateway and both cross-implementation directions exercise
	// native tunnel routing. The pinned i2pd release must remain new enough for
	// Java's tunnel peer selector; older releases silently fall back to zero hop.
	javaEndpoint, err := startTrafficEndpointWithRetry(ctx, runID, "java", addresses["java"])
	if err != nil {
		runner.Close()
		return nil, fmt.Errorf("start java SAM stream endpoint: %w", err)
	}
	runner.endpoints["java"] = javaEndpoint
	for _, name := range []string{"ivnp-client", "ivnp-site"} {
		endpoint, err := startTrafficEndpointWithRetry(ctx, runID, name, addresses["ivnp"])
		if err != nil {
			runner.Close()
			return nil, fmt.Errorf("start %s SAM stream endpoint: %w", name, err)
		}
		runner.endpoints[name] = endpoint
	}
	var udp *samMessageProbes
	for attempt := 1; ; attempt++ {
		udp, err = newSAMMessageProbes(ctx, addresses["ivnp"], udpAddress, runID+"-"+strconv.Itoa(attempt))
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			runner.Close()
			return nil, fmt.Errorf("start IVNP DATAGRAM/RAW sessions: %w (last attempt: %v)", ctx.Err(), err)
		case <-time.After(2 * time.Second):
		}
	}
	runner.udp = udp
	return runner, nil
}

// newLocalTrafficRunner starts only IVNP-owned SAM endpoints. Native Java and
// i2pd routers remain topology peers, but no foreign SAM client participates in
// this focused UDP-to-STREAM diagnostic.
func newLocalTrafficRunner(ctx context.Context, runID, address, udpAddress string) (*trafficRunner, error) {
	runner := &trafficRunner{runID: runID, endpoints: make(map[string]*trafficEndpoint, 2), sequence: make(map[string]uint64, 1)}
	for _, name := range []string{"ivnp-client", "ivnp-site"} {
		endpoint, err := startTrafficEndpointWithRetry(ctx, runID, name, address)
		if err != nil {
			runner.Close()
			return nil, fmt.Errorf("start %s SAM stream endpoint: %w", name, err)
		}
		runner.endpoints[name] = endpoint
	}
	var err error
	for attempt := 1; ; attempt++ {
		runner.udp, err = newSAMMessageProbes(ctx, address, udpAddress, runID+"-"+strconv.Itoa(attempt))
		if err == nil {
			return runner, nil
		}
		select {
		case <-ctx.Done():
			runner.Close()
			return nil, fmt.Errorf("start IVNP DATAGRAM/RAW sessions: %w (last attempt: %v)", ctx.Err(), err)
		case <-time.After(2 * time.Second):
		}
	}
}

func startTrafficEndpointWithRetry(ctx context.Context, runID, name, address string) (*trafficEndpoint, error) {
	var last error
	for attempt := 1; ; attempt++ {
		endpoint, err := startTrafficEndpoint(ctx, runID+"-"+strconv.Itoa(attempt), name, address)
		if err == nil {
			return endpoint, nil
		}
		last = err
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: last attempt: %v", ctx.Err(), last)
		case <-time.After(2 * time.Second):
		}
	}
}
func startTrafficEndpoint(ctx context.Context, runID, name, address string) (*trafficEndpoint, error) {
	var sessionOptions map[string]string

	if name == "java" {
		sessionOptions = map[string]string{
			"inbound.length":          "1",
			"outbound.length":         "1",
			"inbound.quantity":        "1",
			"outbound.quantity":       "1",
			"inbound.backupQuantity":  "0",
			"outbound.backupQuantity": "0",
		}
	}
	leaseSetEncTypes := []ivnp.CryptoKeyType{ivnp.CryptoX25519}
	network, err := client.SimpleAnonymousMessagingNew(client.SimpleAnonymousMessagingConfig{
		Address:          address,
		ID:               safeSAMID(runID + "-stream-" + name),
		LeaseSetType:     3,
		LeaseSetEncTypes: leaseSetEncTypes,
		SignatureType:    ivnp.SigningEdDSASHA512Ed25519,
		SessionOptions:   sessionOptions,
	})
	if err != nil {
		return nil, err
	}
	if err = network.Start(ctx); err != nil {
		network.Close()
		return nil, err
	}
	listener, err := network.ListenI2P(ctx, fmt.Sprintf(":%d", streamProbePort))
	if err != nil {
		network.Close()
		return nil, err
	}
	endpoint := &trafficEndpoint{
		name: name, address: address, network: network, listener: listener,
		eepsiteBody: "ivnp-eepsite:" + runID + ":" + name,
		done:        make(chan struct{}),
	}
	go endpoint.serveEepsite()
	return endpoint, nil
}
func (e *trafficEndpoint) serveEepsite() {
	defer close(e.done)
	server := http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/ivnp-probe" {
			http.NotFound(writer, request)
			return
		}
		size, err := strconv.Atoi(request.URL.Query().Get("size"))
		body := e.probeBody(size)
		if err != nil || len(body) == 0 {
			http.Error(writer, "invalid probe size", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	})}
	_ = server.Serve(e.listener)
}

func (e *trafficEndpoint) probeBody(size int) []byte {
	if size < 1 || size > maxStreamProbeSize || len(e.eepsiteBody) == 0 {
		return nil
	}
	body := make([]byte, size)
	pattern := []byte(e.eepsiteBody)
	for offset := 0; offset < len(body); {
		offset += copy(body[offset:], pattern)
	}
	return body
}

func (e *trafficEndpoint) Close() {
	if e == nil {
		return
	}
	_ = e.listener.Close()
	_ = e.network.Close()
	select {
	case <-e.done:
	case <-time.After(5 * time.Second):
	}
}

func (r *trafficRunner) ProbeAll(ctx context.Context) []probeResult {
	results := make([]probeResult, len(requiredDirections)+2)
	var group sync.WaitGroup
	for index, route := range requiredDirections {
		group.Add(1)
		go func() {
			probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			defer group.Done()
			r.sequenceMu.Lock()
			sequence := r.sequence[route.name] + 1
			r.sequence[route.name] = sequence
			r.sequenceMu.Unlock()
			size := probeSizes[(sequence-1)%uint64(len(probeSizes))]
			started := time.Now()
			err := r.probeStream(probeCtx, route, sequence, size)
			results[index] = probeResult{Direction: route.name + "-eepsite", Sequence: sequence, Size: size, Duration: time.Since(started), Err: err}
		}()
	}
	for index, style := range []string{"DATAGRAM", "RAW"} {
		group.Go(func() {
			probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			started := time.Now()
			payload := []byte(fmt.Sprintf("%s:%s:%d", r.runID, style, time.Now().UnixNano()))
			err := r.udp.probeUDP(probeCtx, style, payload)
			results[len(requiredDirections)+index] = probeResult{Direction: "ivnp-" + strings.ToLower(style) + "-udp-loopback", Sequence: 1, Size: len(payload), Duration: time.Since(started), Err: err}
		})
	}
	group.Wait()
	return results
}

// ProbeInitial isolates first-use tunnel and LeaseSet establishment for each
// protocol path. Every operation gets its own 30-second budget and a fresh
// stream; sustained concurrency is exercised separately by RunStreamLoad.
func (r *trafficRunner) ProbeInitial(ctx context.Context) []probeResult {
	results := make([]probeResult, 0, len(requiredDirections)+2)
	for _, route := range requiredDirections {
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		r.sequenceMu.Lock()
		sequence := r.sequence[route.name] + 1
		r.sequence[route.name] = sequence
		r.sequenceMu.Unlock()
		size := probeSizes[(sequence-1)%uint64(len(probeSizes))]
		started := time.Now()
		err := r.probeStream(probeCtx, route, sequence, size)
		cancel()
		results = append(results, probeResult{
			Direction: route.name + "-eepsite", Sequence: sequence, Size: size,
			Duration: time.Since(started), Err: err,
		})
	}
	for _, style := range []string{"DATAGRAM", "RAW"} {
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		started := time.Now()
		payload := []byte(fmt.Sprintf("%s:%s:%d", r.runID, style, time.Now().UnixNano()))
		err := r.udp.probeUDP(probeCtx, style, payload)
		cancel()
		results = append(results, probeResult{
			Direction: "ivnp-" + strings.ToLower(style) + "-udp-loopback",
			Sequence:  1, Size: len(payload), Duration: time.Since(started), Err: err,
		})
	}
	return results
}

type probeResult struct {
	Direction string
	Sequence  uint64
	Size      int
	Duration  time.Duration
	Err       error
}
type loadResult struct {
	StartedUTC          time.Time         `json:"started_utc"`
	DurationSeconds     float64           `json:"duration_seconds"`
	WindowSeconds       float64           `json:"window_seconds"`
	Concurrency         int               `json:"concurrency"`
	TargetBytesPerSec   uint64            `json:"target_bytes_per_second"`
	OfferedBytes        uint64            `json:"offered_bytes"`
	CompletedBytes      uint64            `json:"completed_bytes"`
	OfferedOperations   uint64            `json:"offered_operations"`
	CompletedOperations uint64            `json:"completed_operations"`
	FailedOperations    uint64            `json:"failed_operations"`
	Errors              map[string]uint64 `json:"errors,omitempty"`
	P50Milliseconds     int64             `json:"p50_milliseconds"`
	P95Milliseconds     int64             `json:"p95_milliseconds"`
	P99Milliseconds     int64             `json:"p99_milliseconds"`
}

func (r *trafficRunner) RunStreamLoad(ctx context.Context, duration time.Duration, concurrency int, targetBytesPerSecond uint64) loadResult {
	return r.runStreamLoad(ctx, duration, concurrency, targetBytesPerSecond, requiredDirections[:])
}

func (r *trafficRunner) runStreamLoad(ctx context.Context, duration time.Duration, concurrency int, targetBytesPerSecond uint64, routes []direction) loadResult {
	const payloadSize = 16 << 10
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 24 {
		concurrency = 24
	}
	if targetBytesPerSecond < payloadSize {
		targetBytesPerSecond = payloadSize
	}
	result := loadResult{
		StartedUTC: time.Now().UTC(), WindowSeconds: duration.Seconds(), Concurrency: concurrency,
		TargetBytesPerSec: targetBytesPerSecond, Errors: make(map[string]uint64),
	}
	started := time.Now()
	jobs := make(chan direction, concurrency*2)
	var mu sync.Mutex
	seconds := max(int64(duration/time.Second), 1)
	latencies := make([]time.Duration, 0, int(targetBytesPerSecond*uint64(seconds)/payloadSize))
	var workers sync.WaitGroup
	for range concurrency {
		workers.Go(func() {
			for route := range jobs {
				probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
				r.sequenceMu.Lock()
				sequence := r.sequence[route.name] + 1
				r.sequence[route.name] = sequence
				r.sequenceMu.Unlock()
				operationStarted := time.Now()
				err := r.probeStream(probeCtx, route, sequence, payloadSize)
				cancel()
				latency := time.Since(operationStarted)
				mu.Lock()
				if err == nil {
					result.CompletedOperations++
					result.CompletedBytes += payloadSize
					latencies = append(latencies, latency)
				} else {
					result.FailedOperations++
					result.Errors[err.Error()]++
				}
				mu.Unlock()
			}
		})
	}
	interval := max(time.Duration(uint64(time.Second)*payloadSize/targetBytesPerSecond), 5*time.Millisecond)
	ticker := time.NewTicker(interval)
	timer := time.NewTimer(duration)
	routeIndex := 0
	dropped := uint64(0)
schedule:
	for {
		select {
		case <-ctx.Done():
			break schedule
		case <-timer.C:
			break schedule
		case <-ticker.C:
			route := routes[routeIndex%len(routes)]
			routeIndex++
			result.OfferedOperations++
			result.OfferedBytes += payloadSize
			select {
			case jobs <- route:
			default:
				dropped++
			}
		}
	}
	ticker.Stop()
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	close(jobs)
	workers.Wait()
	result.FailedOperations += dropped
	if dropped != 0 {
		result.Errors["scheduler queue full"] += dropped
	}
	result.DurationSeconds = time.Since(started).Seconds()
	slices.Sort(latencies)
	result.P50Milliseconds = percentileLatency(latencies, 50).Milliseconds()
	result.P95Milliseconds = percentileLatency(latencies, 95).Milliseconds()
	result.P99Milliseconds = percentileLatency(latencies, 99).Milliseconds()
	return result
}

func percentileLatency(values []time.Duration, percentile int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	index := min(max((len(values)*percentile+99)/100, 1), len(values))
	return values[index-1]
}

func (r *trafficRunner) probeStream(ctx context.Context, route direction, sequence uint64, size int) error {
	source := r.endpoints[route.from]
	target := r.endpoints[route.to]
	if source == nil || target == nil {
		return errors.New("traffic endpoint unavailable")
	}
	address := net.JoinHostPort(target.network.B32(), strconv.Itoa(streamProbePort))
	connection, err := source.network.DialI2P(ctx, address)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/ivnp-probe?sequence="+strconv.FormatUint(sequence, 10)+"&size="+strconv.Itoa(size), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Connection", "close")
	if err = request.Write(connection); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxStreamProbeSize+1))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("eepsite HTTP status = %d", response.StatusCode)
	}
	expected := target.probeBody(size)
	if len(body) != len(expected) || !bytes.Equal(body, expected) {
		return fmt.Errorf("eepsite body mismatch: got %d bytes, want %d", len(body), len(expected))
	}
	return nil
}

func (r *trafficRunner) RestartIVNP(ctx context.Context, address string) error {
	udpAddress := ""
	if r.udp != nil {
		udpAddress = r.udp.udpAddress
		r.udp.Close()
		r.udp = nil
	}
	for _, name := range []string{"ivnp-client", "ivnp-site"} {
		if current := r.endpoints[name]; current != nil {
			current.Close()
		}
		endpoint, err := startTrafficEndpoint(ctx, r.runID+"-restart", name, address)
		if err != nil {
			return err
		}
		r.endpoints[name] = endpoint
	}
	var err error
	r.udp, err = newSAMMessageProbes(ctx, address, udpAddress, r.runID+"-restart")
	return err
}

func (r *trafficRunner) Close() {
	if r == nil {
		return
	}
	if r.udp != nil {
		r.udp.Close()
	}
	for _, endpoint := range r.endpoints {
		endpoint.Close()
	}
}

func safeSAMID(value string) string {
	var builder strings.Builder
	for _, character := range value {
		safeSAMIDSelected := (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
		if !safeSAMIDSelected {
			safeSAMIDSelected = character == '-'
		}
		if safeSAMIDSelected {
			builder.WriteRune(character)
		}
	}
	result := builder.String()
	if len(result) > 48 {
		result = result[:48]
	}
	return result
}

type samControl struct {
	conn   net.Conn
	reader *bufio.Reader
	udp    *net.UDPConn
	id     string
	public string
}

type samMessagePair struct {
	style    string
	sender   *samControl
	receiver *samControl
}

type samMessageProbes struct {
	samAddress string
	udpAddress string
	runID      string
	ingress    *net.UDPConn
	datagram   *samMessagePair
	raw        *samMessagePair
}

func newSAMMessageProbes(ctx context.Context, address, udpAddress, runID string) (*samMessageProbes, error) {
	if udpAddress == "" {
		return nil, errors.New("SAM UDP address is required")
	}
	remote, err := net.ResolveUDPAddr("udp4", udpAddress)
	if err != nil {
		return nil, err
	}
	ingress, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, remote)
	if err != nil {
		return nil, err
	}
	result := &samMessageProbes{samAddress: address, udpAddress: udpAddress, runID: runID, ingress: ingress}
	var group sync.WaitGroup
	group.Add(2)
	var datagramErr, rawErr error
	go func() {
		defer group.Done()
		result.datagram, datagramErr = newSAMMessagePair(ctx, address, "DATAGRAM", safeSAMID(runID+"-dg"))
	}()
	go func() {
		defer group.Done()
		result.raw, rawErr = newSAMMessagePair(ctx, address, "RAW", safeSAMID(runID+"-raw"))
	}()
	group.Wait()
	if datagramErr != nil {
		result.Close()
		return nil, datagramErr
	}
	if rawErr != nil {
		result.Close()
		return nil, rawErr
	}
	return result, nil
}

func newSAMMessagePair(ctx context.Context, address, style, id string) (*samMessagePair, error) {
	session, err := createSAMMessageSession(ctx, address, style, id, true)
	if err != nil {
		return nil, err
	}
	// One SAM message session can send to its own Destination and receive on its
	// configured UDP socket. Separate sender Destinations add two unrelated
	// tunnel pools without expanding the DATAGRAM/RAW ingress contract.
	return &samMessagePair{style: style, sender: session, receiver: session}, nil
}

func createSAMMessageSession(ctx context.Context, address, style, id string, udpDelivery bool) (*samControl, error) {
	private, public, err := generateSAMDestination(ctx, address)
	if err != nil {
		return nil, err
	}
	control, err := openSAMControl(ctx, address)
	if err != nil {
		return nil, err
	}
	if udpDelivery {
		control.udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			control.Close()
			return nil, err
		}
	}
	line := fmt.Sprintf("SESSION CREATE STYLE=%s ID=%s DESTINATION=%s i2cp.leaseSetType=3 i2cp.leaseSetEncType=4", style, id, private)
	if control.udp != nil {
		line += fmt.Sprintf(" HOST=127.0.0.1 PORT=%d", control.udp.LocalAddr().(*net.UDPAddr).Port)
	}
	if style == "RAW" {
		line += " PROTOCOL=18"
	}
	fields, err := control.command(ctx, line, nil)
	if err != nil || fields["RESULT"] != "OK" {
		control.Close()

		if err ==
			nil {
			err = fmt.
				Errorf("SESSION CREATE %s result %q", style, fields["RESULT"])
		}
		return nil, err
	}
	control.id, control.public = id, public
	return control, nil
}

func generateSAMDestination(ctx context.Context, address string) (string, string, error) {
	control, err := openSAMControl(ctx, address)
	if err != nil {
		return "", "", err
	}
	defer control.Close()
	fields, err := control.command(ctx, "DEST GENERATE SIGNATURE_TYPE=7", nil)
	if err != nil {
		return "", "", err
	}
	generateSAMDestinationRejected := (fields["RESULT"] != "" && fields["RESULT"] != "OK") || fields["PRIV"] == ""
	if !generateSAMDestinationRejected {
		generateSAMDestinationRejected = fields["PUB"] == ""
	}
	if generateSAMDestinationRejected {
		return "", "", errors.New("SAM DEST GENERATE returned no key material")
	}
	return fields["PRIV"], fields["PUB"], nil
}

func openSAMControl(ctx context.Context, address string) (*samControl, error) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	control := &samControl{conn: connection, reader: bufio.NewReader(connection)}
	fields, err := control.command(ctx, "HELLO VERSION MIN=3.3 MAX=3.3", nil)
	if err != nil || fields["RESULT"] != "OK" {
		connection.Close()

		if err == nil {
			err = errors.New("SAM 3.3 negotiation failed")
		}
		return nil, err
	}
	return control, nil
}

func (c *samControl) command(ctx context.Context, line string, body []byte) (map[string]string, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(deadline)
	}
	if _, err := io.WriteString(c.conn, line+"\n"); err != nil {
		return nil, err
	}
	if len(body) != 0 {
		if _, err := c.conn.Write(body); err != nil {
			return nil, err
		}
	}
	reply, err := c.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return samFields(reply), nil
}

func samFields(line string) map[string]string {
	fields := make(map[string]string)
	for token := range strings.FieldsSeq(line) {
		key, value, ok := strings.Cut(token, "=")
		if ok {
			fields[strings.ToUpper(key)] = value
		}
	}
	return fields
}

func (p *samMessageProbes) probeUDP(ctx context.Context, style string, payload []byte) error {
	pair := p.datagram
	if style == "RAW" {
		pair = p.raw
	}
	if pair == nil || p.ingress == nil {
		return errors.New("SAM UDP message session unavailable")
	}
	wire := []byte(fmt.Sprintf("3.3 %s %s\n", pair.sender.id, pair.receiver.public))
	wire = append(wire, payload...)
	if deadline, ok := ctx.Deadline(); ok {
		_ = p.ingress.SetWriteDeadline(deadline)
	}
	if _, err := p.ingress.Write(wire); err != nil {
		return err
	}
	return pair.receiveUDP(ctx, payload)
}

func (p *samMessageProbes) ValidateUDPIngress(ctx context.Context) (map[string]uint64, error) {
	malformed := [][]byte{
		[]byte(fmt.Sprintf("3.3 ID=%s %s\nmalformed-id", p.datagram.sender.id, p.datagram.receiver.public)),
		[]byte(fmt.Sprintf("3.3  %s %s\nmalformed-spacing", p.datagram.sender.id, p.datagram.receiver.public)),
		[]byte(fmt.Sprintf("3.3 %s %s\r\nmalformed-cr", p.datagram.sender.id, p.datagram.receiver.public)),
	}
	for _, wire := range malformed {
		if _, err := p.ingress.Write(wire); err != nil {
			return nil, err
		}
		marker := wire[bytes.LastIndexByte(wire, '\n')+1:]
		if p.datagram.receiveUnexpected(marker, 200*time.Millisecond) {
			return nil, errors.New("SAM UDP accepted a malformed strict header")
		}
	}
	wrongRemote, err := net.ResolveUDPAddr("udp4", p.udpAddress)
	if err != nil {
		return nil, err
	}
	wrong, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")}, wrongRemote)
	if err != nil {
		return nil, fmt.Errorf("bind wrong-source SAM UDP probe: %w", err)
	}
	marker := []byte("wrong-source-must-not-arrive")
	wire := append([]byte(fmt.Sprintf("3.3 %s %s\n", p.datagram.sender.id, p.datagram.receiver.public)), marker...)
	_, writeErr := wrong.Write(wire)
	_ = wrong.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if p.datagram.receiveUnexpected(marker, 300*time.Millisecond) {
		return nil, errors.New("SAM UDP accepted a source IP different from the control session")
	}

	const floodPackets = 1024
	payload := make([]byte, 8<<10)
	copy(payload, "IVNP-UDP-BACKPRESSURE|")
	offered := uint64(0)
	for sequence := range floodPackets {
		binary.BigEndian.PutUint32(payload[len("IVNP-UDP-BACKPRESSURE|"):], uint32(sequence))
		wire := append([]byte(fmt.Sprintf("3.3 %s %s\n", p.datagram.sender.id, p.datagram.receiver.public)), payload...)
		if _, err = p.ingress.Write(wire); err == nil {
			offered++
		}
	}
	received := p.datagram.drainFlood(ctx, []byte("IVNP-UDP-BACKPRESSURE|"), offered)
	clear(payload)
	if offered < 64 {
		return nil, fmt.Errorf("SAM UDP backpressure offered only %d packets", offered)
	}
	if received >= offered {
		return nil, fmt.Errorf("SAM UDP bounded ingress admitted every flood packet: offered=%d received=%d", offered, received)
	}
	return map[string]uint64{"malformed_rejected": 3, "wrong_source_rejected": 1, "backpressure_offered": offered, "backpressure_delivered": received, "backpressure_rejected": offered - received}, nil
}

func (p *samMessagePair) receiveUDP(ctx context.Context, expected []byte) error {
	if p == nil || p.receiver == nil || p.receiver.udp == nil {
		return errors.New("SAM UDP receive target unavailable")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	buffer := make([]byte, 65535)
	for time.Now().Before(deadline) {
		_ = p.receiver.udp.SetReadDeadline(deadline)
		n, _, err := p.receiver.udp.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		body := buffer[:n]
		if p.style == "DATAGRAM" {
			if split := bytes.Index(body, []byte("\n\n")); split >= 0 {
				body = body[split+2:]
			}
		}
		if bytes.Equal(body, expected) {
			return nil
		}
	}
	return errors.New("SAM UDP expected payload was not delivered")
}

func (p *samMessagePair) receiveUnexpected(marker []byte, timeout time.Duration) bool {
	if p == nil || p.receiver == nil || p.receiver.udp == nil {
		return false
	}
	buffer := make([]byte, 65535)
	_ = p.receiver.udp.SetReadDeadline(time.Now().Add(timeout))
	n, _, err := p.receiver.udp.ReadFromUDP(buffer)
	return err == nil && bytes.Contains(buffer[:n], marker)
}

func (p *samMessagePair) drainFlood(ctx context.Context, marker []byte, offered uint64) uint64 {
	if p == nil || p.receiver == nil || p.receiver.udp == nil {
		return 0
	}
	deadline := time.Now().Add(5 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	buffer := make([]byte, 65535)
	var received uint64
	for received < offered && time.Now().Before(deadline) {
		_ = p.receiver.udp.SetReadDeadline(minTime(deadline, time.Now().Add(100*time.Millisecond)))
		n, _, err := p.receiver.udp.ReadFromUDP(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			break
		}
		if bytes.Contains(buffer[:n], marker) {
			received++
		}
	}
	return received
}

func (p *samMessageProbes) Close() {
	if p == nil {
		return
	}
	if p.ingress != nil {
		_ = p.ingress.Close()
	}
	if p.datagram != nil {
		p.datagram.Close()
	}
	if p.raw != nil {
		p.raw.Close()
	}
}

func (p *samMessagePair) Close() {
	if p == nil {
		return
	}
	if p.sender == p.receiver {
		p.sender.Close()
		return
	}
	p.sender.Close()
	p.receiver.Close()
}

func (c *samControl) Close() {
	if c == nil {
		return
	}
	if c.udp != nil {
		_ = c.udp.Close()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

var _ = sync.Once{}
