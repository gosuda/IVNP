package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	certificationDuration  = time.Hour
	policyVersion          = "one-hour-v1"
	consecutiveFailureMax  = 3
	localUDPStreamScenario = "local-udp-stream"
)

type options struct {
	mode            string
	scope           string
	scenario        string
	durationText    string
	duration        time.Duration
	runID           string
	warmup          time.Duration
	artifacts       string
	binary          string
	config          string
	javaSAM         string
	i2pdASAM        string
	i2pdBSAM        string
	ivnpSAM         string
	ivnpSAMUDP      string
	metricsURL      string
	controlURL      string
	controlToken    string
	javaContainer   string
	i2pdAContainer  string
	i2pdBContainer  string
	javaImage       string
	i2pdImage       string
	builderImage    string
	pinnedRouters   map[string]string
	probeInterval   time.Duration
	sampleInterval  time.Duration
	loadConcurrency int
	loadRate        uint64
	publicEvidence  string
	publicProbeKey  string
	publicHost      string
	loadWindow      time.Duration
}

type processEpoch struct {
	cmd      *exec.Cmd
	exited   chan struct{}
	mu       sync.Mutex
	waitErr  error
	log      *os.File
	label    string
	identity processSample
}

type soakSample struct {
	At         time.Time         `json:"at"`
	Elapsed    float64           `json:"elapsed_seconds"`
	Epoch      string            `json:"epoch"`
	Health     string            `json:"health"`
	Metrics    map[string]uint64 `json:"metrics"`
	Process    processSample     `json:"process"`
	Containers []containerSample `json:"containers"`
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	opts, err := parseOptions(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 2
	}
	recorder, err := newArtifactRecorder(opts.artifacts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: create artifacts:", err)
		return 1
	}
	runID, seed, err := newRunIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: create run identity:", err)
		return 1
	}
	if opts.runID != "" {
		runID = opts.runID
	}
	binaryDigest, err := sha256File(opts.binary)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: hash IVNP binary:", err)
		return 1
	}
	configDigest, err := sha256File(opts.config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: hash IVNP config:", err)
		return 1
	}
	revision, dirty := gitIdentity()
	manifestValue := manifest{
		Schema: artifactSchema, RunID: runID, Mode: opts.mode, Scope: opts.scope, Policy: policyVersion,
		GitRevision: revision, GitDirty: dirty, BinarySHA256: binaryDigest,
		Images:       map[string]string{"java_i2p": opts.javaImage, "i2pd_a": opts.i2pdImage, "i2pd_b": opts.i2pdImage, "builder": opts.builderImage},
		ConfigSHA256: configDigest, GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		Kernel: kernelRelease(), CPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), Seed: seed,
		Endpoints:        map[string]string{"java_sam": opts.javaSAM, "i2pd_a_sam": opts.i2pdASAM, "i2pd_b_sam": opts.i2pdBSAM, "ivnp_sam": opts.ivnpSAM, "ivnp_sam_udp": opts.ivnpSAMUDP, "metrics": opts.metricsURL, "control": opts.controlURL},
		RequestedSeconds: int64(opts.duration / time.Second), StartedUTC: time.Now().UTC(),
	}
	_ = writeAtomicJSON(filepath.Join(opts.artifacts, "manifest.json"), manifestValue)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	verdict, reason := "fail", "run did not complete"
	e5 := "not_run"
	criteria := []criterion{}
	var traffic *trafficRunner
	var daemon *processEpoch
	measured := time.Duration(0)
	sampleCount := 0
	restartVerified := false
	failureStatus := "fail"

	defer func() {
		if traffic != nil {
			traffic.Close()
		}
		if daemon != nil {
			_ = stopProcess(daemon, 30*time.Second)
		}
		manifestValue.MeasuredSeconds = measured.Seconds()
		manifestValue.RestartVerified = restartVerified
		_ = writeAtomicJSON(filepath.Join(opts.artifacts, "manifest.json"), manifestValue)
		if opts.mode == "smoke" && verdict == "smoke_pass" {
			e5 = "not_run"
		}
		criteria = append(criteria, criterion{
			ID: "E-5-one-hour", Status: e5, Scope: opts.scope,
			Assertion: "one contiguous measured interval of at least 3600 monotonic seconds with scope-appropriate reachability plus all publication, tunnel, vector-I/O, process, hard-failure, traffic, and restart gates passing",
			Observed:  map[string]any{"scope": opts.scope, "measured_seconds": measured.Seconds(), "samples": sampleCount, "restart_verified": restartVerified},
			Policy:    policyVersion, Evidence: []string{"events.jsonl", "samples.jsonl", "ivnp-first.log", "ivnp-restart.log"},
			Limitations: []string{"local scope is pinned topology evidence, not public forwarding or zero-configuration proof", "finite-run evidence does not prove universal absence of loss, leaks, or crashes"},
		})
		_ = recorder.close()
		captureContainerLog(opts.javaContainer, filepath.Join(opts.artifacts, "java-i2p.log"))
		captureContainerLog(opts.i2pdAContainer, filepath.Join(opts.artifacts, "i2pd-a.log"))
		captureContainerLog(opts.i2pdBContainer, filepath.Join(opts.artifacts, "i2pd-b.log"))
		_ = writeAtomicJSON(filepath.Join(opts.artifacts, "summary.json"), summary{Schema: artifactSchema, RunID: runID, Mode: opts.mode, Scope: opts.scope, Verdict: verdict, E5OneHour: e5, Reason: reason, Criteria: criteria})
		_ = writeChecksums(opts.artifacts)
	}()

	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		reason = "authoritative vector-I/O harness requires linux/amd64"
		failureStatus = "not_run"
		verdict = failureStatus
		fmt.Fprintln(os.Stderr, "ERROR:", reason)
		return 1
	}
	if runtime.NumCPU() < 4 {
		reason = "authoritative vector-I/O harness requires at least four logical CPUs"
		failureStatus = "not_run"
		verdict = failureStatus
		fmt.Fprintln(os.Stderr, "ERROR:", reason)
		return 1
	}
	allocationContext, allocationCancel := context.WithTimeout(ctx, 10*time.Minute)
	err = runAllocationPreflight(allocationContext, opts.artifacts, binaryDigest)
	allocationCancel()
	if err != nil {
		reason = "allocation preflight: " + err.Error()
		verdict = "not_run"
		fmt.Fprintln(os.Stderr, "ERROR:", reason)
		return 1
	}
	if err = nativeRoutersReady(ctx, opts); err != nil {
		reason = err.Error()
		failureStatus = "not_run"
		verdict = failureStatus
		fmt.Fprintln(os.Stderr, "ERROR:", reason)
		return 1
	}
	if err = recorder.writeEvent(event{At: time.Now().UTC(), Type: "native_routers_ready", Fields: map[string]any{"scope": opts.scope, "pinned_routers": opts.pinnedRouters}}); err != nil {
		reason = err.Error()
		return 1
	}

	daemon, err = startProcess(opts, "first", opts.artifacts)
	if err != nil {
		reason = "start IVNP: " + err.Error()
		verdict = "not_run"
		fmt.Fprintln(os.Stderr, "ERROR:", reason)
		return 1
	}
	if err = waitForReadiness(ctx, opts, daemon, recorder); err != nil {
		reason = err.Error()
		if processExited(daemon) {
			failureStatus = "fail"
		} else {
			failureStatus = "not_run"
		}
		verdict = failureStatus
		fmt.Fprintln(os.Stderr, "ERROR:", reason)
		return 1
	}
	initialDest, err := defaultDestination(ctx, opts)
	if err != nil {
		reason = "read default destination: " + err.Error()
		verdict = "not_run"
		fmt.Fprintln(os.Stderr, "ERROR:", reason)
		return 1
	}
	initialRouterHash, err := routerIdentity(ctx, opts)
	if err != nil {
		reason = "read public router identity: " + err.Error()
		verdict = "not_run"
		return 1
	}
	if opts.scope == "public" {
		request := map[string]any{
			"schema": "ivnp.public-probe-request/v1", "run_id": runID, "router_hash": initialRouterHash,
			"tcp_endpoint": net.JoinHostPort(opts.publicHost, "29442"), "udp_endpoint": net.JoinHostPort(opts.publicHost, "29443"),
			"evidence_path": opts.publicEvidence,
		}
		if err = writeAtomicJSON(filepath.Join(opts.artifacts, "public-probe-request.json"), request); err != nil {
			reason = "write public probe request: " + err.Error()
			verdict = "not_run"
			return 1
		}
	}
	_, protocolBaseline, err := scrapeMetrics(ctx, opts.metricsURL)
	if err != nil {
		reason = "capture protocol baseline: " + err.Error()
		verdict = "not_run"
		return 1
	}
	_ = recorder.writeEvent(event{At: time.Now().UTC(), Type: "native_session_tunnel_policy", Fields: map[string]any{
		"router_hash": initialRouterHash, "inbound_length": 1, "outbound_length": 1,
		"inbound_quantity": 1, "outbound_quantity": 1, "inbound_backup_quantity": 0, "outbound_backup_quantity": 0,
	}})
	trafficCtx, trafficCancel := context.WithTimeout(ctx, opts.warmup)
	if opts.scenario == localUDPStreamScenario {
		traffic, err = newLocalTrafficRunner(trafficCtx, runID, opts.ivnpSAM, opts.ivnpSAMUDP)
	} else {
		traffic, err = newTrafficRunner(trafficCtx, runID, map[string]string{"java": opts.javaSAM, "i2pd-a": opts.i2pdASAM, "i2pd-b": opts.i2pdBSAM, "ivnp": opts.ivnpSAM}, opts.ivnpSAMUDP)
	}
	trafficCancel()
	if err != nil {
		reason = "create black-box SAM traffic: " + err.Error()
		verdict = "not_run"
		fmt.Fprintln(os.Stderr, "ERROR:", reason)
		return 1
	}
	if opts.scenario == localUDPStreamScenario {
		if err = runLocalUDPStreamDiagnostic(ctx, opts, traffic, recorder); err != nil {
			reason = err.Error()
			verdict = "fail"
			fmt.Fprintln(os.Stderr, "ERROR:", reason)
			return 1
		}
		verdict, reason = "smoke_pass", "LOCAL_UDP_STREAM_PASS"
		fmt.Println(reason)
		return 0
	}
	if err = waitForInitialTraffic(ctx, opts, traffic, recorder); err != nil {
		reason = err.Error()
		verdict = "not_run"
		fmt.Fprintln(os.Stderr, "ERROR:", reason)
		return 1
	}
	udpValidationCtx, udpValidationCancel := context.WithTimeout(ctx, 90*time.Second)
	udpValidation, udpValidationErr := validateSAMUDPWithMetrics(udpValidationCtx, opts.metricsURL, traffic.udp)
	udpValidationCancel()
	if udpValidationErr != nil {
		reason = "SAM UDP ingress validation: " + udpValidationErr.Error()
		verdict = "not_run"
		return 1
	}
	_ = recorder.writeEvent(event{At: time.Now().UTC(), Type: "sam_udp_validation", Fields: map[string]any{"epoch": "first", "result": udpValidation}})
	loadCtx, loadCancel := context.WithTimeout(ctx, opts.loadWindow+2*time.Minute)
	initialLoad := traffic.RunStreamLoad(loadCtx, opts.loadWindow, opts.loadConcurrency, opts.loadRate)
	loadCancel()
	if err = evaluateLoad(initialLoad); err != nil {
		reason = "initial STREAM load: " + err.Error()
		verdict = "not_run"
		return 1
	}
	_ = recorder.writeEvent(event{At: time.Now().UTC(), Type: "stream_load", Fields: map[string]any{"epoch": "first", "result": initialLoad}})
	if opts.scope == "local" {
		if err = waitForPinnedConnectivity(ctx, opts, daemon, recorder); err != nil {
			reason = err.Error()
			verdict = "not_run"
			fmt.Fprintln(os.Stderr, "ERROR:", reason)
			return 1
		}
	}

	manifestValue.MeasurementStartUTC = time.Now().UTC()
	measurementStart := time.Now()
	_ = writeAtomicJSON(filepath.Join(opts.artifacts, "manifest.json"), manifestValue)
	_ = recorder.writeEvent(event{At: manifestValue.MeasurementStartUTC, Type: "measurement_started", Fields: map[string]any{"required_seconds": opts.duration.Seconds()}})
	_, baselineMetrics, err := scrapeMetrics(ctx, opts.metricsURL)
	if err != nil {
		reason = err.Error()
		return 1
	}
	var samples []soakSample
	if err = checkHardCounters(baselineMetrics, baselineMetrics); err != nil {
		reason = err.Error()
		verdict = "fail"
		return 1
	}
	initialSample, err := collectSample(ctx, opts, daemon, measurementStart)
	if err != nil {
		reason = err.Error()
		verdict = "fail"
		return 1
	}
	samples = append(samples, initialSample)
	sampleCount++
	if err = recorder.writeSample(initialSample); err != nil {
		reason = "write initial sample: " + err.Error()
		return 1
	}
	failureCounts := make(map[string]int)
	probeTicker := time.NewTicker(opts.probeInterval)
	sampleTicker := time.NewTicker(opts.sampleInterval)
	defer probeTicker.Stop()
	defer sampleTicker.Stop()

	for time.Since(measurementStart) < opts.duration {
		select {
		case <-ctx.Done():
			measured = time.Since(measurementStart)
			reason = "measurement interrupted: " + ctx.Err().Error()
			verdict = "inconclusive"
			return 1
		case <-daemon.exited:
			measured = time.Since(measurementStart)
			reason = fmt.Sprintf("IVNP exited during measurement: %v", daemon.exitError())
			verdict = "fail"
			daemon = nil
			return 1
		case <-probeTicker.C:
			probeCtx, probeCancel := context.WithTimeout(ctx, opts.loadWindow+2*time.Minute)
			load := traffic.RunStreamLoad(probeCtx, opts.loadWindow, opts.loadConcurrency, opts.loadRate)
			results := traffic.ProbeAll(probeCtx)
			probeCancel()
			if loadErr := evaluateLoad(load); loadErr != nil {
				measured = time.Since(measurementStart)
				reason = "STREAM load gate: " + loadErr.Error()
				verdict = "fail"
				return 1
			}
			_ = recorder.writeEvent(event{At: time.Now().UTC(), Elapsed: time.Since(measurementStart).Seconds(), Type: "stream_load", Fields: map[string]any{"epoch": daemon.label, "result": load}})
			for _, result := range results {
				fields := map[string]any{"direction": result.Direction, "sequence": result.Sequence, "bytes": result.Size, "duration_ms": result.Duration.Milliseconds()}
				if result.Err != nil {
					fields["error"] = result.Err.Error()
					failureCounts[result.Direction]++
				} else {
					failureCounts[result.Direction] = 0
				}
				_ = recorder.writeEvent(event{At: time.Now().UTC(), Elapsed: time.Since(measurementStart).Seconds(), Type: "traffic_probe", Fields: fields})
				if failureCounts[result.Direction] >= consecutiveFailureMax {
					measured = time.Since(measurementStart)
					reason = fmt.Sprintf("%s failed %d consecutive probes: %v", result.Direction, failureCounts[result.Direction], result.Err)
					verdict = "fail"
					return 1
				}
			}
		case <-sampleTicker.C:
			sample, sampleErr := collectSample(ctx, opts, daemon, measurementStart)
			if sampleErr != nil {
				measured = time.Since(measurementStart)
				reason = sampleErr.Error()
				verdict = "fail"
				return 1
			}
			if !sample.Containers[0].Running || !sample.Containers[1].Running || !sample.Containers[2].Running {
				measured = time.Since(measurementStart)
				reason = "native router exited during measurement"
				verdict = "inconclusive"
				return 1
			}
			if missing := readinessMissingForScope(opts.scope, sample.Health, sample.Metrics); len(missing) != 0 {
				measured = time.Since(measurementStart)
				reason = "IVNP readiness regressed: " + strings.Join(missing, ", ")
				verdict = "fail"
				return 1
			}
			if err = checkHardCounters(baselineMetrics, sample.Metrics); err != nil {
				measured = time.Since(measurementStart)
				reason = err.Error()
				verdict = "fail"
				return 1
			}
			samples = append(samples, sample)
			sampleCount++
			if err = recorder.writeSample(sample); err != nil {
				measured = time.Since(measurementStart)
				reason = "write sample: " + err.Error()
				return 1
			}
		}
	}
	measured = time.Since(measurementStart)
	manifestValue.MeasurementEndUTC = time.Now().UTC()
	_ = recorder.writeEvent(event{At: manifestValue.MeasurementEndUTC, Elapsed: measured.Seconds(), Type: "measurement_completed"})
	if measured < opts.duration {
		reason = "measured interval shorter than requested duration"
		verdict = "fail"
		return 1
	}
	time.Sleep(2 * time.Second)
	_, finalMetrics, finalErr := scrapeMetrics(ctx, opts.metricsURL)
	if finalErr != nil {
		reason = "final metric scrape: " + finalErr.Error()
		verdict = "fail"
		return 1
	}
	if err = checkHardCounters(baselineMetrics, finalMetrics); err != nil {
		reason = err.Error()
		verdict = "fail"
		return 1
	}
	if err = checkFinalEvidence(protocolBaseline, finalMetrics); err != nil {
		reason = err.Error()
		verdict = "fail"
		return 1
	}
	allocationTrend, allocationErr := evaluateAllocationTrend(samples)
	if allocationErr != nil {
		reason = allocationErr.Error()
		verdict = "fail"
		return 1
	}
	_ = recorder.writeEvent(event{At: time.Now().UTC(), Elapsed: measured.Seconds(), Type: "allocation_gc_trend", Fields: allocationTrend})
	if opts.scope == "public" {
		if err = validatePublicProbeEvidence(opts.publicEvidence, opts.publicProbeKey, runID, initialRouterHash, opts.publicHost, opts.artifacts, manifestValue.MeasurementStartUTC, manifestValue.MeasurementEndUTC); err != nil {
			reason = err.Error()
			verdict = "fail"
			return 1
		}
		_ = recorder.writeEvent(event{At: time.Now().UTC(), Type: "public_reachability_verified", Fields: map[string]any{"run_id": runID, "router_hash": initialRouterHash, "tcp_endpoint": net.JoinHostPort(opts.publicHost, "29442"), "udp_endpoint": net.JoinHostPort(opts.publicHost, "29443")}})
	}
	if opts.mode == "certify" {
		expected := int(opts.duration / opts.sampleInterval)
		if expected > 0 && sampleCount*100 < expected*99 {
			reason = fmt.Sprintf("sample coverage below 99%%: got %d, expected at least %d", sampleCount, expected)
			verdict = "fail"
			return 1
		}
		if err = evaluateResources(samples, opts.duration); err != nil {
			reason = err.Error()
			verdict = "fail"
			return 1
		}
	}

	if err = stopProcess(daemon, 30*time.Second); err != nil {
		reason = "graceful IVNP stop: " + err.Error()
		verdict = "fail"
		return 1
	}
	daemon = nil
	daemon, err = startProcess(opts, "restart", opts.artifacts)
	if err != nil {
		reason = "restart IVNP: " + err.Error()
		verdict = "fail"
		return 1
	}
	if err = waitForReadiness(ctx, opts, daemon, recorder); err != nil {
		reason = "restart readiness: " + err.Error()
		verdict = "fail"
		return 1
	}
	restartedDest, err := defaultDestination(ctx, opts)
	if err != nil || restartedDest != initialDest {
		reason = fmt.Sprintf("default destination identity changed across restart: before=%s after=%s error=%v", initialDest, restartedDest, err)
		verdict = "fail"
		return 1
	}
	restartedRouterHash, identityErr := routerIdentity(ctx, opts)
	if identityErr != nil || restartedRouterHash != initialRouterHash {
		reason = fmt.Sprintf("router identity changed across restart: before=%s after=%s error=%v", initialRouterHash, restartedRouterHash, identityErr)
		verdict = "fail"
		return 1
	}
	restartCtx, restartCancel := context.WithTimeout(ctx, opts.warmup)
	err = traffic.RestartIVNP(restartCtx, opts.ivnpSAM)
	restartCancel()
	if err != nil {
		reason = "restore IVNP SAM probes after restart: " + err.Error()
		verdict = "fail"
		return 1
	}
	if opts.scope == "local" {
		if err = waitForPinnedConnectivity(ctx, opts, daemon, recorder); err != nil {
			reason = "restart local connectivity: " + err.Error()
			verdict = "fail"
			return 1
		}
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 2*time.Minute)
	results := traffic.ProbeAll(probeCtx)
	probeCancel()
	for _, result := range results {
		if result.Err != nil {
			reason = fmt.Sprintf("post-restart %s probe failed: %v", result.Direction, result.Err)
			verdict = "fail"
			return 1
		}
	}
	restartUDPContext, restartUDPCancel := context.WithTimeout(ctx, 90*time.Second)
	restartUDP, restartUDPErr := validateSAMUDPWithMetrics(restartUDPContext, opts.metricsURL, traffic.udp)
	restartUDPCancel()
	if restartUDPErr != nil {
		reason = "post-restart SAM UDP ingress validation: " + restartUDPErr.Error()
		verdict = "fail"
		return 1
	}
	_ = recorder.writeEvent(event{At: time.Now().UTC(), Type: "sam_udp_validation", Fields: map[string]any{"epoch": "restart", "result": restartUDP}})
	restartLoadCtx, restartLoadCancel := context.WithTimeout(ctx, opts.loadWindow+2*time.Minute)
	restartLoad := traffic.RunStreamLoad(restartLoadCtx, opts.loadWindow, opts.loadConcurrency, opts.loadRate)
	restartLoadCancel()
	if err = evaluateLoad(restartLoad); err != nil {
		reason = "post-restart STREAM load: " + err.Error()
		verdict = "fail"
		return 1
	}
	_ = recorder.writeEvent(event{At: time.Now().UTC(), Type: "stream_load", Fields: map[string]any{"epoch": "restart", "result": restartLoad}})
	restartVerified = true
	_ = recorder.writeEvent(event{At: time.Now().UTC(), Type: "restart_verified", Fields: map[string]any{"default_destination": initialDest}})
	criteria = append(criteria, criterion{ID: "restart-under-live-load", Status: "pass", Scope: opts.scope, Assertion: "same binary/state/default destination restored and all traffic directions resumed while native routers remained live", Observed: map[string]any{"default_destination": initialDest}, Policy: policyVersion, Evidence: []string{"events.jsonl", "ivnp-restart.log"}})

	if opts.mode == "certify" {
		if measured < certificationDuration {
			reason = "certification interval was less than 3600 monotonic seconds"
			verdict = "fail"
			return 1
		}
		if opts.scope == "local" {
			verdict, e5, reason = "pass", "local_pass", "E5_ONE_HOUR_LOCAL_PASS"
			fmt.Println("E5_ONE_HOUR_LOCAL_PASS")
		} else {
			verdict, e5, reason = "pass", "public_pass", "PUBLIC_PASS"
			fmt.Println("PUBLIC_PASS")
		}
	} else {
		verdict, e5, reason = "smoke_pass", "not_run", "SMOKE_PASS"
		fmt.Println("SMOKE_PASS")
	}
	return 0
}

func runLocalUDPStreamDiagnostic(ctx context.Context, opts options, traffic *trafficRunner, recorder *artifactRecorder) error {
	route := direction{name: "ivnp-client-to-ivnp-site", from: "ivnp-client", to: "ivnp-site"}
	deadline := time.Now().Add(opts.warmup)
	var streamErr error
	for attempt := uint64(1); time.Now().Before(deadline); attempt++ {
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		started := time.Now()
		streamErr = traffic.probeStream(probeCtx, route, attempt, 1024)
		cancel()
		fields := map[string]any{"direction": route.name, "sequence": attempt, "bytes": 1024, "duration_ms": time.Since(started).Milliseconds()}
		if streamErr != nil {
			fields["error"] = streamErr.Error()
		}
		if err := recorder.writeEvent(event{At: time.Now().UTC(), Type: "local_stream_baseline", Fields: fields}); err != nil {
			return err
		}
		if streamErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if streamErr != nil {
		return fmt.Errorf("local STREAM baseline: %w", streamErr)
	}
	for _, style := range []string{"DATAGRAM", "RAW"} {
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		payload := []byte("pre-flood-" + strings.ToLower(style))
		started := time.Now()
		err := traffic.udp.probeUDP(probeCtx, style, payload)
		cancel()
		fields := map[string]any{"style": style, "phase": "before_flood", "bytes": len(payload), "duration_ms": time.Since(started).Milliseconds()}
		if err != nil {
			fields["error"] = err.Error()
		}
		if writeErr := recorder.writeEvent(event{At: time.Now().UTC(), Type: "local_udp_probe", Fields: fields}); writeErr != nil {
			return writeErr
		}
		if err != nil {
			return fmt.Errorf("%s before flood: %w", style, err)
		}
	}
	udpCtx, cancelUDP := context.WithTimeout(ctx, 90*time.Second)
	udpValidation, err := validateSAMUDPWithMetrics(udpCtx, opts.metricsURL, traffic.udp)
	cancelUDP()
	if err != nil {
		return fmt.Errorf("SAM UDP ingress validation: %w", err)
	}
	floodFinished := time.Now()
	if err = recorder.writeEvent(event{At: floodFinished.UTC(), Type: "sam_udp_validation", Fields: map[string]any{"epoch": "focused", "result": udpValidation}}); err != nil {
		return err
	}
	loadCtx, cancelLoad := context.WithTimeout(ctx, opts.loadWindow+2*time.Minute)
	load := traffic.runStreamLoad(loadCtx, opts.loadWindow, opts.loadConcurrency, opts.loadRate, []direction{route})
	cancelLoad()
	if err = recorder.writeEvent(event{At: time.Now().UTC(), Type: "stream_load", Fields: map[string]any{
		"epoch": "immediate_after_udp_flood", "udp_to_stream_gap_ms": load.StartedUTC.Sub(floodFinished.UTC()).Milliseconds(), "result": load,
	}}); err != nil {
		return err
	}
	if err = evaluateLoad(load); err != nil {
		return fmt.Errorf("STREAM load immediately after SAM UDP flood: %w", err)
	}
	for _, style := range []string{"DATAGRAM", "RAW"} {
		for sequence := range 2 {
			probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
			payload := []byte(fmt.Sprintf("post-flood-%s-%d", strings.ToLower(style), sequence))
			started := time.Now()
			probeErr := traffic.udp.probeUDP(probeCtx, style, payload)
			cancel()
			fields := map[string]any{"style": style, "phase": "after_stream_load", "sequence": sequence, "bytes": len(payload), "duration_ms": time.Since(started).Milliseconds()}
			if probeErr != nil {
				fields["error"] = probeErr.Error()
			}
			if writeErr := recorder.writeEvent(event{At: time.Now().UTC(), Type: "local_udp_probe", Fields: fields}); writeErr != nil {
				return writeErr
			}
			if probeErr != nil {
				return fmt.Errorf("%s after STREAM load %d: %w", style, sequence, probeErr)
			}
		}
	}
	return nil
}

func parseOptions(args []string) (options, error) {
	var opts options
	var pinnedRouterText string
	flags := flag.NewFlagSet("ivnp-soak", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.mode, "mode", "", "smoke or certify")
	flags.StringVar(&opts.scenario, "scenario", "", "focused diagnostic scenario")
	flags.StringVar(&opts.scope, "scope", "", "local or public certification scope")
	flags.StringVar(&opts.durationText, "duration", "", "smoke measurement duration")
	flags.StringVar(&opts.runID, "run-id", "", "externally coordinated 32-hex-character run identity")
	flags.DurationVar(&opts.warmup, "warmup-timeout", 30*time.Minute, "router and tunnel warm-up timeout")
	flags.StringVar(&opts.artifacts, "artifacts", "", "retained artifact directory")
	flags.StringVar(&opts.binary, "ivnp-binary", "", "once-built IVNP binary")
	flags.StringVar(&opts.config, "ivnp-config", "", "IVNP production override config")
	flags.StringVar(&opts.javaSAM, "java-sam", "127.0.0.1:7656", "Java I2P SAM address")
	flags.StringVar(&opts.i2pdASAM, "i2pd-a-sam", "127.0.0.1:27656", "first i2pd SAM address")
	flags.StringVar(&opts.i2pdBSAM, "i2pd-b-sam", "127.0.0.1:28656", "second i2pd SAM address")
	flags.StringVar(&opts.ivnpSAM, "ivnp-sam", "127.0.0.1:37656", "IVNP SAM address")
	flags.StringVar(&opts.ivnpSAMUDP, "ivnp-sam-udp", "127.0.0.1:37655", "IVNP SAM UDP address")
	flags.StringVar(&opts.metricsURL, "metrics-url", "http://127.0.0.1:39090", "IVNP observability base URL")
	flags.StringVar(&opts.controlURL, "control-url", "http://127.0.0.1:37650", "IVNP control base URL")
	flags.StringVar(&opts.controlToken, "control-token-file", "", "file containing IVNP control bearer token")
	flags.StringVar(&opts.javaContainer, "java-container", "", "Java container name")
	flags.StringVar(&opts.i2pdAContainer, "i2pd-a-container", "", "first i2pd container name")
	flags.StringVar(&opts.i2pdBContainer, "i2pd-b-container", "", "second i2pd container name")
	flags.StringVar(&opts.javaImage, "java-image-id", "", "resolved Java image ID")
	flags.StringVar(&opts.i2pdImage, "i2pd-image-id", "", "resolved i2pd image ID")
	flags.StringVar(&opts.publicEvidence, "public-evidence", "", "signed off-host public reachability evidence JSON")
	flags.StringVar(&opts.publicProbeKey, "public-probe-key", "", "base64 Ed25519 public probe verification key")
	flags.StringVar(&opts.publicHost, "public-host", "", "advertised public IPv4 address")
	flags.StringVar(&opts.builderImage, "builder-image-id", "", "resolved builder image ID")
	flags.StringVar(&pinnedRouterText, "pinned-router-hashes", "", "comma-separated java=hash,i2pd-a=hash,i2pd-b=hash")
	flags.DurationVar(&opts.probeInterval, "probe-interval", 30*time.Second, "black-box probe cadence")
	flags.DurationVar(&opts.sampleInterval, "sample-interval", time.Minute, "measurement cadence")
	flags.IntVar(&opts.loadConcurrency, "stream-load-concurrency", 6, "bounded concurrent STREAM workers")
	flags.Uint64Var(&opts.loadRate, "stream-load-rate", 64<<10, "aggregate offered STREAM payload bytes per second")
	flags.DurationVar(&opts.loadWindow, "stream-load-window", 5*time.Second, "STREAM load duration per interval")
	if err := flags.Parse(args); err != nil {
		return opts, err
	}
	if flags.NArg() != 0 {
		return opts, errors.New("unexpected positional arguments")
	}
	if opts.mode != "smoke" && opts.mode != "certify" {
		return opts, errors.New("--mode must be smoke or certify")
	}
	if opts.scenario != "" && opts.scenario != localUDPStreamScenario {
		return opts, errors.New("--scenario must be local-udp-stream")
	}
	if opts.scenario != "" && (opts.mode != "smoke" || opts.scope != "local") {
		return opts, errors.New("--scenario requires --mode smoke --scope local")
	}
	if opts.mode == "certify" {
		if opts.durationText != "" {
			return opts, errors.New("--duration is forbidden in certify mode; the measured interval is fixed at 3600 seconds")
		}
		opts.duration = certificationDuration
	} else {
		if opts.durationText == "" {
			opts.duration = 2 * time.Minute
		} else {
			parsed, err := time.ParseDuration(opts.durationText)
			if err != nil {
				return opts, fmt.Errorf("invalid smoke duration: %w", err)
			}
			opts.duration = parsed
		}
	}
	if opts.runID != "" {
		decoded, decodeErr := hex.DecodeString(opts.runID)
		if decodeErr != nil || len(decoded) != 16 || opts.runID != strings.ToLower(opts.runID) {
			return opts, errors.New("--run-id must be exactly 32 lowercase hexadecimal characters")
		}
	}
	if opts.scope == "public" {
		if opts.publicEvidence == "" || opts.publicProbeKey == "" || net.ParseIP(opts.publicHost) == nil {
			return opts, errors.New("public scope requires --public-evidence, --public-probe-key, and --public-host")
		}
	}
	if opts.scope != "local" && opts.scope != "public" {
		return opts, errors.New("--scope must be local or public")
	}
	if opts.duration <= 0 || opts.warmup <= 0 || opts.probeInterval <= 0 || opts.sampleInterval <= 0 || opts.loadWindow <= 0 {
		return opts, errors.New("durations and intervals must be positive")
	}
	if opts.loadConcurrency < 2 || opts.loadConcurrency > 24 || opts.loadRate < 16<<10 || opts.loadRate > 64<<20 {
		return opts, errors.New("STREAM load policy is outside bounded limits")
	}
	for name, value := range map[string]string{"--artifacts": opts.artifacts, "--ivnp-binary": opts.binary, "--ivnp-config": opts.config, "--control-token-file": opts.controlToken, "--java-container": opts.javaContainer, "--i2pd-a-container": opts.i2pdAContainer, "--i2pd-b-container": opts.i2pdBContainer, "--java-image-id": opts.javaImage, "--i2pd-image-id": opts.i2pdImage, "--builder-image-id": opts.builderImage, "--pinned-router-hashes": pinnedRouterText} {
		if value == "" {
			return opts, fmt.Errorf("%s is required", name)
		}
	}

	opts.pinnedRouters = make(map[string]string, 3)
	for item := range strings.SplitSeq(pinnedRouterText, ",") {
		name, hash, ok := strings.Cut(item, "=")
		parseOptionsRejected := !ok || (name != "java" && name != "i2pd-a" && name != "i2pd-b")
		if !parseOptionsRejected {
			parseOptionsRejected = len(hash) != 44
		}
		if parseOptionsRejected {
			return opts, errors.New("--pinned-router-hashes must contain java, i2pd-a, and i2pd-b I2P hashes")
		}
		if _, duplicate := opts.pinnedRouters[name]; duplicate {
			return opts, errors.New("--pinned-router-hashes contains a duplicate name")
		}
		opts.pinnedRouters[name] = hash
	}
	if len(opts.pinnedRouters) != 3 {
		return opts, errors.New("--pinned-router-hashes must contain java, i2pd-a, and i2pd-b")
	}
	token, err := os.ReadFile(opts.controlToken)

	if err != nil {
		return opts, fmt.Errorf("read control token: %w", err)
	}
	opts.controlToken = strings.TrimSpace(string(token))
	if opts.controlToken == "" {
		return opts, errors.New("control token file is empty")
	}
	return opts, nil
}

type publicProbePayload struct {
	Schema      string    `json:"schema"`
	RunID       string    `json:"run_id"`
	RouterHash  string    `json:"router_hash"`
	TCPEndpoint string    `json:"tcp_endpoint"`
	UDPEndpoint string    `json:"udp_endpoint"`
	VantageIP   string    `json:"vantage_ip"`
	Nonce       string    `json:"nonce"`
	StartedUTC  time.Time `json:"started_utc"`
	EndedUTC    time.Time `json:"ended_utc"`
	TCPPassed   bool      `json:"tcp_passed"`
	UDPPassed   bool      `json:"udp_passed"`
}

type signedPublicProbeEvidence struct {
	Payload   publicProbePayload `json:"payload"`
	Signature string             `json:"signature"`
}

func validatePublicProbeEvidence(path, encodedKey, runID, routerHash, publicHost, artifacts string, measurementStart, measurementEnd time.Time) error {
	wire, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read signed public reachability evidence: %w", err)
	}
	if len(wire) == 0 || len(wire) > 64<<10 {
		return errors.New("signed public reachability evidence has invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var evidence signedPublicProbeEvidence
	if err = decoder.Decode(&evidence); err != nil {
		return fmt.Errorf("decode signed public reachability evidence: %w", err)
	}
	var trailing any
	if trailingErr := decoder.Decode(&trailing); !errors.Is(trailingErr, io.EOF) {
		return errors.New("signed public reachability evidence contains trailing data")
	}
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(encodedKey)
	}
	signature, signatureErr := base64.StdEncoding.DecodeString(evidence.Signature)
	if signatureErr != nil {
		signature, signatureErr = base64.RawStdEncoding.DecodeString(evidence.Signature)
	}
	payloadWire, marshalErr := json.Marshal(evidence.Payload)
	validatePublicProbeEvidenceRejected := err != nil || signatureErr != nil || marshalErr != nil || len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize
	if !validatePublicProbeEvidenceRejected {
		validatePublicProbeEvidenceRejected = !ed25519.Verify(ed25519.PublicKey(key), payloadWire, signature)
	}
	if validatePublicProbeEvidenceRejected {
		return errors.New("public reachability evidence signature is invalid")
	}
	payload := evidence.Payload
	if payload.Schema != "ivnp.public-reachability/v1" || payload.RunID != runID || payload.RouterHash != routerHash || !payload.TCPPassed || !payload.UDPPassed {
		return errors.New("public reachability evidence is not bound to this run/router or reports a failed probe")
	}
	if payload.TCPEndpoint != net.JoinHostPort(publicHost, "29442") || payload.UDPEndpoint != net.JoinHostPort(publicHost, "29443") {
		return errors.New("public reachability evidence endpoint binding mismatch")
	}
	vantage := net.ParseIP(payload.VantageIP)
	public := net.ParseIP(publicHost)
	if vantage == nil || !vantage.IsGlobalUnicast() || vantage.IsPrivate() || vantage.IsLoopback() || vantage.Equal(public) {
		return errors.New("public reachability evidence does not identify an off-host public vantage")
	}
	if payload.Nonce == "" || len(payload.Nonce) > 128 || payload.StartedUTC.Before(measurementStart) || payload.EndedUTC.After(measurementEnd) || payload.EndedUTC.Before(payload.StartedUTC) {
		return errors.New("public reachability evidence nonce/timestamp is outside the measured interval")
	}
	target := filepath.Join(artifacts, "public-reachability-evidence.json")
	if err = os.WriteFile(target, wire, 0o600); err != nil {
		return err
	}
	return nil
}

type allocationBenchmarkObservation struct {
	Name        string  `json:"name"`
	AllocsPerOp float64 `json:"allocs_per_op"`
	Ceiling     float64 `json:"ceiling"`
}

type allocationPreflightEvidence struct {
	Schema       string                           `json:"schema"`
	BinarySHA256 string                           `json:"binary_sha256"`
	GoVersion    string                           `json:"go_version"`
	CompletedUTC time.Time                        `json:"completed_utc"`
	Benchmarks   []allocationBenchmarkObservation `json:"benchmarks"`
	Profiles     []string                         `json:"profiles"`
	Passed       bool                             `json:"passed"`
}

func runAllocationPreflight(ctx context.Context, artifacts, binaryDigest string) error {
	type benchmarkSpec struct {
		pkg      string
		pattern  string
		profile  string
		ceilings map[string]float64
	}
	specs := []benchmarkSpec{
		{pkg: "./network/router", pattern: "^(BenchmarkSSU2FragmentSendFraming|BenchmarkNTCP2ManagerMarshalFrame)$", profile: "allocation-router.pprof", ceilings: map[string]float64{"BenchmarkSSU2FragmentSendFraming": 0, "BenchmarkNTCP2ManagerMarshalFrame": 0}},
		{pkg: "./network/tunnel", pattern: "^BenchmarkRuntimeSendBlockParallel$", profile: "allocation-tunnel.pprof", ceilings: map[string]float64{"BenchmarkRuntimeSendBlockParallel": 1}},
		{pkg: "./protocol/garlic/ecies", pattern: "^BenchmarkRatchetExistingWithScratch$", profile: "allocation-garlic.pprof", ceilings: map[string]float64{"BenchmarkRatchetExistingWithScratch": 0}},
		{pkg: "./protocol/streaming", pattern: "^BenchmarkStreamingPacketMarshalTo$", profile: "allocation-streaming.pprof", ceilings: map[string]float64{"BenchmarkStreamingPacketMarshalTo": 0}},
	}
	var combined bytes.Buffer
	evidence := allocationPreflightEvidence{Schema: "ivnp.allocation-preflight/v1", BinarySHA256: binaryDigest, GoVersion: runtime.Version(), Profiles: make([]string, 0, len(specs))}
	for _, spec := range specs {
		profilePath := filepath.Join(artifacts, spec.profile)
		command := exec.CommandContext(ctx, "go", "test", "-run=^$", "-bench="+spec.pattern, "-benchmem", "-benchtime=100x", "-count=1", "-memprofile="+profilePath, spec.pkg)
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		err := command.Run()
		combined.WriteString("$ " + strings.Join(command.Args, " ") + "\n")
		combined.Write(output.Bytes())
		combined.WriteByte('\n')
		if err != nil {
			_ = os.WriteFile(filepath.Join(artifacts, "allocation-benchmarks.txt"), combined.Bytes(), 0o600)
			return fmt.Errorf("%s benchmark failed: %w", spec.pkg, err)
		}
		evidence.Profiles = append(evidence.Profiles, spec.profile)
		for expected, ceiling := range spec.ceilings {
			allocations, ok := benchmarkAllocs(output.String(), expected)
			if !ok {
				return fmt.Errorf("%s did not report allocs/op", expected)
			}
			evidence.Benchmarks = append(evidence.Benchmarks, allocationBenchmarkObservation{Name: expected, AllocsPerOp: allocations, Ceiling: ceiling})
			if allocations > ceiling {
				return fmt.Errorf("%s allocations %.2f exceed ceiling %.2f", expected, allocations, ceiling)
			}
		}
	}
	sort.Slice(evidence.Benchmarks, func(left, right int) bool { return evidence.Benchmarks[left].Name < evidence.Benchmarks[right].Name })
	evidence.CompletedUTC, evidence.Passed = time.Now().UTC(), true
	if err := os.WriteFile(filepath.Join(artifacts, "allocation-benchmarks.txt"), combined.Bytes(), 0o600); err != nil {
		return err
	}
	return writeAtomicJSON(filepath.Join(artifacts, "allocation-preflight.json"), evidence)
}

func benchmarkAllocs(output, benchmark string) (float64, bool) {
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasPrefix(fields[0], benchmark+"-") || fields[len(fields)-1] != "allocs/op" {
			continue
		}
		value, err := strconv.ParseFloat(fields[len(fields)-2], 64)
		if err == nil {
			return value, true
		}
	}
	return 0, false
}

func newRunIdentity() (string, int64, error) {
	var wire [16]byte
	if _, err := rand.Read(wire[:]); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(wire[:]), int64(binaryUint64(wire[:8])), nil
}

func binaryUint64(wire []byte) uint64 {
	var value uint64
	for _, current := range wire {
		value = value<<8 | uint64(current)
	}
	return value
}

func startProcess(opts options, label, artifactDir string) (*processEpoch, error) {
	logFile, err := os.OpenFile(filepath.Join(artifactDir, "ivnp-"+label+".log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	command := exec.Command(opts.binary, "-config", opts.config)
	command.Stdout, command.Stderr = logFile, logFile
	if err = command.Start(); err != nil {
		logFile.Close()
		return nil, err
	}
	epoch := &processEpoch{cmd: command, exited: make(chan struct{}), log: logFile, label: label}
	go func() {
		err := command.Wait()
		epoch.mu.Lock()
		epoch.waitErr = err
		epoch.mu.Unlock()
		close(epoch.exited)
		_ = logFile.Sync()
		_ = logFile.Close()
	}()
	return epoch, nil
}

func stopProcess(epoch *processEpoch, timeout time.Duration) error {
	if epoch == nil || epoch.cmd == nil || epoch.cmd.Process == nil {
		return nil
	}
	if err := epoch.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-epoch.exited:
		return epoch.exitError()
	case <-time.After(timeout):
		_ = epoch.cmd.Process.Kill()
		<-epoch.exited
		return errors.New("process did not stop after SIGTERM")
	}
}

func (epoch *processEpoch) exitError() error {
	epoch.mu.Lock()
	defer epoch.mu.Unlock()
	return epoch.waitErr
}

func processExited(epoch *processEpoch) bool {
	if epoch == nil {
		return true
	}
	select {
	case <-epoch.exited:
		return true
	default:
		return false
	}
}

func nativeRoutersReady(ctx context.Context, opts options) error {
	deadline := time.Now().Add(opts.warmup)
	for time.Now().Before(deadline) {
		java := sampleContainer(ctx, opts.javaContainer)
		i2pdA := sampleContainer(ctx, opts.i2pdAContainer)
		i2pdB := sampleContainer(ctx, opts.i2pdBContainer)
		if !java.Running || !i2pdA.Running || !i2pdB.Running {
			return errors.New("pinned Java I2P or i2pd container exited before readiness")
		}
		if tcpReady(ctx, opts.javaSAM) && tcpReady(ctx, opts.i2pdASAM) && tcpReady(ctx, opts.i2pdBSAM) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("timed out waiting for distinct Java and two i2pd SAM listeners")
}

func tcpReady(ctx context.Context, address string) bool {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	connection.Close()
	return true
}

func waitForReadiness(ctx context.Context, opts options, epoch *processEpoch, recorder *artifactRecorder) error {
	deadline := time.Now().Add(opts.warmup)
	var lastMissing []string
	for time.Now().Before(deadline) {
		select {
		case <-epoch.exited:
			return fmt.Errorf("IVNP exited before readiness: %v", epoch.exitError())
		default:
		}
		health, metrics, err := scrapeMetrics(ctx, opts.metricsURL)
		if err == nil && tcpReady(ctx, opts.ivnpSAM) {
			lastMissing = readinessMissingForScope(opts.scope, health, metrics)
			if len(lastMissing) == 0 {
				epoch.identity, err = sampleProcess(epoch.cmd.Process.Pid)
				if err != nil {
					return err
				}
				_ = recorder.writeEvent(event{At: time.Now().UTC(), Type: "ivnp_core_ready", Fields: map[string]any{"pid": epoch.identity.PID, "epoch": epoch.label, "scope": opts.scope}})
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if len(lastMissing) == 0 {
		return errors.New("timed out waiting for IVNP HTTP/SAM readiness")
	}
	return errors.New("timed out waiting for authoritative IVNP readiness: " + strings.Join(lastMissing, ", "))
}

func readinessMissing(health string, metrics map[string]uint64) []string {
	return readinessMissingForScope("public", health, metrics)
}

func readinessMissingForScope(scope, health string, metrics map[string]uint64) []string {
	required := map[string]uint64{
		"ivnp_bootstrap_stage":                         4,
		"ivnp_netdb_routers":                           50,
		"ivnp_publication_router_info_successes_total": 1,
		"ivnp_publication_lease_set2_successes_total":  1,
		"ivnp_tunnel_exploratory_inbound_active":       1,
		"ivnp_tunnel_exploratory_outbound_active":      1,
		"ivnp_tunnel_client_inbound_active":            1,
		"ivnp_tunnel_client_outbound_active":           1,
		"ivnp_ssu2_vector_io_enabled":                  1,
		"ivnp_ssu2_kernel_drop_accounting":             1,
		"ivnp_process_goroutines":                      1,
		"ivnp_process_heap_inuse_bytes":                1,
		"ivnp_process_heap_objects":                    1,
	}
	if scope == "local" {
		required["ivnp_bootstrap_stage"] = 2
		required["ivnp_netdb_routers"] = 3
	}
	if scope == "public" {
		required["ivnp_router_reachable"] = 1
	}
	missing := make([]string, 0)
	for _, name := range []string{
		"ivnp_process_allocated_bytes_total",
		"ivnp_process_mallocs_total",
		"ivnp_process_gc_cycles_total",
		"ivnp_process_gc_pause_nanoseconds_total",
	} {
		if _, ok := metrics[name]; !ok {
			missing = append(missing, name+"=present")
		}
	}
	if health != "ok" {
		missing = append(missing, "healthz=ok")
	}
	for name, minimum := range required {
		if metrics[name] < minimum {
			missing = append(missing, fmt.Sprintf("%s>=%d", name, minimum))
		}
	}
	sort.Strings(missing)
	return missing
}

func waitForPinnedConnectivity(ctx context.Context, opts options, epoch *processEpoch, recorder *artifactRecorder) error {
	deadline := time.Now().Add(opts.warmup)
	var missing []string
	for time.Now().Before(deadline) {
		missing = authenticatedPinnedMissing(epoch.log.Name(), opts.pinnedRouters)
		if len(missing) == 0 {
			return recorder.writeEvent(event{At: time.Now().UTC(), Type: "ivnp_ready", Fields: map[string]any{
				"epoch": epoch.label, "scope": "local", "authenticated_bidirectional_peers": opts.pinnedRouters,
			}})
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-epoch.exited:
			return fmt.Errorf("IVNP exited before pinned connectivity: %v", epoch.exitError())
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("timed out waiting for local authenticated connectivity: " + strings.Join(missing, ", "))
}

func authenticatedPinnedMissing(logPath string, pinned map[string]string) []string {
	wire, err := os.ReadFile(logPath)
	if err != nil {
		return []string{"authenticated pinned transport log readable"}
	}
	lines := strings.Split(string(wire), "\n")
	var missing []string
	for name, hash := range pinned {
		found := false
		for _, line := range lines {
			if strings.Contains(line, `"msg":"authenticated public transport session established"`) &&
				strings.Contains(line, `"peer":"`+hash+`"`) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, "authenticated bidirectional transport session with "+name)
		}
	}
	return missing
}

func scrapeMetrics(ctx context.Context, base string) (string, map[string]uint64, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	healthRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/healthz", nil)
	healthResponse, err := client.Do(healthRequest)
	if err != nil {
		return "", nil, err
	}
	healthWire, err := io.ReadAll(io.LimitReader(healthResponse.Body, 4096))
	healthResponse.Body.Close()
	if err != nil {
		return "", nil, err
	}
	var healthValue struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(healthWire, &healthValue) != nil {
		return "", nil, errors.New("invalid /healthz response")
	}
	metricsRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/metrics", nil)
	metricsResponse, err := client.Do(metricsRequest)
	if err != nil {
		return "", nil, err
	}
	metricsWire, err := io.ReadAll(io.LimitReader(metricsResponse.Body, 1<<20))
	metricsResponse.Body.Close()
	if err != nil {
		return "", nil, err
	}
	return healthValue.Status, parsePrometheus(metricsWire), nil
}

func parsePrometheus(wire []byte) map[string]uint64 {
	values := make(map[string]uint64)
	for line := range strings.SplitSeq(string(wire), "\n") {
		if line == "" || line[0] == '#' || strings.Contains(line, "{") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			values[fields[0]] = value
		}
	}
	return values
}

func defaultDestination(ctx context.Context, opts options) (string, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(opts.controlURL, "/")+"/destinations", nil)
	request.Header.Set("Authorization", "Bearer "+opts.controlToken)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("control /destinations status %d", response.StatusCode)
	}
	var body struct {
		Destinations []struct {
			Address string `json:"address"`
			Default bool   `json:"default"`
		} `json:"destinations"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&body); err != nil {
		return "", err
	}
	for _, destination := range body.Destinations {
		if destination.Default && destination.Address != "" {
			return destination.Address, nil
		}
	}
	return "", errors.New("default destination is absent")
}

func routerIdentity(ctx context.Context, opts options) (string, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(opts.controlURL, "/")+"/status", nil)
	request.Header.Set("Authorization", "Bearer "+opts.controlToken)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("control /status status %d", response.StatusCode)
	}
	var body struct {
		RouterHash string `json:"router_hash"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&body); err != nil {
		return "", err
	}

	if body.RouterHash == "" || strings.ContainsAny(body.RouterHash, " \t\r\n,") {
		return "", errors.New("control status omitted a valid public router hash")
	}
	return body.RouterHash, nil
}
func evaluateLoad(result loadResult) error {
	if result.OfferedOperations < uint64(result.Concurrency) {
		return fmt.Errorf("insufficient offered operations: offered=%d concurrency=%d", result.OfferedOperations, result.Concurrency)
	}
	minimumOffered := uint64(float64(result.TargetBytesPerSec) * result.WindowSeconds * 0.90)
	if result.OfferedBytes < minimumOffered {
		return fmt.Errorf("offered-byte rate below 90%% target: offered=%d minimum=%d", result.OfferedBytes, minimumOffered)
	}
	if result.CompletedOperations*100 < result.OfferedOperations*95 {
		return fmt.Errorf("STREAM completion below 95%%: completed=%d offered=%d failed=%d", result.CompletedOperations, result.OfferedOperations, result.FailedOperations)
	}
	if result.FailedOperations != result.OfferedOperations-result.CompletedOperations {
		return fmt.Errorf("STREAM operation conservation failed: offered=%d completed=%d failed=%d", result.OfferedOperations, result.CompletedOperations, result.FailedOperations)
	}
	if result.P95Milliseconds > (30*time.Second).Milliseconds() || result.P99Milliseconds > (60*time.Second).Milliseconds() {
		return fmt.Errorf("STREAM latency gate exceeded: p95=%dms p99=%dms", result.P95Milliseconds, result.P99Milliseconds)
	}
	return nil
}
func validateSAMUDPWithMetrics(ctx context.Context, metricsURL string, probes *samMessageProbes) (map[string]uint64, error) {
	_, before, err := scrapeMetrics(ctx, metricsURL)
	if err != nil {
		return nil, err
	}
	result, err := probes.ValidateUDPIngress(ctx)
	if err != nil {
		return nil, err
	}
	_, after, err := scrapeMetrics(ctx, metricsURL)
	if err != nil {
		return nil, err
	}
	invalidBefore, invalidOK := before["ivnp_sam_udp_invalid_total"]
	invalidAfter, invalidAfterOK := after["ivnp_sam_udp_invalid_total"]
	backpressureBefore, backpressureOK := before["ivnp_sam_udp_backpressure_rejections_total"]
	backpressureAfter, backpressureAfterOK := after["ivnp_sam_udp_backpressure_rejections_total"]
	if !invalidOK || !invalidAfterOK || invalidAfter < invalidBefore+4 {
		return nil, fmt.Errorf("SAM UDP invalid/source-binding rejection metric did not advance by four: before=%d after=%d", invalidBefore, invalidAfter)
	}
	if !backpressureOK || !backpressureAfterOK || backpressureAfter <= backpressureBefore {
		return nil, fmt.Errorf("SAM UDP backpressure rejection metric did not advance: before=%d after=%d", backpressureBefore, backpressureAfter)
	}
	result["invalid_metric_delta"] = invalidAfter - invalidBefore
	result["backpressure_metric_delta"] = backpressureAfter - backpressureBefore
	return result, nil
}

func waitForInitialTraffic(ctx context.Context, opts options, traffic *trafficRunner, recorder *artifactRecorder) error {
	deadline := time.Now().Add(opts.warmup)
	var last []probeResult
	passedSizes := make(map[string]map[int]bool, len(requiredDirections))
	for time.Now().Before(deadline) {
		probeCtx, cancel := context.WithTimeout(ctx, time.Duration(len(requiredDirections)+2)*probeTimeout+5*time.Second)
		last = traffic.ProbeInitial(probeCtx)
		cancel()
		all := recordWarmupResults(last, passedSizes, recorder)
		warmed := allProbeSizesPassed(passedSizes)
		if all && warmed {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
	var failures []string
	for _, result := range last {
		if result.Err != nil {
			failures = append(failures, result.Direction+": "+result.Err.Error())
		}
	}
	return errors.New("timed out waiting for initial black-box traffic: " + strings.Join(failures, "; "))
}

func recordWarmupResults(results []probeResult, passedSizes map[string]map[int]bool, recorder *artifactRecorder) bool {
	all := true
	for _, result := range results {
		fields := map[string]any{"direction": result.Direction, "sequence": result.Sequence, "bytes": result.Size, "duration_ms": result.Duration.Milliseconds()}
		if result.Err != nil {
			fields["error"] = result.Err.Error()
			all = false
		} else {
			recordPassedProbe(result, passedSizes)
		}
		_ = recorder.writeEvent(event{At: time.Now().UTC(), Type: "warmup_probe", Fields: fields})
	}
	return all
}

func recordPassedProbe(result probeResult, passedSizes map[string]map[int]bool) {
	for _, route := range requiredDirections {
		if result.Direction != route.name+"-eepsite" {
			continue
		}
		if passedSizes[result.Direction] == nil {
			passedSizes[result.Direction] = make(map[int]bool, len(probeSizes))
		}
		passedSizes[result.Direction][result.Size] = true
		return
	}
}

func allProbeSizesPassed(passedSizes map[string]map[int]bool) bool {
	for _, route := range requiredDirections {
		direction := route.name + "-eepsite"
		for _, size := range probeSizes {
			if !passedSizes[direction][size] {
				return false
			}
		}
	}
	return true
}

func collectSample(ctx context.Context, opts options, epoch *processEpoch, start time.Time) (soakSample, error) {
	health, metrics, err := scrapeMetrics(ctx, opts.metricsURL)
	if err != nil {
		return soakSample{}, fmt.Errorf("scrape IVNP: %w", err)
	}
	process, err := sampleProcess(epoch.cmd.Process.Pid)
	if err != nil {
		return soakSample{}, fmt.Errorf("sample IVNP process: %w", err)
	}
	if process.StartTimeTick != epoch.identity.StartTimeTick || process.Executable != epoch.identity.Executable {
		return soakSample{}, errors.New("IVNP process/binary identity changed during epoch")
	}
	return soakSample{At: time.Now().UTC(), Elapsed: time.Since(start).Seconds(), Epoch: epoch.label, Health: health, Metrics: metrics, Process: process, Containers: []containerSample{sampleContainer(ctx, opts.javaContainer), sampleContainer(ctx, opts.i2pdAContainer), sampleContainer(ctx, opts.i2pdBContainer)}}, nil
}

func checkHardCounters(baseline, current map[string]uint64) error {
	strict := []string{
		"ivnp_lifecycle_failures_total",
		"ivnp_ingress_recovered_panics_total",
		"ivnp_ssu2_receive_queue_drops_total",
		"ivnp_ssu2_kernel_drops_total",
		"ivnp_ssu2_send_failed_datagrams_total",
		"ivnp_ssu2_send_queue_drops_total",
		"ivnp_proxy_failures_total",
		"ivnp_control_failures_total",
		"ivnp_sam_protocol_failures_total",
	}
	for _, name := range strict {
		baselineValue, baselinePresent := baseline[name]
		value, present := current[name]
		if !baselinePresent || !present {
			return fmt.Errorf("required hard-failure metric missing: %s", name)
		}
		if baselineValue != 0 || value != baselineValue {
			return fmt.Errorf("strict failure policy violated: %s baseline=%d current=%d", name, baselineValue, value)
		}
	}
	type boundedPolicy struct {
		failures string
		events   string
		minimum  uint64
		divisor  uint64
	}
	for _, policy := range []boundedPolicy{
		{failures: "ivnp_transport_handshake_failures_total", events: "ivnp_transport_connections_total", minimum: 6, divisor: 20},
		{failures: "ivnp_publication_send_failures_total", events: "ivnp_publication_attempts_total", minimum: 4, divisor: 10},
		{failures: "ivnp_publication_timeouts_total", events: "ivnp_publication_attempts_total", minimum: 2, divisor: 20},
		{failures: "ivnp_tunnel_build_failures_total", events: "ivnp_tunnel_builds_total", minimum: 4, divisor: 10},
		{failures: "ivnp_netdb_lookup_failures_total", events: "ivnp_netdb_lookups_total", minimum: 2, divisor: 20},
		{failures: "ivnp_netdb_store_failures_total", events: "ivnp_netdb_stores_total", minimum: 2, divisor: 100},
		{failures: "ivnp_reseed_failures_total", events: "ivnp_reseed_attempts_total", minimum: 1, divisor: 100},
	} {
		failureBase, failureOK := baseline[policy.failures]
		failureNow, currentOK := current[policy.failures]
		eventBase, eventBaseOK := baseline[policy.events]
		eventNow, eventNowOK := current[policy.events]
		if !failureOK || !currentOK || !eventBaseOK || !eventNowOK {
			return fmt.Errorf("bounded failure policy metric missing: %s/%s", policy.failures, policy.events)
		}
		if failureNow < failureBase || eventNow < eventBase {
			return fmt.Errorf("counter regressed: %s/%s", policy.failures, policy.events)
		}
		failures, events := failureNow-failureBase, eventNow-eventBase
		allowed := max(policy.minimum, events/policy.divisor)
		if failures > allowed {
			return fmt.Errorf("bounded failure policy exceeded: %s delta=%d allowed=%d events=%d", policy.failures, failures, allowed, events)
		}
	}
	return nil
}

func checkFinalEvidence(baseline, current map[string]uint64) error {
	requiredDeltas := []string{
		"ivnp_transport_received_bytes_total",
		"ivnp_transport_sent_bytes_total",
		"ivnp_netdb_lookups_total",
		"ivnp_netdb_stores_total",
		"ivnp_garlic_ecies_new_session_sent_total",
		"ivnp_garlic_ecies_new_session_received_total",
		"ivnp_garlic_ecies_existing_session_sent_total",
		"ivnp_garlic_ecies_existing_session_received_total",
		"ivnp_garlic_tunnel_cloves_forwarded_total",
		"ivnp_ssu2_received_datagrams_total",
		"ivnp_ssu2_sent_datagrams_total",
	}
	for _, name := range requiredDeltas {
		value, present := current[name]
		if !present {
			return fmt.Errorf("required protocol evidence metric missing: %s", name)
		}
		if value <= baseline[name] {
			return fmt.Errorf("required protocol evidence did not advance: %s baseline=%d final=%d", name, baseline[name], value)
		}
	}
	// DH rekeys, transit selection, and vector coalescing depend on remote-peer
	// timing and traffic density; a valid one-hour run need not observe them.
	// Their counters must still be exposed, while direct client/tunnel and SSU2
	// syscall activity above must advance.
	for _, name := range []string{
		"ivnp_garlic_ecies_dh_steps_sent_total",
		"ivnp_garlic_ecies_dh_steps_received_total",
		"ivnp_tunnel_participating_forwarded_total",
		"ivnp_ssu2_receive_multi_batches_total",
		"ivnp_ssu2_send_multi_batches_total",
	} {
		if _, present := current[name]; !present {
			return fmt.Errorf("required protocol accounting metric missing: %s", name)
		}
	}
	for _, name := range []string{"ivnp_sam_udp_invalid_total", "ivnp_sam_udp_backpressure_rejections_total", "ivnp_sam_protocol_failures_total"} {
		if _, present := current[name]; !present {
			return fmt.Errorf("required SAM accounting metric missing: %s", name)
		}
	}
	required := []string{
		"ivnp_ssu2_received_datagrams_total",
		"ivnp_ssu2_enqueued_datagrams_total",
		"ivnp_ssu2_processed_datagrams_total",
		"ivnp_ssu2_receive_queue_drops_total",
		"ivnp_ssu2_kernel_drops_total",
		"ivnp_ssu2_send_enqueued_datagrams_total",
		"ivnp_ssu2_sent_datagrams_total",
		"ivnp_ssu2_send_failed_datagrams_total",
		"ivnp_ssu2_send_queue_drops_total",
		"ivnp_ssu2_ingress_queue_depth",
		"ivnp_ssu2_egress_queue_depth",
	}
	for _, name := range required {
		if _, present := current[name]; !present {
			return fmt.Errorf("required SSU2 accounting metric missing: %s", name)
		}
	}
	if current["ivnp_ssu2_received_datagrams_total"] != current["ivnp_ssu2_enqueued_datagrams_total"]+current["ivnp_ssu2_receive_queue_drops_total"] {
		return errors.New("SSU2 receive/enqueue/drop conservation failed")
	}
	if current["ivnp_ssu2_enqueued_datagrams_total"] != current["ivnp_ssu2_processed_datagrams_total"]+current["ivnp_ssu2_ingress_queue_depth"] {
		return errors.New("SSU2 enqueue/process/depth conservation failed")
	}
	if current["ivnp_ssu2_send_enqueued_datagrams_total"] != current["ivnp_ssu2_sent_datagrams_total"]+current["ivnp_ssu2_send_failed_datagrams_total"]+current["ivnp_ssu2_send_queue_drops_total"]+current["ivnp_ssu2_egress_queue_depth"] {
		return errors.New("SSU2 send/depth conservation failed")
	}
	return nil
}

func evaluateAllocationTrend(samples []soakSample) (map[string]any, error) {
	if len(samples) < 2 {
		return nil, errors.New("insufficient live allocation/GC samples")
	}
	first, last := samples[0], samples[len(samples)-1]
	elapsed := last.Elapsed - first.Elapsed
	if elapsed <= 0 {
		return nil, errors.New("invalid allocation/GC sample interval")
	}
	rate := func(name string, left, right soakSample) (float64, error) {
		before, beforeOK := left.Metrics[name]
		after, afterOK := right.Metrics[name]
		seconds := right.Elapsed - left.Elapsed
		if !beforeOK || !afterOK || after < before || seconds <= 0 {
			return 0, fmt.Errorf("invalid monotonic process metric %s", name)
		}
		return float64(after-before) / seconds, nil
	}
	allocatedRate, err := rate("ivnp_process_allocated_bytes_total", first, last)
	if err != nil {
		return nil, err
	}
	mallocRate, err := rate("ivnp_process_mallocs_total", first, last)
	if err != nil {
		return nil, err
	}
	gcRate, err := rate("ivnp_process_gc_cycles_total", first, last)
	if err != nil {
		return nil, err
	}
	pauseRate, err := rate("ivnp_process_gc_pause_nanoseconds_total", first, last)
	if err != nil {
		return nil, err
	}
	if allocatedRate > 128<<20 {
		return nil, fmt.Errorf("production allocation rate exceeded 128 MiB/s: %.0f", allocatedRate)
	}
	if mallocRate > 500_000 {
		return nil, fmt.Errorf("production malloc rate exceeded 500k/s: %.0f", mallocRate)
	}
	if gcRate > 20 {
		return nil, fmt.Errorf("production GC rate exceeded 20/s: %.2f", gcRate)
	}
	if pauseRate > float64(50*time.Millisecond) {
		return nil, fmt.Errorf("production GC pause ratio exceeded 5%%: %.0f ns/s", pauseRate)
	}
	trend := map[string]any{
		"allocated_bytes_per_second":      allocatedRate,
		"mallocs_per_second":              mallocRate,
		"gc_cycles_per_second":            gcRate,
		"gc_pause_nanoseconds_per_second": pauseRate,
	}
	if len(samples) >= 4 {
		initialRate, initialErr := rate("ivnp_process_allocated_bytes_total", samples[0], samples[1])
		terminalRate, terminalErr := rate("ivnp_process_allocated_bytes_total", samples[len(samples)-2], samples[len(samples)-1])
		if initialErr != nil || terminalErr != nil {
			return nil, errors.Join(initialErr, terminalErr)
		}
		allowance := max(float64(32<<20), initialRate*2)
		if terminalRate > allowance {
			return nil, fmt.Errorf("production allocation-rate trend grew without bound: initial=%.0f terminal=%.0f allowance=%.0f", initialRate, terminalRate, allowance)
		}
		trend["initial_allocated_bytes_per_second"] = initialRate
		trend["terminal_allocated_bytes_per_second"] = terminalRate
		trend["terminal_rate_allowance"] = allowance
	}
	return trend, nil
}

func evaluateResources(samples []soakSample, duration time.Duration) error {
	if len(samples) < 10 {
		return errors.New("insufficient resource samples for one-hour policy")
	}
	baselineEnd := 10 * time.Minute
	terminalStart := duration - 10*time.Minute
	var baseline, terminal []soakSample
	for _, sample := range samples {
		elapsed := time.Duration(sample.Elapsed * float64(time.Second))
		if elapsed <= baselineEnd {
			baseline = append(baseline, sample)
		}
		if elapsed >= terminalStart {
			terminal = append(terminal, sample)
		}
	}
	if len(baseline) == 0 || len(terminal) == 0 {
		return errors.New("resource baseline or terminal window is empty")
	}
	baseRSS, endRSS := medianSampleMetric(baseline, func(value soakSample) uint64 { return value.Process.RSSBytes }), medianSampleMetric(terminal, func(value soakSample) uint64 { return value.Process.RSSBytes })
	baseFD, endFD := medianSampleMetric(baseline, func(value soakSample) uint64 { return value.Process.FDs }), medianSampleMetric(terminal, func(value soakSample) uint64 { return value.Process.FDs })
	baseGo, endGo := medianSampleMetric(baseline, func(value soakSample) uint64 { return value.Metrics["ivnp_process_goroutines"] }), medianSampleMetric(terminal, func(value soakSample) uint64 { return value.Metrics["ivnp_process_goroutines"] })
	baseHeap, endHeap := medianSampleMetric(baseline, func(value soakSample) uint64 { return value.Metrics["ivnp_process_heap_inuse_bytes"] }), medianSampleMetric(terminal, func(value soakSample) uint64 { return value.Metrics["ivnp_process_heap_inuse_bytes"] })
	if endFD > baseFD+10 {
		return fmt.Errorf("FD resource policy exceeded: baseline=%d terminal=%d", baseFD, endFD)
	}
	if endGo > baseGo+10 {
		return fmt.Errorf("goroutine resource policy exceeded: baseline=%d terminal=%d", baseGo, endGo)
	}
	heapAllowance := maxUint64(16<<20, baseHeap/10)
	if endHeap > baseHeap+heapAllowance {
		return fmt.Errorf("heap resource policy exceeded: baseline=%d terminal=%d allowance=%d", baseHeap, endHeap, heapAllowance)
	}
	rssAllowance := maxUint64(32<<20, baseRSS/10)
	if endRSS > baseRSS+rssAllowance {
		return fmt.Errorf("RSS resource policy exceeded: baseline=%d terminal=%d allowance=%d", baseRSS, endRSS, rssAllowance)
	}
	return nil
}

func medianSampleMetric(values []soakSample, extract func(soakSample) uint64) uint64 {
	numbers := make([]uint64, len(values))
	for index, value := range values {
		numbers[index] = extract(value)
	}
	slices.Sort(numbers)
	return numbers[len(numbers)/2]
}

func maxUint64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func gitIdentity() (string, bool) {
	wire, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown", true
	}
	revision := strings.TrimSpace(string(wire))
	err = exec.Command("git", "diff", "--quiet", "--ignore-submodules", "HEAD", "--").Run()
	return revision, err != nil
}

func captureContainerLog(name, path string) {
	if name == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", "logs", name)
	command.Stdout, command.Stderr = file, file
	_ = command.Run()
	_ = file.Sync()
}
