//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type processSample struct {
	PID           int      `json:"pid"`
	RSSBytes      uint64   `json:"rss_bytes"`
	VirtualBytes  uint64   `json:"virtual_bytes"`
	CPUJiffies    uint64   `json:"cpu_jiffies"`
	Threads       uint64   `json:"threads"`
	FDs           uint64   `json:"fds"`
	SocketInodes  []string `json:"socket_inodes"`
	UDPDrops      uint64   `json:"udp_drops"`
	Executable    string   `json:"executable"`
	StartTimeTick uint64   `json:"start_time_tick"`
}

type containerSample struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	Stats   string `json:"stats,omitempty"`
	Error   string `json:"error,omitempty"`
}

func sampleProcess(pid int) (processSample, error) {
	if pid < 1 {
		return processSample{}, errors.New("invalid PID")
	}
	root := filepath.Join("/proc", strconv.Itoa(pid))
	statusWire, err := os.ReadFile(filepath.Join(root, "status"))
	if err != nil {
		return processSample{}, err
	}
	result := processSample{PID: pid}
	for _, line := range strings.Split(string(statusWire), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "VmRSS":
			result.RSSBytes, _ = kibibytes(fields[1])
		case "VmSize":
			result.VirtualBytes, _ = kibibytes(fields[1])
		case "Threads":
			result.Threads, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}
	statWire, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return processSample{}, err
	}
	closing := strings.LastIndexByte(string(statWire), ')')
	if closing < 0 {
		return processSample{}, errors.New("malformed process stat")
	}
	statFields := strings.Fields(string(statWire[closing+1:]))
	if len(statFields) < 20 {
		return processSample{}, errors.New("short process stat")
	}
	user, _ := strconv.ParseUint(statFields[11], 10, 64)
	system, _ := strconv.ParseUint(statFields[12], 10, 64)
	result.CPUJiffies = user + system
	result.StartTimeTick, _ = strconv.ParseUint(statFields[19], 10, 64)
	entries, err := os.ReadDir(filepath.Join(root, "fd"))
	if err != nil {
		return processSample{}, err
	}
	result.FDs = uint64(len(entries))
	for _, entry := range entries {
		target, linkErr := os.Readlink(filepath.Join(root, "fd", entry.Name()))
		if linkErr == nil && strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			result.SocketInodes = append(result.SocketInodes, strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"))
		}
	}
	result.UDPDrops = udpDrops(result.SocketInodes)
	result.Executable, _ = os.Readlink(filepath.Join(root, "exe"))
	return result, nil
}

func kibibytes(value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed * 1024, err
}

func udpDrops(inodes []string) uint64 {
	wanted := make(map[string]struct{}, len(inodes))
	for _, inode := range inodes {
		wanted[inode] = struct{}{}
	}
	var total uint64
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 11 {
				continue
			}
			if _, ok := wanted[fields[9]]; !ok {
				continue
			}
			drops, parseErr := strconv.ParseUint(fields[len(fields)-1], 10, 64)
			if parseErr == nil {
				total += drops
			}
		}
		file.Close()
	}
	return total
}

func sampleContainer(ctx context.Context, name string) containerSample {
	result := containerSample{Name: name}
	inspectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	wire, err := exec.CommandContext(inspectCtx, "docker", "inspect", "--format", "{{.State.Running}}", name).Output()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Running = strings.TrimSpace(string(wire)) == "true"
	if !result.Running {
		return result
	}
	statsCtx, statsCancel := context.WithTimeout(ctx, 10*time.Second)
	defer statsCancel()
	wire, err = exec.CommandContext(statsCtx, "docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.PIDs}}", name).Output()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Stats = strings.TrimSpace(string(wire))
	if len(result.Stats) > 512 {
		result.Stats = result.Stats[:512]
	}
	return result
}

func kernelRelease() string {
	wire, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return fmt.Sprintf("unavailable: %v", err)
	}
	return strings.TrimSpace(string(wire))
}
