//go:build linux

// bpfprobe queries TCX attachment state and optionally holds a kernel runtime
// statistics descriptor open for a separate profiling run.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type program struct {
	ID        ebpf.ProgramID `json:"id"`
	Name      string         `json:"name"`
	LinkID    link.ID        `json:"link_id"`
	RunCount  *uint64        `json:"run_count,omitempty"`
	RuntimeNS *int64         `json:"runtime_ns,omitempty"`
}

type kernelMap struct {
	ID         ebpf.MapID `json:"id"`
	Name       string     `json:"name"`
	MaxEntries uint32     `json:"max_entries"`
	KeyBytes   uint32     `json:"key_bytes"`
	ValueBytes uint32     `json:"value_bytes"`
	Memlock    *uint64    `json:"fdinfo_memlock_bytes,omitempty"`
}

type snapshot struct {
	Ingress []program   `json:"ingress"`
	Egress  []program   `json:"egress"`
	Maps    []kernelMap `json:"maps"`
}

func inspectProgram(attached link.AttachedProgram, maps map[ebpf.MapID]bool) (program, error) {
	p, err := ebpf.NewProgramFromID(attached.ID)
	if err != nil {
		return program{}, err
	}
	defer p.Close()
	info, err := p.Info()
	if err != nil {
		return program{}, err
	}
	id, _ := attached.LinkID()
	observed := program{ID: attached.ID, Name: info.Name, LinkID: id}
	if stats, err := p.Stats(); err == nil {
		observed.RunCount = &stats.RunCount
		ns := stats.Runtime.Nanoseconds()
		observed.RuntimeNS = &ns
	}
	if mapIDs, ok := info.MapIDs(); ok {
		for _, id := range mapIDs {
			maps[id] = true
		}
	}
	return observed, nil
}

func inspectMap(m *ebpf.Map) (kernelMap, error) {
	info, err := m.Info()
	if err != nil {
		return kernelMap{}, err
	}
	id, _ := info.ID()
	observed := kernelMap{ID: id, Name: info.Name, MaxEntries: info.MaxEntries, KeyBytes: info.KeySize, ValueBytes: info.ValueSize}
	fdinfo, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", m.FD()))
	if err != nil {
		return kernelMap{}, err
	}
	for _, line := range strings.Split(string(fdinfo), "\n") {
		if value, ok := strings.CutPrefix(line, "memlock:"); ok {
			memlock, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return kernelMap{}, err
			}
			observed.Memlock = &memlock
		}
	}
	return observed, nil
}

func observeMaps(id ebpf.MapID) ([]kernelMap, error) {
	m, err := ebpf.NewMapFromID(id)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	outer, err := inspectMap(m)
	if err != nil {
		return nil, err
	}
	if m.Type() != ebpf.ArrayOfMaps {
		return []kernelMap{outer}, nil
	}

	var inner *ebpf.Map
	if err := m.Lookup(uint32(0), &inner); err != nil {
		return nil, fmt.Errorf("observeMaps: reading active generation: %w", err)
	}
	defer inner.Close()
	active, err := inspectMap(inner)
	if err != nil {
		return nil, err
	}
	return []kernelMap{outer, active}, nil
}

func observe(ifaceName string) (snapshot, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return snapshot{}, err
	}
	result := snapshot{Ingress: []program{}, Egress: []program{}, Maps: []kernelMap{}}
	maps := make(map[ebpf.MapID]bool)
	for _, hook := range []struct {
		attach ebpf.AttachType
		target *[]program
	}{{ebpf.AttachTCXIngress, &result.Ingress}, {ebpf.AttachTCXEgress, &result.Egress}} {
		attached, err := link.QueryPrograms(link.QueryOptions{Target: iface.Index, Attach: hook.attach})
		if err != nil {
			return snapshot{}, err
		}
		for _, p := range attached.Programs {
			info, err := inspectProgram(p, maps)
			if err != nil {
				return snapshot{}, err
			}
			*hook.target = append(*hook.target, info)
		}
	}
	for id := range maps {
		observed, err := observeMaps(id)
		if err != nil {
			return snapshot{}, err
		}
		result.Maps = append(result.Maps, observed...)
	}
	return result, nil
}

func holdStats() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	handle, err := ebpf.EnableStats(0) // BPF_STATS_RUN_TIME
	if err != nil {
		return err
	}
	fmt.Println("runtime statistics enabled")
	<-ctx.Done()
	return handle.Close()
}

func run() error {
	iface := flag.String("interface", "", "isolated interface to query")
	stats := flag.Bool("hold-stats", false, "hold a BPF_ENABLE_STATS runtime descriptor until signalled")
	flag.Parse()
	if *stats && *iface == "" {
		return holdStats()
	}
	if *iface == "" || *stats {
		return errors.New("choose --interface or --hold-stats")
	}
	snap, err := observe(*iface)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(snap)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
