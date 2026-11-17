//go:build linux

package bpf

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

func openTestObjects(t *testing.T, capacity uint32) *Objects {
	t.Helper()
	if os.Getenv("ARGUS_BPF_TEST") != "1" {
		t.Skip("set ARGUS_BPF_TEST=1 in a privileged Linux test environment")
	}
	objects, err := openObjects(capacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := objects.Close(); err != nil {
			t.Error(err)
		}
	})
	return objects
}

func frame(protocol byte, source, destination uint16, payload []byte) ([]byte, FlowKey) {
	headerSize := 20
	if protocol == 17 {
		headerSize = 8
	}
	packet := make([]byte, 14+20+headerSize+len(payload))
	binary.BigEndian.PutUint16(packet[12:], 0x0800)
	ip := packet[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(ip[2:], uint16(len(packet)-14))
	copy(ip[12:], []byte{198, 18, 0, 1, 198, 18, 0, 2})
	l4 := packet[34:]
	binary.BigEndian.PutUint16(l4, source)
	binary.BigEndian.PutUint16(l4[2:], destination)
	if protocol == 17 {
		binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
	} else {
		l4[12] = 0x50
	}
	copy(l4[headerSize:], payload)
	return packet, FlowKey{
		SrcIp: binary.NativeEndian.Uint32(ip[12:]), DstIp: binary.NativeEndian.Uint32(ip[16:]),
		SrcPort: binary.NativeEndian.Uint16(l4), DstPort: binary.NativeEndian.Uint16(l4[2:]),
		Protocol: protocol,
	}
}

func runProgram(t *testing.T, prog *ebpf.Program, packet []byte) {
	t.Helper()
	result, _, err := prog.Test(packet)
	if err != nil || result != ^uint32(0) {
		t.Fatalf("TCX_NEXT expected, got result %#x and error %v", result, err)
	}
}

func TestKernelProtocolDetection(t *testing.T) {
	objects := openTestObjects(t, 64)
	query := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	tests := []struct {
		name    string
		proto   byte
		port    uint16
		payload []byte
		want    uint32
	}{
		{"HTTP", 6, 1234, []byte("POST / HTTP/1.1\r\n\r\n"), 1},
		{"HTTP prefix only", 6, 80, []byte("POSTER"), 0},
		{"TLS", 6, 1234, []byte{0x16, 3, 3, 0, 4, 1, 0, 0, 0}, 2},
		{"TLS invalid size", 6, 443, []byte{0x16, 3, 3, 0, 1}, 0},
		{"SSH", 6, 1234, []byte("SSH-2.0-example\r\n"), 4},
		{"UDP DNS", 17, 53, query, 3},
		{"TCP DNS", 6, 53, append([]byte{0, byte(len(query))}, query...), 3},
		{"misleading DNS port", 17, 53, []byte("arbitrary bytes"), 0},
		{"empty DNS TCP packet", 6, 53, nil, 0},
		{"misleading HTTPS port", 6, 443, []byte("arbitrary bytes"), 0},
		{"misleading SSH port", 6, 22, []byte("arbitrary bytes"), 0},
		{"HTTP bytes over UDP", 17, 80, []byte("GET / HTTP/1.1"), 0},
	}
	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet, key := frame(test.proto, uint16(20000+i), test.port, test.payload)
			runProgram(t, objects.bpfObjs.TcIngress, packet)
			var got FlowMetrics
			if err := objects.FlowMap().Lookup(key, &got); err != nil {
				t.Fatal(err)
			}
			if got.L7Proto != test.want || got.PktsIngress != 1 || got.PktsEgress != 0 {
				t.Fatalf("got %+v, expected protocol %d and one ingress packet", got, test.want)
			}
		})
	}

	t.Run("padding past UDP header is ignored", func(t *testing.T) {
		packet, key := frame(17, 21000, 53, query)
		binary.BigEndian.PutUint16(packet[38:], 8)
		runProgram(t, objects.bpfObjs.TcIngress, packet)
		var got FlowMetrics
		if err := objects.FlowMap().Lookup(key, &got); err != nil || got.L7Proto != 0 {
			t.Fatalf("flow %+v; error %v", got, err)
		}
	})
}

func TestKernelFlowMapCapacity(t *testing.T) {
	objects := openTestObjects(t, 2)
	first, key := frame(17, 20000, 20001, []byte("one"))
	second, _ := frame(17, 20002, 20001, []byte("two"))
	overflow, _ := frame(17, 20003, 20001, []byte("three"))
	runProgram(t, objects.bpfObjs.TcIngress, first)
	runProgram(t, objects.bpfObjs.TcIngress, second)
	runProgram(t, objects.bpfObjs.TcIngress, overflow)
	runProgram(t, objects.bpfObjs.TcEgress, first)

	var got FlowMetrics
	if err := objects.FlowMap().Lookup(key, &got); err != nil {
		t.Fatal(err)
	}
	if got.PktsIngress != 1 || got.PktsEgress != 1 {
		t.Fatalf("existing flow should keep counting when full: %+v", got)
	}
	failures, err := objects.FlowUpdateFailures()
	if err != nil || failures != 1 {
		t.Fatalf("flow update failures = %d, %v; want 1", failures, err)
	}
	totals, err := objects.ObservationTotals()
	wantUDP := [2]ObservationCount{
		{Bytes: uint64(len(first) + len(second) + len(overflow)), Packets: 3},
		{Bytes: uint64(len(first)), Packets: 1},
	}
	if err != nil || totals.UDP != wantUDP {
		t.Fatalf("eligible UDP observations = %+v, %v; want %+v", totals.UDP, err, wantUDP)
	}
}

func TestKernelTCXLifecycle(t *testing.T) {
	if os.Getenv("ARGUS_BPF_TEST") != "1" {
		t.Skip("requires privileged Linux")
	}
	name := os.Getenv("ARGUS_TEST_INTERFACE")
	if name == "" {
		t.Skip("set ARGUS_TEST_INTERFACE to a task-owned isolated interface")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	check := func(wantIngress, wantEgress int, preserved ebpf.ProgramID) {
		t.Helper()
		directions := []struct {
			attach ebpf.AttachType
			want   int
		}{
			{ebpf.AttachTCXIngress, wantIngress},
			{ebpf.AttachTCXEgress, wantEgress},
		}
		for _, direction := range directions {
			result, err := link.QueryPrograms(link.QueryOptions{Target: iface.Index, Attach: direction.attach})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Programs) != direction.want {
				t.Fatalf("%s: got %d TCX programs, want %d", direction.attach, len(result.Programs), direction.want)
			}
			if direction.attach == ebpf.AttachTCXIngress && preserved != 0 {
				if len(result.Programs) == 0 || result.Programs[0].ID != preserved {
					t.Errorf("existing ingress TCX program %d missing from the head of the chain", preserved)
				}
			}
		}
	}
	check(0, 0, 0)
	other, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS, AttachType: ebpf.AttachTCXIngress, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index, Program: other, Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = otherLink.Close() })
	info, err := otherLink.Info()
	if err != nil {
		t.Fatal(err)
	}
	check(1, 0, info.Program)

	objects, err := Load(name, 64, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objects.Close() })
	check(2, 1, info.Program)
	if err := objects.CheckInterface(); err != nil {
		t.Fatal(err)
	}
	if err := objects.Close(); err != nil {
		t.Fatal(err)
	}
	check(1, 0, info.Program)
	if err := otherLink.Close(); err != nil {
		t.Fatal(err)
	}
	check(0, 0, 0)
}

func TestKernelObservationScope(t *testing.T) {
	objects := openTestObjects(t, 4)
	first, key := frame(6, 20000, 80, nil)
	http, _ := frame(6, 20000, 80, []byte("GET / HTTP/1.1"))
	ssh, _ := frame(6, 20000, 80, []byte("SSH-2.0"))
	malformed := append([]byte(nil), first...)
	binary.BigEndian.PutUint16(malformed[16:], 0)
	unsupported := append([]byte(nil), first...)
	binary.BigEndian.PutUint16(unsupported[12:], 0x86dd)

	for _, packet := range [][]byte{first, http, ssh, malformed, unsupported} {
		runProgram(t, objects.bpfObjs.TcIngress, packet)
	}
	totals, err := objects.ObservationTotals()
	want := ObservationTotals{
		TCP:       [2]ObservationCount{{Bytes: uint64(len(first) + len(http) + len(ssh)), Packets: 3}},
		Malformed: 1, Unsupported: 1,
	}
	if err != nil || totals != want {
		t.Fatalf("observation totals = %+v, %v; want %+v", totals, err, want)
	}
	var got FlowMetrics
	if err := objects.FlowMap().Lookup(key, &got); err != nil {
		t.Fatal(err)
	}
	if got.L7Proto != 1 || got.PktsIngress != 3 || got.FirstSeenNs == 0 || got.LastSeenNs < got.FirstSeenNs {
		t.Fatalf("first recognized L7 protocol and valid observation span expected: %+v", got)
	}
}

func TestKernelFlowMapRotation(t *testing.T) {
	objects := openTestObjects(t, 2)
	active, activeKey := frame(17, 20100, 20001, []byte("active"))
	program := objects.bpfObjs.TcIngress
	var bytesTotal, packetsTotal uint64
	var previous FlowKey
	var previousSeen uint64
	for window := range 24 {
		idle, idleKey := frame(17, uint16(20000+window), 20001, []byte("idle"))
		runProgram(t, program, active)
		runProgram(t, program, idle)
		bytesTotal += uint64(len(active) + len(idle))
		packetsTotal += 2

		sealed, err := objects.RotateFlowMap()
		if err != nil {
			t.Fatal(err)
		}
		t.Run("sealed", func(t *testing.T) {
			defer sealed.Close()
			var got FlowMetrics
			if err := sealed.Lookup(activeKey, &got); err != nil || got.PktsIngress != 1 ||
				got.FirstSeenNs <= previousSeen || got.LastSeenNs != got.FirstSeenNs {
				t.Fatalf("reused tuple has a separate lifetime in each window: %+v, %v", got, err)
			}
			previousSeen = got.FirstSeenNs
			if err := sealed.Lookup(idleKey, &got); err != nil || got.PktsIngress != 1 {
				t.Fatalf("new tuple should be admitted in each window: %+v, %v", got, err)
			}
			if window > 0 {
				if err := sealed.Lookup(previous, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("idle tuple persisted into the next window: %v", err)
				}
			}
			previous = idleKey
			if err := objects.FlowMap().Lookup(activeKey, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("replacement map should be empty: %v", err)
			}
		})
	}
	totals, err := objects.ObservationTotals()
	want := ObservationCount{Bytes: bytesTotal, Packets: packetsTotal}
	if err != nil || totals.UDP[0] != want {
		t.Fatalf("observations across windows = %+v, %v; want %+v", totals.UDP[0], err, want)
	}
	failures, err := objects.FlowUpdateFailures()
	if failures != 0 || err != nil {
		t.Fatalf("flow update failures = %d, %v; want 0", failures, err)
	}
}

func TestKernelConcurrentRotation(t *testing.T) {
	objects := openTestObjects(t, 2)
	packet, key := frame(17, 20000, 20001, []byte("active"))
	program := objects.bpfObjs.TcIngress
	runProgram(t, program, packet)

	const concurrent = 64
	done := make(chan error, concurrent)
	for range concurrent {
		go func() {
			_, _, err := program.Test(packet)
			done <- err
		}()
	}
	sealed, rotateErr := objects.RotateFlowMap()
	for range concurrent {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	if rotateErr != nil {
		t.Fatal(rotateErr)
	}
	defer sealed.Close()
	runProgram(t, program, packet)

	var first, second FlowMetrics
	if err := sealed.Lookup(key, &first); err != nil {
		t.Fatal(err)
	}
	if err := objects.FlowMap().Lookup(key, &second); err != nil {
		t.Fatal(err)
	}
	wantPackets := uint64(concurrent + 2)
	wantBytes := wantPackets * uint64(len(packet))
	if first.PktsIngress+second.PktsIngress != wantPackets || first.BytesIngress+second.BytesIngress != wantBytes ||
		first.LastSeenNs < first.FirstSeenNs || second.LastSeenNs < second.FirstSeenNs {
		t.Fatalf("inconsistent concurrent rotation: %+v + %+v, want %d packets and %d bytes", first, second, wantPackets, wantBytes)
	}
	totals, err := objects.ObservationTotals()
	if err != nil || totals.UDP[0] != (ObservationCount{Bytes: wantBytes, Packets: wantPackets}) {
		t.Fatalf("concurrent observations = %+v, %v; want %d packets and %d bytes", totals.UDP[0], err, wantPackets, wantBytes)
	}
}
