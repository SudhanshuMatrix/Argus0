//go:build linux

package bpf

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

func openTestObjects(t *testing.T, capacity uint32) *NetworkStatsObjects {
	t.Helper()
	if os.Getenv("ARGUS_BPF_TEST") != "1" {
		t.Skip("set ARGUS_BPF_TEST=1 in a privileged Linux test environment")
	}
	spec, err := LoadNetworkStats()
	if err != nil {
		t.Fatal(err)
	}
	spec.Maps["flow_map"].MaxEntries = capacity
	var objects NetworkStatsObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := objects.Close(); err != nil {
			t.Error(err)
		}
	})
	return &objects
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
		want    uint8
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
			runProgram(t, objects.TcIngress, packet)
			var got FlowMetrics
			if err := objects.FlowMap.Lookup(key, &got); err != nil {
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
		runProgram(t, objects.TcIngress, packet)
		var got FlowMetrics
		if err := objects.FlowMap.Lookup(key, &got); err != nil || got.L7Proto != 0 {
			t.Fatalf("flow %+v; error %v", got, err)
		}
	})
}

func TestKernelFlowMapCapacity(t *testing.T) {
	objects := openTestObjects(t, 2)
	first, key := frame(17, 20000, 20001, []byte("one"))
	second, _ := frame(17, 20002, 20001, []byte("two"))
	overflow, _ := frame(17, 20003, 20001, []byte("three"))
	runProgram(t, objects.TcIngress, first)
	runProgram(t, objects.TcIngress, second)
	runProgram(t, objects.TcIngress, overflow)
	runProgram(t, objects.TcEgress, first)

	var got FlowMetrics
	if err := objects.FlowMap.Lookup(key, &got); err != nil {
		t.Fatal(err)
	}
	if got.PktsIngress != 1 || got.PktsEgress != 1 {
		t.Fatalf("existing flow should keep counting when full: %+v", got)
	}
	failures, err := readFlowUpdateFailures(objects.FlowUpdateFailures)
	if err != nil || failures != 1 {
		t.Fatalf("flow update failures = %d, %v; want 1", failures, err)
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
	check := func(want int) {
		t.Helper()
		for _, direction := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
			result, err := link.QueryPrograms(link.QueryOptions{Target: iface.Index, Attach: direction})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Programs) != want {
				t.Errorf("%s: got %d TCX programs, want %d", direction, len(result.Programs), want)
			}
		}
	}
	check(0)
	objects, err := Load(name, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objects.Close() })
	check(1)
	if err := objects.Close(); err != nil {
		t.Fatal(err)
	}
	check(0)
}
