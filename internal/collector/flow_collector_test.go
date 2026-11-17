package collector

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/sudhanshu-singh/argus/internal/bpf"
	"github.com/sudhanshu-singh/argus/internal/store"
)

func TestBuildFlow(t *testing.T) {
	key := bpf.FlowKey{
		SrcIp:    binary.NativeEndian.Uint32([]byte{198, 18, 0, 1}),
		DstIp:    binary.NativeEndian.Uint32([]byte{198, 18, 0, 2}),
		SrcPort:  binary.NativeEndian.Uint16([]byte{0xc0, 0x01}),
		DstPort:  binary.NativeEndian.Uint16([]byte{0, 53}),
		Protocol: 17,
	}
	clock := flowClock{wall: time.Now(), monoNS: 5000001, recent: 3 * time.Millisecond}
	metrics := bpf.FlowMetrics{
		PktsEgress: 1 << 33, FirstSeenNs: 1, LastSeenNs: 2500001, L7Proto: 3,
	}
	flow := buildFlow(key, metrics, clock)
	if flow.SrcIP != (store.IPv4{198, 18, 0, 1}) || flow.DstIP != (store.IPv4{198, 18, 0, 2}) ||
		flow.SrcPort != 49153 || flow.DstPort != 53 || flow.Protocol != "UDP" ||
		flow.L7Protocol != "DNS" || flow.PktsEgress != 1<<33 ||
		flow.DurationMs != 2.5 || flow.LatencyMs != 0 || flow.PID != 0 ||
		!flow.LastSeen.Equal(clock.wall.Add(-2500*time.Microsecond)) || !flow.Recent {
		t.Fatalf("incorrect decoded flow: %+v", flow)
	}
	clock.monoNS += 4 * uint64(time.Millisecond)
	if buildFlow(key, metrics, clock).Recent {
		t.Fatal("idle tuple marked recent")
	}
}
