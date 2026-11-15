package collector

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/sudhanshu-singh/argus/internal/bpf"
)

func TestBuildFlow(t *testing.T) {
	key := bpf.FlowKey{
		SrcIp:    binary.NativeEndian.Uint32([]byte{198, 18, 0, 1}),
		DstIp:    binary.NativeEndian.Uint32([]byte{198, 18, 0, 2}),
		SrcPort:  binary.NativeEndian.Uint16([]byte{0xc0, 0x01}),
		DstPort:  binary.NativeEndian.Uint16([]byte{0, 53}),
		Protocol: 17,
	}
	flow := buildFlow(key, bpf.FlowMetrics{
		PktsEgress: 1 << 33, FirstSeenNs: 1, LastSeenNs: 2500001, L7Proto: 3,
	}, time.Now())
	if flow.SrcIP != "198.18.0.1" || flow.DstIP != "198.18.0.2" ||
		flow.SrcPort != 49153 || flow.DstPort != 53 || flow.Protocol != "UDP" ||
		flow.L7Protocol != "DNS" || flow.PktsEgress != 1<<33 ||
		flow.DurationMs != 2.5 || flow.LatencyMs != 0 || flow.PID != 0 {
		t.Fatalf("incorrect decoded flow: %+v", flow)
	}
}
