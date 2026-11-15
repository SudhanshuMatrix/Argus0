// Package bpf loads and attaches the embedded Argus programs.
package bpf

import (
	"errors"
	"fmt"
	"net"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

// Objects owns the loaded programs, maps and TCX links.
type Objects struct {
	bpfObjs NetworkStatsObjects
	ingress link.Link
	egress  link.Link
}

type FlowKey = NetworkStatsFlowKeyT
type FlowMetrics = NetworkStatsFlowMetricsT

// Load attaches both programs without configuring a legacy clsact qdisc.
func Load(ifaceName string, log *logrus.Logger) (*Objects, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("Linux is required for eBPF and TCX (running on %s)", runtime.GOOS)
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("finding interface %q: %w", ifaceName, err)
	}
	objs := &Objects{}
	if err := LoadNetworkStatsObjects(&objs.bpfObjs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	objs.ingress, err = link.AttachTCX(link.TCXOptions{
		Interface: iface.Index, Program: objs.bpfObjs.TcIngress, Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("attaching ingress TCX link: %w", err), objs.Close())
	}

	objs.egress, err = link.AttachTCX(link.TCXOptions{
		Interface: iface.Index, Program: objs.bpfObjs.TcEgress, Attach: ebpf.AttachTCXEgress,
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("attaching egress TCX link: %w", err), objs.Close())
	}

	log.WithField("interface", ifaceName).Info("Attached ingress and egress TCX programs")
	return objs, nil
}

func (o *Objects) FlowMap() *ebpf.Map {
	return o.bpfObjs.FlowMap
}

// FlowUpdateFailures returns the sum of the cumulative per-CPU counters.
func (o *Objects) FlowUpdateFailures() (uint64, error) {
	return readFlowUpdateFailures(o.bpfObjs.FlowUpdateFailures)
}

func readFlowUpdateFailures(m *ebpf.Map) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, count := range perCPU {
		total += count
	}
	return total, nil
}

// Close detaches the TCX links and releases the programs and maps.
func (o *Objects) Close() error {
	var err error
	if o.egress != nil {
		err = o.egress.Close()
		o.egress = nil
	}
	if o.ingress != nil {
		err = errors.Join(err, o.ingress.Close())
		o.ingress = nil
	}
	if o.bpfObjs.FlowMap != nil {
		err = errors.Join(err, o.bpfObjs.Close())
		o.bpfObjs = NetworkStatsObjects{}
	}
	return err
}
