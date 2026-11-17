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

type kernelObjects struct {
	TcIngress          *ebpf.Program `ebpf:"tc_ingress"`
	TcEgress           *ebpf.Program `ebpf:"tc_egress"`
	FlowMaps           *ebpf.Map     `ebpf:"flow_maps"`
	Observations       *ebpf.Map     `ebpf:"observations"`
	FlowUpdateFailures *ebpf.Map     `ebpf:"flow_update_failures"`
}

// Objects owns the embedded programs, maps and TCX links.
type Objects struct {
	bpfObjs   kernelObjects
	ingress   link.Link
	egress    link.Link
	ifaceName string
	ifIndex   uint32
	flowSpec  *ebpf.MapSpec
	flowMap   *ebpf.Map
}

type FlowKey = NetworkStatsFlowKeyT
type FlowMetrics = NetworkStatsFlowMetricsT

type ObservationCount struct {
	Bytes   uint64
	Packets uint64
}

// ObservationTotals contains process-lifetime per-hook counts from the kernel.
// In each traffic pair, element zero is ingress and element one is egress.
type ObservationTotals struct {
	TCP, UDP           [2]ObservationCount
	Malformed          uint64
	Unsupported        uint64
	AccountingFailures uint64
}

// Load attaches both programs without configuring a legacy clsact qdisc.
func Load(ifaceName string, capacity uint32, log *logrus.Logger) (*Objects, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("Linux is required for eBPF and TCX (running on %s)", runtime.GOOS)
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("finding interface %q: %w", ifaceName, err)
	}
	objs, err := openObjects(capacity)
	if err != nil {
		return nil, err
	}
	objs.ifaceName, objs.ifIndex = ifaceName, uint32(iface.Index)
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

func openObjects(capacity uint32) (*Objects, error) {
	if capacity == 0 {
		return nil, errors.New("flow map capacity must be positive")
	}
	spec, err := LoadNetworkStats()
	if err != nil {
		return nil, fmt.Errorf("reading embedded BPF objects: %w", err)
	}
	outer := spec.Maps["flow_maps"]
	if outer == nil || outer.InnerMap == nil {
		return nil, errors.New("embedded BPF object has no flow map template")
	}
	inner := outer.InnerMap.Copy()
	inner.Name = "flow_map"
	inner.MaxEntries = capacity
	outer.InnerMap = inner
	flowMap, err := ebpf.NewMap(inner)
	if err != nil {
		return nil, fmt.Errorf("openObjects: allocating initial flow generation: %w", err)
	}
	outer.Contents = []ebpf.MapKV{{Key: uint32(0), Value: flowMap}}
	objs := &Objects{flowSpec: inner, flowMap: flowMap}
	if err := spec.LoadAndAssign(&objs.bpfObjs, nil); err != nil {
		return nil, errors.Join(fmt.Errorf("openObjects: loading eBPF objects: %w", err), flowMap.Close())
	}
	return objs, nil
}

func (o *Objects) FlowMap() *ebpf.Map { return o.flowMap }

// RotateFlowMap installs an empty map. The caller owns the previous map,
// whose writers have drained by the time the outer-map update returns.
func (o *Objects) RotateFlowMap() (*ebpf.Map, error) {
	next, err := ebpf.NewMap(o.flowSpec)
	if err != nil {
		return nil, fmt.Errorf("RotateFlowMap: allocating flow generation: %w", err)
	}
	if err := o.bpfObjs.FlowMaps.Put(uint32(0), next); err != nil {
		return nil, errors.Join(fmt.Errorf("RotateFlowMap: installing flow generation: %w", err), next.Close())
	}
	previous := o.flowMap
	o.flowMap = next
	return previous, nil
}

func (o *Objects) CheckInterface() error {
	for _, attachment := range []struct {
		direction string
		link      link.Link
	}{{"ingress", o.ingress}, {"egress", o.egress}} {
		if attachment.link == nil {
			return fmt.Errorf("%s TCX link on %q is closed", attachment.direction, o.ifaceName)
		}
		info, err := attachment.link.Info()
		if err != nil {
			return fmt.Errorf("CheckInterface: checking %s TCX link on %q: %w", attachment.direction, o.ifaceName, err)
		}
		if tcx := info.TCX(); tcx == nil || tcx.Ifindex != o.ifIndex {
			return fmt.Errorf("%s TCX link detached from %q", attachment.direction, o.ifaceName)
		}
	}
	return nil
}

func (o *Objects) ObservationTotals() (ObservationTotals, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return ObservationTotals{}, err
	}
	perCPU := make([]ObservationCount, cpus)
	var values [7]ObservationCount
	for i := range values {
		if err := o.bpfObjs.Observations.Lookup(uint32(i), perCPU); err != nil {
			return ObservationTotals{}, fmt.Errorf("ObservationTotals: reading counter %d: %w", i, err)
		}
		for _, count := range perCPU {
			values[i].Bytes += count.Bytes
			values[i].Packets += count.Packets
		}
	}
	return ObservationTotals{
		TCP:                [2]ObservationCount{values[0], values[1]},
		UDP:                [2]ObservationCount{values[2], values[3]},
		Malformed:          values[4].Packets,
		Unsupported:        values[5].Packets,
		AccountingFailures: values[6].Packets,
	}, nil
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
	if o.flowMap != nil {
		err = errors.Join(err, o.flowMap.Close())
		o.flowMap = nil
	}
	if o.bpfObjs.FlowMaps != nil {
		err = errors.Join(err,
			o.bpfObjs.TcIngress.Close(), o.bpfObjs.TcEgress.Close(),
			o.bpfObjs.FlowMaps.Close(), o.bpfObjs.Observations.Close(), o.bpfObjs.FlowUpdateFailures.Close())
		o.bpfObjs = kernelObjects{}
	}
	return err
}
