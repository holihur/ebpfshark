package capture

import "github.com/cilium/ebpf"

// bpfObjects is the common surface of the small (2 KiB) and large (256 KiB)
// capture objects. Both are generated from capture.c; only the ring entry size
// differs.
type bpfObjects interface {
	IngressProgram() *ebpf.Program
	EgressProgram() *ebpf.Program
	ConfigMap() *ebpf.Map
	StatsMap() *ebpf.Map
	EventsMap() *ebpf.Map
	Close() error
}

func (o *captureObjects) IngressProgram() *ebpf.Program { return o.CaptureIngress }
func (o *captureObjects) EgressProgram() *ebpf.Program  { return o.CaptureEgress }
func (o *captureObjects) ConfigMap() *ebpf.Map          { return o.CaptureCfg }
func (o *captureObjects) StatsMap() *ebpf.Map           { return o.Stats }
func (o *captureObjects) EventsMap() *ebpf.Map          { return o.Events }

func (o *capture_largeObjects) IngressProgram() *ebpf.Program { return o.CaptureIngress }
func (o *capture_largeObjects) EgressProgram() *ebpf.Program  { return o.CaptureEgress }
func (o *capture_largeObjects) ConfigMap() *ebpf.Map          { return o.CaptureCfg }
func (o *capture_largeObjects) StatsMap() *ebpf.Map           { return o.Stats }
func (o *capture_largeObjects) EventsMap() *ebpf.Map          { return o.Events }
