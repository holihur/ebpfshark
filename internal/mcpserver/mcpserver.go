// Package mcpserver exposes ebpfshark's capture data and controls as Model
// Context Protocol tools. The same server works over stdio and streamable HTTP.
package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ebpfshark/internal/capture"
	"ebpfshark/internal/decode"
	"ebpfshark/internal/filter"
	"ebpfshark/internal/instrument/target"
	"ebpfshark/internal/packet"
	"ebpfshark/internal/store"
	"ebpfshark/internal/stream"
	"ebpfshark/internal/trace"
)

// TraceController is implemented by the HTTP server for function tracing.
type TraceController interface {
	StartTrace(pid int, functions string) error
	StopTrace()
	TraceStatus() trace.Status
	TraceEvents(limit int, after uint64) ([]trace.Event, trace.Status)
}

// New creates an MCP server bound to the live store and capture manager.
// apiPort is excluded from captures when the MCP client starts one.
func New(st *store.Store, mgr *capture.Manager, version string, apiPort uint32, traceCtl ...TraceController) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:        "ebpfshark",
		Title:       "ebpfshark",
		Description: "eBPF packet capture and protocol analysis for Linux",
		Version:     version,
	}, &mcp.ServerOptions{
		Instructions: "ebpfshark captures packets with eBPF on Linux. " +
			"Use get_status and list_interfaces first, then start_capture. " +
			"query_packets accepts Wireshark-style display filters (e.g. 'tcp port 443 and not arp'). " +
			"follow_stream reassembles TCP payloads for a packet id. " +
			"Capture tools require root or CAP_BPF/CAP_NET_ADMIN.",
	})

	addStatusTool(srv, st, mgr, version)
	addInterfaceTool(srv)
	addCaptureTools(srv, st, mgr, apiPort)
	addPacketTools(srv, st)
	addAnalysisTools(srv, st)
	if len(traceCtl) > 0 && traceCtl[0] != nil {
		addTraceTools(srv, traceCtl[0])
	}
	return srv
}

// ---------------------------------------------------------------- helpers

func textResult(v any) (*mcp.CallToolResult, any, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

type packetSummary struct {
	ID        uint64   `json:"id"`
	Time      int64    `json:"time"`
	Iface     string   `json:"iface"`
	Direction string   `json:"direction"`
	Len       uint32   `json:"len"`
	CapLen    uint32   `json:"capLen"`
	Truncated bool     `json:"truncated,omitempty"`
	Protocol  string   `json:"protocol"`
	Layers    []string `json:"layers"`
	Src       string   `json:"src"`
	Dst       string   `json:"dst"`
	SrcIP     string   `json:"srcIp,omitempty"`
	DstIP     string   `json:"dstIp,omitempty"`
	SrcPort   uint16   `json:"srcPort,omitempty"`
	DstPort   uint16   `json:"dstPort,omitempty"`
	Info      string   `json:"info"`
}

func summarise(p *packet.Packet) packetSummary {
	layers := p.Summary.Layers
	if layers == nil {
		layers = []string{}
	}
	return packetSummary{
		ID:        p.ID,
		Time:      p.Time.UnixNano(),
		Iface:     p.IfName,
		Direction: p.Direction.String(),
		Len:       p.WireLen,
		CapLen:    p.CapLen,
		Truncated: p.Truncated,
		Protocol:  p.Summary.Protocol,
		Layers:    layers,
		Src:       p.Summary.Src,
		Dst:       p.Summary.Dst,
		SrcIP:     p.Summary.SrcIP,
		DstIP:     p.Summary.DstIP,
		SrcPort:   p.Summary.SrcPort,
		DstPort:   p.Summary.DstPort,
		Info:      p.Summary.Info,
	}
}

// ------------------------------------------------------------------- tools

type statusOutput struct {
	Version    string              `json:"version"`
	Capture    capture.Status      `json:"capture"`
	Store      store.Stats         `json:"store"`
	Interfaces []capture.Interface `json:"interfaces"`
	ServerTime int64               `json:"serverTime"`
}

func addStatusTool(srv *mcp.Server, st *store.Store, mgr *capture.Manager, version string) {
	type empty struct{}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_status",
		Description: "Get capture status, buffer statistics, TCP stream reassembly stats, and network interfaces.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, any, error) {
		ifaces, err := capture.ListInterfaces()
		if err != nil {
			ifaces = []capture.Interface{}
		}
		return textResult(statusOutput{
			Version:    version,
			Capture:    mgr.Status(),
			Store:      st.Stats(),
			Interfaces: ifaces,
			ServerTime: time.Now().UnixNano(),
		})
	})
}

type interfacesOutput struct {
	Interfaces []capture.Interface `json:"interfaces"`
}

func addInterfaceTool(srv *mcp.Server) {
	type empty struct{}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_interfaces",
		Description: "List network interfaces available for capture, with addresses, state and default-route flag.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, any, error) {
		ifaces, err := capture.ListInterfaces()
		if err != nil {
			return nil, nil, err
		}
		return textResult(interfacesOutput{Interfaces: ifaces})
	})
}

type startCaptureInput struct {
	Interfaces []string `json:"interfaces" jsonschema:"interface names to capture on, e.g. [\"eth0\"]"`
	Snaplen    uint32   `json:"snaplen,omitempty" jsonschema:"bytes captured per packet (default 2048, max 262144)"`
	SampleRate uint32   `json:"sampleRate,omitempty" jsonschema:"capture 1 out of every N packets (default 1)"`
	RingSize   uint32   `json:"ringSize,omitempty" jsonschema:"BPF ring buffer size in bytes (default 32 MiB)"`
	Clear      bool     `json:"clear,omitempty" jsonschema:"clear the packet buffer before starting"`
	Cgroup     string   `json:"cgroup,omitempty" jsonschema:"capture only sockets in a cgroup: ID, path, pid:N, pod:NAME or container:ID"`
	Filter     string   `json:"filter,omitempty" jsonschema:"optional display filter; its safe L2-L4 subset is applied in the kernel"`
}

func addCaptureTools(srv *mcp.Server, st *store.Store, mgr *capture.Manager, apiPort uint32) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "start_capture",
		Description: "Start eBPF capture on one or more interfaces. Replaces any running capture. Requires root or CAP_BPF.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in startCaptureInput) (*mcp.CallToolResult, any, error) {
		if len(in.Interfaces) == 0 {
			return nil, nil, fmt.Errorf("interfaces must contain at least one interface name")
		}
		if in.Snaplen == 0 {
			in.Snaplen = 2048
			if in.Snaplen > capture.MaxSnaplen {
				in.Snaplen = capture.MaxSnaplen
			}
		}
		if in.SampleRate == 0 {
			in.SampleRate = 1
		}
		var cgroupID uint64
		if in.Cgroup != "" {
			var err error
			cgroupID, err = capture.ResolveCgroup(in.Cgroup)
			if err != nil {
				return nil, nil, err
			}
		}
		var captureFilter filter.CaptureSpec
		if in.Filter != "" {
			var err error
			captureFilter, err = filter.CompileCapture(in.Filter)
			if err != nil {
				return nil, nil, err
			}
		}
		if in.Clear {
			st.Clear()
		}
		if err := mgr.Start(capture.Options{
			Interfaces:    in.Interfaces,
			Snaplen:       in.Snaplen,
			SampleRate:    in.SampleRate,
			RingSize:      in.RingSize,
			ExcludePort:   apiPort,
			CgroupID:      cgroupID,
			CaptureFilter: captureFilter,
		}); err != nil {
			return nil, nil, err
		}
		return textResult(mgr.Status())
	})

	type empty struct{}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "stop_capture",
		Description: "Stop the current eBPF capture session. Buffered packets remain available.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, any, error) {
		mgr.Stop()
		return textResult(mgr.Status())
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "clear_capture",
		Description: "Clear buffered packets, statistics, conversations and reassembled streams. Capture keeps running.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, any, error) {
		st.Clear()
		return textResult(map[string]any{"ok": true})
	})
}

type queryPacketsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"Wireshark-style display filter, e.g. tcp port 443 and not arp"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum packets to return (default 100, max 1000)"`
}

type packetsOutput struct {
	Count   int             `json:"count"`
	Stored  int             `json:"stored"`
	Packets []packetSummary `json:"packets"`
}

type packetInput struct {
	ID         uint64 `json:"id" jsonschema:"packet number from query_packets"`
	IncludeRaw bool   `json:"includeRaw,omitempty" jsonschema:"include the captured frame as base64"`
}

type packetDetailOutput struct {
	Packet   packetSummary   `json:"packet"`
	Fields   []*decode.Field `json:"fields"`
	LinkType uint32          `json:"linkType"`
	RawBytes int             `json:"rawBytes"`
	RawB64   string          `json:"rawBase64,omitempty"`
}

func addPacketTools(srv *mcp.Server, st *store.Store) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "query_packets",
		Description: "Return the most recent packets matching a display filter, oldest first. Use follow_stream for payloads.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in queryPacketsInput) (*mcp.CallToolResult, any, error) {
		flt, err := filter.Parse(in.Filter)
		if err != nil {
			return nil, nil, err
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 100
		}
		if limit > 1000 {
			limit = 1000
		}
		pkts := st.Snapshot(flt, limit)
		out := make([]packetSummary, 0, len(pkts))
		for _, p := range pkts {
			out = append(out, summarise(p))
		}
		return textResult(packetsOutput{Count: len(out), Stored: st.Stats().Stored, Packets: out})
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_packet",
		Description: "Get one packet with its full decoded protocol tree. Use the id from query_packets.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in packetInput) (*mcp.CallToolResult, any, error) {
		p, ok := st.Get(in.ID)
		if !ok {
			return nil, nil, fmt.Errorf("packet %d not found (it may have been evicted)", in.ID)
		}
		res := decode.Decode(p.Data, p.LinkType, int(p.WireLen))
		out := packetDetailOutput{
			Packet:   summarise(p),
			Fields:   res.Fields,
			LinkType: uint32(p.LinkType),
			RawBytes: len(p.Data),
		}
		if in.IncludeRaw {
			out.RawB64 = base64.StdEncoding.EncodeToString(p.Data)
		}
		return textResult(out)
	})
}

type streamInput struct {
	PacketID      uint64 `json:"packetId" jsonschema:"any packet id belonging to the TCP conversation"`
	MaxBytes      int    `json:"maxBytes,omitempty" jsonschema:"maximum bytes returned per direction (default 65536, max 1048576)"`
	IncludeBase64 bool   `json:"includeBase64,omitempty" jsonschema:"also return raw bytes as base64"`
}

type streamDirectionOutput struct {
	From          stream.Endpoint `json:"from"`
	To            stream.Endpoint `json:"to"`
	CapturedBytes int             `json:"capturedBytes"`
	ReturnedBytes int             `json:"returnedBytes"`
	Truncated     bool            `json:"truncated"`
	Gaps          int             `json:"gaps"`
	Text          string          `json:"text,omitempty"`
	Base64        string          `json:"base64,omitempty"`
}

type streamOutput struct {
	Key   string                `json:"key"`
	A     stream.Endpoint       `json:"a"`
	B     stream.Endpoint       `json:"b"`
	AtoB  streamDirectionOutput `json:"aToB"`
	BtoA  streamDirectionOutput `json:"bToA"`
	First time.Time             `json:"first"`
	Last  time.Time             `json:"last"`
}

func printable(data []byte) string {
	var b strings.Builder
	b.Grow(len(data))
	for _, c := range data {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			b.WriteByte(c)
		case c >= 32 && c <= 126:
			b.WriteByte(c)
		default:
			b.WriteByte('.')
		}
	}
	return b.String()
}

func directionOutput(d stream.Direction, maxBytes int, includeB64 bool) streamDirectionOutput {
	data := d.Data
	if maxBytes > 0 && len(data) > maxBytes {
		data = data[:maxBytes]
	}
	out := streamDirectionOutput{
		From:          d.From,
		To:            d.To,
		CapturedBytes: d.Bytes,
		ReturnedBytes: len(data),
		Truncated:     d.Truncated,
		Gaps:          d.Gaps,
		Text:          printable(data),
	}
	if includeB64 {
		out.Base64 = base64.StdEncoding.EncodeToString(data)
	}
	return out
}

func addTraceTools(srv *mcp.Server, c TraceController) {
	type inspectInput struct {
		PID    int    `json:"pid,omitempty" jsonschema:"target process ID"`
		Binary string `json:"binary,omitempty" jsonschema:"optional binary path; inferred from PID when empty"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "inspect_function_target",
		Description: "Inspect an ELF target for build-id, stripped status, symbol count and debuginfo suggestions before starting a function trace.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in inspectInput) (*mcp.CallToolResult, any, error) {
		info, err := target.Inspect(in.PID, in.Binary)
		if err != nil {
			return nil, nil, err
		}
		return textResult(info)
	})

	type startInput struct {
		PID       int    `json:"pid" jsonschema:"target process ID (0 = all processes loading the binary)"`
		Functions string `json:"functions" jsonschema:"comma separated binary:symbol uprobe targets"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "start_function_trace",
		Description: "Start an experimental uprobe/uretprobe trace for explicit application functions. Requires root/CAP_BPF/CAP_PERFMON and an unstripped or debug-symbol-bearing binary.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in startInput) (*mcp.CallToolResult, any, error) {
		if err := c.StartTrace(in.PID, in.Functions); err != nil {
			return nil, nil, err
		}
		return textResult(c.TraceStatus())
	})

	type empty struct{}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "stop_function_trace",
		Description: "Stop the current function-call trace.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, any, error) {
		c.StopTrace()
		return textResult(c.TraceStatus())
	})

	type queryInput struct {
		Limit int    `json:"limit,omitempty" jsonschema:"maximum events (default 500, max 2000)"`
		After uint64 `json:"after,omitempty" jsonschema:"return events with id greater than this value"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "query_function_trace",
		Description: "Return function-call trace status and recent completed calls.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in queryInput) (*mcp.CallToolResult, any, error) {
		events, status := c.TraceEvents(in.Limit, in.After)
		return textResult(map[string]any{"status": status, "events": events})
	})
}

func addAnalysisTools(srv *mcp.Server, st *store.Store) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "follow_stream",
		Description: "Reassemble and return both directions of the TCP stream for a packet. Useful for HTTP/Redis/etc. Requires snaplen large enough to capture payload.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in streamInput) (*mcp.CallToolResult, any, error) {
		p, ok := st.Get(in.PacketID)
		if !ok {
			return nil, nil, fmt.Errorf("packet %d not found (it may have been evicted)", in.PacketID)
		}
		if !p.Meta.HasLayer("tcp") {
			return nil, nil, fmt.Errorf("packet %d is not TCP", in.PacketID)
		}
		snap, ok := st.StreamForPacket(p)
		if !ok {
			return nil, nil, fmt.Errorf("no reassembled stream for packet %d (payload not captured or stream evicted)", in.PacketID)
		}
		maxBytes := in.MaxBytes
		if maxBytes <= 0 {
			maxBytes = 65536
		}
		if maxBytes > 1<<20 {
			maxBytes = 1 << 20
		}
		return textResult(streamOutput{
			Key:   snap.Key,
			A:     snap.A,
			B:     snap.B,
			AtoB:  directionOutput(snap.AtoB, maxBytes, in.IncludeBase64),
			BtoA:  directionOutput(snap.BtoA, maxBytes, in.IncludeBase64),
			First: snap.First,
			Last:  snap.Last,
		})
	})

	type conversationsInput struct {
		Limit int `json:"limit,omitempty" jsonschema:"maximum conversations (default 100, max 1000)"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_conversations",
		Description: "List bidirectional IP conversations sorted by bytes, including packet/byte counts and TCP state.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in conversationsInput) (*mcp.CallToolResult, any, error) {
		limit := in.Limit
		if limit <= 0 {
			limit = 100
		}
		if limit > 1000 {
			limit = 1000
		}
		flows := st.Flows(limit)
		return textResult(map[string]any{"count": len(flows), "flows": flows})
	})

	type empty struct{}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_stats",
		Description: "Return buffer/protocol/rate statistics and TCP reassembly memory usage.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, any, error) {
		return textResult(st.Stats())
	})

	type validateInput struct {
		Filter string `json:"filter" jsonschema:"display filter expression to validate"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "validate_filter",
		Description: "Validate a display filter expression before using it in query_packets or wait_for_packets.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in validateInput) (*mcp.CallToolResult, any, error) {
		_, err := filter.Parse(in.Filter)
		if err != nil {
			return textResult(map[string]any{"valid": false, "error": err.Error()})
		}
		return textResult(map[string]any{"valid": true})
	})

	type waitInput struct {
		Filter         string `json:"filter,omitempty" jsonschema:"display filter (empty matches every packet)"`
		Limit          int    `json:"limit,omitempty" jsonschema:"maximum packets to return (default 50, max 1000)"`
		TimeoutSeconds int    `json:"timeoutSeconds,omitempty" jsonschema:"maximum wait time in seconds (default 5, max 60)"`
	}
	type waitOutput struct {
		TimedOut bool            `json:"timedOut"`
		Count    int             `json:"count"`
		Packets  []packetSummary `json:"packets"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "wait_for_packets",
		Description: "Wait for live packets matching a display filter. Returns early on timeout. Useful for watching traffic after start_capture.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in waitInput) (*mcp.CallToolResult, any, error) {
		flt, err := filter.Parse(in.Filter)
		if err != nil {
			return nil, nil, err
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 50
		}
		if limit > 1000 {
			limit = 1000
		}
		timeout := in.TimeoutSeconds
		if timeout <= 0 {
			timeout = 5
		}
		if timeout > 60 {
			timeout = 60
		}
		sub := st.Subscribe(flt, limit*2+64)
		defer st.Unsubscribe(sub)
		timer := time.NewTimer(time.Duration(timeout) * time.Second)
		defer timer.Stop()

		out := make([]packetSummary, 0, limit)
		timedOut := false
		for len(out) < limit {
			select {
			case p := <-sub.C:
				out = append(out, summarise(p))
			case <-timer.C:
				timedOut = true
				return textResult(waitOutput{TimedOut: true, Count: len(out), Packets: out})
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		return textResult(waitOutput{TimedOut: timedOut, Count: len(out), Packets: out})
	})
}
