// Demo dynamic plugin. Build with:
//
//	go build -buildmode=plugin -o plugins/demo.so ./examples/plugins/demo
package main

import (
	"fmt"

	"ebpfshark/pkg/pluginapi"
)

type demo struct{}

func (demo) Name() string                   { return "demo" }
func (demo) Priority() int                  { return 500 }
func (demo) Transport() pluginapi.Transport { return pluginapi.UDP }
func (demo) Match(req pluginapi.Request) bool {
	return req.Meta.SrcPort == 9999 || req.Meta.DstPort == 9999
}
func (demo) Dissect(req pluginapi.Request) (pluginapi.Result, bool) {
	if len(req.Data) < 2 {
		return pluginapi.Result{}, false
	}
	return pluginapi.Result{
		Layers: []string{"demo"},
		Proto:  "demo",
		Info:   fmt.Sprintf("demo payload %d bytes", len(req.Data)),
		Fields: []pluginapi.Field{{
			Label:  "Demo Payload",
			Value:  string(req.Data),
			Offset: req.Base,
			Length: len(req.Data),
		}},
	}, true
}

// Plugin is the exported symbol loaded by ebpfshark.
var Plugin pluginapi.Plugin = demo{}
