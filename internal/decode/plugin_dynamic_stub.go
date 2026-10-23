//go:build !cgo || (!linux && !darwin && !freebsd)

package decode

import "fmt"

func PluginSupported() bool { return false }

func LoadDynamicPlugins(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	return fmt.Errorf("dynamic Go plugins are not supported on this platform/build (need cgo on linux, darwin or freebsd)")
}
