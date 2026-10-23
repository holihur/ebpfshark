//go:build cgo && (linux || darwin || freebsd)

package decode

import (
	"errors"
	"fmt"
	"plugin"
	"strings"

	"ebpfshark/pkg/pluginapi"
)

// PluginSupported reports whether this binary can load Go shared-object
// plugins. It is false on Windows and in cgo-disabled builds.
func PluginSupported() bool { return true }

// LoadDynamicPlugins loads trusted Go plugin shared objects. Plugins must be
// built with the same Go toolchain, module graph and cgo settings as this
// binary. Loading a plugin executes its init functions with full process
// privileges.
func LoadDynamicPlugins(paths []string) error {
	var errs []error
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if err := loadDynamicPlugin(path); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

func loadDynamicPlugin(path string) error {
	p, err := plugin.Open(path)
	if err != nil {
		return err
	}
	for _, name := range []string{"Plugin", "New"} {
		sym, err := p.Lookup(name)
		if err != nil {
			continue
		}
		switch v := sym.(type) {
		case pluginapi.Plugin:
			registerExternalPlugin(v)
			return nil
		case *pluginapi.Plugin:
			if v != nil && *v != nil {
				registerExternalPlugin(*v)
				return nil
			}
		case func() pluginapi.Plugin:
			registerExternalPlugin(v())
			return nil
		case func() (pluginapi.Plugin, error):
			pl, err := v()
			if err != nil {
				return err
			}
			registerExternalPlugin(pl)
			return nil
		}
	}
	return fmt.Errorf("plugin does not export Plugin or New with the pluginapi ABI")
}
