package instrument

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ParseTargets parses comma-separated binary:symbol entries. A symbol may
// contain colons, so the first colon separates the executable.
func ParseTargets(s string) ([]Target, error) {
	var out []Target
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		i := strings.IndexByte(item, ':')
		if i < 0 || i == len(item)-1 {
			return nil, fmt.Errorf("invalid function %q (want binary:symbol or binary:0xADDR)", item)
		}
		binary, target := item[:i], item[i+1:]
		f := Target{Binary: binary}
		if strings.HasPrefix(target, "@") {
			v, err := strconv.ParseUint(strings.TrimPrefix(target, "@"), 0, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", target, err)
			}
			f.Address = v
		} else if strings.HasPrefix(target, "0x") || strings.HasPrefix(target, "0X") {
			v, err := strconv.ParseUint(target, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", target, err)
			}
			f.Address = v
		} else {
			f.Symbol = target
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, errors.New("no functions selected")
	}
	return out, nil
}
