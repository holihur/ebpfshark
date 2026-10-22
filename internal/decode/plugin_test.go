package decode

func chainNames(chain []appDissector) map[string]bool {
	out := make(map[string]bool, len(chain))
	for _, d := range chain {
		out[d.name] = true
	}
	return out
}
