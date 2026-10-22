# Performance baseline

Baselines are from GitHub Actions (`ubuntu-24.04`, Go 1.25) using:

```bash
go test -run=^$ -bench=. -benchmem -benchtime=50ms \
  ./internal/decode ./internal/filter ./internal/stream
```

Latest smoke run: `39787092592`.

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| `DecodeHTTPDetail` | 12464 | 4414 | 151 |
| `DecodeHTTPSummary` | 4503 | 2248 | 67 |
| `DecodeTLSHandshake` | 15278 | 5383 | 173 |
| `DecodeDNS` | 10435 | 3684 | 114 |
| `FilterMatchTCPTLS` | 52.83 | 0 | 0 |
| `AssemblerInOrder` | 1207 | 3729 | 8 |

## Profiling

CPU profile for the decode benchmarks:

```bash
go test -run=^$ -bench='Decode' -benchtime=2s \
  -cpuprofile=/tmp/decode.cpu -memprofile=/tmp/decode.mem ./internal/decode
go tool pprof -http=:0 /tmp/decode.cpu
go tool pprof -http=:0 /tmp/decode.mem
```

Store / lock profiling:

```bash
go test -run=^$ -bench='Store|Assembler' -benchtime=2s \
  -cpuprofile=/tmp/store.cpu ./internal/store ./internal/stream
go tool pprof -http=:0 /tmp/store.cpu
```

## Notes

- These numbers are for regression detection, not cross-machine comparisons.
- GitHub runner performance varies; use `benchstat` with several runs before drawing conclusions.
- Summary path now skips Ethernet/IP/TCP/UDP field construction and its allocation
  count dropped from 132 to 67 in the CI smoke run. Remaining summary cost is mostly
  app-layer field formatting and packet metadata strings.
