# Performance baseline

Baselines are from GitHub Actions (`ubuntu-24.04`, Go 1.25) using:

```bash
go test -run=^$ -bench=. -benchmem -benchtime=50ms \
  ./internal/decode ./internal/filter ./internal/stream
```

Latest smoke run: `39783951563`.

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| `DecodeHTTPDetail` | 10337 | 4349 | 149 |
| `DecodeHTTPSummary` | 8092 | 3593 | 132 |
| `DecodeTLSHandshake` | 12715 | 5318 | 171 |
| `DecodeDNS` | 8685 | 3684 | 114 |
| `FilterMatchTCPTLS` | 39.25 | 0 | 0 |
| `AssemblerInOrder` | 1201 | 3733 | 8 |

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
- `DecodeHTTPSummary` still evaluates many field-formatting arguments even though it
  discards the tree. Lazy field formatting is the next expected win.
