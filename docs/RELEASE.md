# Release with GoReleaser

Releases are built by GoReleaser from `.goreleaser.yaml`.

## Local commands

```bash
goreleaser check
goreleaser release --snapshot --clean
```

A real release requires a pushed tag:

```bash
git tag v1.2.3
git push origin v1.2.3
```

The GitHub `Release` workflow runs GoReleaser with `release --clean`.

## Build prerequisites

GoReleaser's `before` hooks run:

```text
make generate   # vmlinux.h + capture/probe bpf2go objects
make web        # React UI copied into internal/server/webdist
```

The release runner therefore needs:

- Go
- Node + pnpm
- clang, llvm, libbpf-dev, bpftool
- access to `/sys/kernel/btf/vmlinux`

## Artifacts

| Archive | Protocols | Platform |
| --- | --- | --- |
| `ebpfshark_<version>_core_linux_amd64.tar.gz` | core | linux/amd64 |
| `ebpfshark_<version>_core_linux_arm64.tar.gz` | core | linux/arm64 |
| `ebpfshark_<version>_full_linux_amd64.tar.gz` | full | linux/amd64 |
| `ebpfshark_<version>_full_linux_arm64.tar.gz` | full | linux/arm64 |
| `ebpfshark_<version>_dynamic_linux_amd64.tar.gz` | full + Go `.so` plugins | linux/amd64 |

Also uploaded:

- `checksums.txt`
- `checksums.txt.sig`
- `checksums.txt.pem`

The dynamic archive is amd64-only because it uses cgo. The core/full archives
are static (`CGO_ENABLED=0`).

## Auto-update

The auto-update manifest must point to a binary URL, not a tar.gz archive.
If auto-update is enabled, extract/copy the binary to the manifest URL or adapt
the updater to an archive-based artifact in a future release.
