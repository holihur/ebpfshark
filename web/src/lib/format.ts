export function formatBytes(n: number, digits = 1): string {
  if (!Number.isFinite(n)) return "0 B"
  if (n < 1024) return `${n} B`
  const units = ["KB", "MB", "GB", "TB"]
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(digits)} ${units[i]}`
}

export function formatCount(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 2 : 1)}k`
  return `${(n / 1_000_000).toFixed(2)}M`
}

/** Wireshark-style "seconds since first packet". */
export function formatRelative(ns: number, baseNs: number): string {
  const s = (ns - baseNs) / 1e9
  return s.toFixed(6)
}

export function formatClock(ns: number): string {
  const d = new Date(ns / 1e6)
  const pad = (v: number, n = 2) => String(v).padStart(n, "0")
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(
    d.getMilliseconds(),
    3,
  )}`
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "0s"
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`
  const m = Math.floor(seconds / 60)
  const s = Math.floor(seconds % 60)
  if (m < 60) return `${m}m ${s}s`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m`
}

export function formatPps(n: number): string {
  if (n < 10) return n.toFixed(1)
  return formatCount(Math.round(n))
}
