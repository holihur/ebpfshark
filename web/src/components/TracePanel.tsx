import { useEffect, useState } from "react"
import { Activity, Play, RefreshCw, Square } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { api } from "@/lib/api"
import { useI18n } from "@/i18n"
import type { TraceEvent, TraceInfo, TraceStatus } from "@/lib/types"

function duration(ns: number): string {
  if (ns < 1000) return `${ns} ns`
  if (ns < 1_000_000) return `${(ns / 1000).toFixed(1)} µs`
  return `${(ns / 1_000_000).toFixed(2)} ms`
}

export function TracePanel({ active }: { active: boolean }) {
  const { t } = useI18n()
  const [pid, setPid] = useState("")
  const [functions, setFunctions] = useState("")
  const [status, setStatus] = useState<TraceStatus | null>(null)
  const [events, setEvents] = useState<TraceEvent[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [info, setInfo] = useState<TraceInfo | null>(null)
  const [inspecting, setInspecting] = useState(false)

  useEffect(() => {
    if (!active) return
    let cancelled = false
    let last = 0
    const load = async () => {
      try {
        const res = await api.trace(500, last)
        if (cancelled) return
        setStatus(res.status)
        if (res.events.length > 0) {
          last = res.events[res.events.length - 1].id
          setEvents((prev) => {
            const byID = new Map<number, TraceEvent>()
            for (const e of [...res.events, ...prev]) byID.set(e.id, e)
            return [...byID.values()].sort((a, b) => b.id - a.id).slice(0, 500)
          })
        }
        setError(res.status.error ?? "")
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err))
      }
    }
    void load()
    const timer = setInterval(() => { void load() }, 1000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [active])

  const start = async () => {
    setBusy(true)
    setError("")
    try {
      const p = Number.parseInt(pid, 10)
      if (!Number.isFinite(p) || p < 0) throw new Error("PID required")
      if (!functions.trim()) throw new Error("binary:symbol required")
      setStatus(await api.traceStart(p, functions.trim()))
      setEvents([])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const inspect = async () => {
    setInspecting(true)
    setError("")
    try {
      const p = Number.parseInt(pid, 10)
      if (!Number.isFinite(p) || p < 0) throw new Error("PID required")
      const binary = functions.split(",")[0]?.split(":")[0] ?? ""
      setInfo(await api.traceInspect(p, binary))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setInspecting(false)
    }
  }

  const stop = async () => {
    setBusy(true)
    try {
      setStatus(await api.traceStop())
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const running = status?.running ?? false

  return (
    <div className="space-y-3 p-3">
      <div className="rounded-md border bg-background/40 p-2">
        <div className="mb-2 flex items-center gap-2 text-2xs font-semibold uppercase tracking-wider text-muted-foreground">
          <Activity className="h-3.5 w-3.5" />
          {t("trace.title")}
        </div>
        <label className="mb-1 block text-2xs text-muted-foreground">{t("trace.pid")}</label>
        <Input
          value={pid}
          onChange={(e) => setPid(e.target.value)}
          placeholder="1234"
          inputMode="numeric"
          className="mb-2 h-8 font-mono text-xs"
        />
        <label className="mb-1 block text-2xs text-muted-foreground">{t("trace.functions")}</label>
        <Input
          value={functions}
          onChange={(e) => setFunctions(e.target.value)}
          placeholder="/usr/bin/app:main.handler"
          className="mb-2 h-8 font-mono text-xs"
        />
        <div className="flex gap-2">
          <Button size="sm" variant="outline" className="h-8" onClick={() => { void inspect() }} disabled={inspecting || running}>
            {t("trace.detect")}
          </Button>
          <Button size="sm" className="h-8 flex-1" onClick={() => { void start() }} disabled={busy || running}>
            <Play className="h-3 w-3" /> {t("trace.start")}
          </Button>
          <Button size="sm" variant="outline" className="h-8" onClick={() => { void stop() }} disabled={busy || !running}>
            <Square className="h-3 w-3" /> {t("trace.stop")}
          </Button>
        </div>
        <p className="mt-2 text-[10px] leading-relaxed text-muted-foreground/60">{t("trace.hint")}</p>
        {info && (
          <div className="mt-2 space-y-0.5 rounded border bg-muted/30 p-1.5 text-[10px] text-muted-foreground">
            <div className="truncate font-mono text-foreground/80">{info.path}</div>
            <div>build-id: <span className="font-mono">{info.buildId || "?"}</span></div>
            <div>stripped: {info.stripped ? "yes" : "no"} · symbols: {info.symbols}</div>
            {info.debugFile && <div className="truncate">debug: {info.debugFile}</div>}
            {(info.suggestions ?? []).map((s) => <div key={s}>· {s}</div>)}
          </div>
        )}
      </div>

      {error && <div className="rounded border border-destructive/40 bg-destructive/10 p-2 text-2xs text-destructive">{error}</div>}

      <div className="flex items-center justify-between text-2xs text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className={`h-1.5 w-1.5 rounded-full ${running ? "bg-emerald-500" : "bg-muted-foreground/40"}`} />
          {running ? t("trace.running") : t("trace.stopped")}
          {status?.pid ? <span className="font-mono">PID {status.pid}</span> : null}
        </span>
        <span className="flex items-center gap-1 tabular-nums">
          {status?.count ?? 0} {t("trace.calls")}
          <RefreshCw className={`h-3 w-3 ${running ? "animate-spin" : ""}`} />
        </span>
      </div>

      {events.length === 0 ? (
        <div className="rounded-md border border-dashed p-4 text-center text-2xs leading-relaxed text-muted-foreground/60">
          {t("trace.empty")}
        </div>
      ) : (
        <div className="space-y-1">
          {events.map((e) => (
            <div key={e.id} className="rounded border bg-background/40 px-2 py-1.5 font-mono text-[10px]">
              <div className="flex items-center gap-2">
                <span className="truncate font-semibold text-foreground/90">{e.function}</span>
                <span className="ml-auto shrink-0 tabular-nums text-primary">{duration(e.durationNs)}</span>
              </div>
              <div className="mt-0.5 flex items-center gap-2 text-muted-foreground/60">
                <span>pid={e.pid}</span>
                <span>tid={e.tid}</span>
                <span className="truncate">{e.comm}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
