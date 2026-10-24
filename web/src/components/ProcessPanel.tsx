import { useEffect, useState } from "react"
import { Boxes, RefreshCw, Search, X } from "lucide-react"
import { Input } from "@/components/ui/input"
import { api } from "@/lib/api"
import { formatCount } from "@/lib/format"
import { cn } from "@/lib/utils"
import { useI18n } from "@/i18n"
import type { ProcessInfo } from "@/lib/types"

interface ProcessPanelProps {
  active: boolean
  mode?: "scope" | "analysis"
  selectedCgroupID?: number
  onSelectCgroup?: (process: ProcessInfo | null) => void
  selectedPID?: number
  onSelectProcess?: (process: ProcessInfo) => void
}

export function ProcessPanel({
  active,
  mode = "scope",
  selectedCgroupID,
  onSelectCgroup,
  selectedPID,
  onSelectProcess,
}: ProcessPanelProps) {
  const { t } = useI18n()
  const [query, setQuery] = useState("")
  const [processes, setProcesses] = useState<ProcessInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!active) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const load = async () => {
      try {
        const res = await api.processes(query)
        if (!cancelled) {
          setProcesses(res.processes)
          setError("")
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err))
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    setLoading(true)
    timer = setTimeout(load, query ? 200 : 0)
    const interval = setInterval(load, 3000)
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
      clearInterval(interval)
    }
  }, [active, query])

  return (
    <div className="space-y-2 p-3">
      <div className="flex items-center justify-between text-2xs text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <Boxes className="h-3.5 w-3.5" />
          {t("process.count", { count: formatCount(processes.length) })}
        </span>
        <button
          type="button"
          className="flex items-center gap-1 hover:text-foreground"
          onClick={() => {
            setLoading(true)
            api
              .processes(query)
              .then((res) => {
                setProcesses(res.processes)
                setError("")
              })
              .catch((err) => setError(err instanceof Error ? err.message : String(err)))
              .finally(() => setLoading(false))
          }}
        >
          <RefreshCw className={cn("h-3 w-3", loading && "animate-spin")} />
          {t("process.refresh")}
        </button>
      </div>

      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={query}
          spellCheck={false}
          placeholder={t("process.search")}
          className="h-8 pl-8 pr-8 font-mono text-[11px]"
          onChange={(e) => setQuery(e.target.value)}
        />
        {query && (
          <button
            type="button"
            className="absolute right-1.5 top-1/2 grid h-5 w-5 -translate-y-1/2 place-items-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
            onClick={() => setQuery("")}
            aria-label={t("process.clearSearch")}
          >
            <X className="h-3 w-3" />
          </button>
        )}
      </div>

      {mode === "scope" && (
      <button
        type="button"
        onClick={() => onSelectCgroup?.(null)}
        className={cn(
          "flex w-full items-center gap-2 rounded-md border px-2 py-1.5 text-left text-xs transition-colors",
          !selectedCgroupID
            ? "border-primary/40 bg-primary/10 text-foreground"
            : "hover:bg-accent/60",
        )}
      >
        <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50" />
        <span>{t("process.all")}</span>
        {selectedCgroupID ? (
          <span className="ml-auto font-mono text-2xs text-muted-foreground">
            {t("process.clear")}
          </span>
        ) : (
          <span className="ml-auto text-2xs text-muted-foreground">{t("process.active")}</span>
        )}
      </button>
      )}

      {mode === "scope" && selectedCgroupID ? (
        <div className="flex items-center gap-2 rounded border border-primary/30 bg-primary/[0.08] px-2 py-1 font-mono text-[10px] text-primary">
          <Boxes className="h-3 w-3 shrink-0" />
          <span className="truncate">{t("process.cgroup", { id: selectedCgroupID })}</span>
          <button
            type="button"
            className="ml-auto shrink-0 text-muted-foreground hover:text-foreground"
            onClick={() => onSelectCgroup?.(null)}
            aria-label={t("process.clear")}
          >
            <X className="h-3 w-3" />
          </button>
        </div>
      ) : null}

      {error && (
        <div className="break-words rounded border border-destructive/30 bg-destructive/10 p-2 text-2xs text-destructive">
          {error}
        </div>
      )}

      {processes.length === 0 && !loading ? (
        <div className="rounded-md border border-dashed p-4 text-center text-2xs leading-relaxed text-muted-foreground/60">
          {query ? t("process.emptySearch") : t("process.empty")}
        </div>
      ) : (
        <div className="space-y-0.5">
          {processes.map((process) => {
            const selected = mode === "analysis"
              ? process.pid === selectedPID
              : process.cgroupID === selectedCgroupID
            return (
              <button
                key={`${process.pid}:${process.cgroupID}`}
                type="button"
                onClick={() => {
                  if (mode === "analysis") onSelectProcess?.(process)
                  else onSelectCgroup?.(process)
                }}
                title={process.cgroupPath}
                className={cn(
                  "w-full rounded-md border px-2 py-1.5 text-left transition-colors",
                  selected
                    ? "border-primary/40 bg-primary/10"
                    : "border-transparent hover:bg-accent/60",
                )}
              >
                <div className="flex items-center gap-2">
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-foreground/90">
                    {process.comm || "?"}
                  </span>
                  <span className="shrink-0 font-mono text-2xs text-muted-foreground/70">
                    {process.pid}
                  </span>
                </div>
                <div className="mt-0.5 truncate font-mono text-[9px] text-muted-foreground/50">
                  {process.cgroupPath}
                </div>
              </button>
            )
          })}
        </div>
      )}

      <p className="px-1 text-[10px] leading-relaxed text-muted-foreground/60">
        {t(mode === "analysis" ? "process.analysisHint" : "process.hint")}
      </p>
    </div>
  )
}
