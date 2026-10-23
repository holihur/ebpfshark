import { Activity, Database, Radio, Users } from "lucide-react"
import { Sparkline } from "@/components/Sparkline"
import { formatBytes, formatCount, formatPps } from "@/lib/format"
import { cn } from "@/lib/utils"
import { useI18n } from "@/i18n"
import { usePacketVersion, type PacketStore } from "@/lib/packetStore"
import type { StatusResponse } from "@/lib/types"

interface StatusBarProps {
  status: StatusResponse | null
  packetStore: PacketStore
  connected: boolean
  totalVisible: number
}

export function StatusBar({ status, packetStore, connected, totalVisible }: StatusBarProps) {
  const { t } = useI18n()
  usePacketVersion()
  const matchCount = packetStore.length
  const capture = status?.capture
  const store = status?.store
  const running = capture?.running ?? false
  const rate = store?.rate ?? []
  const pps = rate.length > 0 ? rate[rate.length - 1].packets : 0
  const spark = rate.map((r) => r.packets)
  const usage = store && store.capacity > 0 ? (store.stored / store.capacity) * 100 : 0

  return (
    <footer className="flex h-7 shrink-0 items-center gap-3 border-t bg-panel/80 px-3 text-2xs text-muted-foreground">
      <span className="flex items-center gap-1.5">
        <Radio
          className={cn("h-3 w-3", running ? "text-emerald-400" : "text-muted-foreground/40")}
        />
        <span className="text-foreground/70">
          {running
            ? t("status.capturing", { ifaces: capture?.interfaces.join(", ") ?? "" })
            : t("status.idle")}
        </span>
      </span>

      <span className="h-3 w-px bg-border" />

      <span className="flex items-center gap-1 tabular-nums">
        <Activity className="h-3 w-3" />
        {formatPps(pps)}
        <span className="text-muted-foreground/50">{t("status.pps")}</span>
      </span>

      <span className="hidden items-center gap-1 tabular-nums sm:flex">
        <Database className="h-3 w-3" />
        {formatCount(store?.total ?? 0)} {t("status.pkts")}
        <span className="text-muted-foreground/40">/</span>
        {formatBytes(store?.bytes ?? 0)}
      </span>

      <span className="hidden items-center gap-1 tabular-nums lg:flex">
        {t("status.buffer")} {formatCount(store?.stored ?? 0)}
        <span className="text-muted-foreground/40">/</span>
        {formatCount(store?.capacity ?? 0)}
        <span className="ml-1 h-1 w-12 overflow-hidden rounded-full bg-muted">
          <span
            className="block h-full rounded-full bg-primary/70"
            style={{ width: `${Math.min(100, usage)}%` }}
          />
        </span>
      </span>

      {(store?.dropped ?? 0) > 0 && (
        <span className="rounded bg-destructive/15 px-1.5 py-0.5 text-destructive">
          {t("status.dropped", { count: formatCount(store?.dropped ?? 0) })}
        </span>
      )}
      {(capture?.kernelSkipped ?? 0) > 0 && (
        <span className="hidden rounded bg-amber-400/10 px-1.5 py-0.5 text-amber-700 dark:text-amber-300 md:inline">
          {t("status.kernelDrops", { count: formatCount(capture?.kernelSkipped ?? 0) })}
        </span>
      )}

      <div className="flex-1" />

      {matchCount !== totalVisible && (
        <span className="tabular-nums text-foreground/70">
          {t("status.inView", { count: formatCount(matchCount) })}
        </span>
      )}

      <span className="hidden items-center gap-1 xl:flex">
        <Users className="h-3 w-3" />
        {status?.subscribers ?? 0}
      </span>

      <span
        className={cn(
          "flex items-center gap-1",
          connected ? "text-emerald-600 dark:text-emerald-400/80" : "text-muted-foreground/50",
        )}
        title={
          connected ? t("status.streamConnected") : t("status.streamDisconnected")
        }
      >
        <span
          className={cn(
            "h-1.5 w-1.5 rounded-full",
            connected ? "bg-emerald-400" : "bg-muted-foreground/40",
          )}
        />
        {t("status.stream")}
      </span>

      <span className="hidden font-mono text-muted-foreground/40 2xl:inline">
        v{status?.version ?? "…"}
      </span>
      <Sparkline values={spark} className="hidden h-4 w-24 sm:block" />
    </footer>
  )
}
