import { useState } from "react"
import { Activity, ChevronUp, Database, Radio, Users } from "lucide-react"
import { QUICK_FILTERS } from "@/lib/protocols"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Sparkline } from "@/components/Sparkline"
import { formatBytes, formatCount, formatDuration, formatPps } from "@/lib/format"
import { cn } from "@/lib/utils"
import { useI18n } from "@/i18n"
import { usePacketVersion, type PacketStore } from "@/lib/packetStore"
import type { StatusResponse } from "@/lib/types"

interface StatusBarProps {
  status: StatusResponse | null
  packetStore: PacketStore
  connected: boolean
  totalVisible: number
  filter: string
  onApplyFilter: (filter: string) => void
}

export function StatusBar({ status, packetStore, connected, totalVisible, filter, onApplyFilter }: StatusBarProps) {
  const { t } = useI18n()
  const [detailsOpen, setDetailsOpen] = useState(false)
  usePacketVersion()
  const matchCount = packetStore.length
  const capture = status?.capture
  const store = status?.store
  const running = capture?.running ?? false
  const rate = store?.rate ?? []
  const pps = rate.length > 0 ? rate[rate.length - 1].packets : 0
  const spark = rate.map((r) => r.packets)
  const usage = store && store.capacity > 0 ? (store.stored / store.capacity) * 100 : 0
  const activeFilter = filter.trim().toLowerCase()
  const protocols = store?.protocols ?? {}

  return (
    <>
    <footer className="flex h-7 shrink-0 flex-nowrap items-center gap-3 overflow-x-auto overflow-y-hidden whitespace-nowrap border-t bg-panel/80 px-3 text-2xs text-muted-foreground scrollbar-thin">
      <span className="flex min-w-0 max-w-[260px] shrink-0 items-center gap-1.5">
        <Radio
          className={cn("h-3 w-3 shrink-0", running ? "text-emerald-400" : "text-muted-foreground/40")}
        />
        <span className="truncate text-foreground/70" title={capture?.interfaces.join(", ")}>
          {running
            ? t("status.capturing", { ifaces: capture?.interfaces.join(", ") ?? "" })
            : t("status.idle")}
        </span>
      </span>

      <span className="h-3 w-px bg-border" />

      <span className="flex shrink-0 items-center gap-1 tabular-nums">
        <Activity className="h-3 w-3" />
        {formatPps(pps)}
        <span className="text-muted-foreground/50">{t("status.pps")}</span>
      </span>

      <span className="hidden shrink-0 items-center gap-1 tabular-nums sm:flex">
        <Database className="h-3 w-3" />
        {formatCount(store?.total ?? 0)} {t("status.pkts")}
        <span className="text-muted-foreground/40">/</span>
        {formatBytes(store?.bytes ?? 0)}
      </span>

      <span className="hidden shrink-0 items-center gap-1 tabular-nums lg:flex">
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

      <div className="hidden items-center gap-1 xl:flex">
        {QUICK_FILTERS.map((proto) => {
          const count = protocols[proto.toUpperCase()] ?? 0
          const active = activeFilter === proto
          return (
            <button
              key={proto}
              type="button"
              onClick={() => onApplyFilter(active ? "" : proto)}
              className={cn(
                "rounded border px-1.5 py-0.5 font-mono text-[10px] transition-colors",
                active
                  ? "border-primary/40 bg-primary/15 text-primary"
                  : "border-border bg-background/40 text-muted-foreground hover:bg-accent",
              )}
              title={`${proto} (${formatCount(count)})`}
            >
              {proto}
              <span className="ml-1 text-muted-foreground/60">{formatCount(count)}</span>
            </button>
          )
        })}
      </div>

      <div className="min-w-0 flex-1" />

      {matchCount !== totalVisible && (
        <span className="tabular-nums text-foreground/70">
          {t("status.inView", { count: formatCount(matchCount) })}
        </span>
      )}

      <span className="hidden items-center gap-1 xl:flex">
        <Users className="h-3 w-3" />
        {status?.subscribers ?? 0}
      </span>

      <Button
        variant="ghost"
        size="sm"
        className="h-6 shrink-0 gap-1 px-1.5 text-2xs"
        onClick={() => setDetailsOpen(true)}
        title={t("status.details")}
      >
        <ChevronUp className="h-3 w-3" />
        {t("status.details")}
      </Button>

      <span
        className={cn(
          "flex shrink-0 items-center gap-1",
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
    <Dialog open={detailsOpen} onOpenChange={setDetailsOpen}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("status.detailsTitle")}</DialogTitle>
          <DialogDescription>{t("status.detailsDesc")}</DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <Detail label={t("status.state")} value={running ? t("sidebar.running") : t("sidebar.stopped")} />
          <Detail label={t("status.interfaces")} value={(capture?.interfaces ?? []).join(", ") || "—"} />
          <Detail label={t("status.uptime")} value={formatDuration(capture?.uptimeSeconds ?? 0)} />
          <Detail label={t("status.pps")} value={formatPps(pps)} />
          <Detail label={t("status.kernelPackets")} value={formatCount(capture?.kernelPackets ?? 0)} />
          <Detail label={t("status.kernelSkipped")} value={formatCount(capture?.kernelSkipped ?? 0)} />
          <Detail label={t("status.total")} value={formatCount(store?.total ?? 0)} />
          <Detail label={t("status.stored")} value={`${formatCount(store?.stored ?? 0)} / ${formatCount(store?.capacity ?? 0)}`} />
          <Detail label={t("status.bytes")} value={formatBytes(store?.bytes ?? 0)} />
          <Detail label={t("status.dropped")} value={formatCount(store?.dropped ?? 0)} />
          <Detail label={t("status.matching")} value={formatCount(matchCount)} />
          <Detail label={t("status.streams")} value={formatCount(store?.streams?.flows ?? 0)} />
        </div>
      </DialogContent>
    </Dialog>
    </>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border bg-background/40 px-2 py-1.5">
      <div className="text-2xs text-muted-foreground">{label}</div>
      <div className="mt-0.5 break-all font-mono text-2xs text-foreground/80">{value}</div>
    </div>
  )
}
