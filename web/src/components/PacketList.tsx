import { Fragment, memo, useEffect, useRef } from "react"
import {
  ArrowDownLeft,
  ArrowUpRight,
  ChevronDown,
  Loader2,
  Radar,
  Scissors,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { useVirtualList } from "@/hooks/useVirtualList"
import { usePacketVersion, type PacketStore } from "@/lib/packetStore"
import { formatRelative } from "@/lib/format"
import { protoStyle } from "@/lib/protocols"
import { useI18n, type MessageKey } from "@/i18n"
import { cn } from "@/lib/utils"
import {
  COLUMN_BY_ID,
  columnTemplate,
  columnsMinWidth,
  type ColumnID,
} from "@/lib/packetColumns"
import type { Packet } from "@/lib/types"

const ROW_HEIGHT = 28
const GRID_BASE = "grid items-center gap-2 px-2"

interface PacketListProps {
  store: PacketStore
  selectedId: number | null
  loading: boolean
  filter: string
  running: boolean
  baseTime?: number
  columns: ColumnID[]
  onSelect: (id: number) => void
  onStart: () => void
}

function PacketListImpl({
  store,
  selectedId,
  loading,
  filter,
  running,
  baseTime,
  columns,
  onSelect,
  onStart,
}: PacketListProps) {
  const { t } = useI18n()
  usePacketVersion()
  const count = store.length
  const headerRef = useRef<HTMLDivElement>(null)
  const { containerRef, onScroll, atBottom, scrollToBottom, startFor, endFor, totalHeight } =
    useVirtualList({ rowHeight: ROW_HEIGHT })

  useEffect(() => {
    if (atBottom && count > 0) scrollToBottom()
  }, [count, atBottom, scrollToBottom])

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    onScroll()
    if (headerRef.current) headerRef.current.scrollLeft = e.currentTarget.scrollLeft
  }

  const start = startFor()
  const end = endFor(count)
  const visible = store.slice(start, end)
  const base = baseTime && baseTime > 0 ? baseTime : (store.at(0)?.time ?? 0)
  const template = columnTemplate(columns)
  const minWidth = columnsMinWidth(columns)

  const renderCell = (id: ColumnID, packet: Packet) => {
    switch (id) {
      case "no":
        return (
          <span className="font-mono tabular-nums text-muted-foreground/70">{packet.id}</span>
        )
      case "time":
        return (
          <span className="font-mono tabular-nums text-muted-foreground">
            {formatRelative(packet.time, base)}
          </span>
        )
      case "source":
        return (
          <span className="flex min-w-0 items-center gap-1">
            <span
              title={packet.direction === "ingress" ? t("list.ingress") : t("list.egress")}
            >
              {packet.direction === "ingress" ? (
                <ArrowDownLeft className="h-3 w-3 shrink-0 text-emerald-400/80" />
              ) : (
                <ArrowUpRight className="h-3 w-3 shrink-0 text-amber-400/80" />
              )}
            </span>
            <span className="truncate font-mono text-foreground/90" title={packet.src}>
              {packet.src}
            </span>
          </span>
        )
      case "destination":
        return (
          <span className="truncate font-mono text-foreground/90" title={packet.dst}>
            {packet.dst}
          </span>
        )
      case "protocol": {
        const proto = protoStyle(packet.protocol)
        return (
          <span className="flex items-center gap-1.5">
            <span className={cn("h-1.5 w-1.5 rounded-full", proto.dot)} />
            <span className={cn("font-mono font-medium", proto.text)}>{packet.protocol}</span>
          </span>
        )
      }
      case "length":
        return (
          <span className="flex items-center justify-end gap-0.5 font-mono tabular-nums text-muted-foreground">
            {packet.len}
            {packet.truncated && (
              <span title={t("list.truncated")}>
                <Scissors className="h-2.5 w-2.5 text-amber-400/80" />
              </span>
            )}
          </span>
        )
      case "info":
        return (
          <span className="truncate font-mono text-foreground/80" title={packet.info}>
            {packet.info}
          </span>
        )
      case "iface":
        return (
          <span className="truncate font-mono text-2xs text-muted-foreground/60">
            {packet.iface}
          </span>
        )
      case "cgroup":
        return packet.cgroupID ? (
          <span
            className="truncate font-mono text-2xs tabular-nums text-muted-foreground/60"
            title={`cgroup #${packet.cgroupID}`}
          >
            {packet.cgroupID}
          </span>
        ) : (
          <span className="font-mono text-2xs text-muted-foreground/30">—</span>
        )
    }
  }

  const handleKey = (e: React.KeyboardEvent) => {
    if (count === 0) return
    let idx = -1
    for (let i = 0; i < count; i++) {
      if (store.at(i)?.id === selectedId) { idx = i; break }
    }
    if (e.key === "ArrowDown") {
      e.preventDefault()
      onSelect(store.at(Math.min(count - 1, idx + 1))?.id ?? store.at(0)!.id)
    } else if (e.key === "ArrowUp") {
      e.preventDefault()
      onSelect(store.at(Math.max(0, (idx < 0 ? count : idx) - 1))?.id ?? store.at(0)!.id)
    } else if (e.key === "Home") {
      e.preventDefault()
      onSelect(store.at(0)!.id)
      if (containerRef.current) containerRef.current.scrollTop = 0
    } else if (e.key === "End") {
      e.preventDefault()
      onSelect(store.at(count - 1)!.id)
      scrollToBottom()
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col bg-background">
      <div
        ref={headerRef}
        className="h-7 shrink-0 overflow-hidden border-b bg-panel/70"
      >
        <div
          className={cn(
            GRID_BASE,
            "h-7 text-2xs font-medium uppercase tracking-wide text-muted-foreground/80",
          )}
          style={{ gridTemplateColumns: template, minWidth }}
        >
          {columns.map((id) => {
            const col = COLUMN_BY_ID.get(id)
            if (!col) return null
            return (
              <span
                key={id}
                className={cn(col.align === "right" && "text-right")}
              >
                {t(col.labelKey as MessageKey)}
              </span>
            )
          })}
        </div>
      </div>

      <div className="relative min-h-0 flex-1">
        <div
          ref={containerRef}
          tabIndex={0}
          onScroll={handleScroll}
          onKeyDown={handleKey}
          className="h-full overflow-auto outline-none scrollbar-thin"
        >
          <div className="relative" style={{ height: totalHeight(count), minWidth }}>
            {visible.map((packet, i) => {
              const index = start + i
              const selected = packet.id === selectedId
              return (
                <div
                  key={packet.id}
                  role="row"
                  aria-selected={selected}
                  onClick={() => onSelect(packet.id)}
                  style={{
                    top: index * ROW_HEIGHT,
                    height: ROW_HEIGHT,
                    gridTemplateColumns: template,
                  }}
                  className={cn(
                    GRID_BASE,
                    "absolute left-0 right-0 cursor-default border-l-2 border-l-transparent text-[11px] transition-colors",
                    index % 2 === 1 && "bg-muted/[0.14]",
                    selected
                      ? "border-l-primary bg-primary/[0.12] hover:bg-primary/[0.16]"
                      : "hover:bg-accent/50",
                  )}
                >
                  {columns.map((id) => (
                    <Fragment key={id}>{renderCell(id, packet)}</Fragment>
                  ))}
                </div>
              )
            })}
          </div>
        </div>

        {count === 0 && (
          <div className="absolute inset-0 flex items-center justify-center p-6">
            <div className="grid-bg pointer-events-none absolute inset-0 opacity-50" />
            <div className="relative flex max-w-sm flex-col items-center text-center animate-fade-in">
              <div className="mb-3 grid h-12 w-12 place-items-center rounded-xl border bg-card/80 shadow-lg">
                {loading ? (
                  <Loader2 className="h-5 w-5 animate-spin text-primary" />
                ) : (
                  <Radar className="h-5 w-5 text-primary" />
                )}
              </div>
              <h3 className="text-sm font-medium">
                {loading
                  ? t("list.loadingTitle")
                  : filter
                    ? t("list.noMatchTitle")
                    : t("list.emptyTitle")}
              </h3>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                {loading
                  ? t("list.loadingDesc")
                  : filter
                    ? t("list.noMatchDesc")
                    : running
                      ? t("list.emptyDescLive")
                      : t("list.emptyDescIdle")}
              </p>
              {!running && !filter && !loading && (
                <Button size="sm" className="mt-3" onClick={onStart}>
                  {t("list.startCapture")}
                </Button>
              )}
            </div>
          </div>
        )}

        {!atBottom && count > 0 && (
          <Button
            size="sm"
            variant="secondary"
            className="absolute bottom-3 right-4 gap-1 shadow-lg animate-slide-in-right"
            onClick={scrollToBottom}
          >
            <ChevronDown className="h-3.5 w-3.5" />
            {t("list.jumpLatest")}
          </Button>
        )}
      </div>
    </div>
  )
}

export const PacketList = memo(PacketListImpl)
