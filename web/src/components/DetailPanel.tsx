import { lazy, memo, Suspense, useState } from "react"
import { AlignLeft, ChevronRight, Copy, Crosshair, Network } from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
const FollowStreamDialog = lazy(() => import("@/components/FollowStreamDialog").then((m) => ({ default: m.FollowStreamDialog })))
import { HexView, type ByteRange } from "@/components/HexView"
import { protoStyle } from "@/lib/protocols"
import { formatClock } from "@/lib/format"
import { useI18n } from "@/i18n"
import { cn } from "@/lib/utils"
import type { Field, PacketDetail } from "@/lib/types"

interface DetailPanelProps {
  detail: PacketDetail | null
  loading: boolean
}

function splitLabel(field: Field, depth: number): { key: string; value: string } {
  if (depth === 0) return { key: field.label, value: "" }
  const idx = field.label.indexOf(": ")
  if (idx < 0) return { key: field.label, value: "" }
  return { key: field.label.slice(0, idx), value: field.label.slice(idx + 2) }
}

interface FieldNodeProps {
  field: Field
  depth: number
  highlight: ByteRange | null
  onHighlight: (range: ByteRange) => void
}

function FieldNode({ field, depth, highlight, onHighlight }: FieldNodeProps) {
  const hasChildren = (field.children?.length ?? 0) > 0
  const [open, setOpen] = useState(depth < 2)
  const { key, value } = splitLabel(field, depth)
  const selected =
    highlight != null &&
    field.length > 0 &&
    highlight.offset === field.offset &&
    highlight.length === field.length

  return (
    <div>
      <div
        role="treeitem"
        aria-expanded={hasChildren ? open : undefined}
        onClick={() => {
          if (hasChildren) setOpen((v) => !v)
          if (field.length > 0) onHighlight({ offset: field.offset, length: field.length })
        }}
        style={{ paddingLeft: 8 + depth * 13 }}
        className={cn(
          "group flex cursor-default items-start gap-1 rounded-sm py-[1px] pr-2 leading-[18px] transition-colors",
          selected ? "bg-primary/15" : "hover:bg-accent/60",
          field.severity === "warn" && "text-amber-700 dark:text-amber-300",
          field.severity === "error" && "text-destructive",
        )}
        title={field.label}
      >
        <span className="mt-[3px] grid h-3 w-3 shrink-0 place-items-center text-muted-foreground/60">
          {hasChildren && (
            <ChevronRight
              className={cn("h-3 w-3 transition-transform", open && "rotate-90")}
            />
          )}
        </span>
        <span className="min-w-0 flex-1 break-words font-mono text-[11px]">
          <span className="text-foreground/90">{key}</span>
          {value && <span className="text-muted-foreground">: {value}</span>}
          {field.value && (
            <span className="ml-1.5 text-primary/90">
              {field.value}
              {field.length > 0 && (
                <span className="ml-1.5 text-2xs text-muted-foreground/50">
                  [{field.offset}:{field.length}]
                </span>
              )}
            </span>
          )}
        </span>
      </div>
      {hasChildren && open && (
        <div role="group">
          {field.children!.map((child, i) => (
            <FieldNode
              key={`${child.label}-${i}`}
              field={child}
              depth={depth + 1}
              highlight={highlight}
              onHighlight={onHighlight}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function DetailPanelImpl({ detail, loading }: DetailPanelProps) {
  const { t } = useI18n()
  const [highlight, setHighlight] = useState<ByteRange | null>(null)
  const [followOpen, setFollowOpen] = useState(false)

  const packet = detail?.packet
  const style = packet ? protoStyle(packet.protocol) : null

  const copy = async () => {
    if (!packet) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(packet, null, 2))
      toast.success(t("detail.copied"))
    } catch {
      toast.error(t("detail.clipboard"))
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col bg-card/30">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b bg-panel/60 px-3">
        <span className="text-2xs font-medium uppercase tracking-wider text-muted-foreground">
          {t("detail.title")}
        </span>
        {packet ? (
          <>
            <Badge className={cn("border-transparent", style?.bg, style?.text)}>
              {packet.protocol}
            </Badge>
            <span className="truncate font-mono text-2xs text-foreground/80">
              {packet.src} <span className="text-muted-foreground">→</span> {packet.dst}
            </span>
            <span className="hidden items-center gap-1.5 text-2xs text-muted-foreground/70 md:flex">
              <span>#{packet.id}</span>
              <span>·</span>
              <span>{packet.len} bytes</span>
              <span>·</span>
              <span>{packet.iface}</span>
              <span>·</span>
              <span>{packet.direction}</span>
              <span>·</span>
              <span>{formatClock(packet.time)}</span>
              {packet.truncated && (
                <span className="text-amber-600 dark:text-amber-400">
                  · {t("detail.truncated")}
                </span>
              )}
            </span>
          </>
        ) : (
          <span className="text-2xs text-muted-foreground/60">
            {loading ? t("detail.loading") : t("detail.noSelection")}
          </span>
        )}
        <div className="flex-1" />
        {packet && (
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => setFollowOpen(true)}
            disabled={!packet.layers.includes("tcp")}
            title={t("detail.follow")}
          >
            <AlignLeft />
          </Button>
        )}
        {packet && (
          <Button variant="ghost" size="icon-sm" onClick={copy} title={t("detail.copy")}>
            <Copy />
          </Button>
        )}
      </div>

      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <div className="min-h-0 flex-1 overflow-auto py-1 scrollbar-thin">
          {detail ? (
            detail.fields.map((field, i) => (
              <FieldNode
                key={`${field.label}-${i}`}
                field={field}
                depth={0}
                highlight={highlight}
                onHighlight={setHighlight}
              />
            ))
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center">
              <div className="grid h-10 w-10 place-items-center rounded-lg border bg-muted/30">
                {loading ? (
                  <Crosshair className="h-4 w-4 animate-pulse text-primary" />
                ) : (
                  <Network className="h-4 w-4 text-muted-foreground/60" />
                )}
              </div>
              <div className="text-xs font-medium text-foreground/70">
                {loading ? t("detail.dissecting") : t("detail.select")}
              </div>
              <p className="max-w-xs text-2xs leading-relaxed text-muted-foreground/60">
                {t("detail.selectDesc")}
              </p>
            </div>
          )}
        </div>

        {detail && (
          <div className="flex min-h-[120px] w-full shrink-0 flex-col border-t lg:h-auto lg:w-[46%] lg:border-l lg:border-t-0">
            <div className="flex h-7 shrink-0 items-center justify-between border-b px-3 text-2xs text-muted-foreground">
              <span>
                {t("detail.bytes")}{" "}
                <span className="text-muted-foreground/50">({detail.dataLen})</span>
              </span>
              <span className="font-mono text-2xs text-muted-foreground/60">
                {highlight
                  ? t("detail.offset", {
                      offset: highlight.offset,
                      length: highlight.length,
                    })
                  : t("detail.highlightHint")}
              </span>
            </div>
            <HexView data={detail.data} highlight={highlight} className="flex-1" />
          </div>
        )}
      </div>

      <Suspense fallback={null}>
        <FollowStreamDialog
          packetId={packet?.id ?? null}
          open={followOpen}
          onOpenChange={setFollowOpen}
        />
      </Suspense>
    </div>
  )
}

export const DetailPanel = memo(DetailPanelImpl)
