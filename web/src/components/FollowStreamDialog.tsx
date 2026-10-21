import { useEffect, useMemo, useState } from "react"
import { AlertCircle, ArrowLeftRight, ArrowRight, Copy, Download, Loader2 } from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { HexView } from "@/components/HexView"
import { ApiError, api } from "@/lib/api"
import { base64ToBytes, toAscii } from "@/lib/bytes"
import { formatBytes } from "@/lib/format"
import { useI18n } from "@/i18n"
import { cn } from "@/lib/utils"
import type { PacketStream, StreamDirectionData, StreamEndpoint } from "@/lib/types"

interface FollowStreamDialogProps {
  packetId: number | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

type Mode = "ascii" | "hex"
type Which = "both" | "a2b" | "b2a"

function endpointLabel(endpoint: StreamEndpoint): string {
  return `${endpoint.ip}:${endpoint.port}`
}

function hexDump(bytes: Uint8Array): string {
  const lines: string[] = []
  const hex2 = (b: number) => b.toString(16).padStart(2, "0")
  for (let off = 0; off < bytes.length; off += 16) {
    const slice = bytes.subarray(off, Math.min(off + 16, bytes.length))
    const hex = Array.from(slice, hex2).join(" ").padEnd(47, " ")
    const ascii = Array.from(slice, (b) =>
      b >= 32 && b <= 126 ? String.fromCharCode(b) : ".",
    ).join("")
    lines.push(`${off.toString(16).padStart(4, "0")}  ${hex}  |${ascii}|`)
  }
  return lines.join("\n")
}

function DirectionBlock({
  direction,
  mode,
  tone,
}: {
  direction: StreamDirectionData
  mode: Mode
  tone: "emerald" | "sky"
}) {
  const { t } = useI18n()
  const ascii = useMemo(
    () => (mode === "ascii" ? toAscii(base64ToBytes(direction.data)) : ""),
    [direction.data, mode],
  )
  const toneClass =
    tone === "emerald"
      ? "bg-emerald-400/[0.06] text-emerald-700 dark:text-emerald-300"
      : "bg-sky-400/[0.06] text-sky-700 dark:text-sky-300"
  const dotClass = tone === "emerald" ? "bg-emerald-500 dark:bg-emerald-400" : "bg-sky-500 dark:bg-sky-400"

  return (
    <div className="overflow-hidden rounded-md border">
      <div className={cn("flex flex-wrap items-center gap-2 border-b px-2.5 py-1.5", toneClass)}>
        <span className={cn("h-1.5 w-1.5 rounded-full", dotClass)} />
        <span className="font-mono text-2xs">{endpointLabel(direction.from)}</span>
        <ArrowRight className="h-3 w-3 opacity-60" />
        <span className="font-mono text-2xs">{endpointLabel(direction.to)}</span>
        <Badge variant="muted">{formatBytes(direction.bytes)}</Badge>
        {direction.truncated && <Badge variant="destructive">{t("follow.truncated")}</Badge>}
        {direction.gaps > 0 && (
          <Badge variant="muted" className="text-amber-700 dark:text-amber-300">
            {t("follow.gaps", { count: direction.gaps })}
          </Badge>
        )}
      </div>
      {direction.bytes === 0 ? (
        <div className="p-3 text-2xs text-muted-foreground">{t("follow.noData")}</div>
      ) : mode === "ascii" ? (
        <pre className="max-h-[34vh] overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-[11px] leading-[1.55] scrollbar-thin">
          {ascii}
        </pre>
      ) : (
        <HexView data={direction.data} className="max-h-[34vh]" maxBytes={32 * 1024} />
      )}
    </div>
  )
}

export function FollowStreamDialog({ packetId, open, onOpenChange }: FollowStreamDialogProps) {
  const { t } = useI18n()
  const [data, setData] = useState<PacketStream | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [mode, setMode] = useState<Mode>("ascii")
  const [which, setWhich] = useState<Which>("both")

  useEffect(() => {
    if (!open || packetId == null) return
    let cancelled = false
    setLoading(true)
    setError(null)
    setData(null)
    api
      .packetStream(packetId)
      .then((stream) => {
        if (!cancelled) setData(stream)
      })
      .catch((err) => {
        if (cancelled) return
        if (err instanceof ApiError && err.status === 404) setError(t("follow.empty"))
        else setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [open, packetId, t])

  const dirs = useMemo(() => {
    if (!data) return []
    const out: { key: "a2b" | "b2a"; dir: StreamDirectionData; tone: "emerald" | "sky" }[] = []
    if (which !== "b2a") out.push({ key: "a2b", dir: data.aToB, tone: "emerald" })
    if (which !== "a2b") out.push({ key: "b2a", dir: data.bToA, tone: "sky" })
    return out
  }, [data, which])

  const totalBytes = data ? data.aToB.bytes + data.bToA.bytes : 0

  const buildText = () => {
    if (!data) return ""
    return dirs
      .filter(({ dir }) => dir.bytes > 0)
      .map(({ dir }) => {
        const header = `=== ${endpointLabel(dir.from)} -> ${endpointLabel(dir.to)} (${dir.bytes} bytes) ===`
        const body =
          mode === "ascii"
            ? toAscii(base64ToBytes(dir.data))
            : hexDump(base64ToBytes(dir.data))
        return `${header}\n${body}`
      })
      .join("\n\n")
  }

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(buildText())
      toast.success(t("follow.copied"))
    } catch {
      toast.error(t("detail.clipboard"))
    }
  }

  const download = () => {
    if (!data) return
    const safe = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, "_")
    const name = `stream-${safe(data.a.ip)}-${data.a.port}-${safe(data.b.ip)}-${data.b.port}.txt`
    const blob = new Blob([buildText()], { type: "text/plain;charset=utf-8" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="h-[84vh] max-w-5xl gap-0 p-0">
        <DialogHeader className="border-b px-4 py-3 pr-10">
          <DialogTitle className="flex items-center gap-2">
            <ArrowLeftRight className="h-4 w-4 text-primary" />
            {t("follow.title")}
          </DialogTitle>
          <DialogDescription>
            {data
              ? `${endpointLabel(data.a)} ↔ ${endpointLabel(data.b)}`
              : t("follow.subtitle")}
          </DialogDescription>
        </DialogHeader>

        <div className="flex shrink-0 flex-wrap items-center gap-2 border-b bg-panel/40 px-4 py-2">
          <div className="flex items-center gap-0.5 rounded-md border bg-background/50 p-0.5">
            {(
              [
                ["both", t("follow.both")],
                ["a2b", t("follow.aToB")],
                ["b2a", t("follow.bToA")],
              ] as const
            ).map(([value, label]) => (
              <Button
                key={value}
                size="sm"
                variant={which === value ? "secondary" : "ghost"}
                className="h-6 px-2 text-2xs"
                onClick={() => setWhich(value)}
              >
                {label}
              </Button>
            ))}
          </div>
          <div className="flex items-center gap-0.5 rounded-md border bg-background/50 p-0.5">
            {(
              [
                ["ascii", t("follow.ascii")],
                ["hex", t("follow.hex")],
              ] as const
            ).map(([value, label]) => (
              <Button
                key={value}
                size="sm"
                variant={mode === value ? "secondary" : "ghost"}
                className="h-6 px-2 text-2xs"
                onClick={() => setMode(value)}
              >
                {label}
              </Button>
            ))}
          </div>
          <div className="flex-1" />
          <Button variant="outline" size="sm" onClick={copy} disabled={!data || totalBytes === 0}>
            <Copy /> {t("follow.copy")}
          </Button>
          <Button variant="outline" size="sm" onClick={download} disabled={!data || totalBytes === 0}>
            <Download /> {t("follow.download")}
          </Button>
        </div>

        <div className="min-h-0 flex-1 space-y-3 overflow-auto p-3 scrollbar-thin">
          {loading && (
            <div className="flex h-full items-center justify-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin text-primary" />
              {t("follow.loading")}
            </div>
          )}
          {!loading && error && (
            <div className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <div>
                <div>{error}</div>
                <div className="mt-0.5 text-2xs text-muted-foreground">{t("follow.emptyHint")}</div>
              </div>
            </div>
          )}
          {!loading && !error && data && totalBytes === 0 && (
            <div className="flex h-full flex-col items-center justify-center gap-1 text-center">
              <div className="text-xs font-medium text-foreground/70">{t("follow.empty")}</div>
              <div className="text-2xs text-muted-foreground">{t("follow.emptyHint")}</div>
            </div>
          )}
          {!loading &&
            !error &&
            dirs.map(({ key, dir, tone }) => (
              <DirectionBlock key={key} direction={dir} mode={mode} tone={tone} />
            ))}
        </div>

        <div className="flex shrink-0 items-center justify-between border-t px-4 py-1.5 text-2xs text-muted-foreground">
          <span>{data ? t("follow.total", { count: formatBytes(totalBytes) }) : ""}</span>
          <span>{t("follow.hint")}</span>
        </div>
      </DialogContent>
    </Dialog>
  )
}
