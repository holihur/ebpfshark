import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Cable, CircleDot, Download, Eraser, Play, RefreshCw, Search, Square, X } from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { api } from "@/lib/api"
import { formatBytes, formatCount } from "@/lib/format"
import { cn } from "@/lib/utils"
import { useI18n } from "@/i18n"
import type { IPCEvent, IPCSocket, IPCStatus, IPCStream } from "@/lib/types"

function errorMessage(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err)
  return msg.length > 240 ? `${msg.slice(0, 237)}…` : msg
}

function timeLabel(value?: string): string {
  if (!value) return "—"
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return `${d.toLocaleTimeString([], { hour12: false })}.${String(d.getMilliseconds()).padStart(3, "0")}`
}

function decodePayload(payload?: string): { text: string; hex: string; length: number } {
  if (!payload) return { text: "", hex: "", length: 0 }
  try {
    const raw = atob(payload)
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0))
    let text = ""
    let hex = ""
    const limit = Math.min(bytes.length, 256)
    for (let i = 0; i < limit; i++) {
      const b = bytes[i]
      text += b >= 32 && b < 127 ? String.fromCharCode(b) : b === 10 ? "↵" : b === 13 ? "" : "·"
      hex += b.toString(16).padStart(2, "0") + " "
    }
    if (bytes.length > limit) {
      text += "…"
      hex += "…"
    }
    return { text: text || "·", hex, length: bytes.length }
  } catch {
    return { text: "[invalid base64]", hex: "", length: 0 }
  }
}

function Stat({ label, value, alert }: { label: string; value: string; alert?: boolean }) {
  return (
    <div className="rounded border bg-background/40 px-2 py-1">
      <div className="text-2xs text-muted-foreground/60">{label}</div>
      <div className={cn("font-mono text-2xs tabular-nums", alert ? "text-destructive" : "text-foreground/80")}>
        {value}
      </div>
    </div>
  )
}

function SocketRow({
  socket,
  selected,
  onClick,
}: {
  socket: IPCSocket
  selected: boolean
  onClick: () => void
}) {
  const { t } = useI18n()
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "w-full border-b px-3 py-2 text-left transition-colors",
        selected ? "bg-primary/[0.10]" : "hover:bg-accent/50",
      )}
    >
      <div className="flex items-center gap-2">
        <Cable className={cn("h-3.5 w-3.5 shrink-0", selected ? "text-primary" : "text-muted-foreground")} />
        <span className="min-w-0 flex-1 truncate font-mono text-xs" title={socket.path}>
          {socket.path || t("ipc.anonymous", { inode: socket.inode })}
        </span>
        <Badge variant={socket.type === "stream" ? "default" : "muted"}>{socket.type}</Badge>
      </div>
      <div className="mt-1 flex items-center gap-2 truncate pl-5 text-2xs text-muted-foreground">
        <span className="font-mono">#{socket.inode}</span>
        {socket.state && <span>{socket.state}</span>}
        {socket.pid ? (
          <span className="truncate">
            PID {socket.pid} {socket.comm ?? ""}
          </span>
        ) : null}
      </div>
    </button>
  )
}

function StreamRow({
  stream,
  selected,
  onClick,
}: {
  stream: IPCStream
  selected: boolean
  onClick: () => void
}) {
  const { t } = useI18n()
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "grid w-full grid-cols-[minmax(0,1fr)_78px_92px_88px] items-center gap-2 border-b px-3 py-1.5 text-left text-2xs transition-colors",
        selected ? "bg-primary/[0.10]" : "hover:bg-accent/50",
      )}
    >
      <span className="min-w-0">
        <span className="block truncate font-mono text-xs" title={stream.path}>
          {stream.path || t("ipc.anonymous", { inode: stream.inode })}
        </span>
        <span className="block truncate text-muted-foreground">
          #{stream.inode} {stream.comm ? `· ${stream.comm}` : ""} {stream.pid ? `· PID ${stream.pid}` : ""}
        </span>
      </span>
      <span className="text-right font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
        {formatBytes(stream.bytesOut)}
      </span>
      <span className="text-right font-mono tabular-nums text-sky-600 dark:text-sky-400">
        {formatBytes(stream.bytesIn)}
      </span>
      <span className="text-right font-mono tabular-nums text-muted-foreground">
        {formatCount(stream.events)} · {timeLabel(stream.last)}
      </span>
    </button>
  )
}

function EventRow({ event }: { event: IPCEvent }) {
  const { t } = useI18n()
  const payload = decodePayload(event.payload)
  return (
    <div className="border-b px-3 py-1.5 text-2xs">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-muted-foreground">{timeLabel(event.time)}</span>
        <Badge variant={event.direction === "send" ? "default" : "secondary"}>
          {event.direction === "send" ? "→ " : "← "}
          {event.direction === "send" ? t("ipc.send") : t("ipc.receive")}
        </Badge>
        <span className="min-w-0 flex-1 truncate font-mono" title={event.path}>
          {event.path || t("ipc.anonymous", { inode: event.inode })}
        </span>
        <span className="font-mono text-muted-foreground">#{event.inode}</span>
        {event.pid > 0 && (
          <span className="text-muted-foreground">
            PID {event.pid} {event.comm ?? ""}
          </span>
        )}
        {(event.parts ?? 0) > 1 && (
          <Badge variant="outline">seg {event.part + 1}/{event.parts}</Badge>
        )}
        <span className="font-mono tabular-nums text-foreground/70">{formatBytes(payload.length)}</span>
        {event.truncated && <Badge variant="destructive">{t("ipc.truncated")}</Badge>}
      </div>
      {payload.text && (
        <div className="mt-1 grid gap-1 pl-1 font-mono text-[11px] leading-relaxed">
          <div className="truncate text-foreground/80" title={payload.text}>{payload.text}</div>
          <div className="truncate text-muted-foreground/60" title={payload.hex}>{payload.hex}</div>
        </div>
      )}
    </div>
  )
}

export function IPCWorkspace() {
  const { t } = useI18n()
  const [status, setStatus] = useState<IPCStatus | null>(null)
  const [sockets, setSockets] = useState<IPCSocket[]>([])
  const [streams, setStreams] = useState<IPCStream[]>([])
  const [events, setEvents] = useState<IPCEvent[]>([])
  const [query, setQuery] = useState("")
  const [type, setType] = useState("all")
  const [pid, setPid] = useState("")
  const [maxPayload, setMaxPayload] = useState("4096")
  const [selectedInode, setSelectedInode] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [socketError, setSocketError] = useState("")
  const lastEventID = useRef(0)
  const loadingEvents = useRef(false)

  const loadSockets = useCallback(async () => {
    try {
      const res = await api.ipcSockets(query, type)
      setSockets(res.sockets)
      setSocketError("")
    } catch (err) {
      setSocketError(errorMessage(err))
    }
  }, [query, type])

  const appendEvents = useCallback((incoming: IPCEvent[]) => {
    if (incoming.length === 0) return
    const fresh = incoming.filter((e) => e.id > lastEventID.current)
    if (fresh.length === 0) return
    lastEventID.current = Math.max(lastEventID.current, ...fresh.map((e) => e.id))
    setEvents((prev) => [...prev, ...fresh].slice(-4000))
  }, [])

  const loadEvents = useCallback(async () => {
    if (loadingEvents.current) return
    loadingEvents.current = true
    try {
      const res = await api.ipcEvents(2000, lastEventID.current)
      setStatus(res.status)
      appendEvents(res.events)
    } catch {
      // The SSE stream is the primary path; this is a slow reconciliation
      // fallback and transient failures should not spam toasts.
    } finally {
      loadingEvents.current = false
    }
  }, [appendEvents])

  const loadStreams = useCallback(async () => {
    try {
      const res = await api.ipcStreams(500)
      setStreams(res.streams)
      setStatus(res.status)
    } catch {
      // Ignore transient polling failures.
    }
  }, [])

  const refreshAll = useCallback(async () => {
    await Promise.all([loadSockets(), loadEvents(), loadStreams()])
  }, [loadSockets, loadEvents, loadStreams])

  useEffect(() => {
    void refreshAll()
  }, [refreshAll])

  useEffect(() => {
    const id = window.setInterval(() => void loadSockets(), 10_000)
    return () => window.clearInterval(id)
  }, [loadSockets])

  useEffect(() => {
    const id = window.setInterval(() => void loadStreams(), 2000)
    return () => window.clearInterval(id)
  }, [loadStreams])

  // Live IPC payloads arrive over SSE; the slow poll above remains a fallback
  // for proxies that buffer event streams.
  useEffect(() => {
    const source = new EventSource("/api/ipc/stream")
    const onIPC = (raw: Event) => {
      try {
        const data = JSON.parse((raw as MessageEvent).data) as {
          events?: IPCEvent[]
          status?: IPCStatus
        }
        if (data.status) setStatus(data.status)
        appendEvents(data.events ?? [])
      } catch {
        // Ignore malformed events and let EventSource reconnect.
      }
    }
    const onReady = (raw: Event) => {
      try {
        const data = JSON.parse((raw as MessageEvent).data) as { status?: IPCStatus }
        if (data.status) setStatus(data.status)
      } catch {
        // Ignore malformed hello frames.
      }
    }
    source.addEventListener("ipc", onIPC)
    source.addEventListener("ready", onReady)
    return () => {
      source.removeEventListener("ipc", onIPC)
      source.removeEventListener("ready", onReady)
      source.close()
    }
  }, [appendEvents])

  useEffect(() => {
    const id = window.setInterval(() => void loadEvents(), 10_000)
    return () => window.clearInterval(id)
  }, [loadEvents])

  const run = useCallback(async (fn: () => Promise<void>) => {
    setBusy(true)
    try {
      await fn()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }, [])

  const handleStart = useCallback(() => run(async () => {
    const parsedPID = Number.parseInt(pid, 10)
    const next = await api.ipcStart({
      pid: Number.isFinite(parsedPID) && parsedPID > 0 ? parsedPID : 0,
      maxPayload: Number.parseInt(maxPayload, 10) || 4096,
    })
    setStatus(next)
    lastEventID.current = 0
    setEvents([])
    toast.success(t("ipc.startedToast"))
  }), [run, pid, maxPayload, t])

  const handleStop = useCallback(() => run(async () => {
    setStatus(await api.ipcStop())
    toast.success(t("ipc.stoppedToast"))
  }), [run, t])

  const handleClear = useCallback(() => run(async () => {
    const res = await api.ipcClear()
    lastEventID.current = 0
    setEvents([])
    setStreams([])
    setStatus(res.status)
  }), [run])

  const selectInode = useCallback((inode: number | null) => setSelectedInode(inode), [])

  const visibleStreams = useMemo(
    () => (selectedInode == null ? streams : streams.filter((s) => s.inode === selectedInode)),
    [streams, selectedInode],
  )
  const visibleEvents = useMemo(
    () => (selectedInode == null ? events : events.filter((e) => e.inode === selectedInode)),
    [events, selectedInode],
  )
  const selectedSocket = useMemo(
    () => sockets.find((s) => s.inode === selectedInode) ?? null,
    [sockets, selectedInode],
  )
  const selectedStream = useMemo(
    () => streams.find((s) => s.inode === selectedInode) ?? null,
    [streams, selectedInode],
  )

  const running = status?.running ?? false
  const dropped = status?.kernel.dropped ?? 0

  return (
    <main className="flex min-w-0 flex-1 flex-col overflow-hidden bg-background">
      <div className="border-b px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="grid h-8 w-8 place-items-center rounded-md border bg-card/60">
            <Cable className="h-4 w-4 text-primary" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-semibold">{t("ipc.title")}</h1>
              <Badge variant={running ? "default" : "muted"}>
                {running ? t("ipc.running") : t("ipc.stopped")}
              </Badge>
              {selectedInode != null && (
                <Button variant="ghost" size="sm" className="h-5 px-1.5" onClick={() => selectInode(null)}>
                  <X className="h-3 w-3" /> {t("ipc.clearFilter")}
                </Button>
              )}
            </div>
            <p className="mt-0.5 truncate text-2xs text-muted-foreground">{t("ipc.subtitle")}</p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <Input
              value={pid}
              onChange={(e) => setPid(e.target.value.replace(/[^0-9]/g, ""))}
              placeholder={t("ipc.pidPlaceholder")}
              className="h-7 w-28 font-mono text-2xs"
              title={t("ipc.pidHint")}
            />
            <Select value={maxPayload} onValueChange={setMaxPayload} disabled={running || busy}>
              <SelectTrigger className="h-7 w-28 text-2xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1024">1 KiB</SelectItem>
                <SelectItem value="2048">2 KiB</SelectItem>
                <SelectItem value="4096">4 KiB</SelectItem>
              </SelectContent>
            </Select>
            {!running ? (
              <Button size="sm" onClick={handleStart} disabled={busy}>
                <Play className="h-3.5 w-3.5" /> {t("ipc.start")}
              </Button>
            ) : (
              <Button size="sm" variant="destructive" onClick={handleStop} disabled={busy}>
                <Square className="h-3.5 w-3.5" /> {t("ipc.stop")}
              </Button>
            )}
            <Button size="sm" variant="outline" onClick={handleClear} disabled={busy}>
              <Eraser className="h-3.5 w-3.5" /> {t("ipc.clear")}
            </Button>
            <Button size="sm" variant="outline" asChild>
              <a href={`/api/ipc/export?format=jsonl${selectedInode == null ? "" : `&inode=${selectedInode}`}`} download>
                <Download className="h-3.5 w-3.5" /> {t("ipc.export")}
              </a>
            </Button>
          </div>
        </div>

        <div className="mt-2 grid grid-cols-2 gap-1.5 sm:grid-cols-4 lg:grid-cols-7">
          <Stat label={t("ipc.sockets")} value={formatCount(sockets.length)} />
          <Stat label={t("ipc.streams")} value={formatCount(streams.length)} />
          <Stat label={t("ipc.events")} value={formatCount(events.length)} />
          <Stat label={t("ipc.captured")} value={formatBytes(status?.store.bytes ?? 0)} />
          <Stat label={t("ipc.kernelEvents")} value={formatCount(status?.kernel.events ?? 0)} />
          <Stat label={t("ipc.truncatedCount")} value={formatCount(status?.kernel.truncated ?? 0)} />
          <Stat label={t("ipc.dropped")} value={formatCount(dropped)} alert={dropped > 0} />
        </div>
        {(status?.lastError || socketError || (status?.attachErrors?.length ?? 0) > 0) && (
          <div className="mt-2 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1.5 text-2xs text-amber-700 dark:text-amber-300">
            {status?.lastError || socketError || status?.attachErrors?.join("; ")}
          </div>
        )}
      </div>

      <div className="flex min-h-0 flex-1">
        <aside className="flex w-[330px] shrink-0 flex-col border-r">
          <div className="space-y-1.5 border-b p-2">
            <div className="flex items-center gap-1.5">
              <div className="relative min-w-0 flex-1">
                <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={t("ipc.searchSockets")}
                  className="h-7 pl-7 text-2xs"
                />
              </div>
              <Select value={type} onValueChange={setType}>
                <SelectTrigger className="h-7 w-24 text-2xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t("ipc.allTypes")}</SelectItem>
                  <SelectItem value="stream">stream</SelectItem>
                  <SelectItem value="dgram">dgram</SelectItem>
                  <SelectItem value="seqpacket">seqpacket</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="ghost" size="icon-sm" onClick={() => void loadSockets()} title={t("ipc.refresh")}>
                <RefreshCw className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto scrollbar-thin">
            {sockets.length === 0 ? (
              <div className="grid h-full place-items-center p-4 text-center text-xs text-muted-foreground">
                {t("ipc.noSockets")}
              </div>
            ) : (
              sockets.map((socket) => (
                <SocketRow
                  key={socket.inode}
                  socket={socket}
                  selected={selectedInode === socket.inode}
                  onClick={() => selectInode(selectedInode === socket.inode ? null : socket.inode)}
                />
              ))
            )}
          </div>
        </aside>

        <section className="flex min-w-0 flex-1 flex-col">
          {(selectedSocket || selectedStream) && (
            <div className="flex flex-wrap items-center gap-2 border-b bg-muted/20 px-3 py-1.5 text-2xs">
              <CircleDot className="h-3 w-3 text-primary" />
              <span className="font-mono">{selectedSocket?.path || selectedStream?.path || `#${selectedInode}`}</span>
              <span className="text-muted-foreground">{selectedSocket?.type || selectedStream?.type}</span>
              {selectedStream && (
                <span className="text-muted-foreground">
                  ↑ {formatBytes(selectedStream.bytesOut)} · ↓ {formatBytes(selectedStream.bytesIn)} · {formatCount(selectedStream.events)} {t("ipc.events")}
                </span>
              )}
              {selectedStream?.truncated && <Badge variant="destructive">{t("ipc.truncated")}</Badge>}
              <span className="min-w-0 flex-1" />
              <Button variant="ghost" size="sm" className="h-5 px-1.5" onClick={() => selectInode(null)}>
                <X className="h-3 w-3" /> {t("ipc.clearFilter")}
              </Button>
            </div>
          )}

          <div className="flex min-h-[180px] max-h-[42%] flex-col border-b">
            <div className="flex items-center gap-2 border-b bg-panel/40 px-3 py-1.5 text-2xs font-medium">
              <span className="flex-1">{t("ipc.streams")}</span>
              <span className="w-[78px] text-right">{t("ipc.bytesOut")}</span>
              <span className="w-[92px] text-right">{t("ipc.bytesIn")}</span>
              <span className="w-[88px] text-right">{t("ipc.activity")}</span>
            </div>
            <div className="flex-1 overflow-y-auto scrollbar-thin">
              {visibleStreams.length === 0 ? (
                <div className="grid h-full place-items-center p-4 text-center text-xs text-muted-foreground">
                  {t("ipc.noStreams")}
                </div>
              ) : (
                visibleStreams.map((stream) => (
                  <StreamRow
                    key={stream.key}
                    stream={stream}
                    selected={selectedInode === stream.inode}
                    onClick={() => selectInode(selectedInode === stream.inode ? null : stream.inode)}
                  />
                ))
              )}
            </div>
          </div>

          <div className="flex min-h-0 flex-1 flex-col">
            <div className="flex items-center gap-2 border-b bg-panel/40 px-3 py-1.5 text-2xs font-medium">
              <span className="flex-1">{t("ipc.events")}</span>
              <span className="text-muted-foreground">{t("ipc.eventHint")}</span>
            </div>
            <div className="flex-1 overflow-y-auto scrollbar-thin">
              {visibleEvents.length === 0 ? (
                <div className="grid h-full place-items-center p-4 text-center text-xs text-muted-foreground">
                  {running ? t("ipc.waiting") : t("ipc.noEvents")}
                </div>
              ) : (
                visibleEvents.map((event) => <EventRow key={event.id} event={event} />)
              )}
            </div>
          </div>
        </section>
      </div>
    </main>
  )
}
