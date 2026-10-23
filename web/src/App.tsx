import { useCallback, useEffect, useRef, useState } from "react"
import { Toaster, toast } from "sonner"
import { DetailPanel } from "@/components/DetailPanel"
import { FilterBar } from "@/components/FilterBar"
import { Header } from "@/components/Header"
import { PacketList } from "@/components/PacketList"
import { Sidebar } from "@/components/Sidebar"
import { StatusBar } from "@/components/StatusBar"
import { TooltipProvider } from "@/components/ui/tooltip"
import { useAuth } from "@/auth/context"
import { useCapture } from "@/hooks/useCapture"
import { useTheme } from "@/hooks/useTheme"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { PacketDetail, ProcessInfo } from "@/lib/types"

function errorMessage(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err)
  return msg.length > 240 ? `${msg.slice(0, 237)}…` : msg
}

export default function App() {
  const { t } = useI18n()
  const auth = useAuth()
  const capture = useCapture()
  const { theme, toggle } = useTheme()

  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [detail, setDetail] = useState<PacketDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  const [selectedIfaces, setSelectedIfaces] = useState<string[]>([])
  const [snaplen, setSnaplen] = useState(2048)
  const [sampleRate, setSampleRate] = useState(1)
  const [clearOnStart, setClearOnStart] = useState(true)
  const [cgroupFilter, setCgroupFilter] = useState<ProcessInfo | null>(null)
  const [busy, setBusy] = useState(false)
  const [splitPct, setSplitPct] = useState(44)

  const workRef = useRef<HTMLDivElement>(null)
  const initialized = useRef(false)
  const wasRunning = useRef(false)

  // Pick a sensible default interface once the status arrives.
  useEffect(() => {
    const s = capture.status
    if (!s || initialized.current) return
    initialized.current = true
    if (s.capture.running && s.capture.interfaces.length > 0) {
      setSelectedIfaces(s.capture.interfaces)
      return
    }
    const list = s.interfaces.filter((i) => i.index >= 0)
    const preferred =
      list.find((i) => i.default) ?? list.find((i) => !i.loopback && i.up) ?? list[0]
    if (preferred) setSelectedIfaces([preferred.name])
  }, [capture.status])

  // Keep the selection in sync with what the backend is actually capturing.
  useEffect(() => {
    const s = capture.status
    if (!s) return
    if (s.capture.running && !wasRunning.current && s.capture.interfaces.length > 0) {
      setSelectedIfaces(s.capture.interfaces)
    }
    wasRunning.current = s.capture.running
  }, [capture.status])

  // Load the protocol tree for the selected packet.
  useEffect(() => {
    if (selectedId == null) {
      setDetail(null)
      return
    }
    let cancelled = false
    setDetailLoading(true)
    api
      .detail(selectedId)
      .then((d) => {
        if (!cancelled) setDetail(d)
      })
      .catch((err) => {
        if (cancelled) return
        setDetail(null)
        toast.error(t("toast.packetLoadFailed"), { description: errorMessage(err) })
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [selectedId])

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

  const activeCgroupID = cgroupFilter?.cgroupID ?? capture.status?.capture.cgroupID ?? 0

  const handleStart = useCallback(() =>
    run(async () => {
      if (selectedIfaces.length === 0) {
        throw new Error(t("toast.selectInterface"))
      }
      const res = await capture.start({
        interfaces: selectedIfaces,
        snaplen,
        sampleRate,
        clear: clearOnStart,
        filter: capture.filter,
        cgroup: activeCgroupID ? String(activeCgroupID) : "",
      })
      toast.success(t("toast.captureStarted"), {
        description: t("toast.captureStartedDesc", {
          ifaces: res.interfaces.join(", "),
          snaplen: res.snaplen,
          rate: res.sampleRate,
        }),
      })
    }), [run, selectedIfaces, snaplen, sampleRate, clearOnStart, capture.start, activeCgroupID, t])

  const handleStop = useCallback(() =>
    run(async () => {
      await capture.stop()
      toast.success(t("toast.captureStopped"))
    }), [run, capture.stop, t])

  const handleClear = useCallback(() =>
    run(async () => {
      await capture.clear()
      setSelectedId(null)
      toast.success(t("toast.bufferCleared"))
    }), [run, capture.clear, t])

  const handleImport = useCallback((file: File) =>
    run(async () => {
      const res = await capture.importFile(file)
      setSelectedId(null)
      toast.success(
        t("toast.imported", { count: res.imported.toLocaleString() }),
        {
          description:
            t("toast.importedDesc", {
              file: file.name,
              ms: res.elapsedMs,
            }) + (res.captureStopped ? t("toast.importedStopped") : ""),
        },
      )
    }), [run, capture.importFile, t])

  const handleApplyFilter = useCallback(
    async (next: string) => {
      const ok = await capture.applyFilter(next)
      if (ok) setSelectedId(null)
    },
    [capture.applyFilter],
  )

  const handleSelectCgroup = useCallback(
    (process: ProcessInfo | null) => {
      setCgroupFilter(process)
      const id = process?.cgroupID ?? 0
      void run(async () => {
        await capture.setCgroup(id ? String(id) : "")
        setSelectedId(null)
      })
    },
    [capture.setCgroup, run],
  )

  const toggleIface = useCallback((name: string) =>
    setSelectedIfaces((prev) =>
      prev.includes(name) ? prev.filter((n) => n !== name) : [...prev, name],
    ), [])

  const selectAllIfaces = useCallback(() =>
    setSelectedIfaces(
      (capture.status?.interfaces ?? []).filter((i) => i.index >= 0).map((i) => i.name),
    ), [capture.status])

  const clearIfaces = useCallback(() => setSelectedIfaces([]), [])

  const handleLogout = useCallback(() => {
    void auth.logout()
  }, [auth.logout])

  // Drag handle between the packet list and the detail pane.
  const startDrag = (e: React.PointerEvent) => {
    e.preventDefault()
    const el = workRef.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    const move = (ev: PointerEvent) => {
      const pct = ((rect.bottom - ev.clientY) / rect.height) * 100
      setSplitPct(Math.min(72, Math.max(20, pct)))
    }
    const up = () => {
      window.removeEventListener("pointermove", move)
      window.removeEventListener("pointerup", up)
      document.body.style.cursor = ""
      document.body.style.userSelect = ""
    }
    document.body.style.cursor = "row-resize"
    document.body.style.userSelect = "none"
    window.addEventListener("pointermove", move)
    window.addEventListener("pointerup", up)
  }

  const running = capture.status?.capture.running ?? false

  return (
    <TooltipProvider delayDuration={350}>
      <div className="flex h-full flex-col overflow-hidden">
        <Header
          status={capture.status}
          connected={capture.connected}
          theme={theme}
          busy={busy}
          filter={capture.filter}
          authEnabled={auth.enabled}
          username={auth.user}
          onLogout={handleLogout}
          onToggleTheme={toggle}
          onStart={handleStart}
          onStop={handleStop}
          onClear={handleClear}
          onImport={handleImport}
        />

        <FilterBar
          filter={capture.filter}
          error={capture.filterError}
          status={capture.status}
          packetStore={capture.packetStore}
          loading={capture.loadingPackets}
          onApply={handleApplyFilter}
        />

        <div className="flex min-h-0 flex-1">
          <Sidebar
            status={capture.status}
            filter={capture.filter}
            selectedIfaces={selectedIfaces}
            snaplen={snaplen}
            sampleRate={sampleRate}
            clearOnStart={clearOnStart}
            busy={busy}
            onToggleIface={toggleIface}
            onSelectAllIfaces={selectAllIfaces}
            onClearIfaces={clearIfaces}
            onSnaplenChange={setSnaplen}
            onSampleRateChange={setSampleRate}
            onClearOnStartChange={setClearOnStart}
            onApplyFilter={handleApplyFilter}
            onStart={handleStart}
            onStop={handleStop}
            onClear={handleClear}
            onImport={handleImport}
            cgroupID={activeCgroupID}
            onSelectCgroup={handleSelectCgroup}
          />

          <main className="flex min-w-0 flex-1 flex-col">
            <div ref={workRef} className="flex min-h-0 flex-1 flex-col">
              <div className="flex min-h-0 flex-1 flex-col">
                <PacketList
                  store={capture.packetStore}
                  selectedId={selectedId}
                  loading={capture.loadingPackets}
                  filter={capture.filter}
                  running={running}
                  baseTime={
                    capture.status?.store.firstPacket
                      ? Date.parse(capture.status.store.firstPacket) * 1e6
                      : undefined
                  }
                  onSelect={setSelectedId}
                  onStart={handleStart}
                />
              </div>

              <div
                role="separator"
                aria-orientation="horizontal"
                onPointerDown={startDrag}
                className="group relative h-1.5 shrink-0 cursor-row-resize border-y border-border/60 bg-panel/60 transition-colors hover:bg-primary/25"
              >
                <div className="absolute left-1/2 top-1/2 h-0.5 w-8 -translate-x-1/2 -translate-y-1/2 rounded-full bg-border group-hover:bg-primary/60" />
              </div>

              <div
                style={{ height: `${splitPct}%` }}
                className="flex min-h-0 shrink-0 flex-col overflow-hidden"
              >
                <DetailPanel detail={detail} loading={detailLoading} />
              </div>
            </div>

            <StatusBar
              status={capture.status}
              packetStore={capture.packetStore}
              totalVisible={capture.status?.store.stored ?? 0}
              connected={capture.connected}
            />
          </main>
        </div>
      </div>

      <Toaster
        theme={theme}
        position="bottom-right"
        closeButton
        toastOptions={{
          classNames: {
            toast: "font-sans text-xs",
            description: "text-muted-foreground text-2xs",
          },
        }}
      />
    </TooltipProvider>
  )
}
