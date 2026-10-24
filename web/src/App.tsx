import { useCallback, useEffect, useRef, useState } from "react"
import { Toaster, toast } from "sonner"
import { ColumnSettingsDialog } from "@/components/ColumnSettingsDialog"
import { DecryptionDialog } from "@/components/DecryptionDialog"
import { DetailPanel } from "@/components/DetailPanel"
import { MITMDialog } from "@/components/MITMDialog"
import { ModuleRail, type WorkspaceModule } from "@/components/ModuleRail"
import { FilterBar } from "@/components/FilterBar"
import { Header } from "@/components/Header"
import { PacketList } from "@/components/PacketList"
import { ProcessWorkspace } from "@/components/ProcessWorkspace"
import { Sidebar } from "@/components/Sidebar"
import { StatusBar } from "@/components/StatusBar"
import { TooltipProvider } from "@/components/ui/tooltip"
import { useAuth } from "@/auth/context"
import { useCapture } from "@/hooks/useCapture"
import { useTheme } from "@/hooks/useTheme"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { usePacketColumns } from "@/lib/packetColumns"
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
  const [ringSize, setRingSize] = useState(32 << 20)
  const [clearOnStart, setClearOnStart] = useState(true)
  const [cgroupFilter, setCgroupFilter] = useState<ProcessInfo | null>(null)
  const [busy, setBusy] = useState(false)
  const [splitPct, setSplitPct] = useState(44)
  const [columns, setColumns] = usePacketColumns()
  const [columnsOpen, setColumnsOpen] = useState(false)
  const [decryptOpen, setDecryptOpen] = useState(false)
  const [mitmOpen, setMitmOpen] = useState(false)
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false)
  const [activeModule, setActiveModule] = useState<WorkspaceModule>("network")
  const [networkTab, setNetworkTab] = useState("capture")

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
    if (s.capture.running && s.capture.ringSize > 0) setRingSize(s.capture.ringSize)
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
        ringSize,
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
    }), [run, selectedIfaces, snaplen, sampleRate, ringSize, clearOnStart, capture.start, activeCgroupID, t])

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

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobileSidebarOpen(false)
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  const running = capture.status?.capture.running ?? false
  const showNetworkFilter = activeModule === "network"

  return (
    <TooltipProvider delayDuration={350}>
      <div className="flex h-full flex-col overflow-hidden">
        <Header
          status={capture.status}
          theme={theme}
          authEnabled={auth.enabled}
          username={auth.user}
          onLogout={handleLogout}
          onToggleTheme={toggle}
          onOpenSidebar={() => setMobileSidebarOpen(true)}
        />

        <div className="flex min-h-0 flex-1">
          <ModuleRail active={activeModule} onSelect={setActiveModule} />
          <Sidebar
            module={activeModule}
            activeTab={networkTab}
            onTabChange={setNetworkTab}
            onModuleChange={setActiveModule}
            onTraceProcess={() => setActiveModule("processes")}
            onOpenProcesses={() => setActiveModule("processes")}
            status={capture.status}
            filter={capture.filter}
            selectedIfaces={selectedIfaces}
            snaplen={snaplen}
            sampleRate={sampleRate}
            ringSize={ringSize}
            clearOnStart={clearOnStart}
            busy={busy}
            onToggleIface={toggleIface}
            onSelectAllIfaces={selectAllIfaces}
            onClearIfaces={clearIfaces}
            onSnaplenChange={setSnaplen}
            onSampleRateChange={setSampleRate}
            onRingSizeChange={setRingSize}
            onClearOnStartChange={setClearOnStart}
            onApplyFilter={handleApplyFilter}
            onStart={handleStart}
            onStop={handleStop}
            onClear={handleClear}
            onImport={handleImport}
            cgroupID={activeCgroupID}
            onSelectCgroup={handleSelectCgroup}
          />

          {activeModule === "network" ? (
            <main className="flex min-w-0 flex-1 flex-col">
            <FilterBar
            filter={capture.filter}
            error={capture.filterError}
            status={capture.status}
            packetStore={capture.packetStore}
            loading={capture.loadingPackets}
            connected={capture.connected}
            running={running}
            busy={busy}
            onApply={handleApplyFilter}
            onStart={handleStart}
            onStop={handleStop}
            onEditColumns={() => setColumnsOpen(true)}
            onDecryption={() => setDecryptOpen(true)}
            onMITM={() => setMitmOpen(true)}
            />
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
                    columns={columns}
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
  
              {showNetworkFilter && (
                <StatusBar
                  status={capture.status}
                  packetStore={capture.packetStore}
                  totalVisible={capture.status?.store.stored ?? 0}
                  connected={capture.connected}
                />
              )}
            </main>
          ) : (
            <ProcessWorkspace
              process={cgroupFilter}
              onClearScope={() => handleSelectCgroup(null)}
              onOpenNetwork={() => setActiveModule("network")}
            />
          )}
        </div>
      </div>

      <ColumnSettingsDialog
        open={columnsOpen}
        onOpenChange={setColumnsOpen}
        columns={columns}
        onChange={setColumns}
      />

      <DecryptionDialog open={decryptOpen} onOpenChange={setDecryptOpen} />

      <MITMDialog open={mitmOpen} onOpenChange={setMitmOpen} />

      {mobileSidebarOpen && (
        <div className="fixed inset-0 z-50 flex md:hidden" role="dialog" aria-modal="true">
          <button
            type="button"
            className="absolute inset-0 bg-black/60 backdrop-blur-[2px]"
            aria-label={t("app.closeSidebar")}
            onClick={() => setMobileSidebarOpen(false)}
          />
          <div className="relative z-10 h-full animate-slide-in-right shadow-2xl">
            <Sidebar
              module={activeModule}
              activeTab={networkTab}
              onTabChange={setNetworkTab}
              onModuleChange={setActiveModule}
              onTraceProcess={() => setActiveModule("processes")}
              onOpenProcesses={() => setActiveModule("processes")}
              status={capture.status}
              filter={capture.filter}
              selectedIfaces={selectedIfaces}
              snaplen={snaplen}
              sampleRate={sampleRate}
              ringSize={ringSize}
              clearOnStart={clearOnStart}
              busy={busy}
              onToggleIface={toggleIface}
              onSelectAllIfaces={selectAllIfaces}
              onClearIfaces={clearIfaces}
              onSnaplenChange={setSnaplen}
              onSampleRateChange={setSampleRate}
              onRingSizeChange={setRingSize}
              onClearOnStartChange={setClearOnStart}
              onApplyFilter={handleApplyFilter}
              onStart={handleStart}
              onStop={handleStop}
              onClear={handleClear}
              onImport={handleImport}
              cgroupID={activeCgroupID}
              onSelectCgroup={handleSelectCgroup}
              mobile
              onClose={() => setMobileSidebarOpen(false)}
            />
          </div>
        </div>
      )}

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
