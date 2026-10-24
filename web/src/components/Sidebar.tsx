import { memo, useEffect, useRef, useState } from "react"
import {
  ArrowLeftRight,
  Boxes,
  CircleAlert,
  X,
  Download,
  FileUp,
  Gauge,
  Layers,
  Play,
  RefreshCw,
  Square,
  Trash2,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { ProcessPanel } from "@/components/ProcessPanel"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { ScrollArea } from "@/components/ui/scroll-area"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { api } from "@/lib/api"
import { formatBytes, formatCount, formatDuration } from "@/lib/format"
import { protoStyle } from "@/lib/protocols"
import { cn } from "@/lib/utils"
import { useI18n } from "@/i18n"
import type { Flow, InterfaceInfo, ProcessInfo, StatusResponse } from "@/lib/types"

interface SidebarProps {
  status: StatusResponse | null
  filter: string
  selectedIfaces: string[]
  snaplen: number
  sampleRate: number
  ringSize: number
  clearOnStart: boolean
  busy: boolean
  onToggleIface: (name: string) => void
  onSelectAllIfaces: () => void
  onClearIfaces: () => void
  onSnaplenChange: (value: number) => void
  onSampleRateChange: (value: number) => void
  onRingSizeChange: (value: number) => void
  onClearOnStartChange: (value: boolean) => void
  onApplyFilter: (filter: string) => void
  onStart: () => void
  onStop: () => void
  onClear: () => void
  onImport: (file: File) => void
  cgroupID?: number
  onSelectCgroup: (process: ProcessInfo | null) => void
  mobile?: boolean
  onClose?: () => void
  activeTab?: string
  onTabChange?: (tab: string) => void
  module?: "network" | "processes"
  onModuleChange?: (module: "network" | "processes") => void
  onTraceProcess?: (process: ProcessInfo) => void
  onOpenProcesses?: () => void
}

function Section({
  title,
  action,
  children,
}: {
  title: string
  action?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <section>
      <div className="mb-1.5 flex items-center justify-between">
        <h3 className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground/70">
          {title}
        </h3>
        {action}
      </div>
      {children}
    </section>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border bg-background/40 px-2 py-1">
      <div className="text-2xs text-muted-foreground/60">{label}</div>
      <div className="font-mono text-2xs tabular-nums text-foreground/80">{value}</div>
    </div>
  )
}

function InterfaceRow({
  iface,
  selected,
  capturing,
  running,
  onToggle,
}: {
  iface: InterfaceInfo
  selected: boolean
  capturing: boolean
  running: boolean
  onToggle: () => void
}) {
  const { t } = useI18n()
  const subtitle = iface.addrs[0] ?? iface.mac ?? iface.kind
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onToggle}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault()
          onToggle()
        }
      }}
      className={cn(
        "group flex w-full cursor-pointer items-start gap-2 rounded-md border border-transparent px-1.5 py-1.5 text-left transition-colors",
        selected ? "bg-primary/[0.08] hover:bg-primary/[0.12]" : "hover:bg-accent/60",
        running && !selected && "opacity-70",
      )}
    >
      <Checkbox
        checked={selected}
        onClick={(e) => e.stopPropagation()}
        onCheckedChange={onToggle}
        className="mt-0.5"
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="truncate font-mono text-xs text-foreground/90">{iface.name}</span>
          {iface.default && (
            <Badge variant="muted" className="px-1 py-0 text-[9px]">
              {t("sidebar.default")}
            </Badge>
          )}
          {!iface.up && (
            <span className="text-[9px] uppercase text-muted-foreground/50">
              {t("sidebar.down")}
            </span>
          )}
          {capturing && (
            <span className="ml-auto flex items-center gap-1 text-[9px] uppercase text-emerald-600 dark:text-emerald-400">
              <span className="h-1 w-1 animate-pulse-dot rounded-full bg-emerald-400" />
              {t("sidebar.live")}
            </span>
          )}
        </div>
        <div className="truncate font-mono text-2xs text-muted-foreground/60" title={subtitle}>
          {subtitle}
        </div>
      </div>
    </div>
  )
}

function CapturePanel(props: SidebarProps) {
  const { t } = useI18n()
  const fileRef = useRef<HTMLInputElement>(null)
  const status = props.status
  const running = status?.capture.running ?? false
  const ifaces = (status?.interfaces ?? []).filter((i) => i.index >= 0)
  const capturingSet = new Set(status?.capture.interfaces ?? [])
  const store = status?.store

  return (
    <div className="space-y-4 p-3">
      <Section
        title={t("sidebar.interfaces", {
          selected: props.selectedIfaces.length,
          total: ifaces.length,
        })}
        action={
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="text-2xs text-muted-foreground hover:text-foreground"
              onClick={props.onSelectAllIfaces}
            >
              {t("sidebar.all")}
            </button>
            <span className="text-muted-foreground/30">·</span>
            <button
              type="button"
              className="text-2xs text-muted-foreground hover:text-foreground"
              onClick={props.onClearIfaces}
            >
              {t("sidebar.none")}
            </button>
          </div>
        }
      >
        <div className="space-y-0.5 rounded-md border bg-background/30 p-1">
          {ifaces.length === 0 && (
            <div className="px-2 py-3 text-center text-2xs text-muted-foreground/60">
              {t("sidebar.noInterfaces")}
            </div>
          )}
          {ifaces.map((iface) => (
            <InterfaceRow
              key={iface.name}
              iface={iface}
              selected={props.selectedIfaces.includes(iface.name)}
              capturing={running && capturingSet.has(iface.name)}
              running={running}
              onToggle={() => props.onToggleIface(iface.name)}
            />
          ))}
        </div>
        {running && (
          <p className="mt-1.5 text-[10px] leading-relaxed text-muted-foreground/60">
            {t("sidebar.selectionNote")}
          </p>
        )}
      </Section>

      <Section title={t("sidebar.options")}>
        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <label className="text-2xs text-muted-foreground/70">{t("sidebar.snaplen")}</label>
            <Select
              value={String(props.snaplen)}
              onValueChange={(v) => props.onSnaplenChange(Number(v))}
              disabled={running}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="256">256 B</SelectItem>
                <SelectItem value="512">512 B</SelectItem>
                <SelectItem value="1024">1 KB</SelectItem>
                <SelectItem value="2048">2 KB</SelectItem>
                <SelectItem value="4096">4 KB</SelectItem>
                <SelectItem value="16384">16 KB</SelectItem>
                <SelectItem value="65536">64 KB</SelectItem>
                <SelectItem value="262144">256 KB</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <label className="text-2xs text-muted-foreground/70">{t("sidebar.sampling")}</label>
            <Select
              value={String(props.sampleRate)}
              onValueChange={(v) => props.onSampleRateChange(Number(v))}
              disabled={running}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1">{t("sidebar.everyPacket")}</SelectItem>
                <SelectItem value="10">{t("sidebar.oneIn", { n: 10 })}</SelectItem>
                <SelectItem value="100">{t("sidebar.oneIn", { n: 100 })}</SelectItem>
                <SelectItem value="1000">{t("sidebar.oneIn", { n: 1000 })}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div className="mt-2 space-y-1">
          <label className="text-2xs text-muted-foreground/70">{t("sidebar.ringBuffer")}</label>
          <Select
            value={String(props.ringSize)}
            onValueChange={(v) => props.onRingSizeChange(Number(v))}
            disabled={running}
          >
            <SelectTrigger className="h-8">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={String(8 << 20)}>8 MB</SelectItem>
              <SelectItem value={String(16 << 20)}>16 MB</SelectItem>
              <SelectItem value={String(32 << 20)}>32 MB</SelectItem>
              <SelectItem value={String(64 << 20)}>64 MB</SelectItem>
              <SelectItem value={String(128 << 20)}>128 MB</SelectItem>
              <SelectItem value={String(256 << 20)}>256 MB</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-[10px] text-muted-foreground/60">{t("sidebar.ringBufferHint")}</p>
        </div>
        <div className="mt-2 flex items-center justify-between rounded-md border bg-background/30 px-2 py-1.5">
          <span className="text-2xs text-muted-foreground">{t("sidebar.clearOnStart")}</span>
          <Switch
            checked={props.clearOnStart}
            onCheckedChange={props.onClearOnStartChange}
            disabled={running}
          />
        </div>
      </Section>

      <Section
        title={t("sidebar.cgroupScope")}
        action={<Boxes className="h-3 w-3 text-muted-foreground/40" />}
      >
        <div className="flex items-center gap-1.5 rounded-md border bg-background/30 px-2 py-1.5">
          <span className="min-w-0 flex-1 truncate font-mono text-2xs text-muted-foreground">
            {props.cgroupID ? `cgroup #${props.cgroupID}` : t("sidebar.cgroupOff")}
          </span>
          <Button size="sm" variant="outline" className="h-7 shrink-0 px-2 text-2xs" onClick={props.onOpenProcesses}>
            {t("sidebar.chooseProcess")}
          </Button>
          {props.cgroupID ? (
            <Button size="icon" variant="ghost" className="h-7 w-7 shrink-0" onClick={() => props.onSelectCgroup(null)} aria-label={t("process.clear")}>
              <X className="h-3.5 w-3.5" />
            </Button>
          ) : null}
        </div>
      </Section>

      <div className="space-y-1.5">
        {running ? (
          <Button variant="outline" className="w-full" onClick={props.onStop} disabled={props.busy}>
            <Square className="fill-current" /> {t("sidebar.stop")}
          </Button>
        ) : (
          <Button className="w-full" onClick={props.onStart} disabled={props.busy}>
            <Play className="fill-current" /> {t("sidebar.start")}
          </Button>
        )}
        <div className="grid grid-cols-3 gap-1.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={props.onClear}
            disabled={props.busy || (store?.total ?? 0) === 0}
          >
            <Trash2 /> {t("sidebar.clear")}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => fileRef.current?.click()}
            disabled={props.busy}
          >
            <FileUp /> {t("sidebar.import")}
          </Button>
          <Button variant="secondary" size="sm" asChild>
            <a href={api.exportUrl("")} download>
              <Download /> {t("sidebar.export")}
            </a>
          </Button>
        </div>
        <input
          ref={fileRef}
          type="file"
          accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0]
            if (file) props.onImport(file)
            e.target.value = ""
          }}
        />
      </div>

      <Separator />

      <Section
        title={t("sidebar.kernel")}
        action={<Gauge className="h-3 w-3 text-muted-foreground/40" />}
      >
        <div className="grid grid-cols-2 gap-1.5">
          <Stat
            label={t("sidebar.captured")}
            value={formatCount(status?.capture.kernelPackets ?? 0)}
          />
          <Stat label={t("sidebar.bytes")} value={formatBytes(status?.capture.kernelBytes ?? 0)} />
          <Stat
            label={t("sidebar.skipped")}
            value={formatCount(status?.capture.kernelSkipped ?? 0)}
          />
          <Stat
            label={t("sidebar.filteredSelf")}
            value={formatCount(status?.capture.kernelFiltered ?? 0)}
          />
          <Stat
            label={t("sidebar.ringBuffer")}
            value={formatBytes(status?.capture.ringSize ?? 0, 0)}
          />
          <Stat
            label={t("sidebar.selfPort")}
            value={
              status?.capture.excludePort
                ? `:${status.capture.excludePort}`
                : t("sidebar.off")
            }
          />
          <Stat
            label={t("sidebar.streams")}
            value={formatCount(status?.store.streams?.flows ?? 0)}
          />
          <Stat
            label={t("sidebar.streamMem")}
            value={formatBytes(status?.store.streams?.bytes ?? 0)}
          />
        </div>
        {(status?.capture.attachErrors?.length ?? 0) > 0 && (
          <div className="mt-2 space-y-1 rounded border border-amber-400/25 bg-amber-400/[0.07] p-2 text-[10px] leading-relaxed text-amber-700 dark:text-amber-300">
            <div className="flex items-center gap-1 font-medium">
              <CircleAlert className="h-3 w-3" /> {t("sidebar.attachWarnings")}
            </div>
            {status?.capture.attachErrors?.map((err) => (
              <div key={err} className="break-words text-amber-700/80 dark:text-amber-200/70">
                {err}
              </div>
            ))}
          </div>
        )}
        {status?.capture.lastError && (
          <div className="mt-2 break-words rounded border border-destructive/30 bg-destructive/10 p-2 text-[10px] text-destructive">
            {status.capture.lastError}
          </div>
        )}
      </Section>
    </div>
  )
}

function ProtocolsPanel({ status, filter, onApplyFilter }: Pick<SidebarProps, "status" | "filter" | "onApplyFilter">) {
  const { t } = useI18n()
  const protocols = status?.store.protocols ?? {}
  const entries = Object.entries(protocols).sort((a, b) => b[1] - a[1])
  const total = entries.reduce((sum, [, n]) => sum + n, 0)
  const active = filter.trim().toLowerCase()
  const max = entries.length > 0 ? entries[0][1] : 1

  return (
    <div className="space-y-3 p-3">
      <div className="flex items-center justify-between text-2xs text-muted-foreground">
        <span>{t("sidebar.protocolsObserved", { count: entries.length })}</span>
        <span className="font-mono tabular-nums">
          {t("sidebar.packetsCount", { count: formatCount(total) })}
        </span>
      </div>
      <button
        type="button"
        onClick={() => onApplyFilter("")}
        className={cn(
          "flex w-full items-center justify-between rounded-md border px-2 py-1.5 text-xs transition-colors",
          !filter ? "border-primary/40 bg-primary/10 text-foreground" : "hover:bg-accent",
        )}
      >
        <span className="flex items-center gap-2">
          <Layers className="h-3.5 w-3.5 text-muted-foreground" />
          {t("sidebar.allTraffic")}
        </span>
        <span className="font-mono text-2xs text-muted-foreground">{formatCount(total)}</span>
      </button>
      {entries.length === 0 && (
        <div className="rounded-md border border-dashed p-4 text-center text-2xs text-muted-foreground/60">
          {t("sidebar.protocolsEmpty")}
        </div>
      )}
      <div className="space-y-1">
        {entries.map(([proto, count]) => {
          const style = protoStyle(proto)
          const keyword = proto.toLowerCase()
          const isActive = active === keyword
          const pct = total > 0 ? (count / total) * 100 : 0
          return (
            <button
              key={proto}
              type="button"
              onClick={() => onApplyFilter(isActive ? "" : keyword)}
              className={cn(
                "w-full rounded-md px-2 py-1.5 text-left transition-colors",
                isActive ? "bg-primary/10 ring-1 ring-primary/30" : "hover:bg-accent/60",
              )}
            >
              <div className="flex items-center gap-2">
                <span className={cn("h-1.5 w-1.5 rounded-full", style.dot)} />
                <span className="font-mono text-xs text-foreground/90">{proto}</span>
                <span className="ml-auto font-mono text-2xs tabular-nums text-muted-foreground">
                  {formatCount(count)}
                </span>
                <span className="w-9 text-right font-mono text-2xs tabular-nums text-muted-foreground/50">
                  {pct.toFixed(0)}%
                </span>
              </div>
              <div className="mt-1 h-0.5 overflow-hidden rounded-full bg-muted/60">
                <div
                  className={cn("h-full rounded-full opacity-80", style.bar)}
                  style={{ width: `${Math.max(1.5, (count / max) * 100)}%` }}
                />
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

function FlowsPanel({
  active,
  filter,
  onApplyFilter,
}: {
  active: boolean
  filter: string
  onApplyFilter: (f: string) => void
}) {
  const { t } = useI18n()
  const [flows, setFlows] = useState<Flow[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!active) return
    let cancelled = false
    const load = async () => {
      try {
        const res = await api.conversations(150)
        if (!cancelled) setFlows(res.flows)
      } catch {
        /* ignore */
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    setLoading(true)
    load()
    const t = setInterval(load, 2000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [active])

  return (
    <div className="space-y-2 p-3">
      <div className="flex items-center justify-between text-2xs text-muted-foreground">
        <span>{t("sidebar.conversations", { count: flows.length })}</span>
        {loading && <RefreshCw className="h-3 w-3 animate-spin" />}
      </div>
      {flows.length === 0 && (
        <div className="rounded-md border border-dashed p-4 text-center text-2xs leading-relaxed text-muted-foreground/60">
          {t("sidebar.flowsEmpty")}
        </div>
      )}
      {flows.map((flow) => {
        const style = protoStyle(flow.app || flow.protocol)
        const duration =
          (new Date(flow.last).getTime() - new Date(flow.first).getTime()) / 1000
        const filterExpr = `ip.addr == ${flow.src} and ip.addr == ${flow.dst}`
        return (
          <button
            key={flow.key}
            type="button"
            onClick={() => onApplyFilter(filterExpr)}
            className={cn(
              "w-full rounded-md border bg-background/40 p-2 text-left transition-colors hover:border-border hover:bg-accent/50",
              filter === filterExpr && "border-primary/40 bg-primary/10",
            )}
          >
            <div className="flex items-center gap-2">
              <span className={cn("h-1.5 w-1.5 rounded-full", style.dot)} />
              <span className={cn("font-mono text-2xs font-medium", style.text)}>
                {flow.app || flow.protocol}
              </span>
              {flow.state && flow.protocol === "TCP" && (
                <Badge variant="muted" className="text-[9px]">
                  {flow.state}
                </Badge>
              )}
              <span className="ml-auto font-mono text-2xs tabular-nums text-muted-foreground">
                {formatBytes(flow.bytes)}
              </span>
            </div>
            <div className="mt-1 truncate font-mono text-[11px] text-foreground/80">
              {flow.src}
              {flow.srcPort ? `:${flow.srcPort}` : ""}
              <span className="mx-1 text-muted-foreground/50">→</span>
              {flow.dst}
              {flow.dstPort ? `:${flow.dstPort}` : ""}
            </div>
            <div className="mt-1 flex items-center gap-2 text-2xs text-muted-foreground/60">
              <span className="tabular-nums">
                {t("sidebar.pkts", { count: formatCount(flow.packets) })}
              </span>
              <span>·</span>
              <span className="tabular-nums">{formatDuration(duration)}</span>
              <span className="ml-auto flex items-center gap-1 tabular-nums">
                <span className="text-emerald-600/80 dark:text-emerald-400/70">↓{formatCount(flow.packetsA)}</span>
                <span className="text-amber-600/80 dark:text-amber-400/70">↑{formatCount(flow.packetsB)}</span>
              </span>
            </div>
          </button>
        )
      })}
    </div>
  )
}

function SidebarImpl(props: SidebarProps) {
  const { t } = useI18n()
  const [localTab, setLocalTab] = useState("capture")
  const tab = props.activeTab ?? localTab
  const setTab = (next: string) => {
    if (props.onTabChange) props.onTabChange(next)
    else setLocalTab(next)
  }
  const module = props.module ?? "network"
  const running = props.status?.capture.running ?? false

  return (
    <aside className={cn(
      "w-[268px] shrink-0 flex-col border-r bg-panel/40",
      props.mobile ? "flex h-full" : "hidden md:flex",
    )}>
      {props.mobile && (
        <div className="shrink-0 border-b px-2 py-2">
          <div className="flex items-center gap-1">
            <span className="mr-auto px-1 text-xs font-semibold">sisyphus</span>
            <Button variant={module === "network" ? "secondary" : "ghost"} size="sm" className="h-7 px-2 text-2xs" onClick={() => props.onModuleChange?.("network")}>
              {t("sidebar.network")}
            </Button>
            <Button variant={module === "processes" ? "secondary" : "ghost"} size="sm" className="h-7 px-2 text-2xs" onClick={() => props.onModuleChange?.("processes")}>
              {t("sidebar.processes")}
            </Button>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={props.onClose} aria-label={t("app.closeSidebar")}>
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {module === "network" ? (
        <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col">
          <div className="shrink-0 border-b p-2">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="capture">
                <Gauge /> {t("sidebar.capture")}
              </TabsTrigger>
              <TabsTrigger value="processes">
                <Boxes /> {t("sidebar.processes")}
              </TabsTrigger>
              <TabsTrigger value="protocols">
                <Layers /> {t("sidebar.protocols")}
              </TabsTrigger>
              <TabsTrigger value="flows">
                <ArrowLeftRight /> {t("sidebar.flows")}
              </TabsTrigger>
            </TabsList>
          </div>
          <TabsContent value="capture" className="mt-0 min-h-0 flex-1">
            <ScrollArea className="h-full">
              <CapturePanel {...props} />
            </ScrollArea>
          </TabsContent>
          <TabsContent value="processes" className="mt-0 min-h-0 flex-1">
            <ScrollArea className="h-full">
              <ProcessPanel
                active={tab === "processes"}
                selectedCgroupID={props.cgroupID}
                onSelectCgroup={props.onSelectCgroup}
                onTraceProcess={props.onTraceProcess}
              />
            </ScrollArea>
          </TabsContent>
          <TabsContent value="protocols" className="mt-0 min-h-0 flex-1">
            <ScrollArea className="h-full">
              <ProtocolsPanel
                status={props.status}
                filter={props.filter}
                onApplyFilter={props.onApplyFilter}
              />
            </ScrollArea>
          </TabsContent>
          <TabsContent value="flows" className="mt-0 min-h-0 flex-1">
            <ScrollArea className="h-full">
              <FlowsPanel
                active={tab === "flows"}
                filter={props.filter}
                onApplyFilter={props.onApplyFilter}
              />
            </ScrollArea>
          </TabsContent>
        </Tabs>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col">
          <div className="shrink-0 border-b px-3 py-2">
            <div className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground/70">
              {t("sidebar.processes")}
            </div>
          </div>
          <ScrollArea className="min-h-0 flex-1">
            <ProcessPanel
              active
              selectedCgroupID={props.cgroupID}
              onSelectCgroup={props.onSelectCgroup}
              onTraceProcess={props.onTraceProcess}
            />
          </ScrollArea>
        </div>
      )}

      <div className="shrink-0 border-t bg-panel/60 px-3 py-1.5 text-[10px] text-muted-foreground/50">
        {t("sidebar.liveStatus")}{" "}
        <span className={running ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"}>
          {running ? t("sidebar.running") : t("sidebar.stopped")}
        </span>
      </div>
    </aside>
  )
}

export const Sidebar = memo(SidebarImpl)
