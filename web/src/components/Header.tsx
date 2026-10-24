import { memo } from "react"
import {
  Download,
  Columns3,
  FileUp,
  Globe2,
  KeyRound,
  Languages,
  LogOut,
  Moon,
  MoreHorizontal,
  PanelLeft,
  Activity,
  Play,
  Square,
  Sun,
  Trash2,
  Waves,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import type { StatusResponse } from "@/lib/types"
import { formatDuration } from "@/lib/format"
import { LOCALE_LABELS, useI18n, type Locale } from "@/i18n"

interface HeaderProps {
  status: StatusResponse | null
  connected: boolean
  theme: "dark" | "light"
  busy: boolean
  filter: string
  authEnabled: boolean
  username: string
  onLogout: () => void
  onToggleTheme: () => void
  onStart: () => void
  onStop: () => void
  onClear: () => void
  onImport: (file: File) => void
  onEditColumns: () => void
  onDecryption: () => void
  onMITM: () => void
  onOpenSidebar: () => void
  onTrace: () => void
}

function HeaderImpl({
  status,
  connected,
  theme,
  busy,
  filter,
  authEnabled,
  username,
  onLogout,
  onToggleTheme,
  onStart,
  onStop,
  onClear,
  onImport,
  onEditColumns,
  onDecryption,
  onMITM,
  onOpenSidebar,
  onTrace,
}: HeaderProps) {
  const { t, locale, setLocale } = useI18n()
  const running = status?.capture.running ?? false
  const ifaces = status?.capture.interfaces ?? []
  const canClear = !busy && (status?.store.total ?? 0) > 0

  return (
    <header className="flex h-12 shrink-0 items-center gap-2 border-b bg-panel/80 px-3 backdrop-blur">
      <Button
        variant="ghost"
        size="icon"
        className="h-8 w-8 shrink-0 md:hidden"
        onClick={onOpenSidebar}
        aria-label={t("app.openSidebar")}
      >
        <PanelLeft />
      </Button>

      <div className="flex items-center gap-2.5">
        <div className="relative grid h-7 w-7 place-items-center rounded-md bg-primary/15 ring-1 ring-primary/30">
          <Waves className="h-4 w-4 text-primary" />
          <span className="absolute -bottom-0.5 -right-0.5 h-2 w-2 rounded-full border-2 border-panel bg-primary" />
        </div>
        <div className="leading-none">
          <div className="text-[13px] font-semibold tracking-tight">ebpfshark</div>
          <div className="mt-1 hidden text-2xs text-muted-foreground sm:block">
            {t("app.subtitle")}
          </div>
        </div>
      </div>

      <div className="mx-1 hidden h-5 w-px bg-border sm:block" />

      <div
        className={cn(
          "flex items-center gap-1.5 rounded-full border px-2 py-1 text-2xs font-medium",
          running
            ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-700 dark:text-emerald-300"
            : "border-border bg-muted/40 text-muted-foreground",
        )}
      >
        <span
          className={cn(
            "h-1.5 w-1.5 rounded-full",
            running ? "animate-pulse-dot bg-emerald-400" : "bg-muted-foreground/50",
          )}
        />
        {running ? t("app.live") : t("app.idle")}
      </div>

      <div className="hidden min-w-0 items-center gap-2 md:flex">
        {running ? (
          <>
            <span className="truncate font-mono text-2xs text-foreground/80">
              {ifaces.join(", ")}
            </span>
            <span className="text-2xs text-muted-foreground">
              {formatDuration(status?.capture.uptimeSeconds ?? 0)}
            </span>
            {!connected && (
              <Badge variant="destructive" className="animate-pulse">
                {t("app.reconnecting")}
              </Badge>
            )}
          </>
        ) : (
          <span className="text-2xs text-muted-foreground">{t("app.noCapture")}</span>
        )}
      </div>

      <div className="flex-1" />

      <input
        id="pcap-input"
        type="file"
        accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0]
          if (file) onImport(file)
          e.target.value = ""
        }}
      />

      {running ? (
        <Button variant="outline" size="sm" onClick={onStop} disabled={busy} className="gap-1.5">
          <Square className="fill-current" />
          {t("app.stop")}
        </Button>
      ) : (
        <Button size="sm" onClick={onStart} disabled={busy} className="gap-1.5">
          <Play className="fill-current" />
          {t("app.start")}
        </Button>
      )}

      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            onClick={onTrace}
            aria-label={t("trace.workspace")}
            title={t("trace.workspace")}
          >
            <Activity />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{t("trace.workspace")}</TooltipContent>
      </Tooltip>

      <DropdownMenu>
        <Tooltip>
          <TooltipTrigger asChild>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" aria-label={t("app.moreTip")}>
                <MoreHorizontal />
              </Button>
            </DropdownMenuTrigger>
          </TooltipTrigger>
          <TooltipContent>{t("app.moreTip")}</TooltipContent>
        </Tooltip>
        <DropdownMenuContent align="end" className="min-w-[13rem]">
          <DropdownMenuLabel>{t("app.more")}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            disabled={busy}
            onSelect={() => document.getElementById("pcap-input")?.click()}
          >
            <FileUp />
            {t("app.importTip")}
          </DropdownMenuItem>
          <DropdownMenuItem asChild disabled={(status?.store.stored ?? 0) === 0}>
            <a href={api.exportUrl("")} download>
              <Download />
              {t("app.exportAll", { count: status?.store.stored ?? 0 })}
            </a>
          </DropdownMenuItem>
          <DropdownMenuItem asChild disabled={!filter}>
            <a href={filter ? api.exportUrl(filter) : "#"} download>
              <Download />
              {filter ? t("app.exportFiltered", { filter }) : t("app.exportFilteredNoFilter")}
            </a>
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={onEditColumns}>
            <Columns3 />
            {t("columns.title")}
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={onDecryption}>
            <KeyRound />
            {t("decrypt.title")}
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={onMITM}>
            <Globe2 />
            {t("mitm.title")}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          {authEnabled && (
            <>
              <DropdownMenuItem disabled className="text-2xs text-muted-foreground">
                {t("auth.signedInAs", { user: username || "—" })}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={onLogout}>
                <LogOut />
                {t("auth.logout")}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
            </>
          )}
          <DropdownMenuItem disabled={!canClear} onSelect={onClear}>
            <Trash2 />
            {t("app.clearBuffer")}
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={onToggleTheme}>
            {theme === "dark" ? <Sun /> : <Moon />}
            {theme === "dark" ? t("app.theme.light") : t("app.theme.dark")}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuLabel className="flex items-center gap-1.5">
            <Languages className="h-3 w-3" />
            {t("app.language")}
          </DropdownMenuLabel>
          {(Object.keys(LOCALE_LABELS) as Locale[]).map((code) => (
            <DropdownMenuCheckboxItem
              key={code}
              checked={locale === code}
              onCheckedChange={() => setLocale(code)}
            >
              {LOCALE_LABELS[code]}
            </DropdownMenuCheckboxItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem disabled className="text-2xs text-muted-foreground">
            {t("app.version", { version: status?.version ?? "…" })}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  )
}

export const Header = memo(HeaderImpl)
