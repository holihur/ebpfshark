import { memo } from "react"
import {
  Languages,
  LogOut,
  MemoryStick,
  Moon,
  MoreHorizontal,
  PanelLeft,
  Server,
  Sun,
  Waves,
} from "lucide-react"
import { Button } from "@/components/ui/button"
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
import type { StatusResponse } from "@/lib/types"
import { formatBytes, formatDuration } from "@/lib/format"
import { LOCALE_LABELS, useI18n, type Locale } from "@/i18n"

interface HeaderProps {
  status: StatusResponse | null
  theme: "dark" | "light"
  authEnabled: boolean
  username: string
  onLogout: () => void
  onToggleTheme: () => void
  onOpenSidebar: () => void
}

function HeaderImpl({
  status,
  theme,
  authEnabled,
  username,
  onLogout,
  onToggleTheme,
  onOpenSidebar,
}: HeaderProps) {
  const { t, locale, setLocale } = useI18n()

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
          <div className="text-[13px] font-semibold tracking-tight">sisyphus</div>
          <div className="mt-1 hidden text-2xs text-muted-foreground sm:block">
            {t("app.subtitle")}
          </div>
        </div>
      </div>

      <div className="flex-1" />

      <div className="hidden items-center gap-2 text-2xs text-muted-foreground md:flex">
        <span className="rounded border bg-background/40 px-1.5 py-0.5 font-mono text-foreground/70">
          v{status?.version ?? "…"}
        </span>
        {status?.system?.kernel && (
          <span className="hidden items-center gap-1 lg:flex" title={status.system.kernel}>
            <Server className="h-3 w-3" />
            Linux {status.system.kernel}
          </span>
        )}
        {status?.system && status.system.memoryTotal > 0 && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="flex items-center gap-1 font-mono tabular-nums">
                <MemoryStick className="h-3 w-3" />
                {formatBytes(status.system.memoryTotal - status.system.memoryAvailable)} /{" "}
                {formatBytes(status.system.memoryTotal)}
              </span>
            </TooltipTrigger>
            <TooltipContent>
              <div className="space-y-0.5 text-2xs">
                <div>{t("app.memory")}</div>
                {status.system.os && <div>{status.system.os}</div>}
                <div>{t("app.uptime", { value: formatDuration(status.system.uptimeSeconds) })}</div>
              </div>
            </TooltipContent>
          </Tooltip>
        )}
      </div>

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
          <DropdownMenuLabel>{t("app.system")}</DropdownMenuLabel>
          <DropdownMenuItem disabled className="text-2xs text-muted-foreground">
            {t("app.version", { version: status?.version ?? "…" })}
          </DropdownMenuItem>
          {status?.system?.kernel && (
            <DropdownMenuItem disabled className="text-2xs text-muted-foreground">
              Linux {status.system.kernel}
            </DropdownMenuItem>
          )}
          {status?.system && status.system.memoryTotal > 0 && (
            <DropdownMenuItem disabled className="text-2xs text-muted-foreground">
              {formatBytes(status.system.memoryTotal - status.system.memoryAvailable)} / {formatBytes(status.system.memoryTotal)}
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  )
}

export const Header = memo(HeaderImpl)
