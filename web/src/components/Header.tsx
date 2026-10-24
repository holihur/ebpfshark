import { memo } from "react"
import {
  Activity,
  Languages,
  LogOut,
  Moon,
  MoreHorizontal,
  PanelLeft,
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
import { LOCALE_LABELS, useI18n, type Locale } from "@/i18n"

interface HeaderProps {
  status: StatusResponse | null
  theme: "dark" | "light"
  authEnabled: boolean
  username: string
  onLogout: () => void
  onToggleTheme: () => void
  onOpenSidebar: () => void
  onTrace: () => void
}

function HeaderImpl({
  status,
  theme,
  authEnabled,
  username,
  onLogout,
  onToggleTheme,
  onOpenSidebar,
  onTrace,
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
          <DropdownMenuItem disabled className="text-2xs text-muted-foreground">
            {t("app.version", { version: status?.version ?? "…" })}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  )
}

export const Header = memo(HeaderImpl)
