import { memo } from "react"
import { Activity, ArrowLeftRight, Boxes, Gauge, Layers } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"
import { useI18n, type MessageKey } from "@/i18n"

export type SidebarModule = "capture" | "processes" | "protocols" | "flows" | "trace"

interface ModuleRailProps {
  active: SidebarModule
  onSelect: (module: SidebarModule) => void
  onTrace: () => void
}

const MODULES: Array<{
  id: Exclude<SidebarModule, "trace">
  icon: typeof Gauge
  label: MessageKey
}> = [
  { id: "capture", icon: Gauge, label: "sidebar.capture" },
  { id: "processes", icon: Boxes, label: "sidebar.processes" },
  { id: "protocols", icon: Layers, label: "sidebar.protocols" },
  { id: "flows", icon: ArrowLeftRight, label: "sidebar.flows" },
]

function ModuleRailImpl({ active, onSelect, onTrace }: ModuleRailProps) {
  const { t } = useI18n()
  return (
    <nav
      className="hidden w-12 shrink-0 flex-col items-center gap-1 border-r bg-panel/60 py-2 md:flex"
      aria-label={t("sidebar.modules")}
    >
      {MODULES.map((module) => {
        const Icon = module.icon
        const selected = active === module.id
        return (
          <Tooltip key={module.id}>
            <TooltipTrigger asChild>
              <Button
                variant={selected ? "secondary" : "ghost"}
                size="icon"
                className={cn("h-8 w-8", selected && "text-primary")}
                onClick={() => onSelect(module.id)}
                aria-label={t(module.label)}
                aria-pressed={selected}
              >
                <Icon className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="right">{t(module.label)}</TooltipContent>
          </Tooltip>
        )
      })}
      <div className="my-1 h-px w-6 bg-border" />
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant={active === "trace" ? "secondary" : "ghost"}
            size="icon"
            className={cn("h-8 w-8", active === "trace" && "text-primary")}
            onClick={() => {
              onSelect("trace")
              onTrace()
            }}
            aria-label={t("sidebar.trace")}
            aria-pressed={active === "trace"}
          >
            <Activity className="h-4 w-4" />
          </Button>
        </TooltipTrigger>
        <TooltipContent side="right">{t("sidebar.trace")}</TooltipContent>
      </Tooltip>
    </nav>
  )
}

export const ModuleRail = memo(ModuleRailImpl)
