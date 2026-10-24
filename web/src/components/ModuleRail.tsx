import { memo } from "react"
import { Activity, Network } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"
import { useI18n, type MessageKey } from "@/i18n"

export type WorkspaceModule = "network" | "processes"
export type SidebarModule = WorkspaceModule | "trace"

interface ModuleRailProps {
  active: WorkspaceModule
  onSelect: (module: WorkspaceModule) => void
  onTrace: () => void
  traceOpen: boolean
}

const MODULES: Array<{
  id: WorkspaceModule
  icon: typeof Network
  label: MessageKey
}> = [
  { id: "network", icon: Network, label: "sidebar.network" },
]

function ModuleRailImpl({ active, onSelect, onTrace, traceOpen }: ModuleRailProps) {
  const { t } = useI18n()
  return (
    <nav
      className="hidden w-12 shrink-0 flex-col items-center gap-1 border-r bg-panel/60 py-2 md:flex"
      aria-label={t("sidebar.modules")}
    >
      {MODULES.map((module) => {
        const Icon = module.icon
        const selected = active === module.id && !traceOpen
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
            variant={traceOpen ? "secondary" : "ghost"}
            size="icon"
            className={cn("h-8 w-8", traceOpen && "text-primary")}
            onClick={onTrace}
            aria-label={t("sidebar.trace")}
            aria-pressed={traceOpen}
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
