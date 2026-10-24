import { useEffect, useMemo, useState } from "react"
import { Activity, Cable, Columns3, Command, Globe2, KeyRound, Layers, Search, Square, Trash2 } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"
import { useI18n } from "@/i18n"

export interface PaletteCommand {
  id: string
  label: string
  keywords?: string
  icon: typeof Search
  run: () => void
}

interface CommandPaletteProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  commands: PaletteCommand[]
}

export function CommandPalette({ open, onOpenChange, commands }: CommandPaletteProps) {
  const { t } = useI18n()
  const [query, setQuery] = useState("")

  useEffect(() => {
    if (!open) setQuery("")
  }, [open])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return commands
    return commands.filter((c) => `${c.label} ${c.keywords ?? ""}`.toLowerCase().includes(q))
  }, [commands, query])

  const run = (command: PaletteCommand) => {
    onOpenChange(false)
    command.run()
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg gap-0 p-0">
        <DialogHeader className="border-b px-4 py-3 pr-10">
          <DialogTitle className="flex items-center gap-2">
            <Command className="h-4 w-4 text-primary" />
            {t("palette.title")}
          </DialogTitle>
          <DialogDescription>{t("palette.hint")}</DialogDescription>
        </DialogHeader>
        <div className="border-b p-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t("palette.search")}
              className="h-8 pl-8 text-xs"
              onKeyDown={(e) => {
                if (e.key === "Enter" && filtered[0]) run(filtered[0])
              }}
            />
          </div>
        </div>
        <div className="max-h-[50vh] overflow-auto p-1 scrollbar-thin">
          {filtered.map((command) => {
            const Icon = command.icon
            return (
              <button
                key={command.id}
                type="button"
                onClick={() => run(command)}
                className={cn("flex w-full items-center gap-2 rounded px-2 py-2 text-left text-xs hover:bg-accent")}
              >
                <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                <span>{command.label}</span>
              </button>
            )
          })}
          {filtered.length === 0 && (
            <div className="px-3 py-6 text-center text-2xs text-muted-foreground">
              {t("palette.empty")}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}

// Re-exported so App can build the command list with consistent icons.
export const PaletteIcons = { Activity, Cable, Columns3, Globe2, KeyRound, Layers, Square, Trash2 }
