import { ArrowDown, ArrowUp, Columns3, RotateCcw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { useI18n, type MessageKey } from "@/i18n"
import { cn } from "@/lib/utils"
import {
  COLUMN_BY_ID,
  COLUMN_DEFS,
  DEFAULT_COLUMNS,
  type ColumnID,
} from "@/lib/packetColumns"

interface ColumnSettingsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  columns: ColumnID[]
  onChange: (columns: ColumnID[]) => void
}

export function ColumnSettingsDialog({
  open,
  onOpenChange,
  columns,
  onChange,
}: ColumnSettingsDialogProps) {
  const { t } = useI18n()
  const visible = columns.map((id) => COLUMN_BY_ID.get(id)).filter((col) => Boolean(col))
  const hidden = COLUMN_DEFS.filter((col) => !columns.includes(col.id))

  const move = (index: number, delta: number) => {
    const next = [...columns]
    const target = index + delta
    if (target < 0 || target >= next.length) return
    const [item] = next.splice(index, 1)
    next.splice(target, 0, item)
    onChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md gap-0 p-0">
        <DialogHeader className="border-b px-4 py-3 pr-10">
          <DialogTitle className="flex items-center gap-2">
            <Columns3 className="h-4 w-4 text-primary" />
            {t("columns.title")}
          </DialogTitle>
          <DialogDescription>{t("columns.subtitle")}</DialogDescription>
        </DialogHeader>

        <div className="max-h-[60vh] space-y-4 overflow-auto p-4 scrollbar-thin">
          <div className="space-y-1.5">
            <div className="text-2xs font-medium uppercase tracking-wide text-muted-foreground">
              {t("columns.visible")}
            </div>
            {visible.map((col, index) => {
              if (!col) return null
              return (
                <div
                  key={col.id}
                  className="flex items-center gap-2 rounded-md border bg-background/40 px-2 py-1.5"
                >
                  <Checkbox
                    checked
                    onCheckedChange={() => {
                      if (columns.length <= 1) return
                      onChange(columns.filter((id) => id !== col.id))
                    }}
                    aria-label={t("columns.hide", { column: t(col.labelKey as MessageKey) })}
                  />
                  <span className="flex-1 font-mono text-[11px]">{t(col.labelKey as MessageKey)}</span>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    className="h-6 w-6"
                    disabled={index === 0}
                    onClick={() => move(index, -1)}
                    title={t("columns.moveUp")}
                    aria-label={t("columns.moveUp")}
                  >
                    <ArrowUp />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    className="h-6 w-6"
                    disabled={index === columns.length - 1}
                    onClick={() => move(index, 1)}
                    title={t("columns.moveDown")}
                    aria-label={t("columns.moveDown")}
                  >
                    <ArrowDown />
                  </Button>
                </div>
              )
            })}
          </div>

          {hidden.length > 0 && (
            <div className="space-y-1.5">
              <div className="text-2xs font-medium uppercase tracking-wide text-muted-foreground">
                {t("columns.hidden")}
              </div>
              {hidden.map((col) => (
                <label
                  key={col.id}
                  className={cn(
                    "flex cursor-pointer items-center gap-2 rounded-md border border-dashed px-2 py-1.5",
                    "text-muted-foreground hover:bg-accent/50",
                  )}
                >
                  <Checkbox
                    checked={false}
                    onCheckedChange={() => onChange([...columns, col.id])}
                    aria-label={t("columns.show", { column: t(col.labelKey as MessageKey) })}
                  />
                  <span className="font-mono text-[11px]">{t(col.labelKey as MessageKey)}</span>
                </label>
              ))}
            </div>
          )}
        </div>

        <DialogFooter className="border-t p-3">
          <Button
            variant="ghost"
            size="sm"
            className="sm:mr-auto"
            onClick={() => onChange([...DEFAULT_COLUMNS])}
          >
            <RotateCcw /> {t("columns.reset")}
          </Button>
          <Button size="sm" onClick={() => onOpenChange(false)}>
            {t("columns.done")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
