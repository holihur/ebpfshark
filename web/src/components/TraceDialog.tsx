import { lazy, Suspense } from "react"
import { Activity } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { useI18n } from "@/i18n"

const TracePanel = lazy(() =>
  import("@/components/TracePanel").then((m) => ({ default: m.TracePanel })),
)

interface TraceDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function TraceDialog({ open, onOpenChange }: TraceDialogProps) {
  const { t } = useI18n()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="h-[82vh] max-w-2xl gap-0 p-0">
        <DialogHeader className="shrink-0 border-b px-4 py-3 pr-10">
          <DialogTitle className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            {t("trace.workspace")}
          </DialogTitle>
          <DialogDescription>{t("trace.workspaceHint")}</DialogDescription>
        </DialogHeader>
        <div className="min-h-0 flex-1 overflow-auto scrollbar-thin">
          <Suspense fallback={null}>
            <TracePanel active={open} />
          </Suspense>
        </div>
      </DialogContent>
    </Dialog>
  )
}
