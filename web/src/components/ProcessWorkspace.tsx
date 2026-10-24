import { lazy, Suspense } from "react"
import { Boxes, ScrollText } from "lucide-react"
import { useI18n } from "@/i18n"
import type { ProcessInfo } from "@/lib/types"

const TracePanel = lazy(() =>
  import("@/components/TracePanel").then((m) => ({ default: m.TracePanel })),
)

interface ProcessWorkspaceProps {
  process: ProcessInfo | null
}

function Item({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-md border bg-background/40 px-3 py-2">
      <div className="text-2xs text-muted-foreground">{label}</div>
      <div className={`mt-1 break-all text-xs ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  )
}

export function ProcessWorkspace({ process }: ProcessWorkspaceProps) {
  const { t } = useI18n()

  return (
    <main className="flex min-w-0 flex-1 flex-col overflow-auto bg-background">
      <div className="border-b px-4 py-3">
        <div className="flex items-center gap-2">
          <Boxes className="h-4 w-4 text-primary" />
          <h1 className="text-sm font-semibold">{t("process.workspace")}</h1>
        </div>
        <p className="mt-1 text-2xs text-muted-foreground">{t("process.workspaceHint")}</p>
      </div>

      {!process ? (
        <div className="grid flex-1 place-items-center p-6">
          <div className="max-w-sm text-center">
            <div className="mx-auto grid h-12 w-12 place-items-center rounded-xl border bg-card/80 shadow-lg">
              <Boxes className="h-5 w-5 text-primary" />
            </div>
            <h2 className="mt-3 text-sm font-medium">{t("process.noSelection")}</h2>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              {t("process.noSelectionHint")}
            </p>
          </div>
        </div>
      ) : (
        <div className="flex-1 space-y-3 p-4">
          <div className="rounded-lg border bg-card/40 p-4">
            <div className="flex flex-wrap items-start gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate font-mono text-lg font-semibold">{process.comm || "?"}</span>
                  <span className="rounded-full border px-2 py-0.5 font-mono text-2xs text-muted-foreground">
                    PID {process.pid}
                  </span>
                </div>
                <div className="mt-1 truncate font-mono text-2xs text-muted-foreground" title={process.cgroupPath}>
                  {process.cgroupPath}
                </div>
              </div>

            </div>
          </div>

          <div className="grid gap-2 sm:grid-cols-2">
            <Item label={t("process.pid")} value={String(process.pid)} mono />
            <Item label={t("process.cgroupId")} value={process.cgroupID ? `#${process.cgroupID}` : "—"} mono />
            <div className="sm:col-span-2">
              <Item label={t("process.cgroupPath")} value={process.cgroupPath || "—"} mono />
            </div>
          </div>

          <div className="min-h-[360px] overflow-hidden rounded-lg border bg-background/40">
            <Suspense fallback={null}>
              <TracePanel active initialPid={process.pid} />
            </Suspense>
          </div>

          <div className="rounded-lg border bg-muted/20 p-3 text-2xs leading-relaxed text-muted-foreground">
            <div className="flex items-center gap-1.5 font-medium text-foreground/80">
              <ScrollText className="h-3.5 w-3.5" /> {t("process.instrumentHint")}
            </div>
            <p className="mt-1">{t("process.instrumentHintBody")}</p>
          </div>
        </div>
      )}
    </main>
  )
}
