import { CircleAlert, ShieldAlert } from "lucide-react"
import { formatCount } from "@/lib/format"
import { useI18n } from "@/i18n"
import type { StatusResponse } from "@/lib/types"

export function NetworkHealth({ status }: { status: StatusResponse | null }) {
  const { t } = useI18n()
  const capture = status?.capture
  const store = status?.store
  if (!capture) return null
  const issues: string[] = []
  for (const err of capture.attachErrors ?? []) issues.push(err)
  if (capture.lastError) issues.push(capture.lastError)
  if (capture.kernelSkipped > 0) {
    issues.push(t("health.kernelSkipped", { count: formatCount(capture.kernelSkipped) }))
  }
  if ((store?.dropped ?? 0) > 0) {
    issues.push(t("health.dropped", { count: formatCount(store?.dropped ?? 0) }))
  }
  const usage = store && store.capacity > 0 ? (store.stored / store.capacity) * 100 : 0
  if (usage > 85) {
    issues.push(t("health.buffer", { pct: usage.toFixed(0) }))
  }
  if (issues.length === 0) return null
  return (
    <div className="shrink-0 border-b border-amber-400/25 bg-amber-400/[0.07] px-3 py-1.5 text-[10px] text-amber-700 dark:text-amber-300">
      <div className="flex items-start gap-1.5">
        <ShieldAlert className="mt-[1px] h-3.5 w-3.5 shrink-0" />
        <div className="min-w-0">
          <div className="font-medium">{t("health.title")}</div>
          {issues.slice(0, 3).map((issue) => (
            <div key={issue} className="mt-0.5 truncate" title={issue}>
              <CircleAlert className="mr-1 inline h-2.5 w-2.5" />
              {issue}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
