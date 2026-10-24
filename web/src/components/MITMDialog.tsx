import { useEffect, useState } from "react"
import { Download, Globe2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { api } from "@/lib/api"
import { useI18n } from "@/i18n"
import type { MITMStatus } from "@/lib/types"

interface MITMDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function MITMDialog({ open, onOpenChange }: MITMDialogProps) {
  const { t } = useI18n()
  const [status, setStatus] = useState<MITMStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!open) return
    setError("")
    api
      .mitmStatus()
      .then((s) => {
        setStatus(s)
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
  }, [open])

  const apply = async (enabled: boolean) => {
    setBusy(true)
    setError("")
    try {
      setStatus(await api.setMITM(enabled, ""))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const proxyURL = `http://${status?.addr || "127.0.0.1:18080"}`

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg gap-0 p-0">
        <DialogHeader className="border-b px-4 py-3 pr-10">
          <DialogTitle className="flex items-center gap-2">
            <Globe2 className="h-4 w-4 text-primary" />
            {t("mitm.title")}
          </DialogTitle>
          <DialogDescription>{t("mitm.subtitle")}</DialogDescription>
        </DialogHeader>

        <div className="space-y-3 p-4">
          <div className="rounded-md border bg-background/40 p-3">
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${status?.enabled ? "bg-emerald-500" : "bg-muted-foreground/40"}`} />
              <span className="text-xs font-medium">
                {status?.enabled ? t("mitm.running") : t("mitm.stopped")}
              </span>
              <span className="ml-auto font-mono text-2xs text-muted-foreground">
                {proxyURL}
              </span>
              <Switch
                checked={status?.enabled ?? false}
                disabled={busy || !status}
                onCheckedChange={(enabled) => { void apply(enabled) }}
                aria-label={t("mitm.title")}
              />
            </div>
            <p className="mt-1 text-[10px] text-muted-foreground">{t("mitm.oneSwitchHint")}</p>
            <div className="mt-2 flex items-center gap-2 text-2xs text-muted-foreground">
              <span className="min-w-0 flex-1 truncate font-mono" title={status?.caPath}>{status?.caPath || "CA unavailable"}</span>
              <Button size="sm" variant="outline" className="h-7 shrink-0" asChild disabled={!status?.enabled}>
                <a href="/api/mitm/ca" download>
                  <Download className="h-3.5 w-3.5" /> {t("mitm.downloadCA")}
                </a>
              </Button>
            </div>
          </div>

          <details className="rounded-md border bg-muted/20 p-3 text-2xs leading-relaxed text-muted-foreground">
            <summary className="cursor-pointer font-medium text-foreground/80">{t("mitm.advanced")}</summary>
            <div className="mt-2 space-y-1.5">
            <div className="font-medium text-foreground/80">{t("mitm.usage")}</div>
            <code className="block break-all rounded bg-background/60 px-2 py-1 font-mono text-[10px] text-foreground/80">
              export HTTPS_PROXY={proxyURL}
            </code>
            <p>{t("mitm.trust")}</p>
            <p>{t("mitm.note")}</p>
            </div>
          </details>

          {error && <div className="rounded border border-destructive/30 bg-destructive/10 p-2 text-2xs text-destructive">{error}</div>}
        </div>

        <DialogFooter className="border-t p-3">
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
            {t("mitm.close")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
