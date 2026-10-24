import { useEffect, useRef, useState } from "react"
import { FileUp, KeyRound, ShieldCheck, Trash2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Switch } from "@/components/ui/switch"
import { api } from "@/lib/api"
import { useI18n } from "@/i18n"
import type { DecryptStatus } from "@/lib/types"

interface DecryptionDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function DecryptionDialog({ open, onOpenChange }: DecryptionDialogProps) {
  const { t } = useI18n()
  const [status, setStatus] = useState<DecryptStatus | null>(null)
  const [keylog, setKeylog] = useState("")
  const [psk, setPSK] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    setError("")
    api
      .decryptStatus()
      .then(setStatus)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
  }, [open])

  const saveKeylog = async () => {
    setBusy(true)
    setError("")
    try {
      const res = await api.setTLSKeylog(keylog)
      setStatus((prev) => ({ ...(prev ?? { wifiPSKConfigured: false, tlsKeylogAuto: false }), tlsKeylogEntries: res.tlsKeylogEntries }))
      setKeylog("")
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const clearKeylog = async () => {
    setBusy(true)
    setError("")
    try {
      await api.setTLSKeylog("")
      setStatus((prev) => ({ ...(prev ?? { wifiPSKConfigured: false, tlsKeylogAuto: false }), tlsKeylogEntries: 0 }))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const savePSK = async () => {
    setBusy(true)
    setError("")
    try {
      const res = await api.setWiFiPSK(psk)
      setStatus((prev) => ({ ...(prev ?? { tlsKeylogEntries: 0, tlsKeylogAuto: false }), wifiPSKConfigured: res.wifiPSKConfigured }))
      setPSK("")
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg gap-0 p-0">
        <DialogHeader className="border-b px-4 py-3 pr-10">
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-primary" />
            {t("decrypt.title")}
          </DialogTitle>
          <DialogDescription>{t("decrypt.subtitle")}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 p-4">
          <div className="rounded-md border bg-background/40 p-3">
            <div className="mb-2 flex items-center justify-between">
              <div>
                <div className="text-xs font-medium">{t("decrypt.tlsKeylog")}</div>
                <div className="mt-0.5 text-2xs text-muted-foreground">{t("decrypt.tlsHint")}</div>
              </div>
              <span className="font-mono text-2xs text-muted-foreground">
                {t("decrypt.entries", { count: status?.tlsKeylogEntries ?? 0 })}
              </span>
            </div>
            <div className="mb-2 flex items-center justify-between gap-3 rounded border bg-background/40 px-2 py-1.5">
              <div className="min-w-0">
                <div className="text-2xs font-medium">{t("decrypt.auto")}</div>
                <div className="text-[10px] text-muted-foreground">{t("decrypt.autoHint")}</div>
              </div>
              <Switch
                checked={status?.tlsKeylogAuto ?? false}
                disabled={busy || !status}
                onCheckedChange={(enabled) => {
                  setBusy(true)
                  setError("")
                  api
                    .setTLSKeylogAuto(enabled)
                    .then((res) => setStatus((prev) => prev ? { ...prev, tlsKeylogAuto: res.tlsKeylogAuto } : prev))
                    .catch((err) => setError(err instanceof Error ? err.message : String(err)))
                    .finally(() => setBusy(false))
                }}
              />
            </div>
            <textarea
              value={keylog}
              onChange={(e) => setKeylog(e.target.value)}
              spellCheck={false}
              rows={5}
              placeholder="CLIENT_RANDOM ...\nCLIENT_TRAFFIC_SECRET_0 ..."
              className="w-full resize-y rounded-md border bg-background/60 p-2 font-mono text-[10px] outline-none focus-visible:ring-1 focus-visible:ring-ring"
            />
            <div className="mt-2 flex flex-wrap gap-1.5">
              <Button size="sm" className="h-7" onClick={() => { void saveKeylog() }} disabled={busy || !keylog.trim()}>
                <ShieldCheck className="h-3.5 w-3.5" /> {t("decrypt.load")}
              </Button>
              <Button size="sm" variant="outline" className="h-7" onClick={() => fileRef.current?.click()} disabled={busy}>
                <FileUp className="h-3.5 w-3.5" /> {t("decrypt.file")}
              </Button>
              <Button size="sm" variant="ghost" className="h-7" onClick={() => { void clearKeylog() }} disabled={busy || !status?.tlsKeylogEntries}>
                <Trash2 className="h-3.5 w-3.5" /> {t("decrypt.clear")}
              </Button>
            </div>
            <input
              ref={fileRef}
              type="file"
              accept=".log,.txt,text/plain"
              className="hidden"
              onChange={async (e) => {
                const file = e.target.files?.[0]
                if (file) setKeylog(await file.text())
                e.target.value = ""
              }}
            />
          </div>

          <div className="rounded-md border bg-background/40 p-3">
            <div className="mb-2 flex items-center justify-between">
              <div>
                <div className="text-xs font-medium">{t("decrypt.wifiPSK")}</div>
                <div className="mt-0.5 text-2xs text-muted-foreground">{t("decrypt.wifiHint")}</div>
              </div>
              <span className="font-mono text-2xs text-muted-foreground">
                {status?.wifiPSKConfigured ? t("decrypt.configured") : t("decrypt.notConfigured")}
              </span>
            </div>
            <div className="flex gap-1.5">
              <Input
                type="password"
                value={psk}
                onChange={(e) => setPSK(e.target.value)}
                autoComplete="new-password"
                placeholder="WPA2 passphrase"
                className="h-8 font-mono text-xs"
              />
              <Button size="sm" className="h-8" onClick={() => { void savePSK() }} disabled={busy || !psk}>
                {t("decrypt.save")}
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-8"
                onClick={() => { setPSK(""); void api.setWiFiPSK("").then((res) => setStatus((prev) => prev ? { ...prev, wifiPSKConfigured: res.wifiPSKConfigured } : prev)).catch((err) => setError(err instanceof Error ? err.message : String(err))) }}
                disabled={busy || !status?.wifiPSKConfigured}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>

          {error && <div className="rounded border border-destructive/30 bg-destructive/10 p-2 text-2xs text-destructive">{error}</div>}
          <p className="text-2xs leading-relaxed text-muted-foreground/60">{t("decrypt.note")}</p>
        </div>

        <DialogFooter className="border-t p-3">
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
            {t("decrypt.close")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
