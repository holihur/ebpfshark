import { useState, type FormEvent } from "react"
import {
  AlertCircle,
  Eye,
  EyeOff,
  Info,
  Languages,
  Loader2,
  Lock,
  Moon,
  Sun,
  User,
  Waves,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ApiError } from "@/lib/api"
import { useTheme } from "@/hooks/useTheme"
import { useI18n } from "@/i18n"
import { useAuth } from "@/auth/context"
import { cn } from "@/lib/utils"

export function LoginPage() {
  const { t, locale, setLocale } = useI18n()
  const { login, expired } = useAuth()
  const { theme, toggle } = useTheme()

  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (busy) return
    setError(null)
    setBusy(true)
    try {
      await login(username.trim(), password)
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) setError(t("auth.invalid"))
        else if (err.status === 429) setError(t("auth.rateLimited"))
        else setError(err.message)
      } else {
        setError(t("auth.connectionError"))
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="relative flex min-h-full flex-col overflow-hidden bg-background">
      <div className="grid-bg pointer-events-none absolute inset-0 opacity-60" />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-64 bg-gradient-to-b from-primary/[0.07] to-transparent" />

      <div className="relative flex items-center justify-end gap-1 p-3">
        <Button
          variant="ghost"
          size="sm"
          className="gap-1 px-2"
          onClick={() => setLocale(locale === "zh" ? "en" : "zh")}
          title={t("auth.switchLanguage")}
          aria-label={t("auth.switchLanguage")}
        >
          <Languages />
          <span className="text-2xs font-semibold uppercase">{locale === "zh" ? "中" : "EN"}</span>
        </Button>
        <Button
          variant="ghost"
          size="icon"
          onClick={toggle}
          title={t("app.themeToggle")}
          aria-label={t("app.themeToggle")}
        >
          {theme === "dark" ? <Sun /> : <Moon />}
        </Button>
      </div>

      <div className="relative flex flex-1 items-center justify-center px-4 pb-20">
        <div className="w-full max-w-[380px] animate-fade-in">
          <div className="mb-6 flex flex-col items-center text-center">
            <div className="relative mb-3 grid h-11 w-11 place-items-center rounded-xl bg-primary/15 ring-1 ring-primary/30">
              <Waves className="h-5 w-5 text-primary" />
              <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-background bg-primary" />
            </div>
            <h1 className="text-base font-semibold tracking-tight">eBPF Analyzer</h1>
            <p className="mt-1 text-xs text-muted-foreground">{t("auth.subtitle")}</p>
          </div>

          <div className="rounded-xl border bg-card/85 p-5 shadow-2xl shadow-black/20 backdrop-blur">
            <h2 className="mb-4 text-sm font-medium">{t("auth.title")}</h2>

            <form onSubmit={submit} className="space-y-3">
              <div className="space-y-1.5">
                <label htmlFor="username" className="text-2xs font-medium text-muted-foreground">
                  {t("auth.username")}
                </label>
                <div className="relative">
                  <User className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground/60" />
                  <Input
                    id="username"
                    name="username"
                    autoComplete="username"
                    autoFocus
                    className="pl-8"
                    value={username}
                    disabled={busy}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label htmlFor="password" className="text-2xs font-medium text-muted-foreground">
                  {t("auth.password")}
                </label>
                <div className="relative">
                  <Lock className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground/60" />
                  <Input
                    id="password"
                    name="password"
                    type={showPassword ? "text" : "password"}
                    autoComplete="current-password"
                    className="pl-8 pr-9"
                    value={password}
                    disabled={busy}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                  <button
                    type="button"
                    className="absolute right-1 top-1/2 grid h-6 w-6 -translate-y-1/2 place-items-center rounded text-muted-foreground/60 transition-colors hover:bg-accent hover:text-foreground"
                    onClick={() => setShowPassword((v) => !v)}
                    title={showPassword ? t("auth.hidePassword") : t("auth.showPassword")}
                    aria-label={showPassword ? t("auth.hidePassword") : t("auth.showPassword")}
                  >
                    {showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </div>

              {expired && !error && (
                <div className="flex items-start gap-1.5 rounded border border-amber-400/25 bg-amber-400/10 px-2 py-1.5 text-2xs text-amber-700 dark:text-amber-300">
                  <Info className="mt-0.5 h-3 w-3 shrink-0" />
                  {t("auth.sessionExpired")}
                </div>
              )}

              {error && (
                <div
                  role="alert"
                  className={cn(
                    "flex items-start gap-1.5 rounded border border-destructive/30 bg-destructive/10 px-2 py-1.5 text-2xs text-destructive",
                  )}
                >
                  <AlertCircle className="mt-0.5 h-3 w-3 shrink-0" />
                  {error}
                </div>
              )}

              <Button type="submit" className="mt-1 w-full" disabled={busy || !username || !password}>
                {busy ? (
                  <>
                    <Loader2 className="animate-spin" />
                    {t("auth.signingIn")}
                  </>
                ) : (
                  t("auth.signIn")
                )}
              </Button>
            </form>

            <p className="mt-3 text-center text-[10px] leading-relaxed text-muted-foreground/60">
              {t("auth.credentialsHint")}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
