import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react"
import { Loader2, Waves } from "lucide-react"
import { LoginPage } from "@/components/LoginPage"
import { api, UNAUTHORIZED_EVENT } from "@/lib/api"
import { useI18n } from "@/i18n"
import { AuthContext, type AuthState } from "./context"

const initialState: AuthState = {
  loading: true,
  enabled: true,
  authenticated: false,
  user: "",
  expired: false,
}

function AuthSplash() {
  const { t } = useI18n()
  return (
    <div className="flex min-h-full flex-col items-center justify-center gap-3 bg-background">
      <div className="grid h-10 w-10 place-items-center rounded-xl bg-primary/15 ring-1 ring-primary/30">
        <Waves className="h-5 w-5 text-primary" />
      </div>
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        {t("auth.checking")}
      </div>
    </div>
  )
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(initialState)

  const refresh = useCallback(async () => {
    try {
      const session = await api.session()
      setState({
        loading: false,
        enabled: session.enabled,
        authenticated: session.authenticated,
        user: session.user ?? "",
        expired: false,
      })
    } catch {
      // Keep the login screen visible if the backend is unreachable.
      setState({
        loading: false,
        enabled: true,
        authenticated: false,
        user: "",
        expired: false,
      })
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    const onUnauthorized = () => {
      setState((prev) => ({
        ...prev,
        loading: false,
        enabled: true,
        authenticated: false,
        user: "",
        expired: true,
      }))
    }
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const session = await api.login(username, password)
    setState({
      loading: false,
      enabled: session.enabled,
      authenticated: session.authenticated,
      user: session.user ?? "",
      expired: false,
    })
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } finally {
      setState((prev) => ({
        ...prev,
        authenticated: false,
        user: "",
        expired: false,
      }))
    }
  }, [])

  const value = useMemo(
    () => ({ ...state, login, logout, refresh }),
    [state, login, logout, refresh],
  )

  return (
    <AuthContext.Provider value={value}>
      {state.loading ? (
        <AuthSplash />
      ) : state.enabled && !state.authenticated ? (
        <LoginPage />
      ) : (
        children
      )}
    </AuthContext.Provider>
  )
}
