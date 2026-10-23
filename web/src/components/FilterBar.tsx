import { lazy, Suspense, useEffect, useRef, useState } from "react"
import { AlertCircle, Check, Search, SlidersHorizontal, X } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
const FilterBuilder = lazy(() => import("@/components/FilterBuilder").then((m) => ({ default: m.FilterBuilder })))
import { QUICK_FILTERS } from "@/lib/protocols"
import { usePacketVersion, type PacketStore } from "@/lib/packetStore"
import { useI18n } from "@/i18n"
import { cn } from "@/lib/utils"
import type { StatusResponse } from "@/lib/types"
import { formatCount } from "@/lib/format"

interface FilterBarProps {
  filter: string
  error: string | null
  status: StatusResponse | null
  packetStore: PacketStore
  loading: boolean
  onApply: (filter: string) => void
}

export function FilterBar({
  filter,
  error,
  status,
  packetStore,
  loading,
  onApply,
}: FilterBarProps) {
  const { t } = useI18n()
  usePacketVersion()
  const matchCount = packetStore.length
  const [draft, setDraft] = useState(filter)
  const [builderOpen, setBuilderOpen] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => setDraft(filter), [filter])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      const typing =
        target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable
      if (e.key === "/" && !typing) {
        e.preventDefault()
        inputRef.current?.focus()
      }
    }
    window.addEventListener("keydown", handler)
    return () => window.removeEventListener("keydown", handler)
  }, [])

  const apply = (value: string) => {
    setDraft(value)
    onApply(value)
  }

  const active = filter.trim().toLowerCase()
  const protocols = status?.store.protocols ?? {}

  return (
    <div className="shrink-0 border-b bg-background/40">
      <div className="flex items-center gap-2 px-3 py-2">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            ref={inputRef}
            value={draft}
            spellCheck={false}
            autoComplete="off"
            placeholder={t("filter.placeholder")}
            className={cn(
              "h-8 pl-8 pr-[104px] font-mono text-[11px]",
              error && "border-destructive/70 focus-visible:ring-destructive/40",
            )}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") apply(draft)
              if (e.key === "Escape") {
                setDraft("")
                apply("")
                e.currentTarget.blur()
              }
            }}
          />
          <div className="absolute right-1 top-1/2 flex -translate-y-1/2 items-center gap-1">
            {draft && (
              <button
                type="button"
                className="grid h-6 w-6 place-items-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
                onClick={() => {
                  setDraft("")
                  if (filter) apply("")
                }}
                aria-label={t("filter.clearAria")}
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
            <Button
              size="sm"
              variant="secondary"
              className="h-6 px-2 text-2xs"
              onClick={() => apply(draft)}
              disabled={loading}
            >
              {loading ? "…" : t("filter.apply")}
            </Button>
          </div>
        </div>

        <Button
          variant="outline"
          size="sm"
          className="h-8 shrink-0 gap-1.5 px-2"
          onClick={() => setBuilderOpen(true)}
          title={t("filter.builderTip")}
          aria-label={t("filter.builderTip")}
        >
          <SlidersHorizontal className="h-3.5 w-3.5" />
          <span className="hidden md:inline">{t("filter.builder")}</span>
        </Button>

        <div className="hidden items-center gap-1 lg:flex">
          {QUICK_FILTERS.map((proto) => {
            const isActive = active === proto
            const count = protocols[proto.toUpperCase()] ?? 0
            return (
              <button
                key={proto}
                type="button"
                onClick={() => apply(isActive ? "" : proto)}
                className={cn(
                  "rounded-full border px-2 py-0.5 font-mono text-2xs transition-colors",
                  isActive
                    ? "border-primary/40 bg-primary/15 text-primary"
                    : "border-border bg-background/50 text-muted-foreground hover:border-border hover:bg-accent hover:text-foreground",
                )}
              >
                {proto}
                {count > 0 && (
                  <span className="ml-1 text-muted-foreground/70">{formatCount(count)}</span>
                )}
              </button>
            )
          })}
        </div>
      </div>

      <div className="flex min-h-[18px] items-center gap-2 px-3 pb-1.5 text-2xs">
        {error ? (
          <span className="flex items-center gap-1 text-destructive">
            <AlertCircle className="h-3 w-3" />
            {error}
          </span>
        ) : filter ? (
          <span className="flex items-center gap-1.5 text-muted-foreground">
            <Check className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
            <span className="font-mono text-foreground/70">{filter}</span>
            <span className="text-muted-foreground/60">·</span>
            <span>{t("filter.matching", { count: formatCount(matchCount) })}</span>
            <button
              type="button"
              className="ml-1 underline decoration-muted-foreground/40 underline-offset-2 hover:text-foreground"
              onClick={() => apply("")}
            >
              {t("filter.reset")}
            </button>
          </span>
        ) : (
          <span className="text-muted-foreground/60">
            {t("filter.press")}{" "}
            <kbd className="rounded border bg-muted px-1 font-mono text-[10px]">/</kbd>{" "}
            {t("filter.focusHint")} ·{" "}
            <kbd className="rounded border bg-muted px-1 font-mono text-[10px]">Enter</kbd>{" "}
            {t("filter.applyHint")}
          </span>
        )}
      </div>

      <Suspense fallback={null}>
        <FilterBuilder
          open={builderOpen}
          onOpenChange={setBuilderOpen}
          currentFilter={filter}
          onApply={onApply}
        />
      </Suspense>
    </div>
  )
}
