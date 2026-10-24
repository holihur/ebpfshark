import { lazy, Suspense, useEffect, useRef, useState } from "react"
import {
  AlertCircle,
  Columns3,
  Globe2,
  KeyRound,
  Play,
  Search,
  Settings2,
  SlidersHorizontal,
  Square,
  X,
} from "lucide-react"
import { Input } from "@/components/ui/input"
import { FilterHighlight } from "@/components/FilterHighlight"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { Button } from "@/components/ui/button"
const FilterBuilder = lazy(() => import("@/components/FilterBuilder").then((m) => ({ default: m.FilterBuilder })))
import { useI18n } from "@/i18n"
import { cn } from "@/lib/utils"
import { useFilterHistory } from "@/lib/filterHistory"
import { api } from "@/lib/api"
import type { FilterField } from "@/lib/types"

interface FilterBarProps {
  filter: string
  error: string | null
  loading: boolean
  running: boolean
  busy: boolean
  onApply: (filter: string) => void
  onStart: () => void
  onStop: () => void
  onEditColumns: () => void
  onDecryption: () => void
  onMITM: () => void
}

export function FilterBar({
  filter,
  error,
  loading,
  running,
  busy,
  onApply,
  onStart,
  onStop,
  onEditColumns,
  onDecryption,
  onMITM,
}: FilterBarProps) {
  const { t } = useI18n()
  const [draft, setDraft] = useState(filter)
  const [builderOpen, setBuilderOpen] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [fields, setFields] = useState<FilterField[]>([])
  const { history, remember, clear: clearHistory } = useFilterHistory()
  const suggestions = history
    .filter((item) => !draft.trim() || item.toLowerCase().includes(draft.trim().toLowerCase()))
    .slice(0, 8)
  const partial = draft.match(/([A-Za-z_][\w.-]*)$/)?.[1]?.toLowerCase() ?? ""
  const fieldSuggestions = fields
    .filter((field) => !partial || field.name.toLowerCase().startsWith(partial))
    .slice(0, 10)
  const inputRef = useRef<HTMLInputElement>(null)
  const highlightRef = useRef<HTMLDivElement>(null)

  useEffect(() => setDraft(filter), [filter])

  useEffect(() => {
    api.filterSchema().then((res) => setFields(res.fields)).catch(() => {})
  }, [])

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
    remember(value)
    onApply(value)
  }


  return (
    <div className="shrink-0 border-b bg-background/40">
      <div className="flex items-center gap-2 px-3 py-2">
        <div className="relative min-w-0 flex-1">
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground">
                <Search className="h-3.5 w-3.5" />
              </span>
            </TooltipTrigger>
            <TooltipContent side="bottom">{t("filter.usage")}</TooltipContent>
          </Tooltip>
          <div
            ref={highlightRef}
            className="pointer-events-none absolute inset-0 overflow-hidden pl-8 pr-[104px] text-[11px] leading-8"
          >
            <FilterHighlight text={draft} />
          </div>
          <Input
            ref={inputRef}
            value={draft}
            spellCheck={false}
            autoComplete="off"
            placeholder={t("filter.placeholder")}
            title={error ?? t("filter.usage")}
            aria-invalid={Boolean(error)}
            className={cn(
              "relative h-8 bg-transparent pl-8 pr-[104px] font-mono text-[11px] text-transparent caret-foreground selection:bg-primary/30",
              error && "border-destructive/70 focus-visible:ring-destructive/40",
            )}
            onFocus={() => setHistoryOpen(true)}
            onBlur={() => window.setTimeout(() => setHistoryOpen(false), 150)}
            onChange={(e) => {
              setDraft(e.target.value)
              setHistoryOpen(true)
            }}
            onScroll={(e) => {
              if (highlightRef.current) highlightRef.current.scrollLeft = e.currentTarget.scrollLeft
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") apply(draft)
              if (e.key === "Escape") {
                setDraft("")
                apply("")
                e.currentTarget.blur()
              }
              if (highlightRef.current && inputRef.current) {
                highlightRef.current.scrollLeft = inputRef.current.scrollLeft
              }
            }}
          />
          <div className="absolute right-1 top-1/2 flex -translate-y-1/2 items-center gap-1">
            {error && (
              <span className="text-destructive" title={error}>
                <AlertCircle className="h-3.5 w-3.5" />
              </span>
            )}
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
          {historyOpen && (suggestions.length > 0 || fieldSuggestions.length > 0) && (
            <div className="absolute left-0 right-0 top-[calc(100%+4px)] z-50 overflow-hidden rounded-md border bg-popover shadow-xl">
              <div className="flex items-center justify-between border-b px-2 py-1 text-2xs text-muted-foreground">
                <span>{t("filter.history")}</span>
                <button
                  type="button"
                  className="rounded px-1 hover:bg-accent hover:text-foreground"
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => {
                    clearHistory()
                    setHistoryOpen(false)
                  }}
                >
                  {t("filter.clearHistory")}
                </button>
              </div>
              {suggestions.map((item) => (
                <button
                  key={item}
                  type="button"
                  className="block w-full truncate px-2 py-1.5 text-left font-mono text-[11px] hover:bg-accent"
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => {
                    apply(item)
                    setHistoryOpen(false)
                    inputRef.current?.blur()
                  }}
                >
                  <FilterHighlight text={item} />
                </button>
              ))}
              {fieldSuggestions.length > 0 && (
                <>
                  <div className="border-t px-2 py-1 text-2xs text-muted-foreground">{t("filter.fields")}</div>
                  {fieldSuggestions.map((field) => (
                    <button
                      key={field.name}
                      type="button"
                      className="flex w-full items-center gap-2 px-2 py-1 text-left font-mono text-[11px] hover:bg-accent"
                      onMouseDown={(e) => e.preventDefault()}
                      onClick={() => {
                        const next = draft.replace(/[A-Za-z_][\w.-]*$/, `${field.name} `)
                        setDraft(next)
                        setHistoryOpen(false)
                        inputRef.current?.focus()
                      }}
                    >
                      <span className="min-w-0 flex-1 truncate">{field.name}</span>
                      <span className="shrink-0 text-2xs text-muted-foreground/60">{field.type}</span>
                    </button>
                  ))}
                </>
              )}
            </div>
          )}
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

        <DropdownMenu>
          <Tooltip>
            <TooltipTrigger asChild>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon" className="h-8 w-8 shrink-0" aria-label={t("filter.tools")}>
                  <Settings2 className="h-3.5 w-3.5" />
                </Button>
              </DropdownMenuTrigger>
            </TooltipTrigger>
            <TooltipContent>{t("filter.tools")}</TooltipContent>
          </Tooltip>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onSelect={onEditColumns}>
              <Columns3 />
              {t("columns.title")}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={onDecryption}>
              <KeyRound />
              {t("decrypt.title")}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={onMITM}>
              <Globe2 />
              {t("mitm.title")}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        {running ? (
          <Button
            size="sm"
            variant="outline"
            className="h-8 shrink-0 gap-1.5 px-2"
            onClick={onStop}
            disabled={busy}
            title={t("sidebar.stop")}
          >
            <Square className="h-3.5 w-3.5 fill-current" />
            <span className="hidden sm:inline">{t("sidebar.stop")}</span>
          </Button>
        ) : (
          <Button
            size="sm"
            className="h-8 shrink-0 gap-1.5 px-2"
            onClick={onStart}
            disabled={busy}
            title={t("sidebar.start")}
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span className="hidden sm:inline">{t("sidebar.start")}</span>
          </Button>
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
