import { useEffect, useMemo, useRef, useState } from "react"
import {
  AlertCircle,
  Check,
  ChevronDown,
  Code2,
  Loader2,
  Plus,
  RotateCcw,
  Search,
  Trash2,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { api } from "@/lib/api"
import { useI18n, type MessageKey } from "@/i18n"
import { cn } from "@/lib/utils"
import type { FilterField } from "@/lib/types"

interface FilterBuilderProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  currentFilter: string
  onApply: (filter: string) => void
}

interface Row {
  id: number
  field: string
  op: string
  value: string
  negate: boolean
}

const GROUP_KEYS: Record<string, MessageKey> = {
  Protocol: "filter.group.protocol",
  Frame: "filter.group.frame",
  Link: "filter.group.link",
  Network: "filter.group.network",
  Transport: "filter.group.transport",
  "ICMP / ARP": "filter.group.icmp",
  Application: "filter.group.application",
  Payload: "filter.group.payload",
}

export function FilterBuilder({
  open,
  onOpenChange,
  currentFilter,
  onApply,
}: FilterBuilderProps) {
  const { t } = useI18n()
  const [fields, setFields] = useState<FilterField[]>([])
  const [fieldsLoading, setFieldsLoading] = useState(false)
  const [fieldsError, setFieldsError] = useState<string | null>(null)
  const [rows, setRows] = useState<Row[]>([])
  const [protocol, setProtocol] = useState("")
  const [protocolOpen, setProtocolOpen] = useState(false)
  const [protocolQuery, setProtocolQuery] = useState("")
  const [combinator, setCombinator] = useState<"and" | "or">("and")
  const [validation, setValidation] = useState<{ valid: boolean; error?: string } | null>(null)
  const [validating, setValidating] = useState(false)

  const nextId = useRef(1)
  const seeded = useRef(false)

  const fieldMap = useMemo(() => new Map(fields.map((f) => [f.name, f])), [fields])
  const rowFields = useMemo(() => fields.filter((f) => f.type !== "layer"), [fields])
  const layers = useMemo(() => fields.filter((f) => f.type === "layer"), [fields])
  const filteredLayers = useMemo(() => {
    const query = protocolQuery.trim().toLowerCase()
    if (!query) return layers
    return layers.filter((field) => field.name.toLowerCase().includes(query))
  }, [layers, protocolQuery])
  const grouped = useMemo(() => {
    const groups = new Map<string, FilterField[]>()
    for (const field of rowFields) {
      const list = groups.get(field.group) ?? []
      list.push(field)
      groups.set(field.group, list)
    }
    return groups
  }, [rowFields])

  const makeRow = (field: FilterField): Row => ({
    id: nextId.current++,
    field: field.name,
    op: field.ops?.[0] ?? "",
    value: field.values?.[0] ?? "",
    negate: false,
  })

  useEffect(() => {
    if (!open) {
      seeded.current = false
      return
    }
    if (fields.length > 0) return
    let cancelled = false
    setFieldsLoading(true)
    setFieldsError(null)
    api
      .filterSchema()
      .then((res) => {
        if (!cancelled) setFields(res.fields)
      })
      .catch((err) => {
        if (!cancelled) setFieldsError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setFieldsLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [open, fields.length])

  // Seed a first condition once per open, after the schema arrives.
  useEffect(() => {
    if (!open || fields.length === 0 || seeded.current) return
    seeded.current = true
    if (rows.length > 0) return
    const def = fields.find((f) => f.name === "ip.addr") ?? fields.find((f) => f.type !== "layer")
    if (def) setRows([makeRow(def)])
    // makeRow is intentionally not a dependency: it only allocates ids.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, fields])

  const updateRow = (id: number, patch: Partial<Row>) => {
    setRows((prev) => prev.map((row) => (row.id === id ? { ...row, ...patch } : row)))
  }

  const changeField = (id: number, name: string) => {
    const field = fieldMap.get(name)
    if (!field) return
    updateRow(id, { field: name, op: field.ops?.[0] ?? "", value: field.values?.[0] ?? "" })
  }

  const addRow = () => {
    const def = rowFields.find((f) => f.name === "ip.addr") ?? rowFields[0]
    if (def) setRows((prev) => [...prev, makeRow(def)])
  }

  const reset = () => {
    setProtocol("")
    setCombinator("and")
    setValidation(null)
    const def = rowFields.find((f) => f.name === "ip.addr") ?? rowFields[0]
    setRows(def ? [makeRow(def)] : [])
    seeded.current = true
  }

  const incomplete = rows.some((row) => {
    const field = fieldMap.get(row.field)
    return field != null && field.type !== "layer" && (!row.op || row.value.trim() === "")
  })

  const rowExpressions = rows
    .map((row) => {
      const field = fieldMap.get(row.field)
      if (!field || field.type === "layer") return ""
      if (!row.op || row.value.trim() === "") return ""
      const raw = row.value.trim()
      const value =
        field.type === "string" || field.type === "bytes"
          ? `"${raw.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`
          : raw
      let expr = `${field.name} ${row.op} ${value}`
      if (row.negate) expr = `not (${expr})`
      return expr
    })
    .filter(Boolean)

  let expression = rowExpressions.join(combinator === "and" ? " and " : " or ")
  if (protocol) {
    expression = expression
      ? combinator === "or"
        ? `${protocol} and (${expression})`
        : `${protocol} and ${expression}`
      : protocol
  }

  useEffect(() => {
    if (!open || !expression) {
      setValidation(null)
      setValidating(false)
      return
    }
    let cancelled = false
    setValidating(true)
    const timer = setTimeout(() => {
      api
        .validate(expression)
        .then((res) => {
          if (!cancelled) setValidation(res)
        })
        .catch((err) => {
          if (!cancelled) {
            setValidation({
              valid: false,
              error: err instanceof Error ? err.message : String(err),
            })
          }
        })
        .finally(() => {
          if (!cancelled) setValidating(false)
        })
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [expression, open])

  const canApply =
    expression.length > 0 &&
    !incomplete &&
    !validating &&
    validation?.valid !== false

  const apply = () => {
    if (!canApply) return
    onApply(expression)
    onOpenChange(false)
  }

  const valueControl = (row: Row, field: FilterField) => {
    if (field.values && field.values.length > 0) {
      return (
        <Select
          value={row.value || field.values[0]}
          onValueChange={(value) => updateRow(row.id, { value })}
        >
          <SelectTrigger className="h-7 w-[140px] font-mono text-[11px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {field.values.map((value) => (
              <SelectItem key={value} value={value} className="font-mono text-[11px]">
                {value}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )
    }
    const placeholder =
      field.type === "ip" ? "10.0.0.0/8" : field.type === "number" ? "443" : t("filter.value")
    const listId = `filter-suggest-${row.id}`
    return (
      <>
        <Input
          value={row.value}
          inputMode={field.type === "number" ? "numeric" : "text"}
          placeholder={placeholder}
          className="h-7 font-mono text-[11px]"
          list={field.suggest ? listId : undefined}
          onChange={(e) => updateRow(row.id, { value: e.target.value })}
        />
        {field.suggest && (
          <datalist id={listId}>
            {field.suggest.map((suggestion) => (
              <option key={suggestion} value={suggestion} />
            ))}
          </datalist>
        )}
      </>
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl gap-0 p-0">
        <DialogHeader className="border-b px-4 py-3 pr-10">
          <DialogTitle className="flex items-center gap-2">
            <Code2 className="h-4 w-4 text-primary" />
            {t("filter.builderTitle")}
          </DialogTitle>
          <DialogDescription>{t("filter.builderSubtitle")}</DialogDescription>
        </DialogHeader>

        <div className="min-h-0 flex-1 space-y-3 overflow-auto p-4 scrollbar-thin">
          <div className="flex flex-wrap items-end gap-3">
            <div className="space-y-1">
              <div className="text-2xs text-muted-foreground">{t("filter.protocol")}</div>
              <Popover
                open={protocolOpen}
                onOpenChange={(open) => {
                  setProtocolOpen(open)
                  if (!open) setProtocolQuery("")
                }}
              >
                <PopoverTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 w-[150px] justify-between px-2 font-mono text-[11px] font-normal"
                  >
                    <span className={cn("truncate", !protocol && "text-muted-foreground")}>
                      {protocol || t("filter.anyProtocol")}
                    </span>
                    <ChevronDown className="h-3.5 w-3.5 shrink-0 opacity-60" />
                  </Button>
                </PopoverTrigger>
                <PopoverContent align="start" className="w-[220px] p-0">
                  <div className="relative border-b p-2">
                    <Search className="pointer-events-none absolute left-4 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      value={protocolQuery}
                      autoFocus
                      spellCheck={false}
                      placeholder={t("filter.searchProtocol")}
                      className="h-7 pl-7 font-mono text-[11px]"
                      onChange={(e) => setProtocolQuery(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && filteredLayers.length > 0) {
                          setProtocol(filteredLayers[0].name)
                          setProtocolOpen(false)
                          setProtocolQuery("")
                        }
                        if (e.key === "Escape") setProtocolOpen(false)
                      }}
                    />
                  </div>
                  <div className="max-h-64 overflow-auto p-1 scrollbar-thin">
                    <button
                      type="button"
                      className={cn(
                        "flex w-full items-center rounded px-2 py-1.5 text-left font-mono text-[11px] hover:bg-accent",
                        !protocol && "bg-primary/10 text-primary",
                      )}
                      onClick={() => {
                        setProtocol("")
                        setProtocolOpen(false)
                        setProtocolQuery("")
                      }}
                    >
                      {t("filter.anyProtocol")}
                    </button>
                    {filteredLayers.map((field) => (
                      <button
                        key={field.name}
                        type="button"
                        className={cn(
                          "flex w-full items-center rounded px-2 py-1.5 text-left font-mono text-[11px] hover:bg-accent",
                          protocol === field.name && "bg-primary/10 text-primary",
                        )}
                        onClick={() => {
                          setProtocol(field.name)
                          setProtocolOpen(false)
                          setProtocolQuery("")
                        }}
                      >
                        {field.name}
                      </button>
                    ))}
                    {filteredLayers.length === 0 && (
                      <div className="px-2 py-3 text-center text-2xs text-muted-foreground">
                        {t("filter.noProtocol")}
                      </div>
                    )}
                  </div>
                </PopoverContent>
              </Popover>
            </div>
            <div className="space-y-1">
              <div className="text-2xs text-muted-foreground">{t("filter.combinator")}</div>
              <div className="flex items-center gap-0.5 rounded-md border bg-background/50 p-0.5">
                {(
                  [
                    ["and", t("filter.and")],
                    ["or", t("filter.or")],
                  ] as const
                ).map(([value, label]) => (
                  <Button
                    key={value}
                    size="sm"
                    variant={combinator === value ? "secondary" : "ghost"}
                    className="h-6 px-2 text-2xs"
                    onClick={() => setCombinator(value)}
                  >
                    {label}
                  </Button>
                ))}
              </div>
            </div>
          </div>

          {fieldsLoading && (
            <div className="flex items-center gap-2 text-2xs text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              {t("filter.fieldsLoading")}
            </div>
          )}
          {fieldsError && (
            <div className="flex items-center gap-2 rounded border border-destructive/30 bg-destructive/10 p-2 text-2xs text-destructive">
              <AlertCircle className="h-3.5 w-3.5" />
              <span>
                {t("filter.fieldsError")} {fieldsError}
              </span>
            </div>
          )}

          <div className="space-y-2">
            {rows.map((row) => {
              const field = fieldMap.get(row.field)
              if (!field) return null
              const ops = field.ops ?? []
              return (
                <div
                  key={row.id}
                  className="flex flex-wrap items-center gap-1.5 rounded-md border bg-background/40 p-1.5"
                >
                  <Button
                    variant={row.negate ? "secondary" : "ghost"}
                    size="icon-sm"
                    className="h-7 w-7 font-mono text-[11px]"
                    title={t("filter.negate")}
                    aria-label={t("filter.negate")}
                    onClick={() => updateRow(row.id, { negate: !row.negate })}
                  >
                    !
                  </Button>
                  <Select value={row.field} onValueChange={(value) => changeField(row.id, value)}>
                    <SelectTrigger className="h-7 w-[200px] font-mono text-[11px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="max-h-[320px]">
                      {Array.from(grouped.entries()).map(([group, items]) => (
                        <SelectGroup key={group}>
                          <SelectLabel>{t(GROUP_KEYS[group] ?? "filter.group.other")}</SelectLabel>
                          {items.map((item) => (
                            <SelectItem
                              key={item.name}
                              value={item.name}
                              className="font-mono text-[11px]"
                            >
                              {item.name}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select
                    value={row.op}
                    onValueChange={(value) => updateRow(row.id, { op: value })}
                  >
                    <SelectTrigger className="h-7 w-[96px] font-mono text-[11px]">
                      <SelectValue placeholder={t("filter.operator")} />
                    </SelectTrigger>
                    <SelectContent>
                      {ops.map((op) => (
                        <SelectItem key={op} value={op} className="font-mono text-[11px]">
                          {op}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <div className="min-w-[150px] flex-1">{valueControl(row, field)}</div>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    className="h-7 w-7 text-muted-foreground hover:text-destructive"
                    title={t("filter.removeCondition")}
                    aria-label={t("filter.removeCondition")}
                    onClick={() => setRows((prev) => prev.filter((r) => r.id !== row.id))}
                  >
                    <Trash2 />
                  </Button>
                </div>
              )
            })}
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={addRow}
            disabled={fieldsLoading || rowFields.length === 0}
          >
            <Plus /> {t("filter.addCondition")}
          </Button>
        </div>

        <div className="space-y-2 border-t bg-panel/40 p-4">
          <div className="flex items-center gap-1.5 text-2xs text-muted-foreground">
            <Code2 className="h-3 w-3" />
            {t("filter.preview")}
          </div>
          <pre
            className={cn(
              "min-h-[42px] whitespace-pre-wrap break-all rounded-md border bg-background/60 p-2 font-mono text-[11px]",
              !expression && "text-muted-foreground/60",
            )}
          >
            {expression || t("filter.previewEmpty")}
          </pre>
          <div className="min-h-[16px] text-2xs">
            {incomplete ? (
              <span className="flex items-center gap-1 text-amber-700 dark:text-amber-300">
                <AlertCircle className="h-3 w-3" />
                {t("filter.incomplete")}
              </span>
            ) : validating ? (
              <span className="flex items-center gap-1 text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" />
                {t("filter.validating")}
              </span>
            ) : validation?.valid === false ? (
              <span className="flex items-center gap-1 text-destructive">
                <AlertCircle className="h-3 w-3" />
                {validation.error}
              </span>
            ) : validation?.valid ? (
              <span className="flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                <Check className="h-3 w-3" />
                {t("filter.valid")}
              </span>
            ) : null}
          </div>
          {currentFilter && currentFilter !== expression && (
            <div className="text-2xs text-muted-foreground/70">
              {t("filter.replaceHint", { filter: currentFilter })}
            </div>
          )}
          <DialogFooter className="pt-1">
            <Button variant="ghost" size="sm" onClick={reset} className="sm:mr-auto">
              <RotateCcw /> {t("filter.resetBuilder")}
            </Button>
            <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
              {t("filter.cancel")}
            </Button>
            <Button size="sm" onClick={apply} disabled={!canApply}>
              {t("filter.applyBuilder")}
            </Button>
          </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  )
}
