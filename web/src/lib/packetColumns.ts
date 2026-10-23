import { useCallback, useState } from "react"

export type ColumnID =
  | "no"
  | "time"
  | "source"
  | "destination"
  | "protocol"
  | "length"
  | "info"
  | "iface"
  | "cgroup"

export interface ColumnDef {
  id: ColumnID
  labelKey: string
  width: string
  minWidth: number
  align?: "right"
}

export const COLUMN_DEFS: ColumnDef[] = [
  { id: "no", labelKey: "list.no", width: "54px", minWidth: 54 },
  { id: "time", labelKey: "list.time", width: "94px", minWidth: 94 },
  { id: "source", labelKey: "list.source", width: "minmax(128px,1fr)", minWidth: 128 },
  { id: "destination", labelKey: "list.destination", width: "minmax(128px,1fr)", minWidth: 128 },
  { id: "protocol", labelKey: "list.protocol", width: "78px", minWidth: 78 },
  { id: "length", labelKey: "list.length", width: "58px", minWidth: 58, align: "right" },
  { id: "info", labelKey: "list.info", width: "minmax(220px,2.4fr)", minWidth: 220 },
  { id: "iface", labelKey: "list.iface", width: "62px", minWidth: 62 },
  { id: "cgroup", labelKey: "list.cgroup", width: "92px", minWidth: 92 },
]

export const COLUMN_BY_ID = new Map(COLUMN_DEFS.map((col) => [col.id, col]))
export const DEFAULT_COLUMNS: ColumnID[] = [
  "no", "time", "source", "destination", "protocol", "length", "info", "iface",
]

const STORAGE_KEY = "ebpfshark.packet-columns"

function normalize(input: unknown): ColumnID[] {
  if (!Array.isArray(input)) return [...DEFAULT_COLUMNS]
  const seen = new Set<ColumnID>()
  const out: ColumnID[] = []
  for (const value of input) {
    if (typeof value !== "string") continue
    const id = value as ColumnID
    if (!COLUMN_BY_ID.has(id) || seen.has(id)) continue
    seen.add(id)
    out.push(id)
  }
  return out.length > 0 ? out : [...DEFAULT_COLUMNS]
}

function load(): ColumnID[] {
  try {
    return normalize(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "null"))
  } catch {
    return [...DEFAULT_COLUMNS]
  }
}

export function usePacketColumns() {
  const [columns, setColumns] = useState<ColumnID[]>(load)
  const update = useCallback((next: ColumnID[]) => {
    const normalized = normalize(next)
    setColumns(normalized)
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(normalized))
    } catch {
      // keep in-memory preference when storage is unavailable
    }
  }, [])
  return [columns, update] as const
}

export function columnTemplate(columns: ColumnID[]): string {
  return columns
    .map((id) => COLUMN_BY_ID.get(id)?.width)
    .filter((width): width is string => Boolean(width))
    .join(" ")
}

export function columnsMinWidth(columns: ColumnID[]): number {
  const width = columns.reduce((sum, id) => sum + (COLUMN_BY_ID.get(id)?.minWidth ?? 0), 0)
  return Math.max(420, width + Math.max(0, columns.length - 1) * 8 + 16)
}
