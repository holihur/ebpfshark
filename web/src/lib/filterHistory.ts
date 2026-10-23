import { useCallback, useState } from "react"

const STORAGE_KEY = "ebpfshark.filter-history"
const MAX_ITEMS = 20

function load(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed
      .filter((v): v is string => typeof v === "string" && v.trim().length > 0)
      .map((v) => v.trim())
      .slice(0, MAX_ITEMS)
  } catch {
    return []
  }
}

export function useFilterHistory() {
  const [history, setHistory] = useState<string[]>(load)

  const remember = useCallback((value: string) => {
    const filter = value.trim()
    if (!filter) return
    setHistory((prev) => {
      const next = [filter, ...prev.filter((item) => item !== filter)].slice(0, MAX_ITEMS)
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next))
      } catch {
        // Private mode / storage disabled: keep in-memory history only.
      }
      return next
    })
  }, [])

  const clear = useCallback(() => {
    setHistory([])
    try {
      localStorage.removeItem(STORAGE_KEY)
    } catch {
      // ignore
    }
  }, [])

  return { history, remember, clear }
}
