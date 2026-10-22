import { startTransition, useCallback, useEffect, useRef, useState } from "react"
import { api } from "@/lib/api"
import type { Packet, StatusResponse } from "@/lib/types"

const MAX_UI_PACKETS = 20000

export interface StartOptions {
  interfaces: string[]
  snaplen: number
  sampleRate: number
  clear?: boolean
}

export function useCapture() {
  const [status, setStatus] = useState<StatusResponse | null>(null)
  const [packets, setPackets] = useState<Packet[]>([])
  const [filter, setFilter] = useState("")
  const [filterError, setFilterError] = useState<string | null>(null)
  const [connected, setConnected] = useState(false)
  const [loadingPackets, setLoadingPackets] = useState(false)
  const filterRef = useRef(filter)
  const instanceRef = useRef<string | null>(null)
  filterRef.current = filter

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api.status())
    } catch {
      /* backend restarting */
    }
  }, [])

  useEffect(() => {
    refreshStatus()
    const t = setInterval(refreshStatus, 1000)
    return () => clearInterval(t)
  }, [refreshStatus])

  const reloadPackets = useCallback(async (expr: string) => {
    setLoadingPackets(true)
    try {
      const res = await api.packets(expr, 5000)
      setPackets(res.packets)
    } catch (err) {
      setFilterError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoadingPackets(false)
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    setLoadingPackets(true)
    api
      .packets(filter, 5000)
      .then((res) => {
        if (!cancelled) setPackets(res.packets)
      })
      .catch((err) => {
        if (!cancelled) setFilterError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setLoadingPackets(false)
      })
    return () => {
      cancelled = true
    }
  }, [filter])

  useEffect(() => {
    const es = new EventSource(api.streamUrl(filter))
    const onReady = (event: MessageEvent<string>) => {
      setConnected(true)
      let instance = ""
      try {
        instance = (JSON.parse(event.data) as { instance?: string }).instance ?? ""
      } catch {
        /* ignore */
      }
      if (instance && instanceRef.current && instance !== instanceRef.current) {
        // The backend restarted: ids restart from zero, so drop the old view.
        setPackets([])
      }
      if (instance) instanceRef.current = instance
      // Re-sync in case packets were missed while the stream was down.
      void reloadPackets(filterRef.current)
    }
    const onPackets = (event: MessageEvent<string>) => {
      try {
        const payload = JSON.parse(event.data) as { packets: Packet[] }
        if (!Array.isArray(payload.packets) || payload.packets.length === 0) return
        startTransition(() => {
          setPackets((prev) => {
            const lastID = prev.length > 0 ? prev[prev.length - 1].id : 0
            const fresh = payload.packets.filter((p) => p.id > lastID)
            if (fresh.length === 0) return prev
            const next = prev.concat(fresh)
            return next.length > MAX_UI_PACKETS ? next.slice(next.length - MAX_UI_PACKETS) : next
          })
        })
      } catch {
        /* ignore malformed frame */
      }
    }
    es.addEventListener("ready", onReady as EventListener)
    es.addEventListener("packets", onPackets as EventListener)
    es.onerror = () => setConnected(false)
    return () => {
      es.removeEventListener("ready", onReady as EventListener)
      es.removeEventListener("packets", onPackets as EventListener)
      es.close()
      setConnected(false)
    }
  }, [filter])

  const applyFilter = useCallback(async (next: string) => {
    const trimmed = next.trim()
    if (!trimmed) {
      setFilter("")
      setFilterError(null)
      return true
    }
    try {
      const res = await api.validate(trimmed)
      if (!res.valid) {
        setFilterError(res.error ?? "invalid filter")
        return false
      }
      setFilterError(null)
      setFilter(trimmed)
      return true
    } catch (err) {
      setFilterError(err instanceof Error ? err.message : String(err))
      return false
    }
  }, [])

  const start = useCallback(
    async (opts: StartOptions) => {
      const res = await api.start({
        interfaces: opts.interfaces,
        snaplen: opts.snaplen,
        sampleRate: opts.sampleRate,
        clear: opts.clear ?? true,
      })
      if (opts.clear ?? true) setPackets([])
      setStatus((prev) => (prev ? { ...prev, capture: res } : prev))
      await refreshStatus()
      return res
    },
    [refreshStatus],
  )

  const stop = useCallback(async () => {
    const res = await api.stop()
    setStatus((prev) => (prev ? { ...prev, capture: res } : prev))
    await refreshStatus()
    return res
  }, [refreshStatus])

  const clear = useCallback(async () => {
    await api.clear()
    setPackets([])
    await refreshStatus()
  }, [refreshStatus])

  const importFile = useCallback(
    async (file: File) => {
      const res = await api.importFile(file)
      await refreshStatus()
      await reloadPackets(filterRef.current)
      return res
    },
    [refreshStatus, reloadPackets],
  )

  return {
    status,
    packets,
    filter,
    filterError,
    connected,
    loadingPackets,
    applyFilter,
    start,
    stop,
    clear,
    importFile,
    refreshStatus,
    reloadPackets,
    setFilterError,
  }
}
