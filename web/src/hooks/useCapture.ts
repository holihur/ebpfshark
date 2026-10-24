import { useCallback, useEffect, useRef, useState } from "react"
import { api } from "@/lib/api"
import { packetStore } from "@/lib/packetStore"
import type { Packet, StatusResponse } from "@/lib/types"

export interface StartOptions {
  interfaces: string[]
  snaplen: number
  sampleRate: number
  ringSize?: number
  clear?: boolean
  filter?: string
  cgroup?: string
}

export function useCapture() {
  const [status, setStatus] = useState<StatusResponse | null>(null)
  const [filter, setFilter] = useState("")
  const [filterError, setFilterError] = useState<string | null>(null)
  const [connected, setConnected] = useState(false)
  const [loadingPackets, setLoadingPackets] = useState(false)
  const filterRef = useRef(filter)
  const instanceRef = useRef<string | null>(null)
  const readyRef = useRef(0)
  filterRef.current = filter

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api.status())
    } catch {
      /* backend restarting */
    }
  }, [])

  useEffect(() => {
    const refresh = () => {
      if (!document.hidden) void refreshStatus()
    }
    refresh()
    const t = setInterval(refresh, 1000)
    const onVisible = () => {
      if (!document.hidden) void refreshStatus()
    }
    document.addEventListener("visibilitychange", onVisible)
    return () => {
      clearInterval(t)
      document.removeEventListener("visibilitychange", onVisible)
    }
  }, [refreshStatus])

  const reloadPackets = useCallback(async (expr: string) => {
    setLoadingPackets(true)
    try {
      const res = await api.packets(expr, 5000)
      packetStore.replace(res.packets)
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
        if (!cancelled) packetStore.replace(res.packets)
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
    readyRef.current = 0
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
        packetStore.clear()
      }
      if (instance) instanceRef.current = instance
      readyRef.current++
      // Initial page load already fetched the snapshot. Only re-sync after a
      // reconnect or backend restart.
      if (readyRef.current > 1) void reloadPackets(filterRef.current)
    }
    const onPackets = (event: MessageEvent<string>) => {
      try {
        const payload = JSON.parse(event.data) as { packets: Packet[] }
        if (!Array.isArray(payload.packets) || payload.packets.length === 0) return
        const lastID = packetStore.lastID
        const fresh = payload.packets.filter((p) => p.id > lastID)
        packetStore.append(fresh)
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
      try { await api.captureFilter("") } catch { /* ignore */ }
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
      try {
        await api.captureFilter(trimmed)
      } catch {
        /* capture may not be running; the next start sends the filter */
      }
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
        ringSize: opts.ringSize ?? 32 << 20,
        clear: opts.clear ?? true,
        filter: opts.filter ?? "",
        cgroup: opts.cgroup,
      })
      if (opts.clear ?? true) packetStore.clear()
      setStatus((prev) => (prev ? { ...prev, capture: res } : prev))
      await refreshStatus()
      return res
    },
    [refreshStatus],
  )

  const setCgroup = useCallback(
    async (cgroup: string) => {
      const res = await api.setCgroup(cgroup)
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
    packetStore.clear()
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
    packetStore,
    filter,
    filterError,
    connected,
    loadingPackets,
    applyFilter,
    setCgroup,
    start,
    stop,
    clear,
    importFile,
    refreshStatus,
    reloadPackets,
    setFilterError,
  }
}
