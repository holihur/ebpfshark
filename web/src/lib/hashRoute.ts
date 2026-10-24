export type RouteModule = "network" | "processes"
export interface RouteState {
  module: RouteModule
  tab: string
  packet?: number
}

const NETWORK_TABS = new Set(["capture", "processes", "protocols", "flows"])

export function parseHash(hash = window.location.hash): RouteState {
  const raw = hash.replace(/^#\/?/, "")
  const [path, query = ""] = raw.split("?")
  const parts = path.split("/").filter(Boolean)
  const module: RouteModule = parts[0] === "processes" ? "processes" : "network"
  let tab = parts[1] ?? "capture"
  if (!NETWORK_TABS.has(tab)) tab = "capture"
  const params = new URLSearchParams(query)
  const packet = Number.parseInt(params.get("packet") ?? "", 10)
  return { module, tab, packet: Number.isFinite(packet) && packet > 0 ? packet : undefined }
}

export function formatHash(route: RouteState): string {
  const base = route.module === "network" ? `/network/${route.tab}` : "/processes"
  const params = new URLSearchParams()
  if (route.packet) params.set("packet", String(route.packet))
  const query = params.toString()
  return `#${base}${query ? `?${query}` : ""}`
}
