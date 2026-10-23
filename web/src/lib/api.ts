import type {
  FilterField,
  FilterFields,
  FilterValidation,
  Flow,
  ImportResult,
  Packet,
  PacketDetail,
  PacketStream,
  SessionInfo,
  StatusResponse,
  StoreStats,
  TraceInfo,
  TraceResponse,
} from "./types"

export const UNAUTHORIZED_EVENT = "ebpfshark:unauthorized"

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = "ApiError"
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers:
      init?.body instanceof FormData
        ? init?.headers
        : { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  })
  const text = await res.text()
  let data: unknown = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
  }
  if (!res.ok) {
    const message =
      (data as { error?: string } | null)?.error ?? `${res.status} ${res.statusText}`
    if (res.status === 401 && !path.startsWith("/api/auth/login")) {
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT))
    }
    throw new ApiError(message, res.status)
  }
  return data as T
}

function enc(filter: string) {
  return encodeURIComponent(filter)
}

export const api = {
  session: () => request<SessionInfo>("/api/auth/session"),
  login: (username: string, password: string) =>
    request<SessionInfo>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<{ ok: boolean }>("/api/auth/logout", { method: "POST" }),
  status: () => request<StatusResponse>("/api/status"),
  stats: () => request<StoreStats>("/api/stats"),
  packets: (filter: string, limit = 5000) =>
    request<{ packets: Packet[]; count: number; stored: number }>(
      `/api/packets?limit=${limit}&filter=${enc(filter)}`,
    ),
  detail: (id: number) => request<PacketDetail>(`/api/packets/${id}`),
  packetStream: (id: number) => request<PacketStream>(`/api/packets/${id}/stream`),
  start: (body: {
    interfaces: string[]
    snaplen: number
    sampleRate: number
    clear: boolean
  }) =>
    request<StatusResponse["capture"]>("/api/capture/start", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  stop: () => request<StatusResponse["capture"]>("/api/capture/stop", { method: "POST" }),
  clear: () => request<{ ok: boolean }>("/api/capture/clear", { method: "POST" }),
  validate: (filter: string) =>
    request<FilterValidation>("/api/filter/validate", {
      method: "POST",
      body: JSON.stringify({ filter }),
    }),
  conversations: (limit = 200) =>
    request<{ flows: Flow[]; count: number }>(`/api/conversations?limit=${limit}`),
  filterFields: () => request<FilterFields>("/api/filter/fields"),
  filterSchema: () => request<{ fields: FilterField[] }>("/api/filter/schema"),
  importFile: (file: File) => {
    const fd = new FormData()
    fd.append("file", file)
    return request<ImportResult>("/api/import", { method: "POST", body: fd })
  },
  exportUrl: (filter: string) => `/api/export/pcap?filter=${enc(filter)}`,
  streamUrl: (filter: string) => `/api/stream?filter=${enc(filter)}`,
  trace: (limit = 500, after = 0) =>
    request<TraceResponse>(`/api/trace?limit=${limit}&after=${after}`),
  traceContext: (cgroup: number, at: number, window = 1_000_000_000) =>
    request<{ count: number; packets: Packet[] }>(`/api/trace/context?cgroup=${cgroup}&at=${at}&window=${window}`),
  traceInspect: (pid: number, binary = "") =>
    request<TraceInfo>(`/api/trace/inspect?pid=${pid}&binary=${enc(binary)}`),
  traceStart: (pid: number, functions: string) =>
    request<TraceResponse["status"]>("/api/trace/start", {
      method: "POST",
      body: JSON.stringify({ pid, functions }),
    }),
  traceStop: () =>
    request<TraceResponse["status"]>("/api/trace/stop", { method: "POST" }),
}
