export interface SessionInfo {
  enabled: boolean
  authenticated: boolean
  user?: string
}

export interface InterfaceInfo {
  name: string
  index: number
  mac: string
  mtu: number
  up: boolean
  loopback: boolean
  default: boolean
  kind: string
  addrs: string[]
}

export interface FilterField {
  name: string
  group: string
  type: "layer" | "string" | "number" | "ip" | "flag" | "enum" | "bytes"
  ops?: string[]
  values?: string[]
  suggest?: string[]
}

export interface Packet {
  id: number
  time: number
  iface: string
  cgroupID?: number
  direction: "ingress" | "egress"
  len: number
  capLen: number
  truncated?: boolean
  protocol: string
  layers: string[]
  src: string
  dst: string
  srcPort?: number
  dstPort?: number
  info: string
}

export interface Field {
  label: string
  value?: string
  offset: number
  length: number
  severity?: "note" | "warn" | "error"
  children?: Field[]
}

export interface PacketDetail {
  packet: Packet
  fields: Field[]
  data: string
  dataLen: number
  linkType: number
}

export interface CaptureStatus {
  running: boolean
  cgroupID?: number
  interfaces: string[]
  snaplen: number
  sampleRate: number
  ringSize: number
  kernelPackets: number
  kernelBytes: number
  kernelSkipped: number
  kernelFiltered: number
  excludePort: number
  uptimeSeconds: number
  attachErrors?: string[]
  lastError?: string
}

export interface MITMStatus {
  enabled: boolean
  addr?: string
  caPath?: string
}

export interface DecryptStatus {
  tlsKeylogEntries: number
  wifiPSKConfigured: boolean
  tlsKeylogAuto: boolean
}

export interface ProcessInfo {
  pid: number
  ppid?: number
  comm: string
  state?: string
  threads?: number
  rss?: number
  vsize?: number
  cgroupID?: number
  cgroupPath?: string
  command?: string
  exe?: string
}

export interface RatePoint {
  time: number
  packets: number
  bytes: number
}

export interface StreamEndpoint {
  ip: string
  port: number
}

export interface StreamDirectionData {
  from: StreamEndpoint
  to: StreamEndpoint
  bytes: number
  truncated: boolean
  gaps: number
  data: string
}

export interface PacketStream {
  key: string
  a: StreamEndpoint
  b: StreamEndpoint
  aToB: StreamDirectionData
  bToA: StreamDirectionData
  first: string
  last: string
}

export interface StreamStats {
  flows: number
  bytes: number
  evicted: number
  budgetBytes: number
}

export interface StoreStats {
  stored: number
  capacity: number
  total: number
  bytes: number
  evicted: number
  dropped: number
  protocols: Record<string, number>
  rate: RatePoint[]
  streams?: StreamStats
  firstPacket?: string
  lastPacket?: string
}

export interface SystemInfo {
  kernel?: string
  os?: string
  hostname?: string
  memoryTotal: number
  memoryAvailable: number
  uptimeSeconds: number
}

export interface StatusResponse {
  capture: CaptureStatus
  store: StoreStats
  interfaces: InterfaceInfo[]
  subscribers: number
  serverTime: number
  version: string
  system?: SystemInfo
}

export interface Flow {
  key: string
  protocol: string
  app?: string
  src: string
  dst: string
  srcPort?: number
  dstPort?: number
  packets: number
  bytes: number
  packetsA: number
  packetsB: number
  bytesA: number
  bytesB: number
  first: string
  last: string
  state?: string
  tcpFlags: number
}

export interface FilterValidation {
  valid: boolean
  error?: string
  empty?: boolean
}

export interface ImportResult {
  imported: number
  elapsedMs: number
  captureStopped: boolean
}

export interface FilterFields {
  fields: string[]
  protocols: string[]
}

export interface TraceEvent {
  id: number
  time: number
  durationNs: number
  pid: number
  tid: number
  function: string
  comm: string
  cgroupID?: number
}

export interface TraceStatus {
  running: boolean
  pid: number
  functions: string[]
  count: number
  startedAt?: string
  error?: string
}

export interface TraceResponse {
  events: TraceEvent[]
  status: TraceStatus
}

export interface TraceSymbol {
  name: string
  address?: number
  kind?: string
}

export interface TraceInfo {
  pid: number
  path: string
  buildId?: string
  stripped: boolean
  symbols: number
  debugFile?: string
  debuginfod: boolean
  comm?: string
  cgroupPath?: string
  containerId?: string
  podUid?: string
  suggestions: string[]
}

export interface IPCSocket {
  inode: number
  path?: string
  type: string
  state?: string
  pid?: number
  comm?: string
  exe?: string
  cgroupPath?: string
}

export interface IPCEvent {
  id: number
  time: string
  inode: number
  pid: number
  tid: number
  cgroupID?: number
  comm?: string
  direction: "send" | "receive"
  type?: string
  path?: string
  part: number
  parts?: number
  truncated?: boolean
  /** Go encodes []byte as base64. */
  payload?: string
}

export interface IPCStream {
  key: string
  inode: number
  pid: number
  comm?: string
  type?: string
  path?: string
  first: string
  last: string
  bytesIn: number
  bytesOut: number
  events: number
  truncated: boolean
}

export interface IPCStats {
  events: number
  streams: number
  total: number
  bytes: number
}

export interface IPCKernelStats {
  events: number
  bytes: number
  truncated: number
  dropped: number
}

export interface IPCStatus {
  running: boolean
  pid: number
  cgroupID?: number
  maxPayload: number
  ringSize: number
  startedAt?: string
  uptimeSeconds: number
  store: IPCStats
  kernel: IPCKernelStats
  attachErrors?: string[]
  lastError?: string
}
