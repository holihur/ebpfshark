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

export interface StatusResponse {
  capture: CaptureStatus
  store: StoreStats
  interfaces: InterfaceInfo[]
  subscribers: number
  serverTime: number
  version: string
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
