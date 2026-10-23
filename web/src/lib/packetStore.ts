import { useSyncExternalStore } from "react"
import type { Packet } from "./types"

/**
 * Bounded ring buffer for the UI packet list. The array is mutated in place;
 * React subscribers only re-render when the version changes. Components use
 * slice()/at() to read the visible window without copying the whole buffer.
 */
export class PacketStore {
  private buf: Packet[]
  private head = 0
  private count = 0
  private version = 0
  private listeners = new Set<() => void>()

  constructor(private readonly max = 20000) {
    this.buf = new Array<Packet>(max)
  }

  get length(): number { return this.count }
  get lastID(): number {
    if (this.count === 0) return 0
    return this.at(this.count - 1)?.id ?? 0
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  getVersion = (): number => this.version

  private notify() {
    this.version++
    for (const l of this.listeners) l()
  }

  append(items: Packet[]) {
    if (items.length === 0) return
    for (const p of items) {
      if (this.count < this.max) {
        this.buf[(this.head + this.count) % this.max] = p
        this.count++
      } else {
        this.buf[this.head] = p
        this.head = (this.head + 1) % this.max
      }
    }
    this.notify()
  }

  replace(items: Packet[]) {
    this.head = 0
    this.count = Math.min(items.length, this.max)
    const start = items.length - this.count
    for (let i = 0; i < this.count; i++) this.buf[i] = items[start + i]
    this.notify()
  }

  clear() {
    this.head = 0
    this.count = 0
    this.buf = new Array<Packet>(this.max)
    this.notify()
  }

  at(index: number): Packet | undefined {
    if (index < 0 || index >= this.count) return undefined
    return this.buf[(this.head + index) % this.max]
  }

  slice(start: number, end = this.count): Packet[] {
    start = Math.max(0, Math.min(start, this.count))
    end = Math.max(start, Math.min(end, this.count))
    const out = new Array<Packet>(end - start)
    for (let i = start; i < end; i++) out[i - start] = this.buf[(this.head + i) % this.max]
    return out
  }
}

export const packetStore = new PacketStore()

export function usePacketVersion(): number {
  return useSyncExternalStore(packetStore.subscribe, packetStore.getVersion, packetStore.getVersion)
}
