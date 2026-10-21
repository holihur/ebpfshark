import { useMemo } from "react"
import { base64ToBytes } from "@/lib/bytes"
import { formatBytes } from "@/lib/format"
import { cn } from "@/lib/utils"
import { useI18n } from "@/i18n"

export interface ByteRange {
  offset: number
  length: number
}

const hex2 = (b: number) => b.toString(16).padStart(2, "0")

interface HexViewProps {
  data: string
  highlight?: ByteRange | null
  className?: string
  /** Limit rendered bytes for very large streams. 0 means no limit. */
  maxBytes?: number
}

export function HexView({ data, highlight, className, maxBytes = 0 }: HexViewProps) {
  const { t } = useI18n()
  const allBytes = useMemo(() => base64ToBytes(data), [data])
  const limited = maxBytes > 0 && allBytes.length > maxBytes
  const bytes = limited ? allBytes.subarray(0, maxBytes) : allBytes
  const rows = Math.ceil(bytes.length / 16)

  if (bytes.length === 0) {
    return (
      <div className={cn("flex items-center justify-center text-2xs text-muted-foreground", className)}>
        {t("detail.noBytes")}
      </div>
    )
  }

  const inRange = (i: number) =>
    highlight != null && i >= highlight.offset && i < highlight.offset + highlight.length

  return (
    <div className={cn("min-h-0 overflow-auto font-mono text-[11px] leading-[18px] scrollbar-thin", className)}>
      <div className="min-w-max px-3 py-1.5">
        {Array.from({ length: rows }, (_, row) => {
          const start = row * 16
          const slice = bytes.subarray(start, Math.min(start + 16, bytes.length))
          return (
            <div key={row} className="flex gap-3 whitespace-pre">
              <span className="select-none text-muted-foreground/50">
                {start.toString(16).padStart(4, "0")}
              </span>
              <span className="flex gap-[3px]">
                {Array.from({ length: 16 }, (_, col) => {
                  const idx = start + col
                  if (idx >= bytes.length) return <span key={col} className="w-[18px]">{"  "}</span>
                  const active = inRange(idx)
                  return (
                    <span
                      key={col}
                      className={cn(
                        "w-[18px] rounded-[2px] text-center",
                        col === 7 && "mr-1.5",
                        active
                          ? "bg-primary/70 font-semibold text-primary-foreground"
                          : "text-foreground/85",
                      )}
                    >
                      {hex2(bytes[idx])}
                    </span>
                  )
                })}
              </span>
              <span className="select-none text-muted-foreground/40">|</span>
              <span>
                {Array.from(slice, (b, col) => {
                  const idx = start + col
                  const ch = b >= 32 && b <= 126 ? String.fromCharCode(b) : "."
                  return (
                    <span
                      key={col}
                      className={cn(
                        inRange(idx)
                          ? "bg-primary/40 text-primary-foreground"
                          : "text-muted-foreground",
                      )}
                    >
                      {ch}
                    </span>
                  )
                })}
              </span>
            </div>
          )
        })}
      </div>
      {limited && (
        <div className="border-t px-3 py-1 text-2xs text-muted-foreground">
          {t("hex.limited", {
            shown: formatBytes(bytes.length),
            total: formatBytes(allBytes.length),
          })}
        </div>
      )}
    </div>
  )
}
