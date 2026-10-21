import { useId } from "react"
import { cn } from "@/lib/utils"

interface SparklineProps {
  values: number[]
  className?: string
  width?: number
  height?: number
  color?: string
}

export function Sparkline({
  values,
  className,
  width = 132,
  height = 24,
  color = "hsl(172 74% 46%)",
}: SparklineProps) {
  const id = useId().replace(/:/g, "")
  const max = Math.max(1, ...values)
  const n = Math.max(values.length, 2)
  const step = width / (n - 1)
  const points = values.map((v, i) => {
    const x = i * step
    const y = height - 2 - (v / max) * (height - 4)
    return [x, y] as const
  })
  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ")
  const area =
    points.length > 0
      ? `M0,${height} L${points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" L")} L${width},${height} Z`
      : ""

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className={cn("overflow-visible", className)}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={`spark-${id}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {area && <path d={area} fill={`url(#spark-${id})`} />}
      <polyline
        points={line}
        fill="none"
        stroke={color}
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}
