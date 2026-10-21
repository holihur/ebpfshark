import { useCallback, useEffect, useRef, useState } from "react"

interface VirtualListOptions {
  rowHeight: number
  overscan?: number
}

export function useVirtualList({ rowHeight, overscan = 12 }: VirtualListOptions) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [viewportHeight, setViewportHeight] = useState(480)
  const atBottomRef = useRef(true)
  const [atBottom, setAtBottom] = useState(true)

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) setViewportHeight(e.contentRect.height)
    })
    ro.observe(el)
    setViewportHeight(el.clientHeight)
    return () => ro.disconnect()
  }, [])

  const onScroll = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    setScrollTop(el.scrollTop)
    const bottom = el.scrollHeight - el.scrollTop - el.clientHeight < rowHeight * 1.5
    if (bottom !== atBottomRef.current) {
      atBottomRef.current = bottom
      setAtBottom(bottom)
    }
  }, [rowHeight])

  const scrollToBottom = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    el.scrollTop = el.scrollHeight
    atBottomRef.current = true
    setAtBottom(true)
  }, [])

  const totalHeight = (count: number) => count * rowHeight
  const startFor = () => Math.max(0, Math.floor(scrollTop / rowHeight) - overscan)
  const endFor = (count: number) =>
    Math.min(count, Math.ceil((scrollTop + viewportHeight) / rowHeight) + overscan)

  return {
    containerRef,
    onScroll,
    scrollTop,
    viewportHeight,
    atBottom,
    scrollToBottom,
    totalHeight,
    startFor,
    endFor,
  }
}
