import { Fragment, memo } from "react"
import { cn } from "@/lib/utils"

type TokenKind = "space" | "string" | "keyword" | "operator" | "number" | "field" | "protocol" | "paren" | "plain"

const TOKEN_RE =
  /(\s+)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\b(?:and|or|not|in|contains|matches)\b)|(==|!=|>=|<=|~=|>|<|=)|(\b(?:0x[0-9a-f]+|\d+(?:\.\d+){0,3}(?:\/\d+)?)\b)|([A-Za-z_][A-Za-z0-9_.-]*)|([()])/gi

const FIELD_NAMES = new Set([
  "frame.len",
  "frame.cap_len",
  "frame.number",
  "frame.protocols",
  "cgroup.id",
  "eth.src",
  "eth.dst",
  "ethertype",
  "vlan.id",
  "ip.src",
  "ip.dst",
  "ip.proto",
  "ip.ttl",
  "ipv6.src",
  "ipv6.dst",
  "tcp.srcport",
  "tcp.dstport",
  "tcp.flags",
  "udp.srcport",
  "udp.dstport",
  "port",
  "host",
  "net",
  "len",
  "proto",
])

const PROTOCOLS = new Set([
  "tcp", "udp", "icmp", "icmpv6", "arp", "ip", "ipv6", "dns", "http", "http2",
  "tls", "quic", "ssh", "dhcp", "dhcpv6", "smtp", "imap", "pop", "ftp", "mqtt",
  "coap", "modbus", "amqp", "radius", "sip", "rtp", "rtcp", "rtsp", "websocket",
  "grpc", "sctp", "vlan", "wifi", "eapol", "ai", "anthropic", "openai",
])

function classify(text: string): TokenKind {
  if (/^\s+$/.test(text)) return "space"
  if (/^["']/.test(text)) return "string"
  if (/^(and|or|not|in|contains|matches)$/i.test(text)) return "keyword"
  if (/^(==|!=|>=|<=|~=|>|<|=)$/.test(text)) return "operator"
  if (/^(?:0x[0-9a-f]+|\d+(?:\.\d+){0,3}(?:\/\d+)?)$/i.test(text)) return "number"
  if (/^[()]$/.test(text)) return "paren"
  const lower = text.toLowerCase()
  if (FIELD_NAMES.has(lower) || (lower.includes(".") && /^[a-z_][\w.-]*$/.test(lower))) return "field"
  if (PROTOCOLS.has(lower)) return "protocol"
  return "plain"
}

const CLASS: Record<TokenKind, string> = {
  space: "",
  string: "text-emerald-600 dark:text-emerald-300",
  keyword: "text-fuchsia-600 dark:text-fuchsia-300",
  operator: "text-amber-600 dark:text-amber-300",
  number: "text-sky-600 dark:text-sky-300",
  field: "text-blue-600 dark:text-blue-300",
  protocol: "text-violet-600 dark:text-violet-300",
  paren: "text-muted-foreground",
  plain: "text-foreground/85",
}

export const FilterHighlight = memo(function FilterHighlight({
  text,
  className,
}: {
  text: string
  className?: string
}) {
  const tokens: Array<{ text: string; kind: TokenKind }> = []
  let last = 0
  for (const match of text.matchAll(TOKEN_RE)) {
    const value = match[0]
    const index = match.index ?? 0
    if (index > last) tokens.push({ text: text.slice(last, index), kind: "plain" })
    tokens.push({ text: value, kind: classify(value) })
    last = index + value.length
  }
  if (last < text.length) tokens.push({ text: text.slice(last), kind: "plain" })

  return (
    <span className={cn("font-mono whitespace-pre", className)} aria-hidden="true">
      {tokens.map((token, i) => (
        <Fragment key={i}>
          <span className={CLASS[token.kind]}>{token.text}</span>
        </Fragment>
      ))}
    </span>
  )
})
