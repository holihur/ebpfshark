export interface ProtoStyle {
  text: string
  bg: string
  dot: string
  bar: string
}

const styles: Record<string, ProtoStyle> = {
  HTTP: {
    text: "text-amber-700 dark:text-amber-300",
    bg: "bg-amber-400/10",
    dot: "bg-amber-500 dark:bg-amber-400",
    bar: "bg-amber-500 dark:bg-amber-400",
  },
  DNS: {
    text: "text-emerald-700 dark:text-emerald-300",
    bg: "bg-emerald-400/10",
    dot: "bg-emerald-500 dark:bg-emerald-400",
    bar: "bg-emerald-500 dark:bg-emerald-400",
  },
  TLS: {
    text: "text-fuchsia-700 dark:text-fuchsia-300",
    bg: "bg-fuchsia-400/10",
    dot: "bg-fuchsia-500 dark:bg-fuchsia-400",
    bar: "bg-fuchsia-500 dark:bg-fuchsia-400",
  },
  DHCP: {
    text: "text-lime-700 dark:text-lime-300",
    bg: "bg-lime-400/10",
    dot: "bg-lime-500 dark:bg-lime-400",
    bar: "bg-lime-500 dark:bg-lime-400",
  },
  TCP: {
    text: "text-sky-700 dark:text-sky-300",
    bg: "bg-sky-400/10",
    dot: "bg-sky-500 dark:bg-sky-400",
    bar: "bg-sky-500 dark:bg-sky-400",
  },
  UDP: {
    text: "text-violet-700 dark:text-violet-300",
    bg: "bg-violet-400/10",
    dot: "bg-violet-500 dark:bg-violet-400",
    bar: "bg-violet-500 dark:bg-violet-400",
  },
  ICMP: {
    text: "text-orange-700 dark:text-orange-300",
    bg: "bg-orange-400/10",
    dot: "bg-orange-500 dark:bg-orange-400",
    bar: "bg-orange-500 dark:bg-orange-400",
  },
  ICMPv6: {
    text: "text-orange-700 dark:text-orange-300",
    bg: "bg-orange-400/10",
    dot: "bg-orange-500 dark:bg-orange-400",
    bar: "bg-orange-500 dark:bg-orange-400",
  },
  ARP: {
    text: "text-rose-700 dark:text-rose-300",
    bg: "bg-rose-400/10",
    dot: "bg-rose-500 dark:bg-rose-400",
    bar: "bg-rose-500 dark:bg-rose-400",
  },
  IPv4: {
    text: "text-cyan-700 dark:text-cyan-300",
    bg: "bg-cyan-400/10",
    dot: "bg-cyan-500 dark:bg-cyan-400",
    bar: "bg-cyan-500 dark:bg-cyan-400",
  },
  IPv6: {
    text: "text-cyan-700 dark:text-cyan-300",
    bg: "bg-cyan-400/10",
    dot: "bg-cyan-500 dark:bg-cyan-400",
    bar: "bg-cyan-500 dark:bg-cyan-400",
  },
  Ethernet: {
    text: "text-slate-700 dark:text-slate-300",
    bg: "bg-slate-400/10",
    dot: "bg-slate-500 dark:bg-slate-400",
    bar: "bg-slate-500 dark:bg-slate-400",
  },
  Frame: {
    text: "text-slate-700 dark:text-slate-300",
    bg: "bg-slate-400/10",
    dot: "bg-slate-500 dark:bg-slate-400",
    bar: "bg-slate-500 dark:bg-slate-400",
  },
}

const fallback: ProtoStyle = {
  text: "text-zinc-700 dark:text-zinc-300",
  bg: "bg-zinc-400/10",
  dot: "bg-zinc-500 dark:bg-zinc-400",
  bar: "bg-zinc-500 dark:bg-zinc-400",
}

export function protoStyle(proto: string): ProtoStyle {
  return styles[proto] ?? fallback
}

export const QUICK_FILTERS = ["tcp", "udp", "http", "dns", "tls", "icmp", "arp"] as const
