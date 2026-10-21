export function base64ToBytes(b64: string): Uint8Array {
  try {
    const bin = atob(b64)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return new Uint8Array()
  }
}

/** Printable ASCII rendering (newline/tab kept, other bytes replaced). */
export function toAscii(bytes: Uint8Array): string {
  let out = ""
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]
    if (b === 10 || b === 13 || b === 9 || (b >= 32 && b <= 126)) {
      out += String.fromCharCode(b)
    } else {
      out += "·"
    }
  }
  return out
}

export function asciiToBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff
  return out
}
