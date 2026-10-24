export interface CaptureSettings {
  snaplen: number
  sampleRate: number
  ringSize: number
  clearOnStart: boolean
}

const KEY = "sisyphus.capture-settings"
export const DEFAULT_CAPTURE_SETTINGS: CaptureSettings = {
  snaplen: 2048,
  sampleRate: 1,
  ringSize: 32 << 20,
  clearOnStart: true,
}

export function loadCaptureSettings(): CaptureSettings {
  try {
    const value = JSON.parse(localStorage.getItem(KEY) ?? "null") as Partial<CaptureSettings> | null
    return {
      snaplen: typeof value?.snaplen === "number" ? value.snaplen : DEFAULT_CAPTURE_SETTINGS.snaplen,
      sampleRate: typeof value?.sampleRate === "number" ? value.sampleRate : DEFAULT_CAPTURE_SETTINGS.sampleRate,
      ringSize: typeof value?.ringSize === "number" ? value.ringSize : DEFAULT_CAPTURE_SETTINGS.ringSize,
      clearOnStart: typeof value?.clearOnStart === "boolean" ? value.clearOnStart : DEFAULT_CAPTURE_SETTINGS.clearOnStart,
    }
  } catch {
    return { ...DEFAULT_CAPTURE_SETTINGS }
  }
}

export function saveCaptureSettings(value: CaptureSettings) {
  try {
    localStorage.setItem(KEY, JSON.stringify(value))
  } catch {
    // storage may be unavailable
  }
}
