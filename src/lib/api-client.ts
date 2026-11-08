// api-client.ts – HTTP client for the Python FastAPI backend (port 5000)
// Falls back gracefully when the backend is unavailable.

const API_BASE = "http://127.0.0.1:5000";
const TIMEOUT_MS = 8000;

async function fetchWithTimeout(url: string, options: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(id);
  }
}

async function apiFetch<T>(url: string, options: RequestInit = {}): Promise<T> {
  const res = await fetchWithTimeout(API_BASE + url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export type BackendStatus = "online" | "offline" | "checking";

export async function checkBackendHealth(): Promise<BackendStatus> {
  try {
    await fetchWithTimeout(`${API_BASE}/health`);
    return "online";
  } catch {
    return "offline";
  }
}

export const api = {
  health: () => apiFetch<{ status: string }>("/health"),
  getDevices: () => apiFetch<{ success: boolean; devices: unknown[] }>("/api/devices"),
  refreshDevices: () => apiFetch<{ success: boolean; devices: unknown[] }>("/api/devices/refresh", { method: "POST" }),
  connectDevice: (serial: string) => apiFetch<{ success: boolean; device: unknown }>("/api/devices/connect", { method: "POST", body: JSON.stringify({ serial }) }),
  disconnectDevice: (serial: string) => apiFetch<{ success: boolean }>("/api/devices/disconnect", { method: "POST", body: JSON.stringify({ serial }) }),
  collectEvidence: (serial: string) => apiFetch<{ success: boolean; total_collected: number; breakdown: Record<string, { count: number; success: boolean }> }>(`/api/evidence/collect/${serial}`, { method: "POST" }),
  loadSampleData: () => apiFetch<{ success: boolean; message: string; counts: Record<string, number> }>("/api/evidence/load-sample", { method: "POST" }),
  importEvidence: (data: unknown) => apiFetch<{ success: boolean }>("/api/evidence/import", { method: "POST", body: JSON.stringify(data) }),
  getAllEvidence: (deviceId: string) => apiFetch<{ success: boolean; sms: unknown[]; calls: unknown[] }>(`/api/evidence/${deviceId}`),
  getEvidenceHashes: (deviceId: string) => apiFetch<{ success: boolean; hashes: { id: string; kind: string; hash: string }[] }>(`/api/evidence/hashes/${deviceId}`),
  getOllamaStatus: () => apiFetch<{ connected: boolean; models: string[]; active_model: string; latency_ms: number }>("/api/analysis/ollama-status"),
  runForensicAnalysis: (deviceId: string) => apiFetch<{ success: boolean; result: unknown }>(`/api/analysis/forensic/${deviceId}`, { method: "POST" }),
  runAIAnalysis: (deviceId: string) => apiFetch<{ success: boolean; result: unknown; source: string }>(`/api/analysis/ai/${deviceId}`, { method: "POST" }),
  getAnalysisResults: (investigationId: string) => apiFetch<{ success: boolean; results: unknown[] }>(`/api/analysis/results/${investigationId}`),
  generateReport: (investigationId: string) => apiFetch<{ success: boolean; report_id: string; download_url: string; size_kb: number }>(`/api/reports/generate/${investigationId}`, { method: "POST" }),
  getReportPreview: (investigationId: string) => apiFetch<{ success: boolean; preview: unknown }>(`/api/reports/preview/${investigationId}`),
  getDownloadUrl: (reportId: string) => `${API_BASE}/api/reports/download/${reportId}`,
  getDashboardStats: () => apiFetch<{ success: boolean; stats: Record<string, number>; evidence_categories: Record<string, number> }>("/api/dashboard/stats"),
};
