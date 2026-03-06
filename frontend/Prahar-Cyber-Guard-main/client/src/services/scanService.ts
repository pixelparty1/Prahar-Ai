export interface ScanStartResponse {
  success: boolean;
  scanId?: string;
  message?: string;
  error?: string;
}

export interface ScanStatusResponse {
  scanId: string;
  type: string;
  target: string;
  status: "queued" | "running" | "completed" | "failed" | "stopped";
  phase: string;
  error?: string;
  hasReport?: boolean;
}

export interface ScanResultResponse {
  scanId: string;
  status: string;
  report?: any;
  error?: string;
  message?: string;
}

async function parseResponse<T>(response: Response): Promise<T> {
  const data = await response.json();
  if (!response.ok) {
    throw new Error((data as any).error || (data as any).message || `Request failed: ${response.status}`);
  }
  return data as T;
}

export async function scanUploadZip(file: File): Promise<ScanStartResponse> {
  const form = new FormData();
  form.append("file", file);

  const response = await fetch("/api/scan/upload", {
    method: "POST",
    body: form,
  });

  return parseResponse<ScanStartResponse>(response);
}

export async function scanLink(url: string, mode: "attack" | "full" = "attack"): Promise<ScanStartResponse> {
  const response = await fetch("/api/scan/link", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, mode }),
  });

  return parseResponse<ScanStartResponse>(response);
}

export async function scanFolder(path: string): Promise<ScanStartResponse> {
  const response = await fetch("/api/scan/folder", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path }),
  });

  return parseResponse<ScanStartResponse>(response);
}

export async function getScanStatus(scanId: string): Promise<ScanStatusResponse> {
  const response = await fetch(`/api/scan/status/${encodeURIComponent(scanId)}`);
  return parseResponse<ScanStatusResponse>(response);
}

export async function getScanResult(scanId: string): Promise<ScanResultResponse> {
  const response = await fetch(`/api/scan/result/${encodeURIComponent(scanId)}`);
  return parseResponse<ScanResultResponse>(response);
}
