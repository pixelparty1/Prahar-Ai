import { Router, type Request, type Response } from "express";
import multer from "multer";
import FormData from "form-data";

const scanRouter = Router();
const upload = multer({ storage: multer.memoryStorage() });

const DEFAULT_PYTHON_BACKEND = "http://localhost:8000";

function getBackendUrl(): string {
  return (process.env.PYTHON_BACKEND_URL || DEFAULT_PYTHON_BACKEND).replace(/\/$/, "");
}

/**
 * POST /api/scan/upload
 * Accepts a ZIP file and forwards it to the Python backend.
 */
scanRouter.post("/upload", upload.single("file"), async (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: "No file uploaded" });
  }

  try {
    const form = new FormData();
    form.append("file", req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype,
    });

    const backendRes = await fetch(`${getBackendUrl()}/scan/upload`, {
      method: "POST",
      body: form as any,
      headers: form.getHeaders(),
    });

    const data = await backendRes.json();
    return res.status(backendRes.status).json(data);
  } catch {
    return res.status(502).json({ success: false, error: "Python backend unavailable" });
  }
});

/**
 * POST /api/scan/link
 * Send a URL to the Python backend for live scanning.
 */
scanRouter.post("/link", async (req: Request, res: Response) => {
  const { url, mode } = req.body as { url?: string; mode?: string };

  if (!url) {
    return res.status(400).json({ success: false, error: "url is required" });
  }

  try {
    const backendRes = await fetch(`${getBackendUrl()}/scan/link`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, mode: mode || "attack" }),
    });

    const data = await backendRes.json();
    return res.status(backendRes.status).json(data);
  } catch {
    return res.status(502).json({ success: false, error: "Python backend unavailable" });
  }
});

/**
 * POST /api/scan/folder
 * Send a folder path to the Python backend.
 */
scanRouter.post("/folder", async (req: Request, res: Response) => {
  const { path } = req.body as { path?: string };

  if (!path) {
    return res.status(400).json({ success: false, error: "path is required" });
  }

  try {
    const backendRes = await fetch(`${getBackendUrl()}/scan/folder`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });

    const data = await backendRes.json();
    return res.status(backendRes.status).json(data);
  } catch {
    return res.status(502).json({ success: false, error: "Python backend unavailable" });
  }
});

/**
 * GET /api/scan/status/:scanId
 * Check the status of a running scan.
 */
scanRouter.get("/status/:scanId", async (req: Request, res: Response) => {
  try {
    const backendRes = await fetch(`${getBackendUrl()}/scan/status/${req.params.scanId}`);
    const data = await backendRes.json();
    return res.status(backendRes.status).json(data);
  } catch {
    return res.status(502).json({ error: "Python backend unavailable" });
  }
});

/**
 * GET /api/scan/result/:scanId
 * Get the full report of a completed scan.
 */
scanRouter.get("/result/:scanId", async (req: Request, res: Response) => {
  try {
    const backendRes = await fetch(`${getBackendUrl()}/scan/result/${req.params.scanId}`);
    const data = await backendRes.json();
    return res.status(backendRes.status).json(data);
  } catch {
    return res.status(502).json({ error: "Python backend unavailable" });
  }
});

export default scanRouter;
