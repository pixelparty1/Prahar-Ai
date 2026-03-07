import { useCallback, useEffect, useRef, useState } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import { useBattleState } from "@/hooks/useBattleState";
import { Scoreboard } from "./Scoreboard";
import { Controls } from "./Controls";
import { NetworkGraph } from "./NetworkGraph";
import { BattleFeed } from "./BattleFeed";
import { ThreatIntel } from "./ThreatIntel";
import { MalwareAnalyzer } from "./MalwareAnalyzer";
import { Navigation } from "./Navigation";
import { useToast } from "@/hooks/use-toast";
import { useCommandCenter } from "@/hooks/useCommandCenter";
import { getScanStatus, scanUploadZip, type ScanStatusResponse } from "@/services/scanService";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PlanDropdown } from "./PlanDropdown";

const BOTS = [
  {
    id: "bot-1",
    emoji: "🔴",
    name: "ATTACK BOT",
    codename: "Ghost",
    description: "Scans the network, finds weaknesses, and launches attacks automatically.",
    status: "online",
  },
  {
    id: "bot-2",
    emoji: "🔵",
    name: "DEFEND BOT",
    codename: "Aegis",
    description: "Watches everything, detects attacks, and blocks them automatically.",
    status: "online",
  },
  {
    id: "bot-3",
    emoji: "⚖️",
    name: "NARRATOR BOT",
    codename: "Oracle",
    description:
      "Watches the attack and defense happening live, explains every move in plain English, and keeps the score.",
    status: "online",
  },
  {
    id: "bot-4",
    emoji: "🌐",
    name: "SPY BOT",
    codename: "Phantom Eye",
    description:
      "Searches the real internet for today's latest threats and hacks, then feeds that info to the Attack Bot.",
    status: "online",
  },
  {
    id: "bot-5",
    emoji: "🕸️",
    name: "TRAP BOT",
    codename: "Mirage",
    description:
      "Sets up fake servers that look real. When the Attack Bot falls for the trap, it captures all its techniques and sends them to the Defend Bot.",
    status: "online",
  },
] as const;

function speakAlert(text: string) {
  if (typeof window === "undefined" || !("speechSynthesis" in window)) return;
  const msg = new SpeechSynthesisUtterance(text);
  msg.rate = 1;
  msg.pitch = 0.9;
  window.speechSynthesis.speak(msg);
}

export function CommandCenter() {
  const { mode, state, latestEvent, connectionStatus, controls } = useBattleState();
  const { runSimulation, stopSimulation, status, error } = useCommandCenter();
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const [targetUrl, setTargetUrl] = useState("");
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [simulationActive, setSimulationActive] = useState(false);
  const [simulationId, setSimulationId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null);
  const [selectedBotId, setSelectedBotId] = useState<string | null>(() => {
    if (typeof window === "undefined") {
      return null;
    }

    const storedBotId = window.localStorage.getItem("selectedBotId");
    return BOTS.some((bot) => bot.id === storedBotId) ? storedBotId : null;
  });

  // ZIP upload state
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [zipDragActive, setZipDragActive] = useState(false);
  const [zipUploading, setZipUploading] = useState(false);
  const [zipScanId, setZipScanId] = useState<string | null>(null);
  const [zipScanStatus, setZipScanStatus] = useState<ScanStatusResponse | null>(null);
  const zipInputRef = useRef<HTMLInputElement>(null);

  const handleZipDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setZipDragActive(false);
    const file = e.dataTransfer.files[0];
    if (file && file.name.toLowerCase().endsWith(".zip")) {
      setZipFile(file);
    } else {
      toast({ title: "⚠️ Only .zip files are accepted" });
    }
  }, [toast]);

  const handleZipSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && file.name.toLowerCase().endsWith(".zip")) {
      setZipFile(file);
    } else if (file) {
      toast({ title: "⚠️ Only .zip files are accepted" });
    }
  }, [toast]);

  const handleZipUploadScan = async () => {
    if (!zipFile) return;
    setZipUploading(true);
    try {
      const res = await scanUploadZip(zipFile);
      if (res.success && res.scanId) {
        setZipScanId(res.scanId);
        toast({ title: `🚀 Sandbox scan started for ${zipFile.name}` });
      } else {
        toast({ title: `⚠️ ${res.error || res.message || "Upload failed"}` });
      }
    } catch (err) {
      toast({ title: `⚠️ ${err instanceof Error ? err.message : "Upload failed"}` });
    } finally {
      setZipUploading(false);
    }
  };

  const handleZipReset = () => {
    setZipFile(null);
    setZipScanId(null);
    setZipScanStatus(null);
    if (zipInputRef.current) zipInputRef.current.value = "";
  };

  // Poll ZIP scan status
  useEffect(() => {
    if (!zipScanId) {
      setZipScanStatus(null);
      return;
    }
    let mounted = true;
    const poll = async () => {
      try {
        const s = await getScanStatus(zipScanId);
        if (mounted) {
          setZipScanStatus(s);
          if (s.status === "completed") {
            toast({ title: "✅ Sandbox scan completed! View results below." });
          }
        }
      } catch { /* backend may not be running */ }
    };
    poll();
    const timer = setInterval(poll, 4000);
    return () => { mounted = false; clearInterval(timer); };
  }, [zipScanId, toast]);

  const handleBotSelect = (botId: string, botLabel: string) => {
    setSelectedBotId(botId);
    window.localStorage.setItem("selectedBotId", botId);
    toast({
      title: `${botLabel} is now active`,
    });
  };

  const getSimulationRoleMessage = (botId: string) => {
    switch (botId) {
      case "bot-1":
        return `Scanning ${targetUrl} for open ports and vulnerabilities...`;
      case "bot-2":
        return `Monitoring incoming responses from ${targetUrl}...`;
      case "bot-3":
        return `Analyzing and logging all activity on ${targetUrl}...`;
      case "bot-4":
        return `Searching for known exploits related to ${targetUrl}...`;
      case "bot-5":
        return `Deploying honeypot to intercept ${targetUrl} responses...`;
      default:
        return "";
    }
  };

  const handleLaunchSimulation = async () => {
    const isValidHttpUrl = /^https?:\/\/.+/i.test(targetUrl.trim());
    if (!isValidHttpUrl) {
      toast({ title: "⚠️ Please enter a valid URL" });
      return;
    }

    try {
      const payload = await runSimulation({
        targetUrl: targetUrl.trim(),
        selectedBotId: selectedBotId ?? "",
      });

      if (!payload?.success) {
        const message = payload?.message || "Failed to launch simulation";
        toast({ title: `⚠️ ${message}` });
        return;
      }

      setSimulationId(payload.simulationId ?? null);
      setSimulationActive(true);
      toast({ title: `🚀 Simulation launched on ${targetUrl.trim()}` });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to launch simulation";
      toast({ title: `⚠️ ${message}` });
    }
  };

  const handleStopSimulation = async () => {
    try {
      await stopSimulation({ simulationId: simulationId ?? "manual-stop" });
    } finally {
      setSimulationActive(false);
      setSimulationId(null);
      toast({ title: "🛑 Simulation stopped" });
    }
  };

  useEffect(() => {
    if (latestEvent?.severity === "critical") {
      speakAlert(`PRAHAAR ALERT. ${latestEvent.message}`);
    }

    if (latestEvent?.type === "end") {
      speakAlert("Battle concluded.");
    }
  }, [latestEvent]);

  useEffect(() => {
    if (!status) {
      return;
    }

    if (typeof status.active === "boolean") {
      setSimulationActive(status.active);
    }

    if (typeof status.simulationId === "string") {
      setSimulationId(status.simulationId);
    }
  }, [status]);

  useEffect(() => {
    if (error) {
      toast({ title: `⚠️ ${error}` });
    }
  }, [error, toast]);

  // Poll scan status from Python backend when a simulation is active
  useEffect(() => {
    if (!simulationId) {
      setScanStatus(null);
      return;
    }

    let mounted = true;

    const poll = async () => {
      try {
        const s = await getScanStatus(simulationId);
        if (mounted) {
          setScanStatus(s);
          if (s.status === "completed") {
            toast({ title: "✅ Vulnerability scan completed! View results below." });
          }
        }
      } catch {
        // Python backend may not be running — ignore silently
      }
    };

    poll();
    const timer = setInterval(poll, 4000);

    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, [simulationId, toast]);

  return (
    <div className="min-h-screen bg-background text-foreground p-4 md:p-6 scanline relative overflow-hidden">
      <Navigation currentPage="Command Center" variant="bar" enableHomeHotkey />
      <div className="absolute inset-0 cyber-grid opacity-20 pointer-events-none" />

      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="relative z-10 space-y-4 pt-16">
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-primary/20 border border-primary/40" />
            <div>
              <h1 className="font-display text-3xl md:text-4xl text-glow">PRAHAAR COMMAND CENTER</h1>
              <p className="font-mono text-xs text-muted-foreground">Red Team vs Blue Team - Live AI Battle Simulation</p>
            </div>
          </div>
          <PlanDropdown />
        </header>

        <Scoreboard state={state} />

        <Controls
          mode={mode}
          state={state}
          connectionStatus={connectionStatus}
          onStart={controls.start}
          onPause={controls.pause}
          onResume={controls.resume}
          onReset={controls.reset}
          onSetSpeed={controls.setSpeed}
          onExport={controls.exportReport}
          onModeChange={controls.setMode}
        />

        <Card className="w-full border-border bg-card shadow-md">
          <CardHeader className="pb-3">
            <CardTitle className="font-display text-xl md:text-2xl">Target</CardTitle>
            <CardDescription>Set an authorized target URL before launching simulation.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <input
              type="text"
              value={targetUrl}
              onChange={(event) => setTargetUrl(event.target.value)}
              placeholder="https://target-url.com"
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />

            <label className="flex items-center gap-2 text-sm text-foreground">
              <input
                type="checkbox"
                checked={isAuthorized}
                onChange={(event) => setIsAuthorized(event.target.checked)}
                className="h-4 w-4 rounded border-border bg-background"
              />
              <span>I confirm I have authorization to test this target</span>
            </label>

            <button
              type="button"
              onClick={handleLaunchSimulation}
              disabled={targetUrl.trim().length === 0 || !isAuthorized}
              className="w-full rounded-md bg-red-600 px-4 py-3 text-sm font-bold text-white transition-colors hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              LAUNCH SIMULATION
            </button>

            <p className="text-xs text-muted-foreground">
              Only test systems you own or have written permission to test.
            </p>
          </CardContent>
        </Card>

        {/* ZIP Upload — Sandbox Scan */}
        <Card className="w-full border-border bg-card shadow-md">
          <CardHeader className="pb-3">
            <CardTitle className="font-display text-xl md:text-2xl">📦 Upload ZIP — Sandbox Scan</CardTitle>
            <CardDescription>
              Upload your website source code as a .zip file. Bots will create a sandbox, launch simulated attacks, and run defenses automatically.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Drop zone */}
            <div
              onDragOver={(e) => { e.preventDefault(); setZipDragActive(true); }}
              onDragLeave={() => setZipDragActive(false)}
              onDrop={handleZipDrop}
              onClick={() => zipInputRef.current?.click()}
              className={`relative flex flex-col items-center justify-center rounded-lg border-2 border-dashed px-4 py-8 cursor-pointer transition-colors ${
                zipDragActive
                  ? "border-primary bg-primary/10"
                  : "border-border bg-background hover:border-primary/50"
              }`}
            >
              <input
                ref={zipInputRef}
                type="file"
                accept=".zip"
                onChange={handleZipSelect}
                className="hidden"
              />
              <span className="text-3xl mb-2">📁</span>
              {zipFile ? (
                <p className="text-sm font-mono text-foreground">{zipFile.name} ({(zipFile.size / 1024 / 1024).toFixed(2)} MB)</p>
              ) : (
                <>
                  <p className="text-sm text-muted-foreground">Drag & drop a .zip file here, or click to browse</p>
                  <p className="text-xs text-muted-foreground mt-1">Max 100 MB — Supports Flask, Django, Node/Express, Next.js, Vite, PHP</p>
                </>
              )}
            </div>

            {zipFile && !zipScanId && (
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleZipUploadScan}
                  disabled={zipUploading}
                  className="flex-1 rounded-md bg-red-600 px-4 py-3 text-sm font-bold text-white transition-colors hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {zipUploading ? "UPLOADING…" : "LAUNCH SANDBOX SCAN"}
                </button>
                <button
                  type="button"
                  onClick={handleZipReset}
                  className="rounded-md border border-border bg-background px-4 py-3 text-sm font-semibold text-foreground transition-colors hover:bg-muted"
                >
                  CLEAR
                </button>
              </div>
            )}

            {zipScanId && zipScanStatus && zipScanStatus.status === "running" && (
              <div className="rounded-lg border border-red-700 bg-red-950 p-3 text-sm text-red-400">
                <p>🔴 SANDBOX ACTIVE — Bots scanning: {zipFile?.name}</p>
                <p className="mt-1 text-xs text-red-400/70 font-mono">Phase: {zipScanStatus.phase}</p>
              </div>
            )}

            {zipScanId && zipScanStatus?.status === "queued" && (
              <div className="rounded-lg border border-yellow-700 bg-yellow-950/50 p-3 text-sm text-yellow-400">
                <p>⏳ Scan queued — waiting for sandbox to start…</p>
              </div>
            )}

            {zipScanId && zipScanStatus?.status === "completed" && (
              <div className="rounded-lg border border-green-700 bg-green-950/50 p-3 text-sm text-green-400">
                <p>✅ Sandbox scan completed for: {zipFile?.name}</p>
                <div className="flex gap-2 mt-3">
                  <button
                    type="button"
                    onClick={() => navigate(`/scan/results/${zipScanId}`)}
                    className="rounded-md border border-green-700 bg-green-900 px-3 py-2 text-xs font-semibold text-green-200 transition-colors hover:bg-green-800"
                  >
                    VIEW SCAN RESULTS
                  </button>
                  <button
                    type="button"
                    onClick={handleZipReset}
                    className="rounded-md border border-border bg-background px-3 py-2 text-xs font-semibold text-foreground transition-colors hover:bg-muted"
                  >
                    SCAN ANOTHER FILE
                  </button>
                </div>
              </div>
            )}

            {zipScanId && zipScanStatus?.status === "failed" && (
              <div className="rounded-lg border border-yellow-700 bg-yellow-950/50 p-3 text-sm text-yellow-400">
                <p>⚠️ Sandbox scan failed: {zipScanStatus.error || "Unknown error"}</p>
                <button
                  type="button"
                  onClick={handleZipReset}
                  className="mt-3 rounded-md border border-border bg-background px-3 py-2 text-xs font-semibold text-foreground transition-colors hover:bg-muted"
                >
                  TRY AGAIN
                </button>
              </div>
            )}

            <p className="text-xs text-muted-foreground">
              Your code runs in an isolated sandbox. Attack and defense bots simulate real-world threats safely.
            </p>
          </CardContent>
        </Card>

        {simulationActive ? (
          <div className="rounded-lg border border-red-700 bg-red-950 p-3 text-sm text-red-400">
            <p>🔴 LIVE — Bots are running on: {targetUrl}</p>
            {scanStatus && scanStatus.status === "running" && (
              <p className="mt-1 text-xs text-red-400/70 font-mono">Scan phase: {scanStatus.phase}</p>
            )}
            <button
              type="button"
              onClick={handleStopSimulation}
              className="mt-3 rounded-md border border-red-700 bg-red-900 px-3 py-2 text-xs font-semibold text-red-200 transition-colors hover:bg-red-800"
            >
              STOP SIMULATION
            </button>
          </div>
        ) : null}

        {scanStatus?.status === "completed" && simulationId && (
          <div className="rounded-lg border border-green-700 bg-green-950/50 p-3 text-sm text-green-400">
            <p>✅ Vulnerability scan completed for: {scanStatus.target}</p>
            <button
              type="button"
              onClick={() => navigate(`/scan/results/${simulationId}`)}
              className="mt-3 rounded-md border border-green-700 bg-green-900 px-3 py-2 text-xs font-semibold text-green-200 transition-colors hover:bg-green-800"
            >
              VIEW SCAN RESULTS
            </button>
          </div>
        )}

        {scanStatus?.status === "failed" && (
          <div className="rounded-lg border border-yellow-700 bg-yellow-950/50 p-3 text-sm text-yellow-400">
            <p>⚠️ Scan encountered an error: {scanStatus.error || "Unknown error"}</p>
          </div>
        )}

        <section className="rounded-xl border border-border bg-card/40 p-4 md:p-6">
          <div className="mb-4">
            <h2 className="font-display text-xl md:text-2xl text-foreground">Bot Selection</h2>
            <p className="text-sm text-muted-foreground">Pick one active bot for this dashboard session.</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {BOTS.map((bot) => {
              const isSelected = selectedBotId === bot.id;
              const isOnline = bot.status === "online";

              return (
                <Card
                  key={bot.id}
                  className={`cursor-pointer transition-colors ${
                    isSelected ? "border-primary" : "border-border"
                  }`}
                  onClick={() => handleBotSelect(bot.id, `${bot.emoji} ${bot.codename}`)}
                >
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <CardTitle className="text-lg font-display font-bold">{bot.emoji} {bot.name}</CardTitle>
                        <p className="text-sm text-muted-foreground">( {bot.codename} )</p>
                      </div>
                      <span
                        className={`h-2.5 w-2.5 rounded-full ${
                          simulationActive && isSelected ? "bg-green-500 animate-pulse" : isOnline ? "bg-green-500" : "bg-gray-500"
                        }`}
                        aria-label={bot.status}
                      />
                    </div>
                    <CardDescription>{bot.description}</CardDescription>
                  </CardHeader>
                  <CardContent className="pt-0">
                    <p className="text-xs uppercase tracking-wide text-muted-foreground">
                      Status: <span className="text-foreground">{bot.status}</span>
                    </p>
                    {simulationActive ? (
                      <p className="mt-2 text-xs text-muted-foreground">{getSimulationRoleMessage(bot.id)}</p>
                    ) : null}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </section>

        <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 min-h-[70vh]">
          <div className="xl:col-span-4">
            <NetworkGraph state={state} />
          </div>

          <div className="xl:col-span-5 h-[420px] xl:h-auto">
            <BattleFeed events={state?.events || []} />
          </div>

          <div className="xl:col-span-3 h-[420px] xl:h-auto">
            <ThreatIntel />
          </div>

          <div className="xl:col-span-12">
            <MalwareAnalyzer />
          </div>
        </div>
      </motion.div>
    </div>
  );
}
