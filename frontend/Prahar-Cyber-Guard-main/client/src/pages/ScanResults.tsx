import { useEffect, useState } from "react";
import { useParams } from "wouter";
import { motion } from "framer-motion";
import { Navigation } from "@/components/Navigation";
import { Shield, AlertTriangle, CheckCircle, Loader2, FileText, Bug, Globe, Wifi } from "lucide-react";
import { getScanStatus, getScanResult, type ScanStatusResponse, type ScanResultResponse } from "@/services/scanService";

export default function ScanResultsPage() {
  const params = useParams<{ scanId: string }>();
  const scanId = params.scanId || "";
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [result, setResult] = useState<ScanResultResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;

    let mounted = true;
    let pollTimer: ReturnType<typeof setInterval>;

    const poll = async () => {
      try {
        const s = await getScanStatus(scanId);
        if (!mounted) return;
        setStatus(s);

        if (s.status === "completed" || s.status === "failed") {
          clearInterval(pollTimer);
          const r = await getScanResult(scanId);
          if (mounted) setResult(r);
        }
      } catch (err) {
        if (mounted) setError(err instanceof Error ? err.message : "Failed to fetch scan status");
        clearInterval(pollTimer);
      }
    };

    poll();
    pollTimer = setInterval(poll, 3000);

    return () => {
      mounted = false;
      clearInterval(pollTimer);
    };
  }, [scanId]);

  const report = result?.report;
  const summary = report?.scan_summary || {};
  const totalVulns =
    (summary.total_vulnerabilities || 0) +
    (summary.total_xss_vulnerabilities || 0) +
    (summary.total_cors_misconfigurations || 0) +
    (summary.total_ddos_vulnerabilities || 0);

  const riskLevel = report?.risk_assessment?.overall_risk || "Unknown";

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navigation currentPage="Scan Results" variant="bar" enableHomeHotkey />

      <main className="pt-24 px-4 md:px-6 pb-20 max-w-6xl mx-auto">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          <h1 className="font-display text-3xl md:text-4xl font-bold mb-2">Scan Results</h1>
          <p className="text-sm text-muted-foreground font-mono mb-8">Scan ID: {scanId}</p>
        </motion.div>

        {error && (
          <div className="rounded-lg border border-red-700 bg-red-950/50 p-4 mb-6 text-sm text-red-400">
            <AlertTriangle className="inline w-4 h-4 mr-2" />
            {error}
          </div>
        )}

        {/* Loading / In-progress state */}
        {status && status.status !== "completed" && status.status !== "failed" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="rounded-xl border border-primary/30 bg-card/60 p-8 text-center"
          >
            <Loader2 className="w-10 h-10 animate-spin text-primary mx-auto mb-4" />
            <h2 className="font-display text-xl mb-2">Scan In Progress</h2>
            <p className="text-muted-foreground font-mono text-sm">{status.phase}</p>
            <p className="text-muted-foreground text-xs mt-2">Target: {status.target}</p>
          </motion.div>
        )}

        {/* Failed state */}
        {status?.status === "failed" && (
          <div className="rounded-xl border border-red-700/50 bg-red-950/30 p-8">
            <AlertTriangle className="w-10 h-10 text-red-500 mx-auto mb-4" />
            <h2 className="font-display text-xl text-center mb-2 text-red-400">Scan Failed</h2>
            <p className="text-center text-red-400/80 text-sm">{status.error || result?.error || "Unknown error"}</p>
          </div>
        )}

        {/* Completed state */}
        {status?.status === "completed" && report && (
          <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <SummaryCard
                icon={<Bug className="w-5 h-5" />}
                label="Total Vulnerabilities"
                value={String(totalVulns)}
                color="var(--theme-danger)"
              />
              <SummaryCard
                icon={<Shield className="w-5 h-5" />}
                label="Risk Level"
                value={riskLevel}
                color="var(--theme-accent)"
              />
              <SummaryCard
                icon={<Globe className="w-5 h-5" />}
                label="Endpoints Scanned"
                value={String(summary.endpoints_scanned || report.crawled_endpoints?.length || 0)}
                color="var(--theme-primary)"
              />
              <SummaryCard
                icon={<Wifi className="w-5 h-5" />}
                label="Scan Type"
                value={status.type === "zip" ? "ZIP Upload" : "Live URL"}
                color="var(--theme-primary)"
              />
            </div>

            {/* SQL Injection Findings */}
            {report.live_scan?.vulnerabilities_found?.length > 0 && (
              <FindingsSection
                title="SQL Injection Findings"
                findings={report.live_scan.vulnerabilities_found}
                getKey={(f: any) => `${f.url}-${f.parameter}`}
                renderItem={(f: any) => (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs" style={{ color: "var(--theme-primary)" }}>{f.url}</span>
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded border" style={{ borderColor: "var(--theme-danger)", color: "var(--theme-danger)" }}>
                        {f.severity || "HIGH"}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      Parameter: {f.parameter} | Payload: {f.payload || "N/A"}
                    </p>
                  </>
                )}
              />
            )}

            {/* XSS Findings */}
            {report.xss_scan?.findings?.length > 0 && (
              <FindingsSection
                title="XSS Findings"
                findings={report.xss_scan.findings}
                getKey={(f: any) => `${f.url}-${f.type}`}
                renderItem={(f: any) => (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs" style={{ color: "var(--theme-primary)" }}>{f.url}</span>
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded border" style={{ borderColor: "var(--theme-accent)", color: "var(--theme-accent)" }}>
                        {f.type || "XSS"}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{f.description || f.payload || "No details"}</p>
                  </>
                )}
              />
            )}

            {/* CORS Findings */}
            {report.cors_scan?.findings?.length > 0 && (
              <FindingsSection
                title="CORS Misconfigurations"
                findings={report.cors_scan.findings}
                getKey={(f: any) => `${f.url}-${f.issue}`}
                renderItem={(f: any) => (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs" style={{ color: "var(--theme-primary)" }}>{f.url}</span>
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded border" style={{ borderColor: "var(--theme-accent)", color: "var(--theme-accent)" }}>
                        CORS
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{f.issue || f.description || "Misconfiguration detected"}</p>
                  </>
                )}
              />
            )}

            {/* DDoS Findings */}
            {report.ddos_scan?.findings?.length > 0 && (
              <FindingsSection
                title="DDoS Vulnerabilities"
                findings={report.ddos_scan.findings}
                getKey={(f: any) => `${f.url}-${f.type}`}
                renderItem={(f: any) => (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs" style={{ color: "var(--theme-primary)" }}>{f.url}</span>
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded border" style={{ borderColor: "var(--theme-danger)", color: "var(--theme-danger)" }}>
                        DDoS
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{f.description || "Vulnerability detected"}</p>
                  </>
                )}
              />
            )}

            {/* Static Analysis */}
            {report.static_analysis?.findings?.length > 0 && (
              <FindingsSection
                title="Static Code Analysis"
                findings={report.static_analysis.findings}
                getKey={(f: any) => `${f.file}-${f.line}`}
                renderItem={(f: any) => (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs" style={{ color: "var(--theme-primary)" }}>{f.file}:{f.line}</span>
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded border" style={{ borderColor: "var(--theme-accent)", color: "var(--theme-accent)" }}>
                        {f.severity || "INFO"}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{f.description || f.issue || "Code issue"}</p>
                  </>
                )}
              />
            )}

            {/* Defense Simulation */}
            {report.defense_simulation?.summary && (
              <div className="rounded-xl border border-primary/20 bg-card/60 p-5">
                <h3 className="font-display text-lg mb-3 flex items-center gap-2">
                  <Shield className="w-5 h-5 text-primary" /> Defense Simulation
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-sm">
                  <div>
                    <div className="text-xs text-muted-foreground">Attacks Analyzed</div>
                    <div className="text-lg font-bold">{report.defense_simulation.summary.total_attacks_analyzed || 0}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Blocked</div>
                    <div className="text-lg font-bold" style={{ color: "var(--theme-primary)" }}>{report.defense_simulation.summary.attacks_blocked || 0}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Defense Rate</div>
                    <div className="text-lg font-bold" style={{ color: "var(--theme-accent)" }}>{report.defense_simulation.summary.defense_rate || 0}%</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Status</div>
                    <div className="text-lg font-bold">
                      <CheckCircle className="inline w-4 h-4 mr-1 text-green-500" />
                      Complete
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Event Timeline */}
            {report.events?.length > 0 && (
              <div className="rounded-xl border border-primary/20 bg-card/60 p-5">
                <h3 className="font-display text-lg mb-3 flex items-center gap-2">
                  <FileText className="w-5 h-5 text-primary" /> Scan Event Log
                </h3>
                <div className="max-h-64 overflow-y-auto space-y-1 font-mono text-xs">
                  {report.events.map((evt: any, idx: number) => (
                    <div key={idx} className="flex items-start gap-2 py-1 border-b border-border/30">
                      <span className="text-muted-foreground shrink-0">{evt.timestamp || ""}</span>
                      <span style={{ color: evt.success === false ? "var(--theme-danger)" : "var(--theme-primary)" }}>
                        [{evt.type}]
                      </span>
                      <span className="text-foreground/80">{evt.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

/* ── Helper Components ─────────────────────────────────── */

function SummaryCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string; color: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-primary/20 bg-card/60 p-4"
    >
      <div className="flex items-center gap-2 mb-2" style={{ color }}>
        {icon}
        <span className="text-xs text-muted-foreground">{label}</span>
      </div>
      <div className="font-display text-2xl font-bold" style={{ color }}>{value}</div>
    </motion.div>
  );
}

function FindingsSection({
  title,
  findings,
  getKey,
  renderItem,
}: {
  title: string;
  findings: any[];
  getKey: (f: any) => string;
  renderItem: (f: any) => React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-primary/20 bg-card/60 p-5">
      <h3 className="font-display text-lg mb-3 flex items-center gap-2">
        <AlertTriangle className="w-5 h-5" style={{ color: "var(--theme-danger)" }} />
        {title}
        <span className="ml-auto text-xs font-mono text-muted-foreground">{findings.length} found</span>
      </h3>
      <div className="max-h-64 overflow-y-auto space-y-2">
        {findings.map((f, idx) => (
          <div
            key={getKey(f) + idx}
            className="rounded-md border p-3"
            style={{ borderColor: "var(--theme-border)", background: "color-mix(in srgb, var(--theme-background) 65%, black)" }}
          >
            {renderItem(f)}
          </div>
        ))}
      </div>
    </div>
  );
}
