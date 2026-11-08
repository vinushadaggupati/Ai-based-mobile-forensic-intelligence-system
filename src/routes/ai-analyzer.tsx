import { createFileRoute, Link } from "@tanstack/react-router";
import { AppLayout } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { PriorityBadge, FindingTypeBadge } from "@/components/PriorityBadge";
import { useState, useEffect, useRef } from "react";
import {
  performForensicAIAnalysis,
  parseEvidenceFile,
  generateForensicReportPDF,
  type AIAnalysisResult,
  type ParsedEvidence,
} from "@/lib/ai-analyzer";
import {
  SMS as DEFAULT_SMS,
  CALLS as DEFAULT_CALLS,
  BROWSER as DEFAULT_BROWSER,
  APPS as DEFAULT_APPS,
  GPS as DEFAULT_GPS,
  CASE as DEFAULT_CASE,
  CONTACTS as DEFAULT_CONTACTS,
  MEDIA as DEFAULT_MEDIA,
  sha256,
} from "@/lib/forensic-data";
import {
  Sparkles,
  Play,
  Cpu,
  Lock,
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Upload,
  FileText,
  Download,
  AlertCircle,
  MessageSquare,
  Phone,
  MapPin,
  Share2,
  Network,
  RefreshCw,
  FileCode,
  ShieldCheck,
  Check,
  ArrowRight,
} from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/ai-analyzer")({
  head: () => ({
    meta: [
      { title: "AI Evidence Analyzer · AI-Based Mobile Forensic Intelligence System" },
      {
        name: "description",
        content:
          "Multi-Modal Forensic AI Analysis Engine. Ingests Android evidence files, correlates SMS, calls, GPS, social media, and automatically generates downloadable PDF forensic reports.",
      },
    ],
  }),
  component: () => (
    <AppLayout>
      <AIAnalyzer />
    </AppLayout>
  ),
});

function AIAnalyzer() {
  const [running, setRunning] = useState(false);
  const [progressStatus, setProgressStatus] = useState("AI Engine Initialized");
  const [progressVal, setProgressVal] = useState(100);
  const [result, setResult] = useState<AIAnalysisResult | null>(null);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [uploadedFileSize, setUploadedFileSize] = useState<number | null>(null);
  const [uploadedFileHash, setUploadedFileHash] = useState<string | null>(null);
  const [parsedEvidence, setParsedEvidence] = useState<ParsedEvidence | null>(null);
  const [activeTab, setActiveTab] = useState<"all" | "sms" | "calls" | "gps" | "social" | "correlations">("all");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Initialize and auto-run on active case evidence on mount
  useEffect(() => {
    runDefaultAnalysis();
  }, []);

  const runDefaultAnalysis = () => {
    setRunning(true);
    setProgressVal(30);
    setProgressStatus("Correlating active case evidence (SMS, calls, GPS, social media, apps)...");

    setTimeout(() => {
      const defaultEvidence: ParsedEvidence = {
        sms: DEFAULT_SMS,
        calls: DEFAULT_CALLS,
        gps: DEFAULT_GPS,
        socialMedia: [
          {
            id: "SOC-WA-01",
            platform: "WhatsApp",
            sender: "Kai M.",
            message: "Switch to Signal or Wickr right now. Delete WhatsApp database from /sdcard.",
            timestamp: "2026-10-31 01:22:00 UTC",
            isDeleted: true,
            isEncrypted: true,
          },
          {
            id: "SOC-TG-02",
            platform: "Telegram",
            sender: "+7-495-555-0143",
            message: "Channel 4 mixer ready. BTC transaction hash will self-destruct.",
            timestamp: "2026-10-31 02:15:00 UTC",
            isEncrypted: true,
            channelOrGroup: "ShadowSync",
          },
        ],
        browser: DEFAULT_BROWSER,
        apps: DEFAULT_APPS,
        contacts: DEFAULT_CONTACTS,
        media: DEFAULT_MEDIA,
      };

      const analysis = performForensicAIAnalysis(defaultEvidence, {
        caseNumber: DEFAULT_CASE.caseNumber,
        filename: "Preserved Android Forensic Storage (Active Case)",
      });

      setParsedEvidence(defaultEvidence);
      setResult(analysis);
      setProgressVal(100);
      setProgressStatus("AI multi-modal correlation complete.");
      setRunning(false);
    }, 400);
  };

  // Handle direct file upload and automatic instant analysis
  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setRunning(true);
    setProgressVal(15);
    setProgressStatus(`Ingesting forensic evidence file: ${file.name}...`);
    toast.loading(`Ingesting ${file.name} and calculating SHA-256...`, { id: "upload-ai" });

    try {
      const text = await file.text();
      setProgressVal(40);
      setProgressStatus("Computing cryptographic SHA-256 hash...");

      // Compute SHA-256 hash
      const hash = await sha256(text);
      setUploadedFileName(file.name);
      setUploadedFileSize(file.size);
      setUploadedFileHash(hash);

      setProgressVal(65);
      setProgressStatus("Parsing available SMS, calls, GPS, and social media artifacts...");

      // Parse file
      const parsed = parseEvidenceFile(text, file.name);
      setParsedEvidence(parsed);

      setProgressVal(85);
      setProgressStatus("Executing ForensicAI Neural Engine correlation across all recovered records...");

      setTimeout(() => {
        const analysis = performForensicAIAnalysis(parsed, {
          filename: file.name,
          fileSize: file.size,
          fileHash: hash,
          caseNumber: DEFAULT_CASE.caseNumber,
        });

        setResult(analysis);
        setProgressVal(100);
        setProgressStatus("AI analysis completed successfully.");
        setRunning(false);

        toast.success(
          `Analyzed ${analysis.evidenceCounts.total} recovered records from ${file.name}!`,
          { id: "upload-ai" }
        );
      }, 350);
    } catch (err: any) {
      toast.error(`Failed to analyze evidence file: ${err?.message || "Invalid format"}`, { id: "upload-ai" });
      setRunning(false);
    }
  };

  // Download PDF report
  const handleDownloadPDF = async () => {
    if (!result) {
      toast.error("No analysis results available to compile.");
      return;
    }
    toast.loading("Generating 15-Section Court-Admissible PDF Report...", { id: "gen-pdf" });
    try {
      await generateForensicReportPDF(result, {
        caseNumber: DEFAULT_CASE.caseNumber,
        investigator: DEFAULT_CASE.investigator,
        agency: DEFAULT_CASE.agency,
      });
      toast.success("Forensic PDF Report downloaded successfully!", { id: "gen-pdf" });
    } catch (err: any) {
      toast.error(`PDF generation failed: ${err?.message || "Unknown error"}`, { id: "gen-pdf" });
    }
  };

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Top Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-semibold flex items-center gap-2">
              <Sparkles className="size-6 text-primary" /> AI-Based Evidence Analyzer
            </h1>
            <Badge variant="outline" className="text-primary border-primary/30 font-mono text-xs">
              Module 5 · ForensicAI Neural Engine v2.4
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground mt-1 max-w-3xl">
            Automatically analyzes uploaded Android evidence files. Detects suspicious SMS messages,
            unusual calling patterns, suspicious GPS telemetry, and social media artifacts (WhatsApp, Telegram, Signal)
            with cross-artifact AI correlation.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          <input
            type="file"
            ref={fileInputRef}
            className="hidden"
            accept=".json,.csv,.txt,.log,.sqlite,.db,.xml"
            onChange={handleFileUpload}
          />
          <Button
            variant="outline"
            onClick={() => fileInputRef.current?.click()}
            disabled={running}
            className="gap-2 border-primary/40 hover:bg-primary/10"
          >
            <Upload className="size-4 text-primary" />
            Upload Evidence File
          </Button>

          <Button
            onClick={handleDownloadPDF}
            disabled={running || !result}
            className="gap-2 bg-primary hover:bg-primary/90 text-primary-foreground font-semibold"
          >
            <Download className="size-4" />
            Download PDF Report
          </Button>
        </div>
      </div>

      {/* MANDATORY FORENSIC AI ADMISSIBILITY DISCLAIMER (NIST SP 800-101) */}
      <Card className="p-4 bg-amber-500/10 border-amber-500/30">
        <div className="flex items-start gap-3">
          <AlertCircle className="size-5 text-amber-400 mt-0.5 shrink-0" />
          <div className="text-xs leading-relaxed space-y-1">
            <div className="font-semibold text-amber-400 text-sm flex items-center gap-2">
              <span>Forensic AI Admissibility Disclaimer (NIST SP 800-101 & ISO/IEC 27037)</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono">
                Examiner Verification Required
              </span>
            </div>
            <p className="text-foreground/90">
              Findings generated by this AI module are categorized strictly into <strong>Confirmed Evidence</strong>,{" "}
              <strong>AI Observation</strong>, and <strong>Possible Lead</strong>. AI predictions and pattern correlations
              serve as <strong>investigative aids only</strong> and must <strong>never</strong> be presented as confirmed courtroom
              facts without independent verification by a certified digital forensics examiner.
            </p>
          </div>
        </div>
      </Card>

      {/* Upload Dropzone & Active Evidence Status Bar */}
      <Card className="p-4 bg-card/70 border-border">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="size-10 rounded-md bg-primary/10 border border-primary/20 grid place-items-center">
              <Cpu className="size-5 text-primary" />
            </div>
            <div>
              <div className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                <span>Active AI Inference Engine</span>
                <span className="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-emerald-400 font-mono text-[11px]">Ready & Connected</span>
              </div>
              <div className="font-mono text-sm font-semibold flex items-center gap-2 mt-0.5">
                <span>{result?.modelUsed || "ForensicAI-Android v2.4 (Multi-Modal Neural Engine)"}</span>
                <span className="text-[10px] font-sans px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/30">
                  Air-Gapped Forensic NLP
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono text-muted-foreground">
            {uploadedFileName ? (
              <div className="flex items-center gap-2 bg-background/60 px-3 py-1.5 rounded border border-border">
                <FileCode className="size-4 text-primary" />
                <span>
                  Uploaded: <strong>{uploadedFileName}</strong> ({Math.round((uploadedFileSize || 0) / 1024)} KB)
                </span>
                <span className="text-[10px] text-muted-foreground">
                  SHA-256: {uploadedFileHash?.substring(0, 10)}...
                </span>
              </div>
            ) : (
              <span className="flex items-center gap-1.5 text-muted-foreground">
                <ShieldCheck className="size-4 text-emerald-400" />
                Analyzing Active Case Scope · No External Cloud Exfiltration
              </span>
            )}
          </div>
        </div>

        {/* Live Progress Bar */}
        {running && (
          <div className="mt-4 pt-3 border-t border-border space-y-2">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-primary animate-pulse">{progressStatus}</span>
              <span className="text-muted-foreground">{progressVal}%</span>
            </div>
            <Progress value={progressVal} className="h-2" />
          </div>
        )}
      </Card>

      {/* Main Results View */}
      {result && (
        <div className="space-y-6">
          {/* Executive Metrics Overview */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card className="p-4 bg-card/70 border-border">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Threat / Risk Level</div>
              <div className="mt-1 text-xl font-mono font-bold text-red-400 flex items-center gap-1.5">
                <ShieldAlert className="size-5" /> {result.riskLevel.toUpperCase()}
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                Evidence destruction & flight indicators
              </div>
            </Card>

            <Card className="p-4 bg-card/70 border-border">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Confirmed Evidence Hits</div>
              <div className="mt-1 text-xl font-mono font-bold text-emerald-400">
                {result.stats.confirmed}
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                Direct bitstream verification
              </div>
            </Card>

            <Card className="p-4 bg-card/70 border-border">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">AI Observations & Leads</div>
              <div className="mt-1 text-xl font-mono font-bold text-sky-400">
                {result.stats.observations + result.stats.leads}
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                {result.stats.observations} Observations · {result.stats.leads} Investigative Leads
              </div>
            </Card>

            <Card className="p-4 bg-card/70 border-border">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Total Records Analyzed</div>
              <div className="mt-1 text-xl font-mono font-bold text-primary">
                {result.evidenceCounts.total}
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                {result.evidenceCounts.sms} SMS · {result.evidenceCounts.calls} Calls · {result.evidenceCounts.gps} GPS · {result.evidenceCounts.socialMedia} Social
              </div>
            </Card>
          </div>

          {/* AI Narrative Investigative Summary */}
          <Card className="p-5 bg-card/70 border-border">
            <div className="flex items-center justify-between pb-3 border-b border-border flex-wrap gap-2">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                <Sparkles className="size-4 text-primary" /> AI Investigative Summary & Explanation
              </h2>
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="font-mono text-[10px] text-primary">
                  {result.source}
                </Badge>
                <Button size="sm" onClick={handleDownloadPDF} className="gap-1.5 h-8 text-xs">
                  <Download className="size-3.5" /> Download PDF Report
                </Button>
              </div>
            </div>
            <div className="p-4 rounded bg-background/50 border border-border text-xs leading-relaxed font-mono whitespace-pre-line mt-3 text-foreground/90">
              {result.summary}
            </div>
          </Card>

          {/* Specific Evidence Discovery Breakdown (SMS, Calls, GPS, Social Media) */}
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Suspicious SMS */}
            <Card className="p-4 bg-card/70 border-border space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <MessageSquare className="size-4 text-red-400" /> Suspicious SMS
                </span>
                <Badge variant="outline" className="text-xs font-mono text-red-400 border-red-500/30">
                  {result.suspiciousSms.length} Flagged
                </Badge>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {result.suspiciousSms.length > 0 ? (
                  result.suspiciousSms.map((s) => (
                    <div key={s.id} className="p-2.5 rounded bg-background/40 border border-border text-xs space-y-1">
                      <div className="flex justify-between font-mono text-[10px] text-muted-foreground">
                        <span>{s.contact}</span>
                        <span>{s.timestamp.split(" ")[1] || s.timestamp.split("T")[1]?.substring(0, 5)}</span>
                      </div>
                      <p className="font-mono text-red-300 font-medium">"{s.body}"</p>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-muted-foreground font-mono">No keyword anomalies detected.</p>
                )}
              </div>
            </Card>

            {/* Unusual Calls */}
            <Card className="p-4 bg-card/70 border-border space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Phone className="size-4 text-amber-400" /> Unusual Calls
                </span>
                <Badge variant="outline" className="text-xs font-mono text-amber-400 border-amber-500/30">
                  {result.unusualCalls.length} Pattern Hits
                </Badge>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {result.unusualCalls.length > 0 ? (
                  result.unusualCalls.map((c) => (
                    <div key={c.id} className="p-2.5 rounded bg-background/40 border border-border text-xs space-y-1">
                      <div className="flex justify-between font-mono text-[10px] text-muted-foreground">
                        <span>{c.number}</span>
                        <span>{c.durationSec}s · {c.type}</span>
                      </div>
                      <p className="font-mono text-amber-300 text-[11px]">
                        Off-hours voice session: {c.timestamp}
                      </p>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-muted-foreground font-mono">No calling anomalies detected.</p>
                )}
              </div>
            </Card>

            {/* Suspicious GPS */}
            <Card className="p-4 bg-card/70 border-border space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <MapPin className="size-4 text-purple-400" /> Suspicious GPS
                </span>
                <Badge variant="outline" className="text-xs font-mono text-purple-400 border-purple-500/30">
                  {result.suspiciousGps.length} Points
                </Badge>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {result.suspiciousGps.length > 0 ? (
                  result.suspiciousGps.map((g) => (
                    <div key={g.id} className="p-2.5 rounded bg-background/40 border border-border text-xs space-y-1">
                      <div className="font-mono text-[11px] font-semibold text-purple-300">
                        {g.place}
                      </div>
                      <div className="font-mono text-[10px] text-muted-foreground">
                        {g.lat.toFixed(4)}, {g.lng.toFixed(4)} at {g.timestamp}
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-muted-foreground font-mono">Standard travel patterns observed.</p>
                )}
              </div>
            </Card>

            {/* Social Media Artifacts */}
            <Card className="p-4 bg-card/70 border-border space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Share2 className="size-4 text-cyan-400" /> Social Media Artifacts
                </span>
                <Badge variant="outline" className="text-xs font-mono text-cyan-400 border-cyan-500/30">
                  {result.socialMediaArtifacts.length} Messages
                </Badge>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {result.socialMediaArtifacts.length > 0 ? (
                  result.socialMediaArtifacts.map((sm) => (
                    <div key={sm.id} className="p-2.5 rounded bg-background/40 border border-border text-xs space-y-1">
                      <div className="flex justify-between font-mono text-[10px] text-cyan-300">
                        <span>[{sm.platform}] {sm.sender}</span>
                        {sm.isDeleted && <span className="text-red-400 font-bold">DELETED</span>}
                      </div>
                      <p className="font-mono text-[11px] text-foreground/90 truncate">"{sm.message}"</p>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-muted-foreground font-mono">No social chat dumps detected.</p>
                )}
              </div>
            </Card>
          </div>

          {/* Cross-Artifact Correlation Matrix */}
          <Card className="p-5 bg-card/70 border-border">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
              <Network className="size-4 text-primary" /> Multi-Modal Cross-Artifact Correlation Matrix
            </h2>
            <div className="grid md:grid-cols-3 gap-3">
              {result.correlations.map((c) => (
                <div key={c.id} className="p-4 rounded-md border border-border bg-background/40 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                      {c.riskWeight} Correlation
                    </span>
                    <span className="text-[10px] font-mono text-muted-foreground">{c.timestampCluster}</span>
                  </div>
                  <div className="text-xs font-semibold text-foreground">{c.title}</div>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">{c.description}</p>
                  <div className="text-[10px] font-mono text-primary flex gap-1 flex-wrap pt-1">
                    <span className="text-muted-foreground">Linked:</span>
                    {c.artifactsInvolved.map((a) => (
                      <span key={a} className="px-1 py-0.2 rounded bg-card border border-border">
                        {a}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* Categorized Findings List */}
          <Card className="p-5 bg-card/70 border-border">
            <div className="flex items-center justify-between pb-3 border-b border-border flex-wrap gap-2">
              <div>
                <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                  AI-Identified Forensic Findings & Explanations ({result.findings.length})
                </h2>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Rigidly classified into Confirmed Evidence, AI Observations, or Possible Leads
                </p>
              </div>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={handleDownloadPDF} className="gap-1.5">
                  <Download className="size-3.5" /> Download Full PDF Report
                </Button>
                <Button asChild size="sm" variant="secondary">
                  <Link to="/report">
                    <FileText className="size-3.5 mr-1" /> View in Report Hub →
                  </Link>
                </Button>
              </div>
            </div>

            <div className="space-y-3 mt-4">
              {result.findings.map((f) => (
                <div
                  key={f.id}
                  className="p-4 rounded-md border border-border bg-background/40 space-y-2 hover:border-primary/40 transition"
                >
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap">
                      <PriorityBadge priority={f.priority} />
                      <FindingTypeBadge type={f.findingType} />
                      <span className="text-[11px] font-mono uppercase text-muted-foreground">
                        [{f.category}]
                      </span>
                    </div>
                    <span className="text-xs font-mono text-muted-foreground">
                      {f.evidenceIds.length} Linked Artifact Record(s)
                    </span>
                  </div>

                  <div className="text-sm font-semibold text-foreground">{f.title}</div>
                  <p className="text-xs text-muted-foreground leading-relaxed">{f.rationale}</p>

                  {f.snippet && (
                    <div className="p-2 rounded bg-background/60 border border-border text-[11px] font-mono text-foreground/80">
                      <span className="text-primary font-semibold">Evidence Excerpt: </span>
                      {f.snippet}
                    </div>
                  )}

                  <div className="flex items-center gap-2 pt-1 text-[11px] font-mono text-primary flex-wrap">
                    <span className="text-muted-foreground">Correlated Artifact IDs:</span>
                    {f.evidenceIds.map((id) => (
                      <span key={id} className="px-1.5 py-0.5 rounded bg-card border border-border">
                        {id}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* Actionable Recommendations */}
          <Card className="p-5 bg-card/70 border-border">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
              <ShieldCheck className="size-4 text-emerald-400" /> Actionable Legal & Forensic Recommendations
            </h2>
            <div className="space-y-2">
              {result.recommendations.map((rec, idx) => (
                <div key={idx} className="flex items-start gap-2.5 text-xs text-foreground/90 font-mono">
                  <span className="size-4 rounded-full bg-emerald-500/20 text-emerald-400 grid place-items-center shrink-0 text-[10px] mt-0.5">
                    {idx + 1}
                  </span>
                  <span>{rec}</span>
                </div>
              ))}
            </div>

            <div className="mt-5 pt-4 border-t border-border flex justify-between items-center flex-wrap gap-3">
              <span className="text-xs text-muted-foreground">
                All evidence verified with binary SHA-256 integrity verification.
              </span>
              <Button onClick={handleDownloadPDF} className="gap-2">
                <Download className="size-4" /> Download Court-Admissible PDF Report
              </Button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
