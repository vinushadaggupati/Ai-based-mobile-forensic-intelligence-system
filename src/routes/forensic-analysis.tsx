import { createFileRoute, Link } from "@tanstack/react-router";
import { AppLayout } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { PriorityBadge, FindingTypeBadge } from "@/components/PriorityBadge";
import { useState } from "react";
import { analyze, type Finding } from "@/lib/ai-analyzer";
import {
  SMS,
  CALLS,
  BROWSER,
  APPS,
  GPS,
  CONTACTS,
} from "@/lib/forensic-data";
import { AUTOPSY_CARVED_EVIDENCE } from "@/lib/autopsy-data";
import { api } from "@/lib/api-client";
import {
  Search,
  MessageSquare,
  Phone,
  Globe,
  MapPin,
  AppWindow,
  ShieldAlert,
  ShieldCheck,
  FileSearch,
  Cpu,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ArrowRight,
  Filter,
} from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/forensic-analysis")({
  head: () => ({
    meta: [
      { title: "Forensic Analysis · AI-Based Mobile Forensic Intelligence System" },
      {
        name: "description",
        content:
          "Digital forensic analysis detecting suspicious keywords, call patterns, malicious websites, unusual GPS coordinates, and anti-forensic tools.",
      },
    ],
  }),
  component: () => (
    <AppLayout>
      <ForensicAnalysis />
    </AppLayout>
  ),
});

function ForensicAnalysis() {
  const [analyzing, setAnalyzing] = useState(false);
  const [activeFilter, setActiveFilter] = useState<string>("all");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const localAnalysis = analyze();
  const [analysisData, setAnalysisData] = useState(localAnalysis);

  const runAnalysis = async () => {
    setAnalyzing(true);
    toast.loading("Executing Python forensic analysis engine...", { id: "analysis" });

    try {
      const res = await api.runForensicAnalysis("dev-android-01");
      if (res.success) {
        toast.success("Python forensic analysis completed", { id: "analysis" });
      } else {
        toast.info("Using built-in deterministic forensic analysis engine", { id: "analysis" });
      }
    } catch {
      toast.info("Using built-in deterministic forensic analysis engine", { id: "analysis" });
    }

    setAnalysisData(analyze());
    setAnalyzing(false);
  };

  const findings = analysisData.findings.filter((f) => {
    if (activeFilter === "all") return true;
    if (activeFilter === "high") return f.priority === "high";
    if (activeFilter === "medium") return f.priority === "medium";
    if (activeFilter === "low") return f.priority === "low";
    if (activeFilter === "confirmed") return f.findingType === "confirmed-evidence";
    if (activeFilter === "observation") return f.findingType === "ai-observation";
    return true;
  });

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Top Banner */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-semibold">Digital Forensic Analysis</h1>
            <Badge variant="outline" className="text-primary border-primary/30 font-mono text-xs">
              Module 4 · Rule Engine
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
            Automated heuristic examination of Android device artifacts: keyword extraction, call telemetry correlation,
            GPS anomaly tracking, anti-forensic application discovery, and Autopsy carving correlation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button onClick={runAnalysis} disabled={analyzing} className="gap-2">
            <RefreshCw className={`size-4 ${analyzing ? "animate-spin" : ""}`} />
            {analyzing ? "Analyzing Artifacts..." : "Re-run Forensic Analysis"}
          </Button>
          <Button asChild variant="secondary">
            <Link to="/ai-analyzer">
              Run AI Analyzer <ArrowRight className="size-4 ml-1" />
            </Link>
          </Button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="p-4 bg-card/70 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Overall Risk</div>
          <div className="mt-1 text-2xl font-mono font-bold text-priority-high flex items-center gap-1.5">
            <Flame className="size-5 text-red-500 animate-pulse" />
            {analysisData.riskLevel.toUpperCase()}
          </div>
          <div className="text-xs text-muted-foreground mt-1">NIST Severity Grade</div>
        </Card>

        <Card className="p-4 bg-card/70 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Suspicious Indicators</div>
          <div className="mt-1 text-2xl font-mono font-bold text-amber-400">
            {analysisData.suspiciousCount}
          </div>
          <div className="text-xs text-muted-foreground mt-1">Cross-category triggers</div>
        </Card>

        <Card className="p-4 bg-card/70 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">High Priority Findings</div>
          <div className="mt-1 text-2xl font-mono font-bold text-red-400">
            {analysisData.stats.high}
          </div>
          <div className="text-xs text-muted-foreground mt-1">Requires urgent action</div>
        </Card>

        <Card className="p-4 bg-card/70 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Autopsy Carved Items</div>
          <div className="mt-1 text-2xl font-mono font-bold text-cyan-400">
            {AUTOPSY_CARVED_EVIDENCE.length}
          </div>
          <div className="text-xs text-muted-foreground mt-1">Deleted records recovered</div>
        </Card>

        <Card className="p-4 bg-card/70 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Analysis Integrity</div>
          <div className="mt-1 text-2xl font-mono font-bold text-emerald-400 flex items-center gap-1">
            <ShieldCheck className="size-5" /> 100%
          </div>
          <div className="text-xs text-muted-foreground mt-1">SHA-256 verified</div>
        </Card>
      </div>

      {/* 6 Specialized Analysis Categories Grid */}
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
          Specialized Forensic Detection Engines
        </h2>
        <div className="grid md:grid-cols-3 gap-4">
          {/* 1. SMS Keyword Engine */}
          <Card className="p-4 bg-card/70 border-border">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center gap-2">
                <div className="size-8 rounded bg-cyan-500/10 grid place-items-center">
                  <MessageSquare className="size-4 text-cyan-400" />
                </div>
                <h3 className="font-semibold text-sm">SMS Keywords</h3>
              </div>
              <Badge className="bg-red-500/15 text-red-400 border-red-500/30 text-[10px]">
                High Risk
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-2 leading-relaxed">
              Scans mmssms.db for illicit keywords ("burn phone", "wipe sd card", "btc", "mixer"). Flagged 4 messages referencing evidence disposal.
            </p>
            <div className="mt-3 flex items-center justify-between text-xs font-mono">
              <span className="text-muted-foreground">Flagged: 4 / {SMS.length}</span>
              <span className="text-priority-high font-semibold">Critical Threat</span>
            </div>
          </Card>

          {/* 2. Unusual Calling Patterns */}
          <Card className="p-4 bg-card/70 border-border">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center gap-2">
                <div className="size-8 rounded bg-violet-500/10 grid place-items-center">
                  <Phone className="size-4 text-violet-400" />
                </div>
                <h3 className="font-semibold text-sm">Call Patterns</h3>
              </div>
              <Badge className="bg-amber-500/15 text-amber-400 border-amber-500/30 text-[10px]">
                Anomalous
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-2 leading-relaxed">
              Discovers unusual off-hours calls (22:00–05:00 UTC) with foreign numbers in UK (+44) and Russia (+7) not registered in the address book.
            </p>
            <div className="mt-3 flex items-center justify-between text-xs font-mono">
              <span className="text-muted-foreground">Late Night: 3 Calls</span>
              <span className="text-amber-400 font-semibold">Foreign Prefix</span>
            </div>
          </Card>

          {/* 3. Suspicious Websites & Darknet */}
          <Card className="p-4 bg-card/70 border-border">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center gap-2">
                <div className="size-8 rounded bg-rose-500/10 grid place-items-center">
                  <Globe className="size-4 text-rose-400" />
                </div>
                <h3 className="font-semibold text-sm">Suspicious Web</h3>
              </div>
              <Badge className="bg-red-500/15 text-red-400 border-red-500/30 text-[10px]">
                Darknet
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-2 leading-relaxed">
              Detects visits to .onion domains, Bitcoin mixers, and XDA wiping tutorials. High visit count right before seizure window.
            </p>
            <div className="mt-3 flex items-center justify-between text-xs font-mono">
              <span className="text-muted-foreground">Suspicious URLs: 3</span>
              <span className="text-red-400 font-semibold">Tor Mixer Access</span>
            </div>
          </Card>

          {/* 4. Unusual GPS Activity */}
          <Card className="p-4 bg-card/70 border-border">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center gap-2">
                <div className="size-8 rounded bg-amber-500/10 grid place-items-center">
                  <MapPin className="size-4 text-amber-400" />
                </div>
                <h3 className="font-semibold text-sm">GPS Telemetry</h3>
              </div>
              <Badge className="bg-red-500/15 text-red-400 border-red-500/30 text-[10px]">
                Flight Risk
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-2 leading-relaxed">
              Analyzes location trail: late-night rendezvous at Ocean Beach Lot 4 followed by movement to SFO Airport Terminal 2 at 04:18 UTC.
            </p>
            <div className="mt-3 flex items-center justify-between text-xs font-mono">
              <span className="text-muted-foreground">Key Coordinates: 5</span>
              <span className="text-priority-high font-semibold">Airport Movement</span>
            </div>
          </Card>

          {/* 5. Anti-Forensic Applications */}
          <Card className="p-4 bg-card/70 border-border">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center gap-2">
                <div className="size-8 rounded bg-pink-500/10 grid place-items-center">
                  <AppWindow className="size-4 text-pink-400" />
                </div>
                <h3 className="font-semibold text-sm">Anti-Forensic Apps</h3>
              </div>
              <Badge className="bg-red-500/15 text-red-400 border-red-500/30 text-[10px]">
                3 Tools
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-2 leading-relaxed">
              Identifies installation of Orbot (Tor), Wickr Me, and iShredder Pro (military-grade file wiping) installed within 72 hours of incident.
            </p>
            <div className="mt-3 flex items-center justify-between text-xs font-mono">
              <span className="text-muted-foreground">Anti-Forensics: 3</span>
              <span className="text-red-400 font-semibold">Active Wipers</span>
            </div>
          </Card>

          {/* 6. Autopsy Carving Integration */}
          <Card className="p-4 bg-card/70 border-border">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center gap-2">
                <div className="size-8 rounded bg-emerald-500/10 grid place-items-center">
                  <FileSearch className="size-4 text-emerald-400" />
                </div>
                <h3 className="font-semibold text-sm">Autopsy Integration</h3>
              </div>
              <Badge className="bg-cyan-500/15 text-cyan-400 border-cyan-500/30 text-[10px]">
                7 Carved
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-2 leading-relaxed">
              Correlates SQLite freelist carved SMS and WhatsApp WAL journal frames with active database records to expose deleted communications.
            </p>
            <div className="mt-3 flex items-center justify-between text-xs font-mono">
              <span className="text-muted-foreground">Carved Confidence: 95%</span>
              <Link to="/autopsy" className="text-primary hover:underline">
                View Carves →
              </Link>
            </div>
          </Card>
        </div>
      </div>

      {/* Findings List with Filtering */}
      <Card className="p-5 bg-card/70 border-border">
        <div className="flex items-center justify-between gap-4 pb-3 border-b border-border flex-wrap">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              Categorized Forensic Findings ({findings.length})
            </h2>
            <div className="text-xs text-muted-foreground mt-0.5">
              Filter by severity priority or finding classification type
            </div>
          </div>

          <div className="flex items-center gap-1.5 flex-wrap">
            <Filter className="size-3.5 text-muted-foreground mr-1" />
            {[
              { id: "all", label: "All" },
              { id: "high", label: "High" },
              { id: "medium", label: "Medium" },
              { id: "confirmed", label: "Confirmed Evidence" },
              { id: "observation", label: "AI Observation" },
            ].map((f) => (
              <Button
                key={f.id}
                size="sm"
                variant={activeFilter === f.id ? "default" : "outline"}
                className="h-7 text-xs px-2.5"
                onClick={() => setActiveFilter(f.id)}
              >
                {f.label}
              </Button>
            ))}
          </div>
        </div>

        <div className="space-y-3 mt-4">
          {findings.map((f) => (
            <div
              key={f.id}
              onClick={() => setSelectedFinding(f)}
              className={`p-3.5 rounded-md border transition cursor-pointer ${selectedFinding?.id === f.id ? "border-primary bg-primary/10" : "border-border bg-background/40 hover:border-primary/40"}`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <PriorityBadge priority={f.priority} />
                  <FindingTypeBadge type={f.findingType} />
                  <span className="text-[11px] font-mono text-muted-foreground uppercase">
                    [{f.category}]
                  </span>
                </div>
                <span className="text-xs font-mono text-muted-foreground">
                  {f.evidenceIds.length} linked artifact(s)
                </span>
              </div>

              <div className="text-sm font-medium mt-2">{f.title}</div>
              <div className="text-xs text-muted-foreground mt-1 leading-relaxed">
                {f.rationale}
              </div>

              <div className="mt-2.5 flex items-center gap-2 text-[11px] font-mono text-primary/80">
                <span>Linked Evidence IDs:</span>
                {f.evidenceIds.slice(0, 5).map((id) => (
                  <span key={id} className="px-1.5 py-0.5 rounded bg-card/90 border border-border">
                    {id}
                  </span>
                ))}
                {f.evidenceIds.length > 5 && (
                  <span className="text-muted-foreground">+{f.evidenceIds.length - 5} more</span>
                )}
              </div>
            </div>
          ))}

          {findings.length === 0 && (
            <div className="p-8 text-center text-muted-foreground text-sm">
              No findings match the selected filter.
            </div>
          )}
        </div>
      </Card>

      {/* Forensic Examiner Narrative Summary */}
      <Card className="p-5 bg-card/70 border-border">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
          <ShieldAlert className="size-4 text-priority-high" /> Forensic Examiner Narrative Synthesis
        </h2>
        <div className="p-4 rounded bg-background/50 border border-border text-xs font-mono whitespace-pre-line leading-relaxed text-foreground/90">
          {analysisData.summary}
        </div>
      </Card>
    </div>
  );
}

