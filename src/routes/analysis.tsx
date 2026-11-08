import { createFileRoute, Link, Navigate } from "@tanstack/react-router";
import { AppLayout } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Search, Sparkles, ArrowRight, ShieldCheck, Cpu } from "lucide-react";

export const Route = createFileRoute("/analysis")({
  head: () => ({
    meta: [
      { title: "Forensic Analysis Hub · AI-Based Mobile Forensic Intelligence System" },
    ],
  }),
  component: () => (
    <AppLayout>
      <div className="space-y-6 max-w-4xl">
        <div>
          <h1 className="text-2xl font-semibold">Forensic Analysis Hub</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Choose between deterministic digital forensic analysis and the ForensicAI Multi-Modal Neural Engine.
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-4">
          <Card className="p-6 bg-card/70 border-border hover:border-primary/50 transition flex flex-col justify-between space-y-4">
            <div className="space-y-2">
              <div className="size-10 rounded-md bg-cyan-500/15 border border-cyan-500/30 grid place-items-center text-cyan-400">
                <Search className="size-5" />
              </div>
              <h2 className="text-lg font-semibold">Digital Forensic Analysis (Module 4)</h2>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Python rule-based heuristic examination. Detects suspicious SMS keywords, unusual calling patterns,
                unusual GPS timestamps, anti-forensic tools (iShredder, Tor), and Autopsy carved records.
              </p>
            </div>
            <Button asChild className="w-full">
              <Link to="/forensic-analysis">
                Open Forensic Analysis <ArrowRight className="size-4 ml-1" />
              </Link>
            </Button>
          </Card>

          <Card className="p-6 bg-card/70 border-border hover:border-primary/50 transition flex flex-col justify-between space-y-4">
            <div className="space-y-2">
              <div className="size-10 rounded-md bg-purple-500/15 border border-purple-500/30 grid place-items-center text-purple-400">
                <Sparkles className="size-5" />
              </div>
              <h2 className="text-lg font-semibold">AI-Based Evidence Analyzer (Module 5)</h2>
              <p className="text-xs text-muted-foreground leading-relaxed">
                ForensicAI Neural Engine v2.4. Ingests evidence files, correlates SMS, calls, GPS, and social media artifacts,
                synthesizes narrative observations, and automatically generates downloadable PDF forensic reports.
              </p>
            </div>
            <Button asChild variant="secondary" className="w-full">
              <Link to="/ai-analyzer">
                Open AI Analyzer <ArrowRight className="size-4 ml-1" />
              </Link>
            </Button>
          </Card>
        </div>
      </div>
    </AppLayout>
  ),
});
