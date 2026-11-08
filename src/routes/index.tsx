import { createFileRoute, Link } from "@tanstack/react-router";
import { AppLayout } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  CASE, DEVICES, SMS, CALLS, CONTACTS, GPS, BROWSER, APPS, MEDIA, getTotalEvidenceCount,
} from "@/lib/forensic-data";
import { analyze } from "@/lib/ai-analyzer";
import { PriorityBadge } from "@/components/PriorityBadge";
import {
  Smartphone, MessageSquare, Phone, MapPin, Globe, AppWindow,
  Image as ImageIcon, ShieldAlert, ArrowRight, User, Database,
  FileText, Activity, Cpu, TrendingUp,
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

export const Route = createFileRoute("/")(({
  head: () => ({
    meta: [
      { title: "Dashboard – AI-Based Mobile Forensic Intelligence System" },
      { name: "description", content: "Overview of active forensic case, connected Android devices, and AI-prioritized suspicious findings." },
    ],
  }),
  component: () => (
    <AppLayout>
      <Dashboard />
    </AppLayout>
  ),
}));

function StatCard({
  icon: Icon, label, value, sub, accent,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <Card className="p-4 bg-card/70 border-border">
      <div className="flex items-center justify-between">
        <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
        <Icon className="size-4 text-primary/70" />
      </div>
      <div className={`mt-2 text-2xl font-semibold font-mono ${accent || ""}`}>{value}</div>
      {sub && <div className="text-xs text-muted-foreground mt-1">{sub}</div>}
    </Card>
  );
}

function Dashboard() {
  const { findings, stats, suspiciousCount, riskLevel, autopsyCarvedCount } = analyze();
  const topFindings = findings.filter((f) => f.priority === "high").slice(0, 4);

  const evidenceData = [
    { name: "SMS", count: SMS.length, color: "#06b6d4" },
    { name: "Calls", count: CALLS.length, color: "#8b5cf6" },
    { name: "Contacts", count: CONTACTS.length, color: "#10b981" },
    { name: "GPS", count: GPS.length, color: "#f59e0b" },
    { name: "Browser", count: BROWSER.length, color: "#ef4444" },
    { name: "Apps", count: APPS.length, color: "#ec4899" },
    { name: "Media", count: MEDIA.length, color: "#64748b" },
  ];

  const riskColor = {
    Critical: "text-red-400",
    High: "text-priority-high",
    Medium: "text-priority-medium",
    Low: "text-priority-low",
  }[riskLevel] || "text-foreground";

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Case banner */}
      <div className="grid-forensic rounded-lg border border-border p-6 bg-card/40">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="text-[11px] uppercase tracking-widest text-primary flex items-center gap-1.5">
              <Activity className="size-3" /> Active Case File
            </div>
            <h1 className="text-2xl font-semibold mt-1">{CASE.title}</h1>
            <div className="text-sm text-muted-foreground mt-1">
              <span className="font-mono text-primary">{CASE.caseNumber}</span>
              {" · "}{CASE.investigator}{" · "}
              <span className="text-priority-low font-medium">{CASE.status.toUpperCase()}</span>
            </div>
            <div className="text-xs text-muted-foreground mt-1">{CASE.description}</div>
          </div>
          <div className="flex gap-2 flex-wrap">
            <Button asChild variant="outline" size="sm">
              <Link to="/autopsy">Autopsy Recovery</Link>
            </Button>
            <Button asChild variant="secondary" size="sm">
              <Link to="/evidence">Browse Evidence</Link>
            </Button>
            <Button asChild size="sm">
              <Link to="/ai-analyzer">
                AI Analysis <ArrowRight className="size-3.5 ml-1" />
              </Link>
            </Button>
          </div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <StatCard icon={Smartphone} label="Devices" value={DEVICES.length} sub={`${DEVICES.filter((d) => d.status === "acquired").length} Android acquired`} />
        <StatCard icon={Database} label="Total Evidence" value={getTotalEvidenceCount()} sub="7 categories" />
        <StatCard icon={ShieldAlert} label="Suspicious" value={suspiciousCount} sub="indicators detected" accent="text-priority-high" />
        <StatCard icon={ShieldAlert} label="Autopsy Carved" value={autopsyCarvedCount} sub="deleted artifacts recovered" />
        <StatCard icon={TrendingUp} label="Risk Level" value={riskLevel} sub={`${stats.high} high · ${stats.medium} med`} accent={riskColor} />
        <StatCard icon={Cpu} label="AI Findings" value={stats.total} sub="heuristic + AI" />
      </div>

      {/* Middle section */}
      <div className="grid md:grid-cols-3 gap-4">
        {/* Top findings */}
        <Card className="md:col-span-2 p-5 bg-card/70">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              Top AI Findings
            </h2>
            <Link to="/forensic-analysis" className="text-xs text-primary hover:underline">
              View all →
            </Link>
          </div>
          <div className="space-y-3">
            {topFindings.map((f) => (
              <div
                key={f.id}
                className="p-3 rounded-md border border-border bg-background/40 flex items-start gap-3"
              >
                <PriorityBadge priority={f.priority} />
                <div className="min-w-0">
                  <div className="text-sm font-medium">{f.title}</div>
                  <div className="text-xs text-muted-foreground mt-1 line-clamp-2">{f.rationale}</div>
                  <div className="mt-1">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${
                      f.findingType === "confirmed-evidence"
                        ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                        : f.findingType === "ai-observation"
                          ? "bg-blue-500/10 text-blue-400 border-blue-500/30"
                          : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                    }`}>
                      {f.findingType}
                    </span>
                  </div>
                </div>
              </div>
            ))}
            {topFindings.length === 0 && (
              <div className="text-sm text-muted-foreground text-center py-4">
                No high-priority findings. Run analysis to generate findings.
              </div>
            )}
          </div>
        </Card>

        {/* Connected devices */}
        <Card className="p-5 bg-card/70">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-4">
            Android Devices
          </h2>
          <div className="space-y-3">
            {DEVICES.map((d) => (
              <div key={d.id} className="p-3 rounded-md border border-border bg-background/40">
                <div className="flex items-center justify-between">
                  <div className="text-sm font-medium">{d.model}</div>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/15 text-primary border border-primary/30">
                    Android
                  </span>
                </div>
                <div className="text-xs text-muted-foreground mt-1 font-mono">
                  {d.acquisitionMethod} · Android {d.osVersion}
                </div>
                <div className="text-xs text-muted-foreground">
                  {d.manufacturer} · Serial: {d.serial}
                </div>
                <div className="mt-1.5 flex items-center gap-1.5">
                  <span className={`size-1.5 rounded-full ${d.status === "acquired" ? "bg-emerald-500" : "bg-amber-500"}`} />
                  <span className="text-[10px] text-muted-foreground">{d.status}</span>
                  <span className="text-[10px] text-muted-foreground ml-auto">
                    {d.dataSource === "sample-data" ? "⚠ SAMPLE DATA" : "● LIVE"}
                  </span>
                </div>
              </div>
            ))}
          </div>
          <Button asChild variant="outline" size="sm" className="w-full mt-3">
            <Link to="/devices">Manage Devices</Link>
          </Button>
        </Card>
      </div>

      {/* Evidence distribution chart + categories */}
      <div className="grid md:grid-cols-2 gap-4">
        <Card className="p-5 bg-card/70">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-4">
            Evidence Distribution
          </h2>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={evidenceData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: "#94a3b8" }} />
              <YAxis tick={{ fontSize: 9, fill: "#94a3b8" }} />
              <Tooltip
                contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 6, fontSize: 11 }}
                labelStyle={{ color: "#e2e8f0" }}
              />
              <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                {evidenceData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card className="p-5 bg-card/70">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
            Evidence Categories
          </h2>
          <div className="grid grid-cols-2 gap-2 text-sm">
            {[
              { icon: MessageSquare, label: "SMS", n: SMS.length, to: "/evidence" },
              { icon: Phone, label: "Calls", n: CALLS.length, to: "/evidence" },
              { icon: User, label: "Contacts", n: CONTACTS.length, to: "/evidence" },
              { icon: MapPin, label: "GPS", n: GPS.length, to: "/evidence" },
              { icon: Globe, label: "Browser", n: BROWSER.length, to: "/evidence" },
              { icon: AppWindow, label: "Apps", n: APPS.length, to: "/evidence" },
              { icon: ImageIcon, label: "Media", n: MEDIA.length, to: "/evidence" },
              { icon: FileText, label: "Reports", n: 0, to: "/report" },
            ].map((c) => (
              <Link
                to={c.to}
                key={c.label}
                className="p-2.5 rounded-md border border-border hover:border-primary/50 hover:bg-primary/5 transition flex items-center gap-2"
              >
                <c.icon className="size-3.5 text-primary" />
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{c.label}</div>
                  <div className="font-mono text-sm font-semibold">{c.n}</div>
                </div>
              </Link>
            ))}
          </div>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card className="p-5 bg-card/70">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
          Investigation Workflow
        </h2>
        <div className="flex flex-wrap gap-2">
          {[
            { label: "1. Connect Device", to: "/devices", icon: Smartphone },
            { label: "2. Collect Evidence", to: "/collection", icon: Database },
            { label: "3. Forensic Analysis", to: "/forensic-analysis", icon: Activity },
            { label: "4. AI Analysis", to: "/ai-analyzer", icon: Cpu },
            { label: "5. Generate Report", to: "/report", icon: FileText },
          ].map((step) => (
            <Button key={step.to} asChild variant="outline" size="sm">
              <Link to={step.to}>
                <step.icon className="size-3.5 mr-1.5" />
                {step.label}
              </Link>
            </Button>
          ))}
        </div>
      </Card>
    </div>
  );
}
