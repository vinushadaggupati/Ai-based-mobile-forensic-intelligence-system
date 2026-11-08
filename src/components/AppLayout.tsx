import { Link, useRouterState } from "@tanstack/react-router";
import { type ReactNode, useEffect, useState } from "react";
import {
  Shield,
  LayoutDashboard,
  Smartphone,
  Database,
  Sparkles,
  FileText,
  FolderSearch,
  Search,
  FileSearch,
  Cpu,
  Radio,
  Server,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { CASE } from "@/lib/forensic-data";
import { checkOllamaConnection, type OllamaStatus } from "@/lib/ollama-client";
import { checkBackendHealth, type BackendStatus } from "@/lib/api-client";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/devices", label: "Device Connection", icon: Smartphone },
  { to: "/collection", label: "Evidence Collection", icon: FolderSearch },
  { to: "/evidence", label: "Evidence Storage", icon: Database },
  { to: "/forensic-analysis", label: "Forensic Analysis", icon: Search },
  { to: "/ai-analyzer", label: "AI Analyzer", icon: Sparkles },
  { to: "/report", label: "Report Generation", icon: FileText },
] as const;

const NAV_SECONDARY = [
  { to: "/autopsy", label: "Autopsy Recovery", icon: FileSearch },
] as const;

export function AppLayout({ children }: { children: ReactNode }) {
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [ollama, setOllama] = useState<OllamaStatus | null>(null);
  const [backend, setBackend] = useState<BackendStatus>("checking");

  useEffect(() => {
    checkOllamaConnection().then(setOllama);
    checkBackendHealth().then(setBackend);

    const interval = setInterval(() => {
      checkOllamaConnection().then(setOllama);
      checkBackendHealth().then(setBackend);
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen flex text-foreground">
      {/* Sidebar */}
      <aside className="w-64 shrink-0 border-r border-sidebar-border bg-sidebar/80 backdrop-blur-sm flex flex-col">
        {/* Logo */}
        <div className="p-5 border-b border-sidebar-border">
          <div className="flex items-center gap-2">
            <div className="size-9 rounded-md bg-primary/15 border border-primary/30 grid place-items-center">
              <Shield className="size-5 text-primary" />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-tight">FORENSIC / MFIS</div>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
                AI Mobile Intelligence
              </div>
            </div>
          </div>
        </div>

        {/* Main Nav */}
        <nav className="p-3 flex-1 space-y-1">
          {NAV.map((n) => {
            const active = n.to === "/" ? path === "/" : path.startsWith(n.to);
            const Icon = n.icon;
            return (
              <Link
                key={n.to}
                to={n.to}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
                  active
                    ? "bg-sidebar-accent text-sidebar-accent-foreground border border-primary/25"
                    : "text-sidebar-foreground/75 hover:bg-sidebar-accent/60 hover:text-sidebar-foreground",
                )}
              >
                <Icon className="size-4" />
                {n.label}
              </Link>
            );
          })}

          <div className="pt-2 pb-1">
            <div className="text-[9px] uppercase tracking-widest text-muted-foreground/60 px-3 pb-1">
              Tools
            </div>
            {NAV_SECONDARY.map((n) => {
              const active = path.startsWith(n.to);
              const Icon = n.icon;
              return (
                <Link
                  key={n.to}
                  to={n.to}
                  className={cn(
                    "flex items-center gap-3 px-3 py-1.5 rounded-md text-xs transition-colors",
                    active
                      ? "bg-sidebar-accent text-sidebar-accent-foreground border border-primary/25"
                      : "text-sidebar-foreground/60 hover:bg-sidebar-accent/60 hover:text-sidebar-foreground",
                  )}
                >
                  <Icon className="size-3.5" />
                  {n.label}
                </Link>
              );
            })}
          </div>
        </nav>

        {/* Status indicators */}
        <div className="p-3 space-y-2">
          {/* Backend status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-card/40 border border-border text-xs">
            <Server className="size-3 text-muted-foreground" />
            <span
              className={cn(
                "size-2 rounded-full",
                backend === "online" ? "bg-emerald-500 animate-pulse" : backend === "checking" ? "bg-amber-400 animate-pulse" : "bg-red-500",
              )}
            />
            <span className="text-muted-foreground">
              {backend === "online" ? "Backend: Online" : backend === "checking" ? "Backend: Checking..." : "Backend: Offline"}
            </span>
          </div>

          {/* Ollama status */}
          {ollama && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-card/40 border border-border text-xs">
              <Cpu className="size-3 text-muted-foreground" />
              <span className={cn("size-2 rounded-full", ollama.connected ? "bg-emerald-500 animate-pulse" : "bg-amber-500")} />
              <span className="text-muted-foreground truncate">
                {ollama.connected ? `Ollama: ${ollama.activeModel}` : "Ollama: Offline"}
              </span>
            </div>
          )}
        </div>

        {/* Active case */}
        <div className="p-3 m-3 rounded-md bg-card/60 border border-border text-xs">
          <div className="text-muted-foreground uppercase tracking-wider text-[10px] mb-1">
            Active Case
          </div>
          <div className="font-mono text-primary">{CASE.caseNumber}</div>
          <div className="mt-1 line-clamp-2 text-foreground/80">{CASE.title}</div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <header className="h-14 border-b border-border bg-background/60 backdrop-blur px-6 flex items-center justify-between">
          <div className="flex items-center gap-4 text-xs">
            <div className="flex items-center gap-2">
              <Radio className="size-3.5 text-priority-low animate-pulse" />
              <span className="text-muted-foreground hidden sm:inline">
                Session secure · Chain-of-custody active
              </span>
            </div>
            {ollama && (
              <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[11px] font-mono bg-card/70">
                <span
                  className={cn(
                    "size-2 rounded-full",
                    ollama.connected ? "bg-emerald-500 animate-pulse" : "bg-amber-500",
                  )}
                />
                <Cpu className="size-3 text-muted-foreground" />
                <span>
                  {ollama.connected
                    ? `Ollama: ${ollama.activeModel} (${ollama.latencyMs}ms)`
                    : "AI Engine: Offline Heuristics"}
                </span>
              </div>
            )}
          </div>
          <div className="text-xs text-muted-foreground font-mono">
            {CASE.investigator} · {CASE.agency}
          </div>
        </header>

        <main className="flex-1 overflow-auto p-6">{children}</main>
      </div>
    </div>
  );
}
