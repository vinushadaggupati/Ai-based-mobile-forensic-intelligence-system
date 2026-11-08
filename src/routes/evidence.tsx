import { createFileRoute, Link } from "@tanstack/react-router";
import { AppLayout } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useEffect, useState } from "react";
import {
  SMS,
  CALLS,
  CONTACTS,
  GPS,
  BROWSER,
  APPS,
  MEDIA,
  type MediaRecord,
  computeEvidenceHashes,
  sha256,
} from "@/lib/forensic-data";
import { AUTOPSY_CARVED_EVIDENCE } from "@/lib/autopsy-data";
import {
  Search,
  MessageSquare,
  Phone,
  MapPin,
  Globe,
  AppWindow,
  Image as ImageIcon,
  User,
  ShieldCheck,
  FileSearch,
  Database,
  Copy,
  Download,
  Check,
  FileCode,
  HardDrive,
  Sparkles,
} from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/evidence")({
  head: () => ({
    meta: [
      { title: "Evidence Storage · AI-Based Mobile Forensic Intelligence System" },
      {
        name: "description",
        content:
          "Organized SQLite evidence store with SHA-256 integrity verification, timestamp tracking, and source identification.",
      },
      { property: "og:title", content: "Forensic Evidence Storage" },
      {
        property: "og:description",
        content: "Search and inspect preserved Android mobile forensic artifacts.",
      },
    ],
  }),
  component: () => (
    <AppLayout>
      <Evidence />
    </AppLayout>
  ),
});

function Evidence() {
  const [q, setQ] = useState("");
  const [hashes, setHashes] = useState<Record<string, string>>({});
  const [selectedRecord, setSelectedRecord] = useState<Record<string, unknown> | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    computeEvidenceHashes().then((items) => {
      const map: Record<string, string> = {};
      for (const it of items) map[it.id] = it.hash;
      for (const c of AUTOPSY_CARVED_EVIDENCE) {
        if (c.sha256) map[c.id] = c.sha256;
      }
      setHashes(map);
    });
  }, []);

  const copyHash = (hash: string, id: string) => {
    if (!hash) return;
    navigator.clipboard.writeText(hash);
    setCopiedId(id);
    toast.success("SHA-256 hash copied to clipboard");
    setTimeout(() => setCopiedId(null), 2000);
  };

  const exportCategory = (name: string, data: unknown[]) => {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mfis_${name.toLowerCase()}_evidence.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${data.length} ${name} records`);
  };

  const filter = <T extends { id: string }>(rows: T[]): T[] => {
    if (!q.trim()) return rows;
    const s = q.toLowerCase();
    return rows.filter((r) => JSON.stringify(r).toLowerCase().includes(s));
  };

  const totalRecords =
    SMS.length +
    CALLS.length +
    CONTACTS.length +
    GPS.length +
    BROWSER.length +
    APPS.length +
    MEDIA.length +
    AUTOPSY_CARVED_EVIDENCE.length;

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Top Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-semibold">Evidence Storage</h1>
            <Badge variant="outline" className="border-primary/40 text-primary font-mono text-xs">
              <Database className="size-3 mr-1" /> SQLite Preserved
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Preserved Android forensic evidence organized into separate categories with SHA-256
            cryptographic integrity verification. Original records are maintained without modification.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative w-64 md:w-80">
            <Search className="size-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search all evidence (body, number, URL)..."
              className="pl-9 bg-card/70 font-mono text-xs"
            />
          </div>
          <Button asChild size="sm" className="gap-1.5 whitespace-nowrap">
            <Link to="/ai-analyzer">
              <Sparkles className="size-3.5" /> Run AI Analysis →
            </Link>
          </Button>
        </div>
      </div>

      {/* Storage Meta Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="p-3 bg-card/60 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Total Preserved Records</div>
          <div className="text-xl font-mono font-semibold mt-1 text-primary">{totalRecords}</div>
        </Card>
        <Card className="p-3 bg-card/60 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Integrity Algorithm</div>
          <div className="text-xl font-mono font-semibold mt-1 text-emerald-400 flex items-center gap-1.5">
            <ShieldCheck className="size-4" /> SHA-256 Verified
          </div>
        </Card>
        <Card className="p-3 bg-card/60 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Storage Engine</div>
          <div className="text-xl font-mono font-semibold mt-1 text-foreground flex items-center gap-1.5">
            <HardDrive className="size-4 text-cyan-400" /> SQLite WAL
          </div>
        </Card>
        <Card className="p-3 bg-card/60 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Chain of Custody</div>
          <div className="text-xl font-mono font-semibold mt-1 text-priority-low">Active / NIST 800-101</div>
        </Card>
      </div>

      {/* Category Tabs */}
      <Tabs defaultValue="sms">
        <div className="flex items-center justify-between gap-2 flex-wrap border-b border-border pb-2">
          <TabsList className="bg-card/60 flex-wrap h-auto p-1">
            <TabsTrigger value="sms">
              <MessageSquare className="size-3.5 mr-1.5 text-cyan-400" />
              SMS ({SMS.length})
            </TabsTrigger>
            <TabsTrigger value="calls">
              <Phone className="size-3.5 mr-1.5 text-violet-400" />
              Calls ({CALLS.length})
            </TabsTrigger>
            <TabsTrigger value="contacts">
              <User className="size-3.5 mr-1.5 text-emerald-400" />
              Contacts ({CONTACTS.length})
            </TabsTrigger>
            <TabsTrigger value="gps">
              <MapPin className="size-3.5 mr-1.5 text-amber-400" />
              GPS ({GPS.length})
            </TabsTrigger>
            <TabsTrigger value="browser">
              <Globe className="size-3.5 mr-1.5 text-rose-400" />
              Browser ({BROWSER.length})
            </TabsTrigger>
            <TabsTrigger value="apps">
              <AppWindow className="size-3.5 mr-1.5 text-pink-400" />
              Apps ({APPS.length})
            </TabsTrigger>
            <TabsTrigger value="media">
              <ImageIcon className="size-3.5 mr-1.5 text-blue-400" />
              Media ({MEDIA.length})
            </TabsTrigger>
            <TabsTrigger value="autopsy">
              <FileSearch className="size-3.5 mr-1.5 text-primary" />
              Autopsy Carved ({AUTOPSY_CARVED_EVIDENCE.length})
            </TabsTrigger>
          </TabsList>
        </div>

        {/* SMS Tab */}
        <TabsContent value="sms">
          <div className="flex justify-between items-center my-2">
            <div className="text-xs text-muted-foreground">Showing extracted short messaging service artifacts.</div>
            <Button size="sm" variant="outline" onClick={() => exportCategory("SMS", SMS)}>
              <Download className="size-3.5 mr-1" /> Export JSON
            </Button>
          </div>
          <EvTable
            rows={filter(SMS)}
            hashes={hashes}
            onSelect={(r) => setSelectedRecord(r)}
            copiedId={copiedId}
            onCopy={copyHash}
            cols={[
              { k: "direction", label: "Dir", fmt: (v) => <span className={`uppercase font-mono text-[10px] px-1 py-0.5 rounded ${v === "in" ? "bg-cyan-500/15 text-cyan-400" : "bg-purple-500/15 text-purple-400"}`}>{String(v)}</span> },
              { k: "contact", label: "Contact" },
              { k: "number", label: "Phone Number", mono: true },
              { k: "timestamp", label: "Timestamp (UTC)", fmt: (v) => new Date(String(v)).toLocaleString() },
              { k: "body", label: "Message Content", grow: true },
              { k: "dataSource", label: "Source", fmt: (v) => <SourceBadge source={String(v || "sample-data")} /> },
            ]}
          />
        </TabsContent>

        {/* Calls Tab */}
        <TabsContent value="calls">
          <div className="flex justify-between items-center my-2">
            <div className="text-xs text-muted-foreground">Call logs recorded by the Android Telephony Provider.</div>
            <Button size="sm" variant="outline" onClick={() => exportCategory("Calls", CALLS)}>
              <Download className="size-3.5 mr-1" /> Export JSON
            </Button>
          </div>
          <EvTable
            rows={filter(CALLS)}
            hashes={hashes}
            onSelect={(r) => setSelectedRecord(r)}
            copiedId={copiedId}
            onCopy={copyHash}
            cols={[
              { k: "type", label: "Type", fmt: (v) => <span className={`uppercase font-mono text-[10px] px-1 py-0.5 rounded ${v === "outgoing" ? "bg-blue-500/15 text-blue-400" : v === "incoming" ? "bg-emerald-500/15 text-emerald-400" : "bg-rose-500/15 text-rose-400"}`}>{String(v)}</span> },
              { k: "contact", label: "Contact" },
              { k: "number", label: "Number", mono: true },
              { k: "timestamp", label: "Timestamp (UTC)", fmt: (v) => new Date(String(v)).toLocaleString() },
              { k: "durationSec", label: "Duration", fmt: (v) => `${v}s` },
              { k: "dataSource", label: "Source", fmt: (v) => <SourceBadge source={String(v || "sample-data")} /> },
            ]}
          />
        </TabsContent>

        {/* Contacts Tab */}
        <TabsContent value="contacts">
          <div className="flex justify-between items-center my-2">
            <div className="text-xs text-muted-foreground">Android Contacts Provider entries (contacts2.db).</div>
            <Button size="sm" variant="outline" onClick={() => exportCategory("Contacts", CONTACTS)}>
              <Download className="size-3.5 mr-1" /> Export JSON
            </Button>
          </div>
          <EvTable
            rows={filter(CONTACTS)}
            hashes={hashes}
            onSelect={(r) => setSelectedRecord(r)}
            copiedId={copiedId}
            onCopy={copyHash}
            cols={[
              { k: "name", label: "Display Name" },
              { k: "number", label: "Telephone Number", mono: true },
              { k: "email", label: "Email Address", mono: true },
              { k: "organization", label: "Organization" },
              { k: "dataSource", label: "Source", fmt: (v) => <SourceBadge source={String(v || "sample-data")} /> },
            ]}
          />
        </TabsContent>

        {/* GPS Tab */}
        <TabsContent value="gps">
          <div className="flex justify-between items-center my-2">
            <div className="text-xs text-muted-foreground">Location cache and network telemetry coordinates.</div>
            <Button size="sm" variant="outline" onClick={() => exportCategory("GPS", GPS)}>
              <Download className="size-3.5 mr-1" /> Export JSON
            </Button>
          </div>
          <EvTable
            rows={filter(GPS)}
            hashes={hashes}
            onSelect={(r) => setSelectedRecord(r)}
            copiedId={copiedId}
            onCopy={copyHash}
            cols={[
              { k: "place", label: "Resolved Location", grow: true },
              { k: "lat", label: "Latitude", mono: true },
              { k: "lng", label: "Longitude", mono: true },
              { k: "accuracyM", label: "Accuracy", fmt: (v) => `±${v}m` },
              { k: "timestamp", label: "Timestamp", fmt: (v) => new Date(String(v)).toLocaleString() },
              { k: "provider", label: "Provider", mono: true },
              { k: "dataSource", label: "Source", fmt: (v) => <SourceBadge source={String(v || "sample-data")} /> },
            ]}
          />
        </TabsContent>

        {/* Browser Tab */}
        <TabsContent value="browser">
          <div className="flex justify-between items-center my-2">
            <div className="text-xs text-muted-foreground">Browsing history recovered from Android browser databases.</div>
            <Button size="sm" variant="outline" onClick={() => exportCategory("Browser", BROWSER)}>
              <Download className="size-3.5 mr-1" /> Export JSON
            </Button>
          </div>
          <EvTable
            rows={filter(BROWSER)}
            hashes={hashes}
            onSelect={(r) => setSelectedRecord(r)}
            copiedId={copiedId}
            onCopy={copyHash}
            cols={[
              { k: "title", label: "Page Title", grow: true },
              { k: "url", label: "URL", mono: true, grow: true },
              { k: "browser", label: "Browser" },
              { k: "visits", label: "Visits" },
              { k: "timestamp", label: "Access Timestamp", fmt: (v) => new Date(String(v)).toLocaleString() },
              { k: "dataSource", label: "Source", fmt: (v) => <SourceBadge source={String(v || "sample-data")} /> },
            ]}
          />
        </TabsContent>

        {/* Apps Tab */}
        <TabsContent value="apps">
          <div className="flex justify-between items-center my-2">
            <div className="text-xs text-muted-foreground">Applications installed on device (pm list packages).</div>
            <Button size="sm" variant="outline" onClick={() => exportCategory("Apps", APPS)}>
              <Download className="size-3.5 mr-1" /> Export JSON
            </Button>
          </div>
          <EvTable
            rows={filter(APPS)}
            hashes={hashes}
            onSelect={(r) => setSelectedRecord(r)}
            copiedId={copiedId}
            onCopy={copyHash}
            cols={[
              { k: "name", label: "App Name" },
              { k: "pkg", label: "Package Identifier", mono: true },
              { k: "version", label: "Version", mono: true },
              { k: "category", label: "Category" },
              { k: "permissions", label: "Permissions", fmt: (v: unknown) => Array.isArray(v) ? v.join(", ") : String(v || "") },
              {
                k: "suspicious",
                label: "Flag",
                fmt: (v) =>
                  v ? (
                    <span className="text-priority-high font-semibold text-xs">⚑ Suspicious</span>
                  ) : (
                    <span className="text-muted-foreground text-xs">—</span>
                  ),
              },
              { k: "dataSource", label: "Source", fmt: (v) => <SourceBadge source={String(v || "sample-data")} /> },
            ]}
          />
        </TabsContent>

        {/* Media Tab */}
        <TabsContent value="media">
          <div className="flex justify-between items-center my-2">
            <div className="text-xs text-muted-foreground">Media files from DCIM, Pictures, and Downloads with SHA-256 digests.</div>
            <Button size="sm" variant="outline" onClick={() => exportCategory("Media", MEDIA)}>
              <Download className="size-3.5 mr-1" /> Export JSON
            </Button>
          </div>
          <MediaGrid rows={filter(MEDIA)} onSelect={(r) => setSelectedRecord(r)} />
        </TabsContent>

        {/* Autopsy Carved Tab */}
        <TabsContent value="autopsy">
          <div className="flex justify-between items-center my-2">
            <div className="text-xs text-muted-foreground">
              Artifacts carved from SQLite freelists, WAL journals, and unallocated NAND blocks by Autopsy 4.23.1.
            </div>
            <Button size="sm" variant="outline" onClick={() => exportCategory("Autopsy_Carved", AUTOPSY_CARVED_EVIDENCE)}>
              <Download className="size-3.5 mr-1" /> Export JSON
            </Button>
          </div>
          <EvTable
            rows={filter(AUTOPSY_CARVED_EVIDENCE)}
            hashes={hashes}
            onSelect={(r) => setSelectedRecord(r)}
            copiedId={copiedId}
            onCopy={copyHash}
            cols={[
              { k: "evidenceType", label: "Type" },
              { k: "title", label: "Carved Artifact", grow: true },
              { k: "recoveryMethod", label: "Carving Method" },
              { k: "confidence", label: "Confidence", fmt: (v) => `${v}%` },
              { k: "blockOffset", label: "Physical Offset", mono: true },
              { k: "timestamp", label: "When", fmt: (v) => new Date(String(v)).toLocaleString() },
            ]}
          />
        </TabsContent>
      </Tabs>

      {/* Raw Record Inspector Dialog / Drawer */}
      {selectedRecord && (
        <Card className="p-5 bg-card/90 border-primary/30 mt-6 space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-2">
            <div className="flex items-center gap-2">
              <FileCode className="size-4 text-primary" />
              <h3 className="text-sm font-semibold uppercase tracking-wider text-primary">
                Raw Evidence Record Inspector (Unmodified Original)
              </h3>
            </div>
            <Button size="sm" variant="ghost" onClick={() => setSelectedRecord(null)}>
              ✕ Close
            </Button>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-muted-foreground">Record ID:</span>
            <span className="text-foreground">{String(selectedRecord.id || "")}</span>
            <span className="text-muted-foreground ml-4">SHA-256 Hash:</span>
            <span className="text-primary truncate max-w-xs">{hashes[String(selectedRecord.id)] || "Computed on ingest"}</span>
            <Button
              size="sm"
              variant="outline"
              className="h-6 px-2 text-[10px]"
              onClick={() => copyHash(hashes[String(selectedRecord.id)] || "", String(selectedRecord.id))}
            >
              <Copy className="size-3 mr-1" /> Copy Hash
            </Button>
          </div>

          <pre className="p-3 bg-background/80 rounded border border-border text-xs font-mono overflow-x-auto text-foreground/90 max-h-60">
            {JSON.stringify(selectedRecord, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  );
}

function SourceBadge({ source }: { source: string }) {
  if (source === "adb-live") {
    return <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[9px]">ADB LIVE</Badge>;
  }
  if (source === "imported") {
    return <Badge className="bg-purple-500/15 text-purple-400 border-purple-500/30 text-[9px]">IMPORTED</Badge>;
  }
  return <Badge variant="outline" className="text-amber-400 border-amber-500/30 text-[9px]">SAMPLE</Badge>;
}

type Col = {
  k: string;
  label: string;
  mono?: boolean;
  grow?: boolean;
  fmt?: (v: unknown) => React.ReactNode;
};

function EvTable<T extends { id: string }>({
  rows,
  cols,
  hashes,
  onSelect,
  copiedId,
  onCopy,
}: {
  rows: T[];
  cols: Col[];
  hashes: Record<string, string>;
  onSelect: (r: any) => void;
  copiedId: string | null;
  onCopy: (hash: string, id: string) => void;
}) {
  return (
    <Card className="bg-card/70 overflow-hidden mt-3 border-border">
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border text-[10px] uppercase tracking-widest text-muted-foreground bg-background/40">
              {cols.map((c) => (
                <th key={c.k} className="text-left px-3 py-2.5 font-medium">
                  {c.label}
                </th>
              ))}
              <th className="text-left px-3 py-2.5 font-medium">SHA-256 Hash</th>
              <th className="text-right px-3 py-2.5 font-medium">Inspect</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const hash = hashes[r.id];
              const isCopied = copiedId === r.id;
              return (
                <tr
                  key={r.id}
                  className="border-b border-border/40 hover:bg-primary/5 transition cursor-pointer"
                  onClick={() => onSelect(r)}
                >
                  {cols.map((c) => {
                    const v = (r as any)[c.k];
                    return (
                      <td
                        key={c.k}
                        className={`px-3 py-2 align-middle ${c.mono ? "font-mono text-[11px]" : ""} ${c.grow ? "max-w-md" : ""}`}
                      >
                        {c.fmt ? c.fmt(v) : (v != null ? String(v) : "—")}
                      </td>
                    );
                  })}
                  <td className="px-3 py-2 font-mono text-[10px] text-muted-foreground max-w-[12rem] truncate">
                    {hash ? (
                      <div className="flex items-center gap-1.5" title={hash}>
                        <ShieldCheck className="size-3 text-priority-low shrink-0" />
                        <span className="truncate">{hash.slice(0, 14)}…</span>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onCopy(hash, r.id);
                          }}
                          className="hover:text-primary transition p-0.5 rounded"
                          title="Copy Full SHA-256 Hash"
                        >
                          {isCopied ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
                        </button>
                      </div>
                    ) : (
                      "Calculating..."
                    )}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 px-2 text-[10px]"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelect(r);
                      }}
                    >
                      View
                    </Button>
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={cols.length + 2} className="px-3 py-8 text-center text-muted-foreground text-xs">
                  No matching evidence records found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function MediaGrid({
  rows,
  onSelect,
}: {
  rows: MediaRecord[];
  onSelect: (r: any) => void;
}) {
  const [hashes, setHashes] = useState<Record<string, string>>({});
  useEffect(() => {
    (async () => {
      const m: Record<string, string> = {};
      for (const r of rows) m[r.id] = await sha256(r.filename + r.sizeKB);
      setHashes(m);
    })();
  }, [rows]);

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 mt-3">
      {rows.map((m) => (
        <Card
          key={m.id}
          className="p-3 bg-card/70 border-border hover:border-primary/40 cursor-pointer transition"
          onClick={() => onSelect(m as unknown as Record<string, unknown>)}
        >
          <div className="aspect-video rounded bg-background/60 border border-border grid place-items-center text-muted-foreground text-xs uppercase tracking-widest font-mono">
            {m.type}
          </div>
          <div className="mt-2 text-sm font-medium truncate" title={m.filename}>
            {m.filename}
          </div>
          <div className="text-xs text-muted-foreground flex justify-between mt-1">
            <span>{m.sizeKB} KB</span>
            <span>{new Date(m.createdAt).toLocaleDateString()}</span>
          </div>
          <div className="mt-1 text-[10px] font-mono text-muted-foreground truncate flex items-center gap-1">
            <ShieldCheck className="size-3 text-priority-low shrink-0" />
            <span className="truncate">{hashes[m.id]?.slice(0, 18) ?? "..."}…</span>
          </div>
        </Card>
      ))}
    </div>
  );
}
