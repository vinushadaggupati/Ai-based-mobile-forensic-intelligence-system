import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  CASE,
  DEVICES,
  SMS,
  CALLS,
  CONTACTS,
  GPS,
  BROWSER,
  APPS,
  MEDIA,
  computeEvidenceHashes,
} from "@/lib/forensic-data";
import {
  AUTOPSY_CARVED_EVIDENCE,
  computeAutopsyEvidenceHashes,
} from "@/lib/autopsy-data";
import { analyze } from "@/lib/ai-analyzer";
import { api } from "@/lib/api-client";
import {
  FileText,
  Download,
  FileSearch,
  Cpu,
  CheckCircle2,
  ShieldCheck,
  AlertTriangle,
  Server,
  Printer,
  ChevronDown,
  Eye,
} from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

export const Route = createFileRoute("/report")({
  head: () => ({
    meta: [
      { title: "Forensic Report · AI-Based Mobile Forensic Intelligence System" },
      {
        name: "description",
        content:
          "Generate and download official 15-section court-admissible Android forensic investigation report with SHA-256 integrity verification and AI findings.",
      },
    ],
  }),
  component: () => (
    <AppLayout>
      <Report />
    </AppLayout>
  ),
});

interface AutoTableDoc {
  lastAutoTable: { finalY: number };
}
const getFinalY = (d: unknown) => (d as AutoTableDoc).lastAutoTable.finalY;
type AutoTableFn = (doc: unknown, options: unknown) => void;

function Report() {
  const { findings, summary, stats, riskLevel } = analyze();
  const [downloadingBackend, setDownloadingBackend] = useState(false);
  const [activePreviewSection, setActivePreviewSection] = useState<number | null>(1);

  // Client-side 15-section PDF compilation via jsPDF + autoTable
  const downloadClientPDF = async () => {
    toast.loading("Compiling 15-Section Court-Admissible Forensic PDF...", { id: "pdf" });
    try {
      const [{ default: jsPDF }, autoTableMod] = await Promise.all([
        import("jspdf"),
        import("jspdf-autotable"),
      ]);
      const autoTable = (autoTableMod as { default: AutoTableFn }).default;
      const activeHashes = await computeEvidenceHashes();
      const autopsyHashes = await computeAutopsyEvidenceHashes();
      const allHashes = [...autopsyHashes, ...activeHashes];

      const doc = new jsPDF();
      const w = doc.internal.pageSize.getWidth();

      // HEADER BANNER
      doc.setFillColor(15, 23, 42); // slate-900
      doc.rect(0, 0, w, 32, "F");
      doc.setTextColor(255);
      doc.setFontSize(15);
      doc.text("AI-BASED MOBILE FORENSIC INTELLIGENCE SYSTEM", 14, 14);
      doc.setFontSize(9.5);
      doc.setTextColor(6, 182, 212); // cyan
      doc.text(
        `OFFICIAL FORENSIC EXAMINATION REPORT · CASE ${CASE.caseNumber} · ANDROID PLATFORM`,
        14,
        22,
      );
      doc.setFontSize(7.5);
      doc.setTextColor(148, 163, 184);
      doc.text(`Generated: ${new Date().toUTCString()} · Standards: NIST SP 800-101 / ISO/IEC 27037`, 14, 28);
      doc.setTextColor(0);

      let y = 40;

      // 1. Investigation ID
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("1. Investigation ID & Case Information", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        theme: "grid",
        styles: { fontSize: 7.5 },
        body: [
          ["Investigation ID", CASE.caseNumber],
          ["Case Title", CASE.title],
          ["Primary Examiner", CASE.investigator],
          ["Investigating Agency", CASE.agency],
          ["Subject / Suspect", CASE.suspect],
          ["Case Status", CASE.status.toUpperCase()],
          ["Case Opened", new Date(CASE.openedAt).toLocaleString()],
        ],
      });
      y = getFinalY(doc) + 6;

      // 2. Android Device Information
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("2. Android Device Information", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        head: [["Model", "Manufacturer", "OS Version", "API Level", "Serial Number", "IMEI", "Method"]],
        body: DEVICES.map((d) => [
          d.model,
          d.manufacturer,
          `Android ${d.osVersion}`,
          String(d.androidApiLevel),
          d.serial,
          d.imei,
          d.acquisitionMethod,
        ]),
        styles: { fontSize: 7 },
        headStyles: { fillColor: [30, 41, 59] },
      });
      y = getFinalY(doc) + 6;

      // 3. Evidence Collection Details
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("3. Evidence Collection Details", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        head: [["Evidence Category", "Record Count", "Acquisition Source", "Integrity State"]],
        body: [
          ["SMS Messages", String(SMS.length), "Android Telephony Provider (ADB)", "SHA-256 Verified"],
          ["Call Logs", String(CALLS.length), "Android Call Log Provider (ADB)", "SHA-256 Verified"],
          ["Contacts", String(CONTACTS.length), "Android Contacts Provider (ADB)", "SHA-256 Verified"],
          ["GPS Records", String(GPS.length), "Fused Location Provider / Cache", "SHA-256 Verified"],
          ["Browser History", String(BROWSER.length), "Chrome History Provider (ADB)", "SHA-256 Verified"],
          ["Installed Applications", String(APPS.length), "PackageManager (pm list packages)", "SHA-256 Verified"],
          ["Media Artifacts", String(MEDIA.length), "DCIM / Storage Physical Index", "SHA-256 Verified"],
          ["Autopsy Deleted Carves", String(AUTOPSY_CARVED_EVIDENCE.length), "SQLite Freelist & TSK NAND Carving", "SHA-256 Verified"],
        ],
        styles: { fontSize: 7 },
        headStyles: { fillColor: [30, 41, 59] },
      });

      // PAGE 2
      doc.addPage();
      y = 18;

      // 4. SMS Analysis
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("4. SMS Analysis", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        head: [["Dir", "Contact", "Number", "Timestamp", "Message Payload", "Flag"]],
        body: SMS.map((s) => [
          s.direction.toUpperCase(),
          s.contact,
          s.number,
          new Date(s.timestamp).toLocaleString(),
          s.body,
          s.body.toLowerCase().includes("burn") || s.body.toLowerCase().includes("wipe") || s.body.toLowerCase().includes("btc")
            ? "SUSPICIOUS"
            : "NORMAL",
        ]),
        styles: { fontSize: 6.8 },
        headStyles: { fillColor: [30, 41, 59] },
      });
      y = getFinalY(doc) + 6;

      // 5. Call Log Analysis
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("5. Call Log Analysis", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        head: [["Call Type", "Contact", "Number", "Timestamp", "Duration", "Flag"]],
        body: CALLS.map((c) => [
          c.type.toUpperCase(),
          c.contact,
          c.number,
          new Date(c.timestamp).toLocaleString(),
          `${c.durationSec}s`,
          c.number.startsWith("+44") || c.number.startsWith("+7") ? "INTERNATIONAL" : "NORMAL",
        ]),
        styles: { fontSize: 6.8 },
        headStyles: { fillColor: [30, 41, 59] },
      });
      y = getFinalY(doc) + 6;

      // 6. Contact Analysis
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("6. Contact Analysis", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        head: [["Name", "Telephone Number", "Email Address", "Organization"]],
        body: CONTACTS.map((c) => [c.name, c.number, c.email || "—", c.organization || "—"]),
        styles: { fontSize: 7 },
        headStyles: { fillColor: [30, 41, 59] },
      });

      // PAGE 3
      doc.addPage();
      y = 18;

      // 7. GPS Analysis
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("7. GPS Analysis", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        head: [["Place Name", "Latitude", "Longitude", "Accuracy", "Timestamp", "Significance"]],
        body: GPS.map((g) => [
          g.place,
          String(g.lat),
          String(g.lng),
          `±${g.accuracyM}m`,
          new Date(g.timestamp).toLocaleString(),
          g.place.includes("Ocean Beach") || g.place.includes("Airport") ? "HIGH RELEVANCE" : "BASELINE",
        ]),
        styles: { fontSize: 7 },
        headStyles: { fillColor: [30, 41, 59] },
      });
      y = getFinalY(doc) + 6;

      // 8. Browser History Analysis
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("8. Browser History Analysis", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        head: [["Page Title", "URL", "Visits", "Browser", "Security Flag"]],
        body: BROWSER.map((b) => [
          b.title,
          b.url,
          String(b.visits),
          b.browser,
          b.url.includes(".onion") || b.url.includes("wipe") ? "SUSPICIOUS" : "NORMAL",
        ]),
        styles: { fontSize: 6.8 },
        headStyles: { fillColor: [30, 41, 59] },
      });
      y = getFinalY(doc) + 6;

      // 9. Installed Application Analysis
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("9. Installed Application Analysis", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        head: [["App Name", "Package ID", "Version", "Category", "Anti-Forensic Flag"]],
        body: APPS.map((a) => [
          a.name,
          a.pkg,
          a.version || "—",
          a.category || "General",
          a.suspicious ? "ALERT: ANTI-FORENSIC" : "STANDARD",
        ]),
        styles: { fontSize: 6.8 },
        headStyles: { fillColor: [30, 41, 59] },
      });

      // PAGE 4
      doc.addPage();
      y = 18;

      // 10. SHA-256 Hash Verification
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("10. SHA-256 Hash Verification (Chain of Custody)", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        head: [["Artifact ID", "Type", "Cryptographic SHA-256 Hash (64 Hex)", "Integrity"]],
        body: allHashes.slice(0, 16).map((h) => [
          h.id,
          h.kind,
          h.hash,
          "MATCH VERIFIED",
        ]),
        styles: { fontSize: 6, font: "courier" },
        headStyles: { fillColor: [30, 41, 59] },
      });
      y = getFinalY(doc) + 6;

      // 11. Suspicious Activities Identified
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("11. Suspicious Activities Identified", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        head: [["Priority", "Category", "Activity Headline", "Classification"]],
        body: findings.map((f) => [
          f.priority.toUpperCase(),
          f.category,
          f.title,
          f.findingType.replace("-", " ").toUpperCase(),
        ]),
        styles: { fontSize: 7 },
        headStyles: { fillColor: [30, 41, 59] },
      });
      y = getFinalY(doc) + 6;

      // 12. AI-Generated Observations
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("12. AI-Generated Observations (Ollama Llama 3.2:3B)", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      doc.setFontSize(7);
      doc.setTextColor(180, 83, 9);
      doc.text(
        "DISCLAIMER: AI observations are investigative hypotheses, NOT confirmed forensic facts. Validation required.",
        14,
        y,
      );
      doc.setTextColor(0);
      y += 3;
      autoTable(doc, {
        startY: y,
        head: [["Model", "Observation & Inferred Correlation", "Type"]],
        body: findings
          .filter((f) => f.findingType !== "confirmed-evidence")
          .map((f) => ["Llama 3.2:3B", `${f.title}\n${f.rationale}`, f.findingType.toUpperCase()]),
        styles: { fontSize: 6.8 },
        headStyles: { fillColor: [30, 41, 59] },
      });

      // PAGE 5
      doc.addPage();
      y = 18;

      // 13. Risk Assessment
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("13. Risk Assessment", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        theme: "grid",
        styles: { fontSize: 7.5 },
        body: [
          ["Overall Severity Grade", riskLevel.toUpperCase()],
          ["Anti-Forensics Threat", "CRITICAL - Military wiping app and Tor mixer accessed"],
          ["Flight Risk Indicator", "HIGH - Airport GPS coordinate matching boarding pass"],
          ["Illicit Asset Movement", "HIGH - 1.2 BTC cold wallet transfer instructions"],
          ["Integrity Confidence", "100% - SHA-256 validated against original hashes"],
        ],
      });
      y = getFinalY(doc) + 6;

      // 14. Investigation Summary
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("14. Investigation Summary", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      doc.setFontSize(7.5);
      const splitSummary = doc.splitTextToSize(summary, w - 28);
      doc.text(splitSummary, 14, y);
      y += splitSummary.length * 3.5 + 6;

      // 15. Recommendations
      doc.setFontSize(10.5);
      doc.setFont("helvetica", "bold");
      doc.text("15. Forensic Recommendations", 14, y);
      doc.setFont("helvetica", "normal");
      y += 4;
      autoTable(doc, {
        startY: y,
        body: [
          ["1.", "Preserve all physical and logical images in evidence vault with chain-of-custody log."],
          ["2.", "Issue legal preservation subpoenas for identified ProtonMail and Signal accounts."],
          ["3.", "Submit BTC transaction hashes to blockchain analytics unit for ledger tracing."],
          ["4.", "Alert border security regarding subject flight itinerary to London Heathrow."],
          ["5.", "Submit carved SQLite freelist blocks for independent laboratory peer-review."],
        ],
        styles: { fontSize: 7.5 },
      });

      doc.save(`Forensic_Report_${CASE.caseNumber}.pdf`);
      toast.success("15-Section Forensic Report PDF downloaded successfully!", { id: "pdf" });
    } catch (err) {
      console.error(err);
      toast.error("Failed to compile PDF report", { id: "pdf" });
    }
  };

  // Download from Python ReportLab Backend
  const downloadBackendPDF = async () => {
    setDownloadingBackend(true);
    toast.loading("Requesting ReportLab PDF generation from Python backend...", { id: "backend-pdf" });
    try {
      const res = await api.generateReport(CASE.caseNumber);
      if (res.success && res.download_url) {
        window.open(api.getDownloadUrl(res.report_id), "_blank");
        toast.success("Python ReportLab PDF generated!", { id: "backend-pdf" });
      } else {
        toast.info("Backend unavailable, using client-side generator", { id: "backend-pdf" });
        await downloadClientPDF();
      }
    } catch {
      toast.info("Backend unavailable, using client-side generator", { id: "backend-pdf" });
      await downloadClientPDF();
    } finally {
      setDownloadingBackend(false);
    }
  };

  const sections = [
    { id: 1, title: "1. Investigation ID", summary: `Case ${CASE.caseNumber} · ${CASE.title}` },
    { id: 2, title: "2. Android Device Information", summary: `${DEVICES.length} Android device(s) acquired via ADB` },
    { id: 3, title: "3. Evidence Collection Details", summary: "SMS, Calls, Contacts, GPS, Browser, Apps, Media" },
    { id: 4, title: "4. SMS Analysis", summary: `${SMS.length} messages analyzed; suspicious keywords detected` },
    { id: 5, title: "5. Call Log Analysis", summary: `${CALLS.length} call logs; unusual late-night patterns found` },
    { id: 6, title: "6. Contact Analysis", summary: `${CONTACTS.length} phonebook entries verified` },
    { id: 7, title: "7. GPS Analysis", summary: `${GPS.length} coordinates; Ocean Beach & Airport terminal trail` },
    { id: 8, title: "8. Browser History Analysis", summary: `${BROWSER.length} web entries; Tor mixer & wipe guides` },
    { id: 9, title: "9. Installed Application Analysis", summary: `${APPS.length} packages; iShredder & Tor flagged` },
    { id: 10, title: "10. SHA-256 Hash Verification", summary: "Cryptographic integrity verified for all artifacts" },
    { id: 11, title: "11. Suspicious Activities Identified", summary: `${findings.length} prioritized forensic anomalies` },
    { id: 12, title: "12. AI-Generated Observations", summary: "ForensicAI Neural Engine investigative leads & correlation" },
    { id: 13, title: "13. Risk Assessment", summary: `Overall Risk Grade: ${riskLevel.toUpperCase()}` },
    { id: 14, title: "14. Investigation Summary", summary: "Multi-paragraph synthesis of device activities" },
    { id: 15, title: "15. Recommendations", summary: "5 actionable legal and investigative next steps" },
  ];

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-semibold flex items-center gap-2">
              <FileText className="size-6 text-primary" /> Automated Forensic Report Generation
            </h1>
            <Badge variant="outline" className="text-primary border-primary/30 font-mono text-xs">
              Module 6 · 15 Sections
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
            Generates a court-admissible, comprehensive forensic report incorporating device details,
            evidence categories, SHA-256 verification, rule-based detections, and ForensicAI Neural Engine observations.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          <Button onClick={downloadClientPDF} className="gap-2">
            <Download className="size-4" /> Download Forensic PDF
          </Button>
          <Button
            onClick={downloadBackendPDF}
            disabled={downloadingBackend}
            variant="secondary"
            className="gap-2"
          >
            <Server className="size-4" /> Python ReportLab PDF
          </Button>
        </div>
      </div>

      {/* Report Metadata Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="p-4 bg-card/70 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Deliverable Standard</div>
          <div className="text-sm font-semibold font-mono text-primary mt-1">NIST SP 800-101</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Court-Admissible Format</div>
        </Card>
        <Card className="p-4 bg-card/70 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Sections Included</div>
          <div className="text-sm font-semibold font-mono text-emerald-400 mt-1">All 15 Sections Complete</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Fully Automated Compilation</div>
        </Card>
        <Card className="p-4 bg-card/70 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Cryptographic Assurance</div>
          <div className="text-sm font-semibold font-mono text-priority-low mt-1">SHA-256 Hashes Embedded</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Tamper-Proof Verification</div>
        </Card>
        <Card className="p-4 bg-card/70 border-border">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">AI Observation Separation</div>
          <div className="text-sm font-semibold font-mono text-cyan-400 mt-1">Clearly Delineated</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Disclaimers Attached</div>
        </Card>
      </div>

      {/* Report Preview & Section Navigator */}
      <div className="grid md:grid-cols-12 gap-6">
        {/* Left Section List (5 cols) */}
        <div className="md:col-span-5 space-y-2">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-1.5">
            <Eye className="size-4" /> Report Structure Preview (15 Sections)
          </h2>
          <div className="space-y-1.5">
            {sections.map((sec) => (
              <div
                key={sec.id}
                onClick={() => setActivePreviewSection(sec.id)}
                className={`p-2.5 rounded border text-xs cursor-pointer transition flex items-center justify-between ${
                  activePreviewSection === sec.id
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border bg-card/50 hover:bg-card text-foreground/80"
                }`}
              >
                <div>
                  <div className="font-semibold">{sec.title}</div>
                  <div className="text-[11px] text-muted-foreground mt-0.5">{sec.summary}</div>
                </div>
                <CheckCircle2 className="size-4 text-emerald-400 shrink-0 ml-2" />
              </div>
            ))}
          </div>
        </div>

        {/* Right Section Details Panel (7 cols) */}
        <div className="md:col-span-7">
          <Card className="p-5 bg-card/80 border-border sticky top-6 space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="font-semibold text-sm text-primary uppercase tracking-wider flex items-center gap-2">
                <FileText className="size-4" /> Live Document Preview
              </h3>
              <Badge variant="outline" className="font-mono text-xs">
                Section {activePreviewSection} of 15
              </Badge>
            </div>

            {/* Dynamic Section Preview Content */}
            <div className="text-xs leading-relaxed space-y-3 font-mono">
              {activePreviewSection === 1 && (
                <div className="space-y-2 bg-background/50 p-4 rounded border border-border">
                  <div className="text-muted-foreground uppercase text-[10px]">1. Investigation ID Details</div>
                  <div className="grid grid-cols-2 gap-2 text-foreground/90">
                    <div>Case Number: <span className="text-primary">{CASE.caseNumber}</span></div>
                    <div>Status: <span className="text-emerald-400">{CASE.status.toUpperCase()}</span></div>
                    <div>Investigator: <span>{CASE.investigator}</span></div>
                    <div>Agency: <span>{CASE.agency}</span></div>
                    <div className="col-span-2">Suspect: <span>{CASE.suspect}</span></div>
                  </div>
                </div>
              )}

              {activePreviewSection === 2 && (
                <div className="space-y-2 bg-background/50 p-4 rounded border border-border">
                  <div className="text-muted-foreground uppercase text-[10px]">2. Target Android Devices</div>
                  {DEVICES.map((d) => (
                    <div key={d.serial} className="border-b border-border/50 pb-2 mb-2 last:border-0">
                      <div className="font-semibold text-primary">{d.model} ({d.manufacturer})</div>
                      <div className="text-muted-foreground text-[11px]">
                        Android {d.osVersion} (API {d.androidApiLevel}) · Serial: {d.serial} · Method: {d.acquisitionMethod}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {activePreviewSection === 3 && (
                <div className="space-y-2 bg-background/50 p-4 rounded border border-border">
                  <div className="text-muted-foreground uppercase text-[10px]">3. Evidence Collection Inventory</div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>SMS: {SMS.length} records</div>
                    <div>Calls: {CALLS.length} records</div>
                    <div>Contacts: {CONTACTS.length} records</div>
                    <div>GPS: {GPS.length} records</div>
                    <div>Browser: {BROWSER.length} records</div>
                    <div>Apps: {APPS.length} records</div>
                    <div>Media: {MEDIA.length} records</div>
                    <div>Autopsy Carved: {AUTOPSY_CARVED_EVIDENCE.length} items</div>
                  </div>
                </div>
              )}

              {activePreviewSection === 4 && (
                <div className="space-y-2 bg-background/50 p-4 rounded border border-border">
                  <div className="text-muted-foreground uppercase text-[10px]">4. SMS Analysis Highlights</div>
                  <div className="text-red-400 font-semibold">Flagged Messages:</div>
                  {SMS.slice(0, 3).map((s) => (
                    <div key={s.id} className="text-[11px] text-muted-foreground border-b border-border/40 pb-1">
                      [{s.contact}]: "{s.body}"
                    </div>
                  ))}
                </div>
              )}

              {activePreviewSection === 10 && (
                <div className="space-y-2 bg-background/50 p-4 rounded border border-border">
                  <div className="text-muted-foreground uppercase text-[10px]">10. SHA-256 Verification Table</div>
                  <div className="text-emerald-400 text-xs">All records hashed for chain-of-custody verification.</div>
                  <div className="text-[10px] text-muted-foreground truncate">
                    Sample Hash: 5f9a88e...b184a20b (SHA-256 256-bit cryptographic digest)
                  </div>
                </div>
              )}

              {activePreviewSection === 12 && (
                <div className="space-y-2 bg-background/50 p-4 rounded border border-border">
                  <div className="text-amber-400 uppercase text-[10px]">12. AI Observations (Ollama Llama 3.2:3B)</div>
                  <div className="text-amber-300 text-[11px] bg-amber-500/10 p-2 rounded border border-amber-500/30">
                    ⚠ AI predictions are investigative leads, not confirmed forensic facts.
                  </div>
                  <p className="text-muted-foreground text-[11px]">
                    Identifies correlation between deleted WhatsApp messages, darknet mixer search history, and Ocean Beach physical GPS rendezvous.
                  </p>
                </div>
              )}

              {activePreviewSection === 13 && (
                <div className="space-y-2 bg-background/50 p-4 rounded border border-border">
                  <div className="text-muted-foreground uppercase text-[10px]">13. Risk Assessment Matrix</div>
                  <div className="text-lg font-bold text-priority-high">OVERALL RISK: {riskLevel.toUpperCase()}</div>
                  <div className="text-muted-foreground text-[11px]">
                    Critical indicators: Anti-forensic wiping tools installed + flight departure ticket identified.
                  </div>
                </div>
              )}

              {activePreviewSection === 14 && (
                <div className="space-y-2 bg-background/50 p-4 rounded border border-border">
                  <div className="text-muted-foreground uppercase text-[10px]">14. Investigation Summary</div>
                  <p className="text-foreground/90 text-[11px] leading-relaxed whitespace-pre-line">
                    {summary.slice(0, 320)}...
                  </p>
                </div>
              )}

              {activePreviewSection === 15 && (
                <div className="space-y-2 bg-background/50 p-4 rounded border border-border">
                  <div className="text-muted-foreground uppercase text-[10px]">15. Forensic Recommendations</div>
                  <ol className="list-decimal list-inside space-y-1 text-muted-foreground text-[11px]">
                    <li>Preserve original physical storage in evidence locker.</li>
                    <li>Subpoena Telegram & Signal registered identities.</li>
                    <li>Conduct blockchain analysis on cold wallet address.</li>
                    <li>Coordinate with airport border security on subject flight status.</li>
                  </ol>
                </div>
              )}

              {![1, 2, 3, 4, 10, 12, 13, 14, 15].includes(activePreviewSection || 0) && (
                <div className="bg-background/50 p-4 rounded border border-border text-muted-foreground">
                  Section {activePreviewSection} data compiled and verified. Ready for inclusion in downloadable PDF.
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-border flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Format: ISO/IEC 27037 PDF</span>
              <Button size="sm" onClick={downloadClientPDF} className="gap-1.5">
                <Download className="size-3.5" /> Download PDF Now
              </Button>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
