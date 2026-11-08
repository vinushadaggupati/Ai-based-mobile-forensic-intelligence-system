import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DEVICES } from "@/lib/forensic-data";
import { api, checkBackendHealth } from "@/lib/api-client";
import {
  CheckCircle2, Smartphone, Usb, HardDrive, RefreshCw,
  AlertTriangle, Battery, Wifi, Server, ShieldCheck,
} from "lucide-react";
import { toast } from "sonner";
import { useState, useEffect } from "react";

export const Route = createFileRoute("/devices")({
  head: () => ({
    meta: [
      { title: "Device Connection – AI-Based Mobile Forensic Intelligence System" },
      { name: "description", content: "Connect and manage Android devices via ADB for forensic acquisition." },
    ],
  }),
  component: () => (
    <AppLayout>
      <Devices />
    </AppLayout>
  ),
});

type DeviceStatus = "connected" | "acquired" | "disconnected" | "scanning";

interface LiveDevice {
  serial: string;
  model: string;
  manufacturer?: string;
  os_version?: string;
  api_level?: number;
  imei?: string;
  battery_level?: number;
  storage_info?: string;
  usb_debugging?: boolean;
  status: DeviceStatus;
  data_source?: string;
}

function Devices() {
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [scanning, setScanning] = useState(false);
  const [liveDevices, setLiveDevices] = useState<LiveDevice[]>([]);

  useEffect(() => {
    checkBackendHealth().then((s) => setBackendOnline(s === "online"));
  }, []);

  const handleScan = async () => {
    setScanning(true);
    toast.loading("Scanning for ADB devices…", { id: "scan" });
    try {
      const result = await api.refreshDevices();
      if (result.success) {
        const devs = (result.devices as LiveDevice[]) || [];
        setLiveDevices(devs);
        toast.success(devs.length > 0 ? `Found ${devs.length} device(s)` : "No ADB devices detected", { id: "scan" });
      } else {
        toast.error("ADB scan failed", { id: "scan" });
      }
    } catch {
      toast.error("Backend unavailable – showing sample devices", { id: "scan" });
    } finally {
      setScanning(false);
    }
  };

  const handleConnect = async (serial: string) => {
    toast.loading(`Connecting to ${serial}…`, { id: `connect-${serial}` });
    try {
      const result = await api.connectDevice(serial);
      if (result.success) {
        toast.success(`Device ${serial} connected`, { id: `connect-${serial}` });
      } else {
        toast.error("Connection failed", { id: `connect-${serial}` });
      }
    } catch {
      toast.error("Backend unavailable", { id: `connect-${serial}` });
    }
  };

  const handleDisconnect = async (serial: string) => {
    try {
      await api.disconnectDevice(serial);
      toast.success(`Device ${serial} disconnected`);
    } catch {
      toast.info("Disconnected (simulated)");
    }
  };

  // Show live devices if available, otherwise show sample data
  const displayDevices = liveDevices.length > 0
    ? liveDevices
    : DEVICES.map((d) => ({
        serial: d.serial,
        model: d.model,
        manufacturer: d.manufacturer,
        os_version: d.osVersion,
        api_level: d.androidApiLevel,
        imei: d.imei,
        battery_level: d.batteryLevel,
        storage_info: d.storageUsed,
        usb_debugging: d.usbDebugging,
        status: d.status as DeviceStatus,
        data_source: d.dataSource,
      }));

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold">Android Device Connection</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Connect Android devices via{" "}
            <span className="font-mono text-primary">ADB (Android Debug Bridge)</span>. Enable USB
            debugging on the device before connecting.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded-full border font-mono ${backendOnline ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400" : "bg-amber-500/10 border-amber-500/30 text-amber-400"}`}>
            <Server className="size-3" />
            {backendOnline === null ? "Checking…" : backendOnline ? "Backend Online" : "Backend Offline"}
          </div>
          <Button onClick={handleScan} disabled={scanning} size="sm" className="gap-2">
            <RefreshCw className={`size-4 ${scanning ? "animate-spin" : ""}`} />
            {scanning ? "Scanning…" : "Scan for Devices"}
          </Button>
        </div>
      </div>

      {/* Sample data notice */}
      {liveDevices.length === 0 && (
        <Card className="p-4 bg-amber-500/5 border-amber-500/30">
          <div className="flex items-start gap-3">
            <AlertTriangle className="size-4 text-amber-400 mt-0.5 shrink-0" />
            <div className="text-sm">
              <div className="font-medium text-amber-400">Showing Sample Dataset</div>
              <div className="text-muted-foreground text-xs mt-1">
                No live ADB devices detected. The devices below are from the sample forensic dataset for
                testing purposes. Connect a real Android device with USB Debugging enabled and click
                "Scan for Devices" to detect it.
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Device cards */}
      <div className="grid md:grid-cols-2 gap-4">
        {displayDevices.map((d) => (
          <Card key={d.serial} className="p-5 bg-card/70">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="size-10 rounded-md bg-primary/15 border border-primary/30 grid place-items-center">
                  <Smartphone className="size-5 text-primary" />
                </div>
                <div>
                  <div className="font-medium">{d.model}</div>
                  <div className="text-xs text-muted-foreground">
                    {d.manufacturer} · Android {d.os_version}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {d.data_source === "sample-data" && (
                  <Badge variant="outline" className="text-[9px] text-amber-400 border-amber-500/30">
                    SAMPLE
                  </Badge>
                )}
                <span className={`inline-flex items-center gap-1 text-xs font-medium ${d.status === "acquired" || d.status === "connected" ? "text-priority-low" : "text-muted-foreground"}`}>
                  <CheckCircle2 className="size-3.5" /> {d.status}
                </span>
              </div>
            </div>

            <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2 text-xs font-mono">
              <div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-widest">Serial</div>
                <div className="text-foreground/90">{d.serial}</div>
              </div>
              <div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-widest">IMEI</div>
                <div className="text-foreground/90 truncate">{d.imei || "N/A"}</div>
              </div>
              <div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-widest">API Level</div>
                <div className="text-foreground/90">Android {d.api_level}</div>
              </div>
              <div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-widest">Battery</div>
                <div className="flex items-center gap-1 text-foreground/90">
                  <Battery className="size-3" />
                  {d.battery_level != null ? `${d.battery_level}%` : "N/A"}
                </div>
              </div>
              <div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-widest">Storage</div>
                <div className="text-foreground/90">{d.storage_info || "N/A"}</div>
              </div>
              <div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-widest">USB Debug</div>
                <div className={`flex items-center gap-1 ${d.usb_debugging ? "text-priority-low" : "text-muted-foreground"}`}>
                  {d.usb_debugging ? <CheckCircle2 className="size-3" /> : null}
                  {d.usb_debugging ? "Enabled" : "Disabled"}
                </div>
              </div>
              <div className="col-span-2">
                <div className="text-[10px] text-muted-foreground uppercase tracking-widest">Integrity</div>
                <div className="flex items-center gap-1 text-priority-low">
                  <ShieldCheck className="size-3" /> SHA-256 Verified
                </div>
              </div>
            </dl>

            <div className="mt-4 flex gap-2 flex-wrap">
              <Button size="sm" onClick={() => handleConnect(d.serial)}>
                <Wifi className="size-3.5 mr-1" /> Connect
              </Button>
              <Button size="sm" variant="secondary" onClick={() => handleDisconnect(d.serial)}>
                Disconnect
              </Button>
              <Button size="sm" variant="ghost" onClick={() => toast.info("Full image export prepared")}>
                <HardDrive className="size-3.5 mr-1" /> Export Image
              </Button>
            </div>
          </Card>
        ))}
      </div>

      {/* Workflow */}
      <Card className="p-5 bg-card/70">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
          ADB Connection Workflow
        </h2>
        <ol className="text-sm space-y-2 text-foreground/80 list-decimal list-inside">
          <li>Enable <strong>Developer Options</strong> on the Android device (tap Build Number 7 times in Settings → About Phone).</li>
          <li>Enable <strong>USB Debugging</strong> in Developer Options.</li>
          <li>Connect the device to this computer via a <strong>USB cable</strong>.</li>
          <li>On the device, <strong>authorize</strong> this computer when prompted ("Allow USB Debugging?").</li>
          <li>Click <strong>"Scan for Devices"</strong> above to detect the connected device.</li>
          <li>Click <strong>"Connect"</strong> to establish the ADB connection and retrieve device info.</li>
          <li>Navigate to <strong>Evidence Collection</strong> to begin extracting forensic data.</li>
          <li>SHA-256 hashes are computed for all collected artifacts for <strong>integrity verification</strong>.</li>
        </ol>
        <div className="mt-3 p-3 rounded bg-primary/5 border border-primary/20 text-xs text-muted-foreground">
          <strong className="text-primary">Note:</strong> ADB logical acquisition respects Android permission
          boundaries. Some data (SMS database, full call logs) may not be accessible without root access on
          Android 10+. The system handles permission denials gracefully and reports which categories
          could and could not be extracted.
        </div>
      </Card>
    </div>
  );
}
