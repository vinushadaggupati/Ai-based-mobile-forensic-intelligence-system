// AI-Based Mobile Forensic Intelligence System
// Android-only forensic data layer with SHA-256 integrity verification
// NOTE: This is sample/demo data for testing when a physical device is unavailable.
// All data is clearly labeled as [SAMPLE DATA] in the UI.

export type Priority = "high" | "medium" | "low";
export type DataSource = "adb-live" | "sample-data" | "imported";

export interface DeviceInfo {
  id: string;
  model: string;
  manufacturer: string;
  os: "Android";
  osVersion: string;
  androidApiLevel: number;
  serial: string;
  imei: string;
  phoneNumber?: string;
  acquisitionMethod: "ADB" | "ADB-Backup" | "Physical";
  acquiredAt: string;
  status: "connected" | "acquired" | "acquiring" | "disconnected" | "pending";
  storageUsed: string;
  batteryLevel?: number;
  usbDebugging: boolean;
  dataSource: DataSource;
}

export interface CaseInfo {
  caseNumber: string;
  title: string;
  investigator: string;
  agency: string;
  openedAt: string;
  status: "active" | "closed";
  suspect: string;
  description: string;
}

export interface SmsRecord {
  id: string;
  direction: "in" | "out";
  contact: string;
  number: string;
  timestamp: string;
  body: string;
  threadId?: string;
  read: boolean;
  dataSource: DataSource;
}

export interface CallRecord {
  id: string;
  type: "incoming" | "outgoing" | "missed" | "rejected";
  contact: string;
  number: string;
  timestamp: string;
  durationSec: number;
  dataSource: DataSource;
}

export interface ContactRecord {
  id: string;
  name: string;
  number: string;
  email?: string;
  organization?: string;
  notes?: string;
  dataSource: DataSource;
}

export interface GpsRecord {
  id: string;
  lat: number;
  lng: number;
  place: string;
  timestamp: string;
  accuracyM: number;
  altitude?: number;
  provider?: string;
  dataSource: DataSource;
}

export interface BrowserRecord {
  id: string;
  title: string;
  url: string;
  timestamp: string;
  visits: number;
  browser: string;
  dataSource: DataSource;
}

export interface AppRecord {
  id: string;
  name: string;
  pkg: string;
  installedAt: string;
  updatedAt?: string;
  version?: string;
  permissions: string[];
  suspicious: boolean;
  category?: string;
  dataSource: DataSource;
}

export interface MediaRecord {
  id: string;
  type: "photo" | "video" | "audio" | "document";
  filename: string;
  sizeKB: number;
  createdAt: string;
  path?: string;
  sha256?: string;
  dataSource: DataSource;
}

// ─── CASE INFORMATION ────────────────────────────────────────────────────────

export const CASE: CaseInfo = {
  caseNumber: "MFIS-2026-0042",
  title: "Operation Nighthawk – Android Device Forensic Investigation",
  investigator: "Forensic Analyst",
  agency: "Digital Forensics Unit",
  openedAt: "2026-11-02T09:00:00Z",
  status: "active",
  suspect: "Subject Alpha (device owner)",
  description:
    "Investigation of suspected data exfiltration and evidence tampering on Android device. Evidence collected via ADB logical acquisition.",
};

// ─── ANDROID DEVICES (Android-only) ──────────────────────────────────────────

export const DEVICES: DeviceInfo[] = [
  {
    id: "dev-android-01",
    model: "Samsung Galaxy S23",
    manufacturer: "Samsung",
    os: "Android",
    osVersion: "14 (One UI 6.1)",
    androidApiLevel: 34,
    serial: "R58N90ABCD1",
    imei: "356938035643809",
    phoneNumber: "+1-415-555-0100",
    acquisitionMethod: "ADB",
    acquiredAt: "2026-11-02T10:22:11Z",
    status: "acquired",
    storageUsed: "184.2 GB / 256 GB",
    batteryLevel: 67,
    usbDebugging: true,
    dataSource: "sample-data",
  },
  {
    id: "dev-android-02",
    model: "Google Pixel 7a",
    manufacturer: "Google",
    os: "Android",
    osVersion: "13 (QPR3)",
    androidApiLevel: 33,
    serial: "GX9K12MNP3",
    imei: "490154203237518",
    acquisitionMethod: "ADB-Backup",
    acquiredAt: "2026-11-02T11:45:00Z",
    status: "acquired",
    storageUsed: "52.8 GB / 128 GB",
    batteryLevel: 42,
    usbDebugging: true,
    dataSource: "sample-data",
  },
];

// ─── SMS MESSAGES ─────────────────────────────────────────────────────────────

export const SMS: SmsRecord[] = [
  {
    id: "s1",
    direction: "in",
    contact: "Kai M.",
    number: "+1-415-555-0132",
    timestamp: "2026-10-30T22:14:00Z",
    body: "did you get the drop? use the encrypted channel next time",
    read: true,
    dataSource: "sample-data",
  },
  {
    id: "s2",
    direction: "out",
    contact: "Kai M.",
    number: "+1-415-555-0132",
    timestamp: "2026-10-30T22:17:00Z",
    body: "yeah wallet address confirmed. burn the phone after",
    read: true,
    dataSource: "sample-data",
  },
  {
    id: "s3",
    direction: "in",
    contact: "Mom",
    number: "+1-408-555-0199",
    timestamp: "2026-10-31T08:02:00Z",
    body: "don't forget lunch on sunday <3",
    read: true,
    dataSource: "sample-data",
  },
  {
    id: "s4",
    direction: "out",
    contact: "Unknown (+44)",
    number: "+44-20-7946-0812",
    timestamp: "2026-10-31T02:41:00Z",
    body: "transfer 0.6 BTC to the cold wallet tonight",
    read: true,
    dataSource: "sample-data",
  },
  {
    id: "s5",
    direction: "in",
    contact: "Bank Alert",
    number: "26426",
    timestamp: "2026-11-01T09:15:00Z",
    body: "Your OTP is 481932. Do not share.",
    read: true,
    dataSource: "sample-data",
  },
  {
    id: "s6",
    direction: "in",
    contact: "Kai M.",
    number: "+1-415-555-0132",
    timestamp: "2026-11-01T01:04:00Z",
    body: "delete the logs and wipe the sd card",
    read: false,
    dataSource: "sample-data",
  },
  {
    id: "s7",
    direction: "out",
    contact: "Alex",
    number: "+1-650-555-0177",
    timestamp: "2026-10-29T18:30:00Z",
    body: "grabbing coffee at 5, cool?",
    read: true,
    dataSource: "sample-data",
  },
  {
    id: "s8",
    direction: "in",
    contact: "Unknown (+7)",
    number: "+7-495-555-0143",
    timestamp: "2026-10-30T23:55:00Z",
    body: "btc mixer confirmed, use channel 4",
    read: false,
    dataSource: "sample-data",
  },
];

// ─── CALL LOGS ────────────────────────────────────────────────────────────────

export const CALLS: CallRecord[] = [
  {
    id: "c1",
    type: "outgoing",
    contact: "Kai M.",
    number: "+1-415-555-0132",
    timestamp: "2026-10-30T22:20:00Z",
    durationSec: 412,
    dataSource: "sample-data",
  },
  {
    id: "c2",
    type: "incoming",
    contact: "Unknown (+44)",
    number: "+44-20-7946-0812",
    timestamp: "2026-10-31T02:38:00Z",
    durationSec: 187,
    dataSource: "sample-data",
  },
  {
    id: "c3",
    type: "missed",
    contact: "Unknown (+7)",
    number: "+7-495-555-0143",
    timestamp: "2026-10-31T03:11:00Z",
    durationSec: 0,
    dataSource: "sample-data",
  },
  {
    id: "c4",
    type: "outgoing",
    contact: "Mom",
    number: "+1-408-555-0199",
    timestamp: "2026-11-01T19:04:00Z",
    durationSec: 621,
    dataSource: "sample-data",
  },
  {
    id: "c5",
    type: "incoming",
    contact: "Kai M.",
    number: "+1-415-555-0132",
    timestamp: "2026-10-31T01:12:00Z",
    durationSec: 89,
    dataSource: "sample-data",
  },
  {
    id: "c6",
    type: "rejected",
    contact: "Unknown (+86)",
    number: "+86-10-5551-0288",
    timestamp: "2026-10-31T04:02:00Z",
    durationSec: 0,
    dataSource: "sample-data",
  },
];

// ─── CONTACTS ─────────────────────────────────────────────────────────────────

export const CONTACTS: ContactRecord[] = [
  {
    id: "con1",
    name: "Kai M.",
    number: "+1-415-555-0132",
    email: "kai@protonmail.com",
    dataSource: "sample-data",
  },
  {
    id: "con2",
    name: "Mom",
    number: "+1-408-555-0199",
    email: "mom@gmail.com",
    dataSource: "sample-data",
  },
  {
    id: "con3",
    name: "Alex",
    number: "+1-650-555-0177",
    organization: "Tech Corp",
    dataSource: "sample-data",
  },
  {
    id: "con4",
    name: "Work IT",
    number: "+1-800-555-0100",
    organization: "IT Department",
    dataSource: "sample-data",
  },
  {
    id: "con5",
    name: "Dr. Patel",
    number: "+1-408-555-0250",
    organization: "Valley Medical",
    dataSource: "sample-data",
  },
];

// ─── GPS RECORDS ──────────────────────────────────────────────────────────────

export const GPS: GpsRecord[] = [
  {
    id: "g1",
    lat: 37.7749,
    lng: -122.4194,
    place: "San Francisco – Financial District",
    timestamp: "2026-10-30T21:44:00Z",
    accuracyM: 8,
    provider: "GPS",
    dataSource: "sample-data",
  },
  {
    id: "g2",
    lat: 37.7599,
    lng: -122.4148,
    place: "Mission District – 16th & Valencia",
    timestamp: "2026-10-30T22:12:00Z",
    accuracyM: 12,
    provider: "GPS",
    dataSource: "sample-data",
  },
  {
    id: "g3",
    lat: 37.7286,
    lng: -122.4756,
    place: "Ocean Beach – Parking Lot 4",
    timestamp: "2026-10-31T02:35:00Z",
    accuracyM: 6,
    provider: "GPS",
    dataSource: "sample-data",
  },
  {
    id: "g4",
    lat: 37.6213,
    lng: -122.379,
    place: "SFO Airport – Terminal 2",
    timestamp: "2026-10-31T04:18:00Z",
    accuracyM: 5,
    provider: "GPS",
    dataSource: "sample-data",
  },
  {
    id: "g5",
    lat: 37.4419,
    lng: -122.143,
    place: "Palo Alto – Home Address",
    timestamp: "2026-11-01T18:02:00Z",
    accuracyM: 10,
    provider: "network",
    dataSource: "sample-data",
  },
];

// ─── BROWSER HISTORY ──────────────────────────────────────────────────────────

export const BROWSER: BrowserRecord[] = [
  {
    id: "b1",
    title: "How to wipe Android securely",
    url: "https://forums.xda-developers.com/wipe-guide",
    timestamp: "2026-11-01T23:11:00Z",
    visits: 4,
    browser: "Chrome",
    dataSource: "sample-data",
  },
  {
    id: "b2",
    title: "Bitcoin mixing services 2026",
    url: "https://darkforum.onion/mixers",
    timestamp: "2026-10-30T20:44:00Z",
    visits: 7,
    browser: "Tor Browser",
    dataSource: "sample-data",
  },
  {
    id: "b3",
    title: "Weather – SFGate",
    url: "https://sfgate.com/weather",
    timestamp: "2026-10-29T09:12:00Z",
    visits: 2,
    browser: "Chrome",
    dataSource: "sample-data",
  },
  {
    id: "b4",
    title: "ProtonMail login",
    url: "https://mail.proton.me/login",
    timestamp: "2026-10-31T02:02:00Z",
    visits: 12,
    browser: "Chrome",
    dataSource: "sample-data",
  },
  {
    id: "b5",
    title: "Signal – Secure Messenger Download",
    url: "https://signal.org/download",
    timestamp: "2026-10-28T15:22:00Z",
    visits: 1,
    browser: "Chrome",
    dataSource: "sample-data",
  },
  {
    id: "b6",
    title: "Cold wallet setup guide",
    url: "https://coldcard.com/docs/quick-start",
    timestamp: "2026-10-30T19:30:00Z",
    visits: 3,
    browser: "Chrome",
    dataSource: "sample-data",
  },
];

// ─── INSTALLED APPLICATIONS ───────────────────────────────────────────────────

export const APPS: AppRecord[] = [
  {
    id: "a1",
    name: "Signal",
    pkg: "org.thoughtcrime.securesms",
    installedAt: "2026-10-28T15:24:00Z",
    version: "6.45.3",
    permissions: ["contacts", "sms", "camera", "mic", "storage"],
    suspicious: false,
    category: "Communication",
    dataSource: "sample-data",
  },
  {
    id: "a2",
    name: "Telegram",
    pkg: "org.telegram.messenger",
    installedAt: "2026-06-10T11:00:00Z",
    version: "10.12.1",
    permissions: ["contacts", "storage", "mic", "camera"],
    suspicious: false,
    category: "Communication",
    dataSource: "sample-data",
  },
  {
    id: "a3",
    name: "Orbot: Tor for Android",
    pkg: "org.torproject.android",
    installedAt: "2026-10-29T02:14:00Z",
    version: "16.6.3",
    permissions: ["network", "boot"],
    suspicious: true,
    category: "Privacy / Anti-Forensic",
    dataSource: "sample-data",
  },
  {
    id: "a4",
    name: "Wickr Me",
    pkg: "com.mywickr.wickr2",
    installedAt: "2026-10-29T02:20:00Z",
    version: "5.111.0",
    permissions: ["contacts", "mic", "camera", "storage"],
    suspicious: true,
    category: "Privacy / Anti-Forensic",
    dataSource: "sample-data",
  },
  {
    id: "a5",
    name: "iShredder Professional",
    pkg: "com.protectstar.ishredder",
    installedAt: "2026-11-01T22:50:00Z",
    version: "7.2.0",
    permissions: ["storage", "admin"],
    suspicious: true,
    category: "Privacy / Anti-Forensic",
    dataSource: "sample-data",
  },
  {
    id: "a6",
    name: "Google Chrome",
    pkg: "com.android.chrome",
    installedAt: "2024-01-14T08:00:00Z",
    version: "120.0.6099.230",
    permissions: ["network", "location", "storage"],
    suspicious: false,
    category: "Browser",
    dataSource: "sample-data",
  },
  {
    id: "a7",
    name: "Exodus Crypto Wallet",
    pkg: "exodusmovement.exodus",
    installedAt: "2026-10-28T20:10:00Z",
    version: "24.8.9",
    permissions: ["network", "biometrics", "camera"],
    suspicious: true,
    category: "Finance / Crypto",
    dataSource: "sample-data",
  },
];

// ─── MEDIA FILES ──────────────────────────────────────────────────────────────

export const MEDIA: MediaRecord[] = [
  {
    id: "m1",
    type: "photo",
    filename: "IMG_20261030_2201.jpg",
    sizeKB: 3421,
    createdAt: "2026-10-30T22:01:00Z",
    path: "/sdcard/DCIM/Camera/IMG_20261030_2201.jpg",
    dataSource: "sample-data",
  },
  {
    id: "m2",
    type: "photo",
    filename: "IMG_20261031_0233.jpg",
    sizeKB: 2988,
    createdAt: "2026-10-31T02:33:00Z",
    path: "/sdcard/DCIM/Camera/IMG_20261031_0233.jpg",
    dataSource: "sample-data",
  },
  {
    id: "m3",
    type: "video",
    filename: "VID_20261031_0240.mp4",
    sizeKB: 41220,
    createdAt: "2026-10-31T02:40:00Z",
    path: "/sdcard/DCIM/Camera/VID_20261031_0240.mp4",
    dataSource: "sample-data",
  },
  {
    id: "m4",
    type: "document",
    filename: "wallet_backup.txt",
    sizeKB: 4,
    createdAt: "2026-10-30T21:12:00Z",
    path: "/sdcard/Documents/wallet_backup.txt",
    dataSource: "sample-data",
  },
  {
    id: "m5",
    type: "document",
    filename: "meeting_notes.pdf",
    sizeKB: 218,
    createdAt: "2026-10-29T14:00:00Z",
    path: "/sdcard/Documents/meeting_notes.pdf",
    dataSource: "sample-data",
  },
  {
    id: "m6",
    type: "audio",
    filename: "voice_memo_1031.m4a",
    sizeKB: 890,
    createdAt: "2026-10-31T03:05:00Z",
    path: "/sdcard/Recordings/voice_memo_1031.m4a",
    dataSource: "sample-data",
  },
];

// ─── SHA-256 INTEGRITY VERIFICATION ──────────────────────────────────────────

export async function sha256(text: string): Promise<string> {
  const buf = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function computeEvidenceHashes() {
  const items: { id: string; kind: string; label: string; hash: string }[] = [];
  const push = async (id: string, kind: string, label: string, payload: string) => {
    items.push({ id, kind, label, hash: await sha256(payload) });
  };
  for (const r of SMS) await push(r.id, "SMS", `${r.contact} ${r.timestamp}`, JSON.stringify(r));
  for (const r of CALLS)
    await push(r.id, "Call", `${r.contact} ${r.timestamp}`, JSON.stringify(r));
  for (const r of CONTACTS) await push(r.id, "Contact", r.name, JSON.stringify(r));
  for (const r of GPS) await push(r.id, "GPS", r.place, JSON.stringify(r));
  for (const r of BROWSER) await push(r.id, "Browser", r.title, JSON.stringify(r));
  for (const r of APPS) await push(r.id, "App", r.name, JSON.stringify(r));
  for (const r of MEDIA) await push(r.id, "Media", r.filename, JSON.stringify(r));
  return items;
}

export function getTotalEvidenceCount(): number {
  return (
    SMS.length +
    CALLS.length +
    CONTACTS.length +
    GPS.length +
    BROWSER.length +
    APPS.length +
    MEDIA.length
  );
}
