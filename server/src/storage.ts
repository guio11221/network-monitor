import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Discovery } from './network.js';
import { classifyDevice, type TcpPort } from './enrichment.js';

export type Status = 'online' | 'observed' | 'offline';
export type Device = { id: string; network_id: string; ip: string; mac: string | null; name: string | null; status: Status; first_seen: string; last_seen: string; hostname: string | null; vendor: string | null; kind: string; ports: TcpPort[]; ports_scanned_at: string | null; trusted: number; notes:string; tags:string[] };
export type Event = { id: number; network_id: string; device_id: string; ip: string; kind: string; created_at: string };

const dataDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'network-monitor.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  mac TEXT,
  name TEXT,
  status TEXT NOT NULL CHECK(status IN ('online','observed','offline')),
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS devices_network ON devices(network_id);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  network_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  kind TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_network ON events(network_id, id DESC);
`);
// Upgrade in place from v0.1, preserving the existing database and custom names.
const columns = new Set((db.pragma('table_info(devices)') as {name:string}[]).map(c => c.name));
for (const [name, definition] of Object.entries({
  hostname: 'TEXT', vendor: 'TEXT', kind: "TEXT NOT NULL DEFAULT 'unknown'", ports_json: "TEXT NOT NULL DEFAULT '[]'", ports_scanned_at: 'TEXT', trusted: "INTEGER NOT NULL DEFAULT 0"
})) {
  if (!columns.has(name)) db.exec(`ALTER TABLE devices ADD COLUMN ${name} ${definition}`);
}
const getOne = db.prepare('SELECT * FROM devices WHERE id = ?');
const insert = db.prepare(`INSERT INTO devices (id,network_id,ip,mac,name,status,first_seen,last_seen)
VALUES (@id,@network_id,@ip,@mac,@name,@status,@first_seen,@last_seen)`);
const update = db.prepare(`UPDATE devices SET ip=@ip, mac=@mac, status=@status, last_seen=@last_seen,
 hostname=COALESCE(@hostname,hostname), vendor=COALESCE(@vendor,vendor), kind=@kind WHERE id=@id`);
const eventInsert = db.prepare('INSERT INTO events (network_id, device_id, ip, kind, created_at) VALUES (?, ?, ?, ?, ?)');
const byNetwork = db.prepare('SELECT * FROM devices WHERE network_id = ?');

export function listDevices(networkId: string): Device[] {
  return (byNetwork.all(networkId) as (Device & { ports_json:string;tags_json:string })[]).map(({ports_json,tags_json,...device}) => ({...device, ports: JSON.parse(ports_json || '[]') as TcpPort[], tags: JSON.parse(tags_json || '[]') as string[]})).sort((a,b) => a.ip.localeCompare(b.ip, undefined, {numeric:true}));
}
export function listEvents(networkId: string): Event[] {
  return db.prepare('SELECT * FROM events WHERE network_id = ? ORDER BY id DESC LIMIT 60').all(networkId) as Event[];
}
export function updateTrust(id: string, networkId: string, trusted: boolean): boolean {
  return db.prepare('UPDATE devices SET trusted=? WHERE id=? AND network_id=?').run(trusted ? 1 : 0,id,networkId).changes > 0;
}
export function exportInventory(networkId: string): string {
  const columns = ['ip','mac','name','hostname','vendor','kind','status','trusted','notes','tags','first_seen','last_seen'];
  const escapeCsv = (v: unknown): string => {
    const value = String(v ?? '');
    const safe = /^[=+@\-\t\r]/.test(value) ? '\'' + value : value;
    return '"' + safe.replace(/"/g,'""') + '"';
  };
  // BOM improves Microsoft Excel UTF-8 compatibility.
  return '\uFEFF' + [columns.join(';'),...listDevices(networkId).map(d=>columns.map(c=>escapeCsv(d[c as keyof Device])).join(';'))].join('\r\n');
}
export type Sample = { id:number; network_id:string; device_id:string; ip:string; checked_at:string; reachable:number; latency_ms:number|null };
db.exec(`CREATE TABLE IF NOT EXISTS probes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, network_id TEXT NOT NULL, device_id TEXT NOT NULL,
 ip TEXT NOT NULL, checked_at TEXT NOT NULL, reachable INTEGER NOT NULL, latency_ms REAL
);CREATE INDEX IF NOT EXISTS probes_device ON probes(network_id,device_id,id DESC);`);
const insertProbe=db.prepare('INSERT INTO probes (network_id,device_id,ip,checked_at,reachable,latency_ms) VALUES (?,?,?,?,?,?)');
export function recordProbe(networkId:string,deviceId:string,ip:string,reachable:boolean,latencyMs:number|null):void {
  insertProbe.run(networkId,deviceId,ip,new Date().toISOString(),reachable?1:0,latencyMs);
  db.prepare('DELETE FROM probes WHERE id NOT IN (SELECT id FROM probes ORDER BY id DESC LIMIT 20000)').run();
}
export function listProbes(networkId:string,deviceId:string,limit=60):Sample[] {
  return db.prepare('SELECT * FROM probes WHERE network_id=? AND device_id=? ORDER BY id DESC LIMIT ?').all(networkId,deviceId,Math.min(Math.max(limit,1),500)) as Sample[];
}
export function updateName(id: string, networkId: string, name: string | null): boolean {
  return db.prepare('UPDATE devices SET name = ? WHERE id = ? AND network_id = ?').run(name, id, networkId).changes > 0;
}
export function updatePorts(id: string, networkId: string, ports: TcpPort[]): boolean {
  const device = db.prepare('SELECT hostname, vendor FROM devices WHERE id=? AND network_id=?').get(id, networkId) as {hostname:string|null;vendor:string|null}|undefined;
  if (!device) return false;
  const kind = classifyDevice(device.hostname, device.vendor, ports);
  return db.prepare(`UPDATE devices SET ports_json=?, ports_scanned_at=?, kind=? WHERE id=? AND network_id=?`).run(
    JSON.stringify(ports), new Date().toISOString(), kind, id, networkId
  ).changes > 0;
}
export function saveDiscovery(networkId: string, found: Discovery[]): void {
  const now = new Date().toISOString();
  db.transaction(() => {
    const seen = new Set<string>();
    // MAC é a identidade primária quando conhecida; IP é fallback.
    for (const entry of found) {
      const id = `${networkId}::${entry.mac ?? entry.ip}`;
      seen.add(id);
      let existing = getOne.get(id) as Device | undefined;
      // When ARP/Nmap temporarily misses a MAC, match an existing record by IP
      // instead of creating a second device and marking the old one offline.
      if (!existing && !entry.mac) {
        const byIp = db.prepare('SELECT * FROM devices WHERE network_id=? AND ip=? ORDER BY last_seen DESC LIMIT 1')
          .get(networkId,entry.ip) as Device | undefined;
        if (byIp) {
          existing = byIp;
          seen.add(byIp.id);
        }
      }
      if (!existing && entry.mac) {
        const fallbackId = `${networkId}::${entry.ip}`;
        const fallback = getOne.get(fallbackId) as Device | undefined;
        if (fallback) {
          db.prepare('UPDATE devices SET id = ? WHERE id = ?').run(id, fallbackId);
          db.prepare('UPDATE events SET device_id = ? WHERE device_id = ?').run(id, fallbackId);
          existing = getOne.get(id) as Device | undefined;
        }
      }
      if (!existing) {
        insert.run({ id, network_id: networkId, ip: entry.ip, mac: entry.mac,
          name: null, status: entry.status, first_seen: now, last_seen: now });
        db.prepare('UPDATE devices SET hostname=?,vendor=?,kind=? WHERE id=?').run(entry.hostname ?? null, entry.vendor ?? null, classifyDevice(entry.hostname ?? null,entry.vendor ?? null, entry.ports),id);
        eventInsert.run(networkId, id, entry.ip, 'new', now);
      } else {
        update.run({ id: existing.id, ip: entry.ip, mac: entry.mac ?? existing.mac, hostname: entry.hostname ?? null, vendor: entry.vendor ?? null,
          kind: classifyDevice(entry.hostname ?? existing.hostname, entry.vendor ?? existing.vendor, Array.isArray(entry.ports) ? entry.ports : JSON.parse((db.prepare('SELECT ports_json FROM devices WHERE id=?').get(existing.id) as {ports_json:string}).ports_json)),
          status: entry.status, last_seen: now });
        if (existing.status !== entry.status) eventInsert.run(networkId, existing.id, entry.ip, entry.status, now);
      }
    }
    for (const old of byNetwork.all(networkId) as Device[]) {
      if (!seen.has(old.id) && old.status !== 'offline') {
        db.prepare("UPDATE devices SET status='offline' WHERE id = ?").run(old.id);
        eventInsert.run(networkId, old.id, old.ip, 'offline', now);
      }
    }
    // Limita volume de eventos, preservando os últimos 5 mil.
    db.prepare('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 5000)').run();
  })();
}
export function closeDb(): void { db.close(); }

export type TrafficPoint = {id:number;network_id:string;adapter:string;sampled_at:string;download_bps:number;upload_bps:number};
db.exec(`CREATE TABLE IF NOT EXISTS traffic (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 network_id TEXT NOT NULL, adapter TEXT NOT NULL, sampled_at TEXT NOT NULL,
 download_bps INTEGER NOT NULL, upload_bps INTEGER NOT NULL
); CREATE INDEX IF NOT EXISTS traffic_recent ON traffic(network_id,id DESC);`);
const trafficInsert = db.prepare('INSERT INTO traffic(network_id,adapter,sampled_at,download_bps,upload_bps) VALUES (?,?,?,?,?)');
export function recordTraffic(networkId:string, adapter:string, downloadBps:number, uploadBps:number):void {
  trafficInsert.run(networkId,adapter,new Date().toISOString(),downloadBps,uploadBps);
  db.prepare('DELETE FROM traffic WHERE id NOT IN (SELECT id FROM traffic ORDER BY id DESC LIMIT 30000)').run();
}
export function listTraffic(networkId:string,limit=120):TrafficPoint[] {
  return db.prepare('SELECT * FROM traffic WHERE network_id=? ORDER BY id DESC LIMIT ?').all(networkId,Math.min(Math.max(limit,1),2000)) as TrafficPoint[];
}
export function listEventsAfter(id:number, networkId:string):Event[] {
  return db.prepare('SELECT * FROM events WHERE network_id=? AND id>? ORDER BY id ASC LIMIT 500').all(networkId,id) as Event[];
}
export function latestEventId():number {
  return (db.prepare('SELECT COALESCE(MAX(id),0) AS id FROM events').get() as {id:number}).id;
}
export type Availability = { deviceId:string; ip:string; name:string|null; samples:number; responsive:number; uptimePct:number; averageLatencyMs:number|null };
export function availabilityReport(networkId:string):Availability[] {
  const rows = db.prepare(`SELECT d.id AS deviceId,d.ip,d.name,COUNT(p.id) AS samples,
 SUM(CASE WHEN p.reachable=1 THEN 1 ELSE 0 END) AS responsive,
 AVG(CASE WHEN p.reachable=1 THEN p.latency_ms ELSE NULL END) AS averageLatencyMs
 FROM devices d LEFT JOIN probes p ON p.device_id=d.id AND p.network_id=d.network_id
 WHERE d.network_id=? GROUP BY d.id ORDER BY d.ip`).all(networkId) as (Omit<Availability,'uptimePct'>)[];
  return rows.map(r=>({...r,uptimePct:r.samples===0?0:Math.round((r.responsive/r.samples)*10000)/100}));
}
export function exportAvailability(networkId:string):string {
  const escape=(x:unknown)=>'"'+String(x??'').replace(/^[=+@\-\t\r]/,"'$&").replace(/"/g,'""')+'"';
  return '\uFEFF'+['IP;Nome;Amostras;Respostas;Disponibilidade (%);Latencia media (ms)',...availabilityReport(networkId).map(r=>[r.ip,r.name,r.samples,r.responsive,r.samples?r.uptimePct:'Sem dados',r.averageLatencyMs].map(escape).join(';'))].join('\r\n');
}

// v0.5: configurations and labels stored in SQLite, without resetting older databases.
db.exec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`);
const readSetting = db.prepare('SELECT value FROM settings WHERE key=?');
const writeSetting = db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
export function setting(key:string):string|null {
  return (readSetting.get(key) as {value:string}|undefined)?.value ?? null;
}
export function setSetting(key:string,value:string):void {writeSetting.run(key,value);}
export type Preferences={scanIntervalSeconds:number;probeIntervalSeconds:number};
export function preferences():Preferences {
  const scanIntervalSeconds=Number(setting('scanIntervalSeconds') ?? '60');
  const probeIntervalSeconds=Number(setting('probeIntervalSeconds') ?? '300');
  return {scanIntervalSeconds,probeIntervalSeconds};
}
export function updatePreferences(value:Preferences):void {
  if (!Number.isInteger(value.scanIntervalSeconds) || value.scanIntervalSeconds<30 || value.scanIntervalSeconds>3600 ||
      !Number.isInteger(value.probeIntervalSeconds) || value.probeIntervalSeconds<60 || value.probeIntervalSeconds>3600) throw new Error('Intervalos inválidos');
  db.transaction(()=>{
    setSetting('scanIntervalSeconds',String(value.scanIntervalSeconds));
    setSetting('probeIntervalSeconds',String(value.probeIntervalSeconds));
  })();
}
const metadata = new Set((db.pragma('table_info(devices)') as {name:string}[]).map(c=>c.name));
for (const [name,definition] of Object.entries({notes:"TEXT NOT NULL DEFAULT ''",tags_json:"TEXT NOT NULL DEFAULT '[]'"})) {
  if(!metadata.has(name)) db.exec(`ALTER TABLE devices ADD COLUMN ${name} ${definition}`);
}
export function updateDeviceMetadata(id:string,networkId:string,notes:string,tags:string[]):boolean {
  if (notes.length > 600 || tags.length > 12 || tags.some(t=>t.length > 32 || !t.trim())) return false;
  return db.prepare('UPDATE devices SET notes=?,tags_json=? WHERE id=? AND network_id=?')
    .run(notes,JSON.stringify([...new Set(tags.map(t=>t.trim()))]),id,networkId).changes>0;
}
export function authDatabase():Database.Database {return db;}
