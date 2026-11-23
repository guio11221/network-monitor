import Fastify from 'fastify';
import { existsSync } from 'node:fs';
import { COOKIE_NAME, SESSION_SECONDS, cookieValue, createAuth } from './security.js';
import { resolve } from 'node:path';
const envPath = [resolve(process.cwd(), '.env'),resolve(process.cwd(),'..','.env')].find(existsSync);
if (envPath) process.loadEnvFile(envPath);
import websocket from '@fastify/websocket';
import { discover, interfaces, type NetInterface, type Discovery } from './network.js';
import { discoverNmap, nmapAvailable, scanTcpPorts, isTargetInNetwork } from './nmap.js';
import { classifyDevice } from './enrichment.js';
import { probeHost, runDiagnostics, type Diagnostics } from './diagnostics.js';
import { promises as dns } from 'node:dns';
import { closeDb, listDevices, listEvents, saveDiscovery, updateName, updatePorts, updateTrust, recordProbe, listProbes, exportInventory, latestEventId, listEventsAfter, listTraffic, recordTraffic, availabilityReport, exportAvailability, preferences, updatePreferences, updateDeviceMetadata, setting, setSetting, authDatabase } from './storage.js';

import { readWindowsCounters, calculateRate, type InterfaceCounters } from './analytics.js';
import { sendTelegram, formatAlert, shouldNotify } from './alerts.js';

const app = Fastify({ logger: true, bodyLimit: 16 * 1024 });
const auth = createAuth(authDatabase());
const loginAttempts = new Map<string,{count:number;until:number}>();
const originAllowed = (origin:string|undefined) => !origin || (()=>{
  try {const url=new URL(origin);return (url.hostname==='127.0.0.1'||url.hostname==='localhost') && (url.port==='5173'||url.port===String(port));}
  catch{return false;}
})();
function authorized(request:{headers:Record<string,string|string[]|undefined>}):boolean {
  const header=request.headers.cookie;
  return auth.valid(cookieValue(typeof header==='string'?header:undefined,COOKIE_NAME));
}
const sessionCookie = (value:string,maxAge:number)=>`${COOKIE_NAME}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
app.addHook('onRequest',async(request,reply)=>{
  if (!originAllowed(request.headers.origin)) return reply.code(403).send({error:'Origem não autorizada.'});
  if (request.url.split('?')[0]==='/api/login') return;
  if (!authorized(request)) return reply.code(401).send({error:'Autenticação necessária.'});
});
app.post<{Body:{username?:string;password?:string}}>('/api/login',async(request,reply)=>{
  const key=request.ip;
  const entry=loginAttempts.get(key);
  if(entry && entry.until>Date.now()) return reply.code(429).send({error:'Muitas tentativas. Tente novamente em 15 minutos.'});
  const username=request.body?.username;
  const password=request.body?.password;
  if(typeof username!=='string'||typeof password!=='string'||password.length>256) return reply.code(400).send({error:'Credenciais inválidas.'});
  const token=auth.login(username,password);
  if(!token){
    const count=(entry?.count??0)+1;
    loginAttempts.set(key,{count,until:count>=5?Date.now()+15*60_000:0});
    return reply.code(401).send({error:'Usuário ou senha inválidos.'});
  }
  loginAttempts.delete(key);
  reply.header('Set-Cookie',sessionCookie(token,SESSION_SECONDS));
  return {ok:true};
});
app.post('/api/logout',async(request,reply)=>{
  auth.logout(cookieValue(request.headers.cookie,COOKIE_NAME));
  reply.header('Set-Cookie',sessionCookie('',0));
  broadcast();
  return {ok:true};
});
app.post<{Body:{oldPassword?:string;newPassword?:string}}>('/api/password',async(request,reply)=>{
  const {oldPassword,newPassword}=request.body??{};
  if(typeof oldPassword!=='string'||typeof newPassword!=='string'||!auth.changePassword(oldPassword,newPassword))
    return reply.code(400).send({error:'Senha atual incorreta ou nova senha fora do limite de 12 a 256 caracteres.'});
  reply.header('Set-Cookie',sessionCookie('',0));
  broadcast();
  return {ok:true};
});
await app.register(websocket);
const sockets = new Map<{ send: (data: string) => void; readyState: number; close:()=>void },string>();
const host = '127.0.0.1';
const port = Number(process.env.PORT || 3001);
let selectedId: string | null = setting('selectedInterface');
let busy = false;
let lastScan: string | null = null;
let scanError: string | null = null;
let mode: 'nmap' | 'fallback' = 'fallback';
let nmapInstalled = false;
let portBusy = false;
let probing = false;
let diagnosticsBusy = false;
let latestDiagnostics: Diagnostics | null = null;
let lastEventId = latestEventId();
let trafficBusy = false;
const previousCounters = new Map<string, InterfaceCounters & {at:number}>();
let lastTrafficError: string | null = null;
let alertsEnabled = !!(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID);

function network(): NetInterface | undefined {
  const all = interfaces();
  return all.find(n => n.id === selectedId) ?? all.find(n => n.supported);
}
function snapshot() {
  const n = network();
  const devices = n ? listDevices(n.id) : [];
  return { preferences:preferences(), interfaces: interfaces(), selectedId: n?.id ?? null, devices, mode, nmapInstalled, portBusy,
    events: n ? listEvents(n.id) : [], traffic: n ? listTraffic(n.id,120) : [], availability: n ? availabilityReport(n.id) : [], telegramConfigured: alertsEnabled, trafficError:lastTrafficError, diagnostics: latestDiagnostics, diagnosticsBusy, probing, scanning: busy, lastScan, error: scanError,
    stats: { total: devices.length, online: devices.filter(d => d.status === 'online').length,
      observed: devices.filter(d => d.status === 'observed').length,
      offline: devices.filter(d => d.status === 'offline').length }
  };
}
function broadcast() {
  const data = JSON.stringify({ type: 'snapshot', payload: snapshot() });
  for (const [socket, token] of sockets) {
    if (!auth.valid(token)) {socket.close();sockets.delete(socket);continue;}
    if (socket.readyState === 1) {
      try { socket.send(data); } catch { sockets.delete(socket); }
    }
  }
}
async function scan(): Promise<void> {
  if (busy || portBusy) return;
  const n = network();
  if (!n) { scanError = 'Nenhuma interface IPv4 de rede disponível.'; broadcast(); return; }
  if (!n.supported) { scanError = 'Sub-rede com mais de 256 endereços não suportada nesta versão.'; broadcast(); return; }
  busy = true;
  scanError = null;
  broadcast();
  try {
    nmapInstalled = await nmapAvailable();
    let devices: Discovery[];
    if (nmapInstalled) {
      try {
        const found = await discoverNmap(n);
        mode = 'nmap';
        // MAC/vendor visibility depends on Windows driver and local topology.
        devices = found.map(h => ({...h, kind: classifyDevice(h.hostname,h.vendor)}));
      } catch (error) {
        app.log.warn({error}, 'Nmap falhou; usando ping/ARP como fallback');
        mode = 'fallback';
        devices = await discover(n);
      }
    } else {
      mode = 'fallback';
      devices = await discover(n);
    }
    // Reverse DNS only on hosts that were found, never across the entire address range.
    let cursor = 0;
    await Promise.all(Array.from({length: Math.min(12, devices.length)}, async () => {
      while (cursor < devices.length) {
        const device = devices[cursor++];
        if (!device || device.hostname) continue;
        try {
          const names = await Promise.race([dns.reverse(device.ip), new Promise<never>((_,reject)=>setTimeout(()=>reject(new Error('DNS timeout')),1200))]);
          device.hostname = names[0] ?? null;
          device.kind = classifyDevice(device.hostname, device.vendor ?? null);
        } catch { /* DNS lookup is optional */ }
      }
    }));
    saveDiscovery(n.id, devices);
    void deliverNewAlerts(n.id);
    lastScan = new Date().toISOString();
  } catch (error) {
    scanError = error instanceof Error ? error.message : String(error);
    app.log.error(error);
  } finally { busy = false; broadcast(); }
}
async function deliverNewAlerts(networkId: string): Promise<void> {
  // Consume newly created events only. Historic events aren't sent on reboot.
  const events = listEventsAfter(lastEventId, networkId);
  if (events.length) lastEventId = Math.max(lastEventId, events[events.length-1]!.id);
  if (!alertsEnabled) return;
  const devices = new Map(listDevices(networkId).map(d => [d.id,d]));
  for (const e of events) {
    const device = devices.get(e.device_id);
    if (!device) continue;
    const alert = {kind:e.kind,ip:e.ip,deviceId:e.device_id,trusted:device.trusted,name:device.name || device.hostname,networkId};
    if (!shouldNotify(alert)) continue;
    try { await sendTelegram(formatAlert(alert)); }
    catch (error) { app.log.warn({error}, 'Falha ao enviar Telegram'); }
  }
}
async function collectTraffic():Promise<void> {
  if (trafficBusy) return;
  const n=network();if(!n)return;
  trafficBusy=true;
  try {
    const counters=await readWindowsCounters();
    const now=Date.now();
    for(const counter of counters){
      // Monitor counters for all adapters, but assign samples to selected network only.
      // This is host traffic, NOT per-client usage.
      const prior=previousCounters.get(counter.name);
      if (prior) {
        const rate=calculateRate(prior,{...counter,at:now});
        recordTraffic(n.id,counter.name,rate.downloadBps,rate.uploadBps);
      }
      previousCounters.set(counter.name,{...counter,at:now});
    }
    lastTrafficError=null;
    broadcast();
  } catch(e){lastTrafficError=e instanceof Error?e.message:String(e);app.log.warn({error:e},'Falha nos contadores de tráfego');}
  finally{trafficBusy=false;}
}
app.get('/api/availability.csv',async(_request,reply)=>{
  const n=network();if(!n)return reply.code(404).send({error:'Rede indisponível.'});
  return reply.header('Content-Type','text/csv; charset=utf-8')
    .header('Content-Disposition','attachment; filename="availability.csv"').send(exportAvailability(n.id));
});
app.get('/api/traffic',async()=>{
  const n=network();return {samples:n?listTraffic(n.id,500):[],source:'Windows Get-NetAdapterStatistics',scope:'local-computer'};
});
app.get('/api/settings',async()=>preferences());
app.patch<{Body:{scanIntervalSeconds?:number;probeIntervalSeconds?:number}}>('/api/settings',async(request,reply)=>{
  const body=request.body;
  if(!body||typeof body.scanIntervalSeconds!=='number'||typeof body.probeIntervalSeconds!=='number')
    return reply.code(400).send({error:'Intervalos inválidos.'});
  try {updatePreferences({scanIntervalSeconds:body.scanIntervalSeconds,probeIntervalSeconds:body.probeIntervalSeconds});}
  catch {return reply.code(400).send({error:'Varredura: 30–3600 s; latência: 60–3600 s.'});}
  restartIntervals();broadcast();return {ok:true};
});
app.patch<{Params:{id:string};Body:{notes?:string;tags?:string[]}}>('/api/devices/:id/metadata',async(request,reply)=>{
  const n=network();if(!n)return reply.code(404).send({error:'Rede indisponível.'});
  const {notes,tags}=request.body??{};
  if(typeof notes!=='string'||!Array.isArray(tags)||!tags.every(t=>typeof t==='string')||notes.length>600||tags.length>12||tags.some(t=>t.length>32))
    return reply.code(400).send({error:'Notas ou etiquetas inválidas.'});
  if(!updateDeviceMetadata(request.params.id,n.id,notes,tags))return reply.code(404).send({error:'Dispositivo não encontrado.'});
  broadcast();return {ok:true};
});
app.get('/api/state', async () => snapshot());
app.post<{ Body: { id?: string } }>('/api/network', async (request, reply) => {
  const id = request.body?.id;
  if (typeof id !== 'string' || !interfaces().some(n => n.id === id)) {
    return reply.code(400).send({ error: 'Interface inválida.' });
  }
  if (busy || portBusy) return reply.code(409).send({ error: 'Varredura em andamento.' });
  selectedId = id;
  setSetting('selectedInterface',id);
  lastScan = null;
  latestDiagnostics = null;
  scanError = null;
  broadcast();
  void scan();
  return { ok: true };
});
app.post<{ Params: { id: string } }>('/api/devices/:id/ports', async (request, reply) => {
  const n = network();
  if (!n || !n.supported) return reply.code(400).send({error:'Interface não suportada.'});
  if (busy || portBusy) return reply.code(409).send({error:'Outra varredura está em andamento.'});
  const device = listDevices(n.id).find(d => d.id === request.params.id);
  if (!device || !isTargetInNetwork(device.ip,n)) return reply.code(404).send({error:'Dispositivo não encontrado nesta sub-rede.'});
  if (!await nmapAvailable()) return reply.code(503).send({error:'Nmap não está instalado ou não foi encontrado no PATH.'});
  portBusy = true;
  broadcast();
  try {
    const ports = await scanTcpPorts(device.ip,n);
    updatePorts(device.id,n.id,ports);
    broadcast();
    return {ok:true, ports};
  } catch(error) {
    app.log.error(error);
    return reply.code(502).send({error:'Falha ao consultar portas TCP. Confirme o Nmap e tente novamente.'});
  } finally { portBusy = false; broadcast(); }
});
app.patch<{ Params:{id:string}; Body:{trusted?:boolean} }>('/api/devices/:id/trust',async(request,reply)=>{
  const n=network();
  if(!n) return reply.code(404).send({error:'Rede indisponível.'});
  if(typeof request.body?.trusted!=='boolean') return reply.code(400).send({error:'trusted deve ser booleano.'});
  if(!updateTrust(request.params.id,n.id,request.body.trusted)) return reply.code(404).send({error:'Dispositivo não encontrado.'});
  broadcast();return {ok:true};
});
app.get('/api/inventory.csv',async(_request,reply)=>{
  const n=network();if(!n) return reply.code(404).send({error:'Rede indisponível.'});
  return reply.header('Content-Type','text/csv; charset=utf-8')
    .header('Content-Disposition','attachment; filename="network-inventory.csv"')
    .send(exportInventory(n.id));
});
app.get<{Params:{id:string}}>('/api/devices/:id/probes',async(request,reply)=>{
  const n=network();if(!n) return reply.code(404).send({error:'Rede indisponível.'});
  const d=listDevices(n.id).find(d=>d.id===request.params.id);
  if(!d) return reply.code(404).send({error:'Dispositivo não encontrado.'});
  return {samples:listProbes(n.id,d.id,100)};
});
app.post('/api/diagnostics',async(_request,reply)=>{
  const n=network();if(!n || !n.supported) return reply.code(400).send({error:'Selecione uma interface IPv4 válida.'});
  if(diagnosticsBusy) return reply.code(409).send({error:'Diagnóstico já em andamento.'});
  diagnosticsBusy=true;broadcast();
  try { latestDiagnostics=await runDiagnostics(n);broadcast();return latestDiagnostics; }
  catch(e){app.log.error(e);return reply.code(502).send({error:'Não foi possível concluir o diagnóstico.'});}
  finally {diagnosticsBusy=false;broadcast();}
});
async function probeKnown(): Promise<void> {
  if(probing || busy || portBusy) return;
  const n=network();if(!n || !n.supported) return;
  probing=true;broadcast();
  try{
    const devices=listDevices(n.id).filter(d=>isTargetInNetwork(d.ip,n)).slice(0,64);
    let cursor=0;
    await Promise.all(Array.from({length:Math.min(8,devices.length)},async()=>{
      while(cursor<devices.length){
        const d=devices[cursor++];if(!d)continue;
        try {const p=await probeHost(d.ip,n);recordProbe(n.id,d.id,d.ip,p.reachable,p.latencyMs);}
        catch(e){app.log.warn({error:e},'Falha de probe');}
      }
    }));
  }finally{probing=false;broadcast();}
}
app.post('/api/probe',async(_request,reply)=>{
  if(probing || busy || portBusy) return reply.code(409).send({error:'Outra análise já está em andamento.'});
  void probeKnown();return {ok:true};
});
app.post('/api/scan', async (_request, reply) => {
  if (busy || portBusy) return reply.code(409).send({ error: 'Varredura já em andamento.' });
  void scan();
  return { ok: true };
});
app.patch<{ Params: { id: string }; Body: { name?: string | null } }>('/api/devices/:id', async (request, reply) => {
  const n = network();
  if (!n) return reply.code(404).send({ error: 'Rede indisponível.' });
  const name = request.body?.name;
  if (name !== null && (typeof name !== 'string' || name.length > 80)) {
    return reply.code(400).send({ error: 'Nome inválido (máximo 80 caracteres).' });
  }
  if (!updateName(request.params.id, n.id, name?.trim() || null)) {
    return reply.code(404).send({ error: 'Dispositivo não encontrado.' });
  }
  broadcast();
  return { ok: true };
});
app.get('/ws', { websocket: true }, (socket,request) => {
  sockets.set(socket,cookieValue(request.headers.cookie,COOKIE_NAME) ?? '');
  socket.send(JSON.stringify({ type: 'snapshot', payload: snapshot() }));
  socket.on('close', () => sockets.delete(socket));
  socket.on('error', () => sockets.delete(socket));
});
let interval:ReturnType<typeof setInterval>;
let probeInterval:ReturnType<typeof setInterval>;
const trafficInterval = setInterval(() => { void collectTraffic(); }, 15000);
const authCleanupInterval=setInterval(()=>auth.cleanup(),60*60*1000);
function restartIntervals():void {
  if(interval)clearInterval(interval);
  if(probeInterval)clearInterval(probeInterval);
  const p=preferences();
  interval=setInterval(()=>{void scan();},p.scanIntervalSeconds*1000);
  probeInterval=setInterval(()=>{void probeKnown();},p.probeIntervalSeconds*1000);
}
restartIntervals();
async function shutdown() {
  clearInterval(interval);
  clearInterval(probeInterval);
  clearInterval(trafficInterval);
  clearInterval(authCleanupInterval);
  await app.close();
  closeDb();
  process.exit(0);
}
process.on('SIGINT', () => { void shutdown(); });
process.on('SIGTERM', () => { void shutdown(); });
await app.listen({ host, port });
app.log.info(`API: http://${host}:${port}`);
void scan();
void collectTraffic();
