import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import type { NetInterface } from './network.js';
import { isTargetInNetwork } from './nmap.js';

const execute = promisify(execFile);
export type Probe = { reachable: boolean; latencyMs: number | null; checkedAt: string };
export type Diagnostics = {
  checkedAt: string;
  gateway: { ip: string | null; probe: Probe | null };
  dns: { ok: boolean; address: string | null; error: string | null };
  internet: { ok: boolean; status: number | null; error: string | null };
};

export function parseWindowsPing(text: string): number | null {
  const exact = text.match(/(?:tempo|time)\s*[=<]\s*(\d+)\s*ms/i);
  if (exact) return Number(exact[1]);
  if (/(?:tempo|time)\s*<\s*1\s*ms/i.test(text)) return 0.5;
  return null;
}
export async function probeHost(ip: string, n: NetInterface): Promise<Probe> {
  if (isIP(ip) !== 4 || !isTargetInNetwork(ip, n)) throw new Error('IP fora da sub-rede selecionada.');
  const checkedAt = new Date().toISOString();
  try {
    const {stdout} = await execute('ping', ['-n','1','-w','900',ip], {windowsHide:true,timeout:3500,maxBuffer:128*1024});
    return {reachable:true,latencyMs:parseWindowsPing(stdout),checkedAt};
  } catch { return {reachable:false,latencyMs:null,checkedAt}; }
}
export async function getDefaultGateway(n: NetInterface): Promise<string | null> {
  try {
    // InterfaceIndex is not reliable in all locales; use the address matched from Get-NetIPConfiguration.
    const script = `$x = Get-NetIPAddress -AddressFamily IPv4 -IPAddress '${n.address}' -ErrorAction SilentlyContinue; if ($x) { (Get-NetIPConfiguration -InterfaceIndex $x.InterfaceIndex).IPv4DefaultGateway.NextHop | Select-Object -First 1 }`;
    const {stdout} = await execute('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{windowsHide:true,timeout:8000,maxBuffer:128*1024});
    const ip = stdout.trim();
    return isIP(ip) === 4 && isTargetInNetwork(ip,n) ? ip : null;
  } catch { return null; }
}
export async function runDiagnostics(n: NetInterface): Promise<Diagnostics> {
  const checkedAt = new Date().toISOString();
  const [gateway, dnsResult, internet] = await Promise.all([
    getDefaultGateway(n),
    lookup('example.com', {family:4}).then(r=>({ok:true,address:r.address,error:null})).catch(e=>({ok:false,address:null,error:String(e)})),
    fetch('https://www.msftconnecttest.com/connecttest.txt',{signal:AbortSignal.timeout(6500)}).then(r=>({ok:r.ok,status:r.status,error:null})).catch(e=>({ok:false,status:null,error:String(e)}))
  ]);
  return {checkedAt, gateway:{ip:gateway,probe:gateway?await probeHost(gateway,n):null},dns:dnsResult,internet};
}
