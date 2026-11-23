import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';

const execFileAsync = promisify(execFile);
export type NetInterface = { id: string; name: string; address: string; netmask: string; cidr: string; totalHosts: number; supported: boolean };
export type Discovery = { ip: string; mac: string | null; status: 'online' | 'observed'; hostname?: string | null; vendor?: string | null; kind?: string; ports?: { port: number; service: string }[] };

export function ipNumber(ip: string): number {
  if (isIP(ip) !== 4) throw new Error('IPv4 inválido');
  return ip.split('.').reduce((n, octet) => ((n << 8) | Number(octet)) >>> 0, 0);
}
export function numberIp(n: number): string {
  return [24, 16, 8, 0].map(shift => (n >>> shift) & 255).join('.');
}
export function subnet(ip: string, mask: string): { first: number; last: number; prefix: number; total: number } {
  const m = ipNumber(mask);
  const bits = m.toString(2).padStart(32, '0');
  if (!/^1*0*$/.test(bits)) throw new Error('Máscara inválida');
  const prefix = bits.indexOf('0') === -1 ? 32 : bits.indexOf('0');
  const network = (ipNumber(ip) & m) >>> 0;
  const broadcast = (network | (~m >>> 0)) >>> 0;
  const first = prefix >= 31 ? network : network + 1;
  const last = prefix >= 31 ? broadcast : broadcast - 1;
  return { first, last, prefix, total: last - first + 1 };
}
export function interfaces(): NetInterface[] {
  const result: NetInterface[] = [];
  for (const [name, addresses] of Object.entries(os.networkInterfaces())) {
    for (const item of addresses ?? []) {
      if (item.family !== 'IPv4' || item.internal || item.address.startsWith('169.254.')) continue;
      try {
        const info = subnet(item.address, item.netmask);
        result.push({ id: `${name}::${item.address}`, name, address: item.address,
          netmask: item.netmask, cidr: `${numberIp(info.first === 0 ? 0 : (ipNumber(item.address) & ipNumber(item.netmask)) >>> 0)}/${info.prefix}`,
          totalHosts: info.total, supported: info.total <= 256 });
      } catch { /* ignora interfaces inválidas */ }
    }
  }
  return result.sort((a, b) => a.name.localeCompare(b.name));
}
export function hosts(network: NetInterface): string[] {
  const info = subnet(network.address, network.netmask);
  if (info.total > 256) throw new Error('Esta versão suporta até 256 endereços por sub-rede.');
  const own = ipNumber(network.address);
  const result: string[] = [];
  for (let i = info.first; i <= info.last; i++) {
    if (i !== own) result.push(numberIp(i));
  }
  return result;
}
export function parseArp(output: string): Map<string, string> {
  const found = new Map<string, string>();
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-f]{2}(?:[-:][\da-f]{2}){5})\s+(\S+)/i);
    if (!match) continue;
    const [, ip, mac, kind] = match;
    if (!ip || !mac || !kind || isIP(ip) !== 4) continue;
    // Em Windows em português: dinâmico; em inglês: dynamic.
    if (!/^din[aâ]mico$|^dynamic$/i.test(kind)) continue;
    found.set(ip, mac.replace(/-/g, ':').toUpperCase());
  }
  return found;
}
async function ping(ip: string): Promise<boolean> {
  try {
    await execFileAsync('ping', ['-n', '1', '-w', '450', ip], {
      windowsHide: true, timeout: 3000, maxBuffer: 128 * 1024
    });
    return true;
  } catch { return false; }
}
export async function discover(network: NetInterface): Promise<Discovery[]> {
  if (process.platform !== 'win32') throw new Error('O scanner desta versão requer Windows.');
  const targets = hosts(network);
  const alive = new Set<string>();
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(32, targets.length) }, async () => {
    while (next < targets.length) {
      const ip = targets[next++];
      if (ip && await ping(ip)) alive.add(ip);
    }
  }));
  let arp = new Map<string, string>();
  try {
    const result = await execFileAsync('arp', ['-a', '-N', network.address], {
      windowsHide: true, timeout: 5000, maxBuffer: 1024 * 1024
    });
    arp = parseArp(result.stdout);
  } catch { /* hosts confirmados por ping continuam válidos */ }
  const valid = new Set(targets);
  const ips = new Set([...alive, ...[...arp.keys()].filter(ip => valid.has(ip))]);
  return [...ips].map(ip => ({ ip, mac: arp.get(ip) ?? null,
    status: alive.has(ip) ? 'online' as const : 'observed' as const
  })).sort((a, b) => ipNumber(a.ip) - ipNumber(b.ip));
}
