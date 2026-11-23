import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';
import { hosts, ipNumber, type NetInterface } from './network.js';
import { parseNmapXml, type NmapHost, type TcpPort } from './enrichment.js';

const execFileAsync = promisify(execFile);
const OPTIONS = { windowsHide: true, timeout: 45_000, maxBuffer: 8 * 1024 * 1024 };
const PORTS = '21,22,23,53,80,139,443,445,554,631,1883,3306,3389,5000,5432,5900,8000,8008,8080,8081,8443,8883,9000,9100';

export async function nmapAvailable(): Promise<boolean> {
  if (process.platform !== 'win32') return false;
  try { await execFileAsync('nmap', ['--version'], { ...OPTIONS, timeout: 4000 }); return true; }
  catch { return false; }
}

export function isTargetInNetwork(ip: string, network: NetInterface): boolean {
  if (isIP(ip) !== 4 || ip === network.address) return false;
  try { return hosts(network).includes(ip); } catch { return false; }
}

export async function discoverNmap(network: NetInterface): Promise<NmapHost[]> {
  const targets = hosts(network);
  if (targets.length === 0) return [];
  // No shell, no user-supplied command arguments: only addresses from the selected interface.
  const { stdout } = await execFileAsync('nmap', ['-sn', '-PR', '-n', '--max-retries', '1', '-oX', '-', ...targets], OPTIONS);
  const allowed = new Set(targets);
  return parseNmapXml(stdout).filter(host => allowed.has(host.ip));
}

export async function scanTcpPorts(ip: string, network: NetInterface): Promise<TcpPort[]> {
  if (!isTargetInNetwork(ip, network)) throw new Error('O IP não pertence à sub-rede selecionada.');
  const { stdout } = await execFileAsync('nmap', [
    '-sT', '-Pn', '-n', '--open', '--max-retries', '1', '--host-timeout', '25s', '-p', PORTS, '-oX', '-', ip
  ], OPTIONS);
  return parseNmapXml(stdout).find(h => h.ip === ip)?.ports ?? [];
}
