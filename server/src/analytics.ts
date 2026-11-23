import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';

const execFileAsync = promisify(execFile);
export type InterfaceCounters = { name: string; receivedBytes: number; sentBytes: number };
export type TrafficSample = { time: string; interface: string; downloadBps: number; uploadBps: number; receivedBytes: number; sentBytes: number };

export function calculateRate(previous: { receivedBytes: number; sentBytes: number; at: number }, current: { receivedBytes: number; sentBytes: number; at: number }): { downloadBps: number; uploadBps: number } {
  const seconds = (current.at - previous.at) / 1000;
  if (seconds <= 0 || current.receivedBytes < previous.receivedBytes || current.sentBytes < previous.sentBytes) return { downloadBps: 0, uploadBps: 0 };
  return { downloadBps: Math.round((current.receivedBytes - previous.receivedBytes) * 8 / seconds), uploadBps: Math.round((current.sentBytes - previous.sentBytes) * 8 / seconds) };
}

export function parseAdapterCounters(value: unknown): InterfaceCounters[] {
  if (value === null || typeof value !== 'object') return [];
  const input = Array.isArray(value) ? value : [value];
  return input.flatMap((entry): InterfaceCounters[] => {
    if (!entry || typeof entry !== 'object') return [];
    const row = entry as Record<string, unknown>;
    const receivedBytes = Number(row.ReceivedBytes);
    const sentBytes = Number(row.SentBytes);
    if (typeof row.Name !== 'string' || !Number.isFinite(receivedBytes) || !Number.isFinite(sentBytes) || receivedBytes < 0 || sentBytes < 0) return [];
    return [{name: row.Name, receivedBytes, sentBytes}];
  });
}

export async function readWindowsCounters(): Promise<InterfaceCounters[]> {
  if (os.platform() !== 'win32') return [];
  // No interpolation of interface names into PowerShell commands.
  const script = 'Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Json -Compress';
  const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
    timeout: 12000, maxBuffer: 1024 * 1024, windowsHide: true
  });
  return parseAdapterCounters(JSON.parse(stdout.replace(/^\uFEFF/, '')));
}
