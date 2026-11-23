import { XMLParser } from 'fast-xml-parser';
import { isIP } from 'node:net';

export type DeviceKind = 'router' | 'computer' | 'phone' | 'printer' | 'tv' | 'camera' | 'iot' | 'unknown';
export type TcpPort = { port: number; service: string };
export type NmapHost = { ip: string; mac: string | null; vendor: string | null; hostname: string | null; status: 'online'; ports: TcpPort[] };

const xml = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', parseAttributeValue: false });
function asArray<T>(value: T | T[] | undefined): T[] { return value === undefined ? [] : Array.isArray(value) ? value : [value]; }
function attr(value: unknown, key: string): string | null {
  if (!value || typeof value !== 'object') return null;
  const x = (value as Record<string, unknown>)[`@_${key}`];
  return typeof x === 'string' ? x : null;
}
function obj(value: unknown): Record<string, unknown> { return value && typeof value === 'object' ? value as Record<string, unknown> : {}; }

export function parseNmapXml(output: string): NmapHost[] {
  const root = obj(xml.parse(output));
  const hosts = asArray(obj(root.nmaprun).host);
  return hosts.flatMap(raw => {
    const host = obj(raw);
    if (attr(host.status, 'state') !== 'up') return [];
    const addresses = asArray(host.address);
    const ip = addresses.find(a => attr(a, 'addrtype') === 'ipv4');
    const ipText = attr(ip, 'addr');
    if (!ipText || isIP(ipText) !== 4) return [];
    const macEntry = addresses.find(a => attr(a, 'addrtype') === 'mac');
    const macRaw = attr(macEntry, 'addr');
    const mac = macRaw && /^(?:[\da-f]{2}:){5}[\da-f]{2}$/i.test(macRaw) ? macRaw.toUpperCase() : null;
    const hostname = asArray(obj(host.hostnames).hostname).map(a => attr(a, 'name')).find(Boolean) ?? null;
    const ports = asArray(obj(host.ports).port).flatMap(item => {
      const p = obj(item);
      if (attr(p.state, 'state') !== 'open' || attr(p, 'protocol') !== 'tcp') return [];
      const port = Number(attr(p, 'portid'));
      return Number.isInteger(port) && port >= 1 && port <= 65535 ? [{port, service: attr(p.service, 'name') ?? 'unknown'}] : [];
    });
    return [{ip: ipText, mac, vendor: attr(macEntry, 'vendor'), hostname, status: 'online' as const, ports}];
  });
}

export function classifyDevice(hostname: string | null, vendor: string | null, ports: TcpPort[] = []): DeviceKind {
  const text = `${hostname ?? ''} ${vendor ?? ''}`.toLowerCase();
  const has = (re: RegExp) => re.test(text);
  const open = (port: number) => ports.some(p => p.port === port);
  if (has(/router|roteador|gateway|mikrotik|openwrt|pfsense|ubiquiti|unifi|tp-link|mercusys|huawei ax/)) return 'router';
  if (has(/printer|impressora|epson|brother|laserjet|deskjet/) || open(9100) || open(631)) return 'printer';
  if (has(/iphone|android|smartphone|pixel|galaxy|redmi|motorola/)) return 'phone';
  if (has(/smart.?tv|chromecast|fire.?tv|roku|webos|bravia|tizen|appletv/)) return 'tv';
  if (has(/camera|cam-|hikvision|dahua|reolink|onvif/) || open(554)) return 'camera';
  if (has(/esp32|esp8266|sonoff|shelly|tuya|iot/)) return 'iot';
  if (has(/desktop|laptop|notebook|macbook|workstation|windows|thinkpad/) || open(3389) || open(445)) return 'computer';
  return 'unknown';
}
