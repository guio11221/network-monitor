import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNmapXml, classifyDevice } from './enrichment.js';
import { isTargetInNetwork } from './nmap.js';
import type { NetInterface } from './network.js';

const network: NetInterface = { id: 'wifi::192.168.1.10', name:'wifi', address:'192.168.1.10', netmask:'255.255.255.0',cidr:'192.168.1.0/24',totalHosts:254,supported:true };
test('XML discovery: hostname, MAC, manufacturer e portas', () => {
  const input = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Test Vendor"/><hostnames><hostname name="gateway.local"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host><host><status state="down"/><address addr="192.168.1.2" addrtype="ipv4"/></host></nmaprun>`;
  assert.deepEqual(parseNmapXml(input), [{ ip:'192.168.1.1',mac:'AA:BB:CC:DD:EE:FF',vendor:'Test Vendor',hostname:'gateway.local',status:'online',ports:[{port:80, service:'http'}] }]);
});
test('classifica sem inventar tipo quando não há sinal', () => {
  assert.equal(classifyDevice(null,null), 'unknown');
  assert.equal(classifyDevice('hp-printer',null), 'printer');
  assert.equal(classifyDevice(null,null,[{port:554,service:'rtsp'}]), 'camera');
});
test('port scan só aceita IP da rede e rejeita IP próprio', () => {
  assert.equal(isTargetInNetwork('192.168.1.15',network),true);
  assert.equal(isTargetInNetwork('192.168.1.10',network),false);
  assert.equal(isTargetInNetwork('8.8.8.8',network),false);
  assert.equal(isTargetInNetwork('invalid',network),false);
});
