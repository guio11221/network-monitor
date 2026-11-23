import test from 'node:test';
import assert from 'node:assert/strict';
import { subnet, parseArp, hosts, type NetInterface } from './network.js';

test('range de sub-rede /24', () => {
  const s = subnet('192.168.1.100', '255.255.255.0');
  assert.equal(s.prefix, 24);
  assert.equal(s.total, 254);
});
test('não inclui próprio IP', () => {
  const n: NetInterface = {id:'wifi::192.168.1.2',name:'wifi', address:'192.168.1.2',netmask:'255.255.255.252',cidr:'192.168.1.0/30',totalHosts:2,supported:true};
  assert.deepEqual(hosts(n), ['192.168.1.1']);
});
test('interpreta ARP Windows português e inglês', () => {
  const result = parseArp('  192.168.1.1      aa-bb-cc-dd-ee-ff     dinâmico\n  192.168.1.2     11-22-33-44-55-66     dynamic\n  192.168.1.255   ff-ff-ff-ff-ff-ff     estático');
  assert.equal(result.get('192.168.1.1'), 'AA:BB:CC:DD:EE:FF');
  assert.equal(result.get('192.168.1.2'), '11:22:33:44:55:66');
  assert.equal(result.has('192.168.1.255'), false);
});
