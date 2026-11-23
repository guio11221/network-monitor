import { test } from 'node:test';
import assert from 'node:assert/strict';
import { calculateRate, parseAdapterCounters } from './analytics.js';
import { shouldNotify, formatAlert } from './alerts.js';

test('calcula bitrate corretamente',()=>{
  assert.deepEqual(calculateRate({receivedBytes:100,sentBytes:100,at:1000},{receivedBytes:1100,sentBytes:600,at:3000}),{downloadBps:4000,uploadBps:2000});
});
test('contador reiniciado nao cria pico falso',()=>{
  assert.deepEqual(calculateRate({receivedBytes:1000,sentBytes:1000,at:1000},{receivedBytes:10,sentBytes:10,at:3000}),{downloadBps:0,uploadBps:0});
});
test('parseia JSON de adaptador unico ou array',()=>{
  assert.equal(parseAdapterCounters({Name:'Wi-Fi',ReceivedBytes:120,SentBytes:300}).length,1);
  assert.equal(parseAdapterCounters([{Name:'Ethernet',ReceivedBytes:1,SentBytes:2}])[0]?.name,'Ethernet');
  assert.equal(parseAdapterCounters({Name:'Invalid',ReceivedBytes:'erro',SentBytes:12}).length,0);
});
test('alertas de desconhecidos e indisponibilidade de confiaveis',()=>{
  const event = {kind:'new',ip:'192.168.1.20',deviceId:'x',trusted:0,name:null,networkId:'Wi-Fi'};
  assert.equal(shouldNotify(event),true);
  assert.equal(shouldNotify({...event,kind:'offline'}),false);
  assert.equal(shouldNotify({...event,kind:'offline',trusted:1}),true);
  assert.match(formatAlert(event),/192.168.1.20/);
});
