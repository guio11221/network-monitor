import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { parseWindowsPing } from './diagnostics.js';
test('parses Windows ping output in English and Portuguese', () => {
  assert.equal(parseWindowsPing('Reply from 192.168.0.1: bytes=32 time=21ms TTL=64'),21);
  assert.equal(parseWindowsPing('Resposta de 192.168.0.1: bytes=32 tempo=7ms TTL=64'),7);
  assert.equal(parseWindowsPing('Resposta de 192.168.0.1: bytes=32 tempo<1ms TTL=64'),0.5);
  assert.equal(parseWindowsPing('Request timed out'),null);
});
