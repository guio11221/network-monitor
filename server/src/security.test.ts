import test from 'node:test';
import assert from 'node:assert/strict';
import { passwordHash, verifyPassword, cookieValue, tokenDigest } from './security.js';

test('scrypt accepts correct password and rejects wrong password',()=>{
  const stored=passwordHash('uma-senha-longa-123');
  assert.ok(stored.startsWith('scrypt:'));
  assert.equal(verifyPassword('uma-senha-longa-123',stored),true);
  assert.equal(verifyPassword('senha-incorreta',stored),false);
  assert.equal(verifyPassword('senha','garbage'),false);
});
test('cookie session extraction and token digest',()=>{
  assert.equal(cookieValue('foo=bar; nm_session=abc123; theme=light','nm_session'),'abc123');
  assert.equal(cookieValue(undefined,'nm_session'),null);
  assert.equal(tokenDigest('abc').length,64);
});
