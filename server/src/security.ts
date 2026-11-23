import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';
import type Database from 'better-sqlite3';

export const COOKIE_NAME = 'nm_session';
export const SESSION_SECONDS = 12 * 60 * 60;

export function passwordHash(password: string, salt = randomBytes(16).toString('hex')): string {
  return `scrypt:${salt}:${scryptSync(password, salt, 64).toString('hex')}`;
}
export function verifyPassword(password: string, stored: string): boolean {
  const [algorithm, salt, encoded] = stored.split(':');
  if (algorithm !== 'scrypt' || !salt || !encoded || !/^[0-9a-f]{128}$/i.test(encoded)) return false;
  const actual = scryptSync(password, salt, 64);
  return timingSafeEqual(actual, Buffer.from(encoded, 'hex'));
}
export function cookieValue(header: string | undefined, name: string): string | null {
  const part = (header ?? '').split(';').map(v => v.trim()).find(v => v.startsWith(`${name}=`));
  return part ? part.slice(name.length + 1) : null;
}
export function tokenDigest(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
export function createAuth(db: Database.Database) {
  db.exec(`CREATE TABLE IF NOT EXISTS auth_users (username TEXT PRIMARY KEY,password_hash TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS auth_sessions_expiry ON auth_sessions(expires_at);`);
  const initial = db.prepare('SELECT COUNT(*) AS total FROM auth_users').get() as {total:number};
  if (initial.total === 0) {
    const bootstrap = process.env.NETWORK_MONITOR_PASSWORD;
    if (!bootstrap || bootstrap.length < 12 || bootstrap.length > 256) {
      throw new Error('Primeira execução: defina NETWORK_MONITOR_PASSWORD com 12 a 256 caracteres no arquivo .env da raiz.');
    }
    db.prepare('INSERT INTO auth_users(username,password_hash) VALUES (?,?)').run('admin', passwordHash(bootstrap));
  }
  const getAdmin = db.prepare('SELECT password_hash FROM auth_users WHERE username=?');
  const saveSession = db.prepare('INSERT INTO auth_sessions(token_hash, expires_at) VALUES(?,?)');
  const getSession = db.prepare('SELECT 1 FROM auth_sessions WHERE token_hash=? AND expires_at>?');
  const deleteSession = db.prepare('DELETE FROM auth_sessions WHERE token_hash=?');
  const invalidPasswordHash = passwordHash('invalid-password-for-timing');
  return {
    login(username:string, password:string): string | null {
      const row = getAdmin.get(username) as {password_hash:string}|undefined;
      if (!verifyPassword(password, row?.password_hash ?? invalidPasswordHash) || !row) return null;
      const token = randomBytes(32).toString('hex');
      saveSession.run(tokenDigest(token), Math.floor(Date.now()/1000)+SESSION_SECONDS);
      return token;
    },
    valid(token:string|null): boolean {
      return !!(token && /^[0-9a-f]{64}$/.test(token) && getSession.get(tokenDigest(token),Math.floor(Date.now()/1000)));
    },
    logout(token:string|null): void {
      if (token && /^[0-9a-f]{64}$/.test(token)) deleteSession.run(tokenDigest(token));
    },
    changePassword(oldPassword:string,newPassword:string): boolean {
      const row = getAdmin.get('admin') as {password_hash:string};
      if (!verifyPassword(oldPassword,row.password_hash) || newPassword.length < 12 || newPassword.length > 256) return false;
      db.prepare('UPDATE auth_users SET password_hash=? WHERE username=?').run(passwordHash(newPassword),'admin');
      db.prepare('DELETE FROM auth_sessions').run();
      return true;
    },
    cleanup():void { db.prepare('DELETE FROM auth_sessions WHERE expires_at<=?').run(Math.floor(Date.now()/1000)); }
  };
}
