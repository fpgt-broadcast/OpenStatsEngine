// Ids can't leave the data folder, and other sites' pages can't change anything.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store, safeId } from '../src/store.js';
import { hostAllowed, crossSite } from '../src/guard.js';
let pass = 0, fail = 0;
const ok = (l, c, x = '') => { console.log(`${c ? '  ok  ' : '  FAIL'} ${l}${x ? ' — ' + x : ''}`); c ? pass++ : fail++; };
const throws = (fn) => { try { fn(); return false; } catch { return true; } };

console.log('\n== ids ==');
for (const good of ['prep', '2026-11-27_football_xavier-at-prep', 'Team_2']) ok(`"${good}" accepted`, safeId(good) === good);
for (const bad of ['', '.', '..', '../x', '..\\..\\Users', 'a/b', 'C:x', '.hidden', 'a\0b']) ok(`${JSON.stringify(bad)} refused`, throws(() => safeId(bad)));

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ose-sec-'));
const outside = path.join(root, 'outside');
fs.mkdirSync(outside);
fs.writeFileSync(path.join(outside, 'keep'), 'x');
const store = new Store(path.join(root, 'data'));
ok('team id with ../ is refused', throws(() => store.saveTeam({ id: '../../outside/pwn', name: 'x' })));
ok('nothing written outside the data folder', !fs.existsSync(path.join(outside, 'pwn.json')));
ok('game id with ../ is refused', throws(() => store.createGame({ id: '../outside', sport: 'football', homeTeamId: 'a', awayTeamId: 'b' })));
ok('deleting ".." is refused', throws(() => store.deleteGame('..')));
ok('deleting "..\\\\outside" is refused', throws(() => store.deleteGame('..\\outside')));
ok('the folder outside is still there', fs.existsSync(path.join(outside, 'keep')));
ok('unknown team id reads as null, not an error', store.getTeam(undefined) === null && store.getTeam('../x') === null);
ok('normal team still saves', store.saveTeam({ name: 'Fairfield Prep' }).id === 'fairfield-prep');
fs.rmSync(root, { recursive: true, force: true });

console.log('\n== host names (DNS rebinding) ==');
for (const h of ['localhost:8080', '127.0.0.1:8080', '192.168.50.21:8080', '[::1]:8080', 'stats-pc:8080', 'stats-pc.local:8080', undefined])
  ok(`${h} allowed`, hostAllowed(h, []));
for (const h of ['evil.com', 'evil.com:8080', 'rebind.attacker.net:8080']) ok(`${h} refused`, !hostAllowed(h, []));
ok('OSE_ALLOWED_HOSTS adds a name', hostAllowed('stats.example.org:8080', ['stats.example.org']));

console.log('\n== cross-site writes ==');
const req = (headers) => ({ headers: { host: '192.168.1.5:8080', ...headers } });
ok('same origin is fine', !crossSite(req({ origin: 'http://192.168.1.5:8080' })));
ok('no Origin (vMix, scripts, curl) is fine', !crossSite(req({})));
ok('another site is refused', crossSite(req({ origin: 'http://evil.com' })));
ok('another port on the same computer is refused', crossSite(req({ origin: 'http://192.168.1.5:3000' })));
ok('a file:// page (Origin null) is refused', crossSite(req({ origin: 'null' })));
ok('Sec-Fetch-Site cross-site is refused', crossSite(req({ 'sec-fetch-site': 'cross-site' })));

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
