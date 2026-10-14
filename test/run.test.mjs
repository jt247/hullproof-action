// Tests of the Action entry point against a stub `hullproof` command and a local stand in for the GitHub API.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { esc, escProp, isForkPr, main, MARKER, resolveTarget } from '../src/run.mjs';

function workspace(code) {
  const ws = mkdtempSync(join(tmpdir(), 'ha-ws-'));
  const bin = join(ws, 'fake-hullproof.sh');
  const a = join(ws, '.hullproof/ci');
  // The stub writes the four files and exits with the wanted code, as `hullproof ci` does.
  writeFileSync(bin, `#!/bin/sh
mkdir -p "${a}"
printf '{"records":[{"kind":"fail","severity":"BLOCKER","sec_ids":["SEC-API-017"],"fingerprint":"a","title":"Bad, 100%% sure\\\\nsecond line","evidence":[{"file":"src/a.js","line":3}]}]}' > "${a}/findings.json"
printf '# report\\n' > "${a}/report.md"
printf '{"version":"2.1.0","runs":[]}' > "${a}/results.sarif"
printf '${MARKER}\\n## Hullproof: 1 blocking finding\\n' > "${a}/pr-comment.md"
exit ${code}
`);
  chmodSync(bin, 0o755);
  return { ws, bin };
}

async function fakeGithub(existing = []) {
  const calls = [];
  const srv = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      calls.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : null, auth: req.headers.authorization });
      res.setHeader('content-type', 'application/json');
      if (req.method === 'GET') return res.end(JSON.stringify(existing));
      res.statusCode = 201;
      res.end(JSON.stringify({ id: 7 }));
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { calls, url: `http://127.0.0.1:${srv.address().port}`, close: () => srv.close() };
}

const base = (ws, bin, url, extra = {}) => {
  const ev = join(ws, 'event.json');
  writeFileSync(ev, JSON.stringify(extra.event ?? { pull_request: { number: 5, head: { repo: { full_name: 'o/r', fork: false } }, base: { repo: { full_name: 'o/r' } } } }));
  return {
    GITHUB_WORKSPACE: ws, GITHUB_API_URL: url, GITHUB_REPOSITORY: 'o/r', GITHUB_SHA: 'a'.repeat(40), GITHUB_REF: 'refs/pull/5/merge',
    GITHUB_EVENT_PATH: ev, GITHUB_OUTPUT: join(ws, 'out.txt'), GITHUB_STEP_SUMMARY: join(ws, 'summary.md'),
    HULLPROOF_BIN: bin, INPUT_PATH: '.', 'INPUT_FAIL-ON': 'blocker', 'INPUT_UPLOAD-SARIF': 'true', INPUT_COMMENT: 'true', 'INPUT_GITHUB-TOKEN': 'tok', ...extra.env,
  };
};
const capture = () => { const lines = []; return { lines, out: (s) => lines.push(s) }; };

test('a blocking run uploads the SARIF file, adds one comment and returns exit code 1', async () => {
  const gh = await fakeGithub([]);
  const { ws, bin } = workspace(1);
  const c = capture();
  const code = await main(base(ws, bin, gh.url), c.out);
  gh.close();
  assert.equal(code, 1);
  const up = gh.calls.find((x) => x.url === '/repos/o/r/code-scanning/sarifs');
  assert.ok(up);
  assert.equal(up.auth, 'Bearer tok');
  assert.equal(up.body.ref, 'refs/pull/5/merge');
  assert.equal(gunzipSync(Buffer.from(up.body.sarif, 'base64')).toString(), readFileSync(join(ws, '.hullproof/ci/results.sarif'), 'utf8'));
  const post = gh.calls.find((x) => x.method === 'POST' && x.url === '/repos/o/r/issues/5/comments');
  assert.ok(post.body.body.startsWith(MARKER));
  assert.match(readFileSync(join(ws, 'out.txt'), 'utf8'), /blocked=true/);
  assert.match(readFileSync(join(ws, 'summary.md'), 'utf8'), /1 blocking finding/);
  // The annotation text from the scanned repository is escaped: a percent sign and a newline cannot end the command early.
  const ann = c.lines.find((l) => l.startsWith('::error file=src/a.js'));
  assert.ok(ann && ann.includes('Bad, 100%25 sure%0Asecond line'), ann);
});

test('an existing comment of the bot is updated, not duplicated', async () => {
  const gh = await fakeGithub([{ id: 41, body: `${MARKER}\nold`, user: { type: 'Bot' } }]);
  const { ws, bin } = workspace(0);
  const code = await main(base(ws, bin, gh.url), capture().out);
  gh.close();
  assert.equal(code, 0);
  assert.ok(gh.calls.find((x) => x.method === 'PATCH' && x.url === '/repos/o/r/issues/comments/41'));
  assert.equal(gh.calls.filter((x) => x.method === 'POST' && x.url.endsWith('/comments')).length, 0);
});

test('a comment that starts with the marker but was not written by a bot is left alone', async () => {
  const gh = await fakeGithub([{ id: 41, body: `${MARKER}\nfake`, user: { type: 'User' } }]);
  const { ws, bin } = workspace(0);
  await main(base(ws, bin, gh.url), capture().out);
  gh.close();
  assert.equal(gh.calls.filter((x) => x.method === 'PATCH').length, 0);
  assert.equal(gh.calls.filter((x) => x.method === 'POST' && x.url.endsWith('/comments')).length, 1);
});

test('a pull request from a fork makes no API call and keeps the exit code', async () => {
  const gh = await fakeGithub();
  const { ws, bin } = workspace(1);
  const event = { pull_request: { number: 9, head: { repo: { full_name: 'x/r', fork: true } }, base: { repo: { full_name: 'o/r' } } } };
  const c = capture();
  const code = await main(base(ws, bin, gh.url, { event }), c.out);
  gh.close();
  assert.equal(code, 1);
  assert.equal(gh.calls.length, 0);
  assert.ok(c.lines.some((l) => /fork/.test(l)));
});

test('no token, or the inputs off, make no API call', async () => {
  const gh = await fakeGithub();
  const { ws, bin } = workspace(0);
  await main(base(ws, bin, gh.url, { env: { 'INPUT_GITHUB-TOKEN': '' } }), capture().out);
  await main(base(ws, bin, gh.url, { env: { 'INPUT_UPLOAD-SARIF': 'false', INPUT_COMMENT: 'false' } }), capture().out);
  gh.close();
  assert.equal(gh.calls.length, 0);
});

test('a failed upload is a notice, not a failed run', async () => {
  const srv = createServer((_q, res) => { res.statusCode = 403; res.setHeader('content-type', 'application/json'); res.end('{"message":"Advanced Security must be enabled for this repository"}'); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { ws, bin } = workspace(0);
  const c = capture();
  const code = await main(base(ws, bin, `http://127.0.0.1:${srv.address().port}`), c.out);
  srv.close();
  assert.equal(code, 0);
  assert.ok(c.lines.some((l) => l.includes('HTTP 403') && l.includes('Advanced Security')));
});

test('bad inputs return 2 before anything runs; the path stays inside the workspace', async () => {
  const { ws, bin } = workspace(0);
  for (const env of [{ 'INPUT_FAIL-ON': 'huge' }, { INPUT_STAGE: 'moon' }, { INPUT_PATH: '../etc' }, { INPUT_PATH: '/etc' }]) {
    const code = await main(base(ws, bin, 'http://127.0.0.1:1', { env }), capture().out);
    assert.equal(code, 2, JSON.stringify(env));
  }
  assert.ok(resolveTarget('/w', 'src').path);
  assert.ok(resolveTarget('/w', '../x').error);
});

test('helpers: escaping and fork detection', () => {
  assert.equal(esc('a%b\r\nc'), 'a%25b%0D%0Ac');
  assert.equal(escProp('a:b,c'), 'a%3Ab%2Cc');
  assert.equal(isForkPr({}), false);
  assert.equal(isForkPr({ pull_request: { head: { repo: { fork: true } } } }), true);
  assert.equal(isForkPr({ pull_request: { head: { repo: { full_name: 'a/b', fork: false } }, base: { repo: { full_name: 'c/d' } } } }), true);
});
