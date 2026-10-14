// Entry point of the Hullproof GitHub Action (runs inside the container). No dependencies, Node built ins only.
// It runs `hullproof ci`, then does the three GitHub specific things: workflow annotations and the job summary, the SARIF upload to code
// scanning, and the pull request comment. Upload and comment need a token that can write; a pull request from a fork has a read only
// token and no secrets, so for it both are skipped with a note and the check result is not changed.
// Text from the scanned repository (finding titles, file names) is data: it is escaped before it goes into a workflow command.
import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const MARKER = '<!-- hullproof-ci -->';
const FAIL_ON = ['blocker', 'critical', 'high', 'medium', 'low', 'none'];
const STAGES = ['', 'LAUNCH', 'GROWTH', 'SCALE'];
const MAX_ANNOTATIONS = 10;

const input = (env, name, fallback = '') => (env[`INPUT_${name.toUpperCase()}`] ?? fallback).trim();
const yes = (v) => /^(true|1|yes)$/i.test(v);

// A value in a workflow command: percent, carriage return and line feed are the characters that end or change a command.
export const esc = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
export const escProp = (s) => esc(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

// The path input, confined to the workspace. Returns the absolute path or an error string.
export function resolveTarget(workspace, given) {
  const abs = resolve(workspace, given || '.');
  const rel = relative(resolve(workspace), abs);
  if (rel.startsWith('..') || isAbsolute(rel)) return { error: `path "${given}" is outside the workspace` };
  return { path: abs };
}

// The commit checked out in the workspace, or null when git cannot say.
export function headCommit(workspace) {
  const r = spawnSync('git', ['-c', 'safe.directory=*', '-C', workspace, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

export function readEvent(env) {
  try { return env.GITHUB_EVENT_PATH ? JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, 'utf8')) : {}; } catch { return {}; }
}

// A pull request whose head lives in another repository (a fork): the token is read only and secrets are not passed.
export function isForkPr(event) {
  const pr = event.pull_request;
  if (!pr) return false;
  return pr.head?.repo?.fork === true || (pr.head?.repo?.full_name && pr.base?.repo?.full_name && pr.head.repo.full_name !== pr.base.repo.full_name);
}

async function api(env, token, method, path, body) {
  const base = env.GITHUB_API_URL || 'https://api.github.com';
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'content-type': 'application/json', 'user-agent': 'hullproof-action' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  return { status: res.status, json, text };
}

export async function uploadSarif(env, token, sarifPath) {
  const body = {
    commit_sha: env.GITHUB_SHA, ref: env.GITHUB_REF,
    sarif: gzipSync(readFileSync(sarifPath)).toString('base64'),
    tool_name: 'Hullproof Engine',
  };
  const r = await api(env, token, 'POST', `/repos/${env.GITHUB_REPOSITORY}/code-scanning/sarifs`, body);
  if (r.status >= 200 && r.status < 300) return { ok: true, note: `SARIF uploaded to code scanning (${r.json?.id ?? 'accepted'})` };
  return { ok: false, note: `SARIF upload to code scanning failed with HTTP ${r.status}: ${String(r.json?.message ?? r.text).slice(0, 200)}. The file is in the workflow artifacts instead.` };
}

export async function upsertComment(env, token, number, text) {
  const repo = env.GITHUB_REPOSITORY;
  let found = null;
  for (let page = 1; page <= 5 && !found; page++) {
    const r = await api(env, token, 'GET', `/repos/${repo}/issues/${number}/comments?per_page=100&page=${page}`);
    if (r.status !== 200 || !Array.isArray(r.json)) return { ok: false, note: `could not list comments (HTTP ${r.status})` };
    found = r.json.find((c) => typeof c.body === 'string' && c.body.startsWith(MARKER) && c.user?.type === 'Bot') ?? null;
    if (r.json.length < 100) break;
  }
  const r = found
    ? await api(env, token, 'PATCH', `/repos/${repo}/issues/comments/${found.id}`, { body: text })
    : await api(env, token, 'POST', `/repos/${repo}/issues/${number}/comments`, { body: text });
  if (r.status >= 200 && r.status < 300) return { ok: true, note: found ? 'pull request comment updated' : 'pull request comment added' };
  return { ok: false, note: `pull request comment failed with HTTP ${r.status}: ${String(r.json?.message ?? r.text).slice(0, 200)}` };
}

function annotate(findingsPath) {
  try {
    const f = JSON.parse(readFileSync(findingsPath, 'utf8'));
    const rank = { BLOCKER: 5, CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const fails = f.records.filter((r) => r.kind === 'fail').sort((a, b) => rank[b.severity] - rank[a.severity] || (a.fingerprint < b.fingerprint ? -1 : 1));
    return fails.slice(0, MAX_ANNOTATIONS).map((r) => {
      const e = r.evidence?.[0];
      const where = e ? `file=${escProp(e.file)},line=${Number(e.line) || 1},` : '';
      return `::error ${where}title=${escProp(`Hullproof ${r.severity} ${r.sec_ids.join(' ')}`)}::${esc(r.title)}`;
    });
  } catch { return []; }
}

export async function main(env = process.env, out = (s) => process.stdout.write(s + '\n')) {
  const workspace = env.GITHUB_WORKSPACE || process.cwd();
  const failOn = input(env, 'fail-on', 'blocker').toLowerCase();
  const stage = input(env, 'stage').toUpperCase();
  if (!FAIL_ON.includes(failOn)) { out(`::error::fail-on takes ${FAIL_ON.join(', ')}`); return 2; }
  if (!STAGES.includes(stage)) { out('::error::stage takes LAUNCH, GROWTH or SCALE, or nothing to read docs/security/STAGE.md'); return 2; }
  const target = resolveTarget(workspace, input(env, 'path', '.'));
  if (target.error) { out(`::error::${esc(target.error)}`); return 2; }

  // pull_request_target runs with a write token and secrets. Scanning the head of the pull request there would hand untrusted code
  // to a privileged job, so the action stops when the checkout is the pull request head. A checkout of the base is fine.
  if (env.GITHUB_EVENT_NAME === 'pull_request_target') {
    const head = readEvent(env).pull_request?.head?.sha;
    if (head && headCommit(workspace) === head) {
      out('::error::This job runs on pull_request_target and has checked out the head of the pull request, which is code from a fork or a branch you do not control. The action will not scan it. Use the pull_request event, or check out the base branch.');
      return 2;
    }
    out('::warning::pull_request_target runs with a write token and secrets. Do not check out the head of the pull request in this workflow.');
  }

  const outDir = join(workspace, '.hullproof');
  const artifacts = join(outDir, 'ci');
  const args = [env.HULLPROOF_BIN || 'hullproof', 'ci', target.path, '--out', outDir, '--artifacts', artifacts, '--fail-on', failOn];
  if (stage) args.push('--stage', stage);
  if (env.HULLPROOF_KIT_DIR) args.push('--kit', env.HULLPROOF_KIT_DIR);
  const childEnv = { ...env, HULLPROOF_TRUST_REPO_OWNER: '1' };
  // The model hunt is not offered by this action. Make sure a stray variable cannot turn it on.
  const r = spawnSync(args[0], args.slice(1), { stdio: ['ignore', 'inherit', 'inherit'], env: childEnv });
  const code = r.status ?? 2;

  const sarif = join(artifacts, 'results.sarif');
  const comment = join(artifacts, 'pr-comment.md');
  const haveFiles = code <= 1 && existsSync(sarif) && existsSync(comment);
  if (haveFiles) {
    for (const line of annotate(join(artifacts, 'findings.json'))) out(line);
    if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, readFileSync(comment, 'utf8').replace(MARKER + '\n', '') + '\n');
  }

  const event = readEvent(env);
  const fork = isForkPr(event);
  const token = input(env, 'github-token');
  const notes = [];
  if (haveFiles && yes(input(env, 'upload-sarif', 'true'))) {
    if (fork) notes.push('SARIF upload skipped: this is a pull request from a fork, so the token is read only. The file is in the workflow artifacts.');
    else if (!token) notes.push('SARIF upload skipped: no github-token.');
    else notes.push((await uploadSarif(env, token, sarif)).note);
  }
  const prNumber = event.pull_request?.number;
  if (haveFiles && yes(input(env, 'comment', 'true')) && prNumber) {
    if (fork) notes.push('Pull request comment skipped: this is a pull request from a fork, so the token is read only. The summary is in the job summary.');
    else if (!token) notes.push('Pull request comment skipped: no github-token.');
    else notes.push((await upsertComment(env, token, prNumber, readFileSync(comment, 'utf8'))).note);
  }
  for (const n of notes) out(`::notice title=Hullproof::${esc(n)}`);

  if (env.GITHUB_OUTPUT) {
    appendFileSync(env.GITHUB_OUTPUT, `exit-code=${code}\nblocked=${code === 1}\nreport-path=${join(artifacts, 'report.md')}\nsarif-path=${sarif}\nartifacts-path=${artifacts}\n`);
  }
  return code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main();
