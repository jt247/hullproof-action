// The image is built from pinned inputs. These tests read the Dockerfile and the vendored files and check the pins; they build nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const read = (p) => readFileSync(root + p, 'utf8');
const docker = read('Dockerfile');

test('the base image is pinned by digest and the engine by exact npm version and published integrity', () => {
  assert.match(docker, /^FROM debian:bookworm-slim@sha256:[0-9a-f]{64}$/m);
  assert.match(docker, /^ARG HULLPROOF_VERSION=0\.5\.0$/m);
  assert.match(docker, /^ARG HULLPROOF_SHASUM=0db69fe5941929a2efabf533ec1dd8aaabcbd0b6$/m);
  assert.match(docker, /^ARG HULLPROOF_INTEGRITY=sha512-QXlcVepYfnyryqadVIEClI00tFMSbq8\+hxF5QcMp5uDbJntYa4X\/Z3ldhEr0vIBL46ibMc\/r\+Fkbz5Q\+llKaWQ==$/m);
  // The tarball is checked before it is installed, a mismatch exits 1, and nothing installs from a range or a tag.
  const step = docker.slice(docker.indexOf('npm pack "hullproof@${HULLPROOF_VERSION}"'));
  assert.ok(step.indexOf('process.exit(1)') > 0 && step.indexOf('process.exit(1)') < step.indexOf('npm install --global'));
  assert.match(step, /npm install --global --ignore-scripts [^\n]*\/tmp\/hullproof-\$\{HULLPROOF_VERSION\}\.tgz/);
  assert.doesNotMatch(docker, /npm install[^\n]*hullproof@/);
});

test('no vendored engine tarball is left', () => {
  assert.equal(existsSync(root + 'engine'), false);
  assert.doesNotMatch(docker, /COPY engine|ENGINE_SHA256|hullproof-engine-0\.4/);
});

test('every download has a sha256 for both CPU architectures, and Semgrep installs from a hash locked file', () => {
  for (const name of ['node_sha', 'gl_sha', 'tv_sha', 'osv_sha']) assert.equal(docker.match(new RegExp(`${name}=[0-9a-f]{64}`, 'g')).length, 2, name);
  assert.match(docker, /sha256sum -c -/);
  assert.match(docker, /pip install --require-hashes --no-deps --only-binary=:all: -r \/tmp\/semgrep\.lock/);
  const lock = read('semgrep.lock').split('\n').filter((l) => /^[a-z0-9_.-]+==/.test(l));
  assert.ok(lock.length > 30);
  assert.ok(lock.every((l) => l.endsWith('\\')), 'every pinned package is followed by hashes');
  assert.match(read('semgrep.lock'), /^semgrep==1\.176\.0 \\$/m);
});

test('the vendored Free kit files are the 0.5.0 ones, with their licences and the commit they came from', () => {
  const c = JSON.parse(read('kit/docs/hullproof/security-controls.json'));
  assert.equal(c.standard_version, '0.5.0');
  assert.equal(c.controls.length, 110);
  assert.ok(c.controls.every((x) => x.edition === 'free'));
  assert.match(read('kit/tools/hullproof/ci/validate-findings.mjs'), /1\.2\.0/);
  for (const f of ['LICENSE', 'LICENSE-DOCS-CC-BY-SA-4.0.txt', 'LICENSING.md', 'NOTICE.md']) assert.ok(existsSync(root + 'kit/' + f), f);
  assert.match(read('kit/SOURCE.txt'), /commit [0-9a-f]{40}\./);
  assert.match(read('kit/LICENSE-DOCS-CC-BY-SA-4.0.txt'), /Attribution-ShareAlike 4\.0/);
});
