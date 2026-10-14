#!/usr/bin/env node
// Hullproof surface ledger validator. No dependencies. Checks the structure and self consistency of the one
// `hullproof-surface-ledger` block in a <report>.surface-ledger.md file, and with --findings checks it against the findings
// record. It proves that units were assigned and recorded. It does not prove that a file was read or that the attack
// surface was fully derived.
//
//   node validate-surface-ledger.mjs <file> [--findings <findings file>]
//   node validate-surface-ledger.mjs --print-schema
//
// Exit codes: 0 no errors, 1 errors found, 2 usage error or unreadable input.
// File level rules reuse the ids F1 to F8 and F15 of the findings validator. Ledger rules: S1 covered, S2 found, S3 routed,
// S4 deferred and similar, S6 planned or carried, S7 recipes, S8 inventory and units, S9 symbol and folder, S10 unit paths,
// S11 blobs, S12 order and uniqueness, S13 evidence file outside the check paths (warning). Cross check rules: X1 reference exists, X2 reference kind, X3 same commit and tree,
// X4 record not named by any unit (warning).
import { pathToFileURL } from 'node:url';
import {
  Collector, InputError, MAX_BLOCK_CHARS, MAX_DEPTH, REF, SCHEMA_VERSION, T, WARN_BLOCK_CHARS, HEADER_FIELDS,
  checkRunHeader, checkShape, cmpUnits, extractBlock, hasOwn, inputProblem, isPlain, parseJson, readInput, scanStructure,
  schemaOf,
} from './hullproof-records-common.mjs';
import { validateFindingsFile } from './validate-findings.mjs';

const TAG = 'hullproof-surface-ledger';
export const SURFACE_KINDS = ['route', 'action', 'webhook', 'job', 'page', 'table', 'function', 'bucket', 'workflow', 'tool', 'manifest', 'config', 'other'];
export const UNIT_STATUSES = ['covered', 'found', 'routed', 'deferred', 'out_of_scope', 'not_applicable'];
const ACTIVE = ['covered', 'found', 'routed'];
const OTHER_STATUS = ['deferred', 'out_of_scope', 'not_applicable'];
const ID_RE = '^[a-z][a-z0-9-]{0,40}$';

const OWNER_EVIDENCE = T.obj({ file: T.path(), hash: T.hash(), hash_kind: T.enum(['git_blob', 'sha256']), date: T.date(), note: T.text(300) });
const CHECK = T.obj({
  agent: T.agentid(),
  paths: T.array(T.path(), 1, 12),
  invariant: T.text(300),
  method: T.enum(['static', 'scanner', 'owner_evidence']),
  sec_ids: T.array(T.secid(), 0, 8), // F5 below: empty only for a failing check that backs an observation or a gap
  result: T.enum(['holds', 'fails', 'unsettled']),
  evidence: T.array(T.raw({ alts: [REF, OWNER_EVIDENCE] }), 1, 6), // REF for static and scanner, OWNER_EVIDENCE for owner_evidence
});
const BAD_STATUS = {
  planned: { rule: 'S6', msg: 'planned is not a legal status in a written file, write unreached units as deferred with a reason' },
  carried: { rule: 'S6', msg: 'carried is not defined in this schema version' },
};
const UNIT = T.obj({
  kind: T.enum(SURFACE_KINDS),
  path: T.path({ allowFolder: true }),
  symbol: T.text(200),
  card: T.pattern('^HC-[A-Z]+$', 40),
  status: T.enum(UNIT_STATUSES, { badWords: BAD_STATUS }),
  round: T.int(1, 3, { opt: true }),
  agent: T.agentid({ opt: true }),
  paths: T.array(T.path(), 1, 40, { opt: true }),
  blobs: T.map(null, T.sha1(), 40, { opt: true }),
  checks: T.array(CHECK, 1, 12, { opt: true }),
  finding_refs: T.array(T.fingerprint(), 1, 12, { opt: true }),
  reason: T.text(200, { opt: true }),
});
const RECIPE = T.obj({ id: T.pattern(ID_RE, 41), how: T.text(200), count: T.int(0) });
const INVENTORY = T.obj({
  kind: T.enum(SURFACE_KINDS), path: T.path({ allowFolder: true }), symbol: T.text(200), recipe: T.pattern(ID_RE, 41),
  members: T.int(1, Number.MAX_SAFE_INTEGER, { opt: true }),
});

export const TOP_SPEC = T.obj({
  schema_version: T.const(SCHEMA_VERSION),
  ledger: T.obj(HEADER_FIELDS),
  recipes: T.array(RECIPE, 0, 100, { maxRule: 'F4' }),
  inventory: T.array(INVENTORY, 0, 2000, { maxRule: 'F4' }),
  units: T.array(UNIT, 0, 600, { maxRule: 'F4' }),
});

// The top level is shape checked with raw arrays, then each entry is checked one by one so that messages carry its index.
const TOP_SHAPE = T.obj({
  ...TOP_SPEC.fields,
  recipes: T.array(T.raw(), 0, 100, { maxRule: 'F4' }),
  inventory: T.array(T.raw(), 0, 2000, { maxRule: 'F4' }),
  units: T.array(T.raw(), 0, 600, { maxRule: 'F4' }),
});

// S9: a folder path (one trailing slash) goes with symbol * and only with it. A whole file unit (a manifest, a config file, a page
// with no named export) uses symbol . and never *.
function symbolProblem(symbol, path) {
  const folder = path.endsWith('/');
  if (symbol === '*' && !folder) return 'symbol * needs a folder path (one trailing slash). Use symbol . for a whole file';
  if (folder && symbol !== '*') return 'a folder path goes only with symbol *';
  return null;
}
const unitKey = (u) => JSON.stringify([u.kind, u.path, u.symbol, u.card]);
const surfaceKey = (u) => JSON.stringify([u.kind, u.path, u.symbol]);
const emptyCounts = () => ({ units: 0, covered: 0, found: 0, routed: 0, deferred: 0, out_of_scope: 0, not_applicable: 0, recipes: 0, inventory: 0, ledger: null });

function checkOrder(list, keyOf, c, label) {
  for (let k = 1; k < list.length; k++) {
    const d = cmpUnits(keyOf(list[k - 1].v), keyOf(list[k].v));
    if (d === 0) c.error('S12', `${label} ${list[k].n}`, `is a duplicate of ${label} ${list[k - 1].n}`);
    else if (d > 0) c.error('S12', `${label} ${list[k].n}`, `is out of order, ${label}s are sorted by their key in code unit order`);
  }
}

function checkUnit(u, n, c) {
  const base = `unit ${n} (${u.status})`;
  const at = (rule, field, msg) => c.error(rule, `${base} ${field}`.trim(), msg);
  const sp = symbolProblem(u.symbol, u.path);
  if (sp) at('S9', 'symbol', sp);
  if (OTHER_STATUS.includes(u.status)) {
    if (!hasOwn(u, 'reason')) at('S4', 'reason', 'is required for this status');
    for (const f of ['round', 'agent', 'paths', 'blobs', 'checks', 'finding_refs']) if (hasOwn(u, f)) at('S4', f, 'is not allowed for this status');
    return;
  }
  if (hasOwn(u, 'reason')) at('F10', 'reason', 'is only for deferred, out_of_scope and not_applicable');
  for (const f of ['round', 'agent', 'paths', 'checks']) if (!hasOwn(u, f)) at('F10', f, 'is required for this status');
  if (u.status !== 'covered' && !hasOwn(u, 'finding_refs')) at('F10', 'finding_refs', 'is required for this status');
  if (!u.checks || !u.paths) return;
  const results = u.checks.map((k) => k.result);
  const has = (r) => results.includes(r);
  if (u.status === 'covered' && (has('fails') || has('unsettled'))) at('S1', 'checks', 'a covered unit needs every check result to be holds');
  if (u.status === 'found' && !has('fails')) at('S2', 'checks', 'a found unit needs at least one check that fails');
  if (u.status === 'routed' && (has('fails') || !has('unsettled'))) at('S3', 'checks', 'a routed unit needs an unsettled check and no failing check (mixed checks make the unit found)');
  u.checks.forEach((k, i) => {
    if (k.sec_ids.length === 0 && k.result !== 'fails') at('F5', `checks[${i + 1}].sec_ids`, 'needs at least 1 entry. Only a failing check that backs an observation or a gap may name no requirement');
    const wantRef = k.method !== 'owner_evidence';
    k.evidence.forEach((ev, j) => {
      const sub = new Collector();
      checkShape(wantRef ? REF : OWNER_EVIDENCE, ev, '', { c: sub, base: '' });
      if (sub.errorCount) at('F5', `checks[${i + 1}].evidence[${j + 1}]`, wantRef ? 'must be a file, line and note entry for this method' : 'must be an owner evidence entry for this method');
      else if (wantRef && !k.paths.includes(ev.file)) c.warn('S13', `${base} checks[${i + 1}].evidence[${j + 1}]`, 'cites a file that is not in the paths of its check');
    });
  });
  const union = [...new Set(u.checks.flatMap((k) => k.paths))].sort(cmpUnits);
  if (u.paths.length !== union.length || u.paths.some((p, i) => p !== union[i])) at('S10', 'paths', 'must be sorted, unique and equal to the union of the paths of its checks');
  if (u.blobs) for (const k of Object.keys(u.blobs)) if (!u.paths.includes(k)) at('S11', 'blobs', 'holds a path that is not in paths');
}

// Cross check of a parsed ledger against a parsed findings record (both already shape checked).
export function crossCheck(ledger, findings, c) {
  const recs = new Map(findings.records.map((r) => [r.fingerprint, r]));
  const kinds = new Map(findings.records.map((r) => [r.fingerprint, r.kind]));
  const named = new Set();
  ledger.units.forEach((u, i) => {
    if (!Array.isArray(u.finding_refs)) return;
    const refs = u.finding_refs.map((f, j) => {
      const k = kinds.get(f);
      if (!k) c.error('X1', `unit ${i + 1} finding_refs[${j + 1}]`, 'names a fingerprint that is not in the findings record');
      else named.add(f);
      return k;
    });
    const base = `unit ${i + 1} (${u.status}) finding_refs`;
    if (u.status === 'found' && u.checks.some((k) => k.result === 'fails' && k.sec_ids.length === 0) && !u.finding_refs.some((f) => { const r = recs.get(f); return r && (r.kind === 'observation' || (r.kind === 'fail' && r.sec_ids.length === 0)); })) {
      c.error('X2', base, 'a failing check with no requirement id needs an observation record or a fail record with no sec_ids among the references');
    }
    if (u.status === 'covered' && refs.some((k) => k && k !== 'refuted')) c.error('X2', base, 'a covered unit may only name refuted records');
    if (u.status === 'found' && !refs.some((k) => k === 'fail' || k === 'observation')) c.error('X2', base, 'a found unit must name at least one fail or observation record');
    if (u.status === 'routed' && !refs.some((k) => k === 'routed')) c.error('X2', base, 'a routed unit must name at least one routed record');
  });
  if (ledger.ledger.commit !== findings.report.commit || ledger.ledger.tree !== findings.report.tree) c.error('X3', 'ledger', 'commit and tree must match the findings record');
  const loose = findings.records.filter((r) => (r.kind === 'fail' || r.kind === 'observation') && !named.has(r.fingerprint)).length;
  if (loose > 0) c.warn('X4', 'findings', `${loose} fail or observation record(s) are not named by any unit`);
}

export function validateLedgerDocument(doc, { c = new Collector(), findings = null } = {}) {
  const counts = emptyCounts();
  const before = c.errorCount;
  checkShape(TOP_SHAPE, doc, '', { c, base: 'file' });
  if (!isPlain(doc) || ['recipes', 'inventory', 'units'].some((k) => !Array.isArray(doc[k]) || doc[k].length > TOP_SPEC.fields[k].max)) return { counts, c, data: null };
  const header = isPlain(doc.ledger) ? doc.ledger : null;
  if (header && c.errorCount === before) { checkRunHeader(header, { c, base: 'ledger' }, { withBudget: false }); counts.ledger = header; }

  // Recipes.
  const recipes = [];
  doc.recipes.forEach((r, i) => {
    const e0 = c.errorCount;
    checkShape(RECIPE, r, '', { c, base: `recipe ${i + 1}` });
    if (c.errorCount === e0) recipes.push({ v: r, n: i + 1 });
  });
  checkOrder(recipes, (r) => r.id, c, 'recipe');
  counts.recipes = doc.recipes.length;

  // Inventory.
  const inv = [];
  let shapeBad = false;
  doc.inventory.forEach((r, i) => {
    const e0 = c.errorCount;
    checkShape(INVENTORY, r, '', { c, base: `inventory ${i + 1}` });
    if (c.errorCount !== e0) { shapeBad = true; return; }
    const sp = symbolProblem(r.symbol, r.path);
    if (sp) c.error('S9', `inventory ${i + 1}`, sp);
    inv.push({ v: r, n: i + 1 });
  });
  checkOrder(inv, surfaceKey, c, 'inventory');
  counts.inventory = doc.inventory.length;

  // Units.
  const units = [];
  doc.units.forEach((u, i) => {
    const e0 = c.errorCount;
    checkShape(UNIT, u, '', { c, base: `unit ${i + 1}` });
    if (c.errorCount !== e0) { shapeBad = true; return; }
    counts.units++; counts[u.status]++;
    checkUnit(u, i + 1, c);
    units.push({ v: u, n: i + 1 });
  });
  checkOrder(units, unitKey, c, 'unit');

  // S7 and S8 only make sense when every entry is well formed.
  if (!shapeBad) {
    const known = new Set(recipes.map((r) => r.v.id));
    const sums = new Map();
    for (const { v, n } of inv) {
      if (!known.has(v.recipe)) c.error('S7', `inventory ${n}`, 'names a recipe that is not in recipes');
      sums.set(v.recipe, (sums.get(v.recipe) || 0) + (v.members ?? 1));
    }
    for (const { v, n } of recipes) if ((sums.get(v.id) || 0) !== v.count) c.error('S7', `recipe ${n}`, 'count must equal the sum of members over its inventory entries (1 each when members is absent)');
    const invKeys = new Set(inv.map((x) => surfaceKey(x.v)));
    const unitKeys = new Set(units.map((x) => surfaceKey(x.v)));
    for (const { v, n } of inv) if (!unitKeys.has(surfaceKey(v))) c.error('S8', `inventory ${n}`, 'has no unit with the same kind, path and symbol');
    for (const { v, n } of units) if (!invKeys.has(surfaceKey(v))) c.error('S8', `unit ${n}`, 'has no inventory entry with the same kind, path and symbol');
  }

  if (findings && !shapeBad && c.errorCount === before) crossCheck(doc, findings, c);
  return { counts, c, data: doc };
}

export function validateLedgerText(text, { findings = null } = {}) {
  const c = new Collector();
  const fail = (rule, where, msg) => { c.error(rule, where, msg); return { counts: emptyCounts(), c, data: null, fatal: true }; };
  let block;
  try { block = extractBlock(text, TAG); } catch (e) { return fail('F3', 'file', e instanceof InputError ? `${e.message} (the tag is ${TAG})` : 'the block could not be read'); }
  if (block.length > MAX_BLOCK_CHARS) return fail('F3', 'block', `is longer than ${MAX_BLOCK_CHARS} characters`);
  if (block.length > WARN_BLOCK_CHARS) c.warn('F3', 'block', `is longer than ${WARN_BLOCK_CHARS} characters`);
  if (!scanStructure(block, { maxDepth: MAX_DEPTH }).ok) return fail('F4', 'block', `is nested deeper than ${MAX_DEPTH} levels`);
  const p = parseJson(block);
  if (!p.ok) return fail('F4', 'block', `is not valid JSON${p.position === null ? '' : ` near position ${p.position}`}`);
  return { ...validateLedgerDocument(p.value, { c, findings }), fatal: false };
}

export function validateLedgerFile(path, { findings = null } = {}) {
  let text;
  try { text = readInput(path); } catch (e) {
    const pr = inputProblem(e);
    const c = new Collector();
    c.error(pr.rule, 'file', pr.message);
    return { counts: emptyCounts(), c, data: null, fatal: true, exit: pr.exit };
  }
  return validateLedgerText(text, { findings });
}

export function ledgerSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://hullproof.invalid/surface-ledger.schema.json',
    title: 'Hullproof surface ledger',
    description: 'The JSON object inside the hullproof-surface-ledger block of a <report>.surface-ledger.md file. This schema states field names, types and limits only. It cannot state the rules that connect fields (status rules, sort order and uniqueness, recipe counts, inventory and unit matching, unit paths, blobs, the findings cross check). validate-surface-ledger.mjs checks those.',
    ...schemaOf(TOP_SPEC),
  };
}

export function formatReport(res) {
  const n = res.counts;
  return `hullproof surface ledger: units ${n.units} (covered ${n.covered}, found ${n.found}, routed ${n.routed}, deferred ${n.deferred}, out of scope ${n.out_of_scope}, not applicable ${n.not_applicable}), recipes ${n.recipes}, inventory ${n.inventory}, errors ${res.c.errorCount}, warnings ${res.c.warningCount}`;
}

function main(argv) {
  if (argv.length === 1 && argv[0] === '--print-schema') {
    process.stdout.write(`${JSON.stringify(ledgerSchema(), null, 2)}\n`);
    return 0;
  }
  const usage = () => { console.error('usage: validate-surface-ledger.mjs <file> [--findings <findings file>] | --print-schema'); return 2; };
  let file = null, findingsPath = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--findings') { findingsPath = argv[++i]; if (!findingsPath) return usage(); }
    else if (argv[i].startsWith('--') || file) return usage();
    else file = argv[i];
  }
  if (!file) return usage();
  let findings = null;
  if (findingsPath) {
    const f = validateFindingsFile(findingsPath);
    if (f.exit === 2) { for (const l of f.c.lines()) console.error(`findings: ${l}`); return 2; }
    if (f.c.errorCount > 0 || !f.data) {
      console.log(`findings record has ${f.c.errorCount} error(s), the ledger was not checked against it`);
      for (const l of f.c.lines()) console.log(`findings: ${l}`);
      return 1;
    }
    findings = f.data;
  }
  const res = validateLedgerFile(file, { findings });
  console.log(formatReport(res));
  for (const l of res.c.lines()) console.log(l);
  if (res.exit === 2) return 2;
  return res.c.errorCount > 0 ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(main(process.argv.slice(2)));
