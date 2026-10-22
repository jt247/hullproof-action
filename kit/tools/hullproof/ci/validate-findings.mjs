#!/usr/bin/env node
// Hullproof findings record validator. No dependencies. Checks the structure and self consistency of the one
// `hullproof-findings` block in a <report>.findings.md file. It cannot show that a file was read or that a trace is true.
//
//   node validate-findings.mjs <file> [--controls docs/hullproof/security-controls.json]
//   node validate-findings.mjs --print-schema
//
// Exit codes: 0 no errors, 1 errors found, 2 usage error or unreadable input.
// Output is counts and numbered messages with record index and field path. Record text is never printed, except the first
// 80 characters of a fingerprint, escaped. Each message names its rule, F1 to F20, as the checks below set it.
// Schemas 1.0.0, 1.1.0 and 1.2.0 are accepted. 1.1.0 adds `machine_evidence` on a fail record (rule F20); 1.2.0 adds its evidence kind and
// run fields (F20, F21), lets a test shown in the sandbox stand in for owner evidence (F13) and adds the reason engine_hunt (F15).
import { pathToFileURL } from 'node:url';
import {
  Collector, EVIDENCE_KIND_VERSION, FINDINGS_INCOMPLETE_REASONS, MIN_PROOF_RUNS, SCHEMA_VERSION, FINDINGS_SCHEMA_VERSIONS, InputError, MACHINE_EVIDENCE, MACHINE_EVIDENCE_VERSION, MAX_BLOCK_CHARS, MAX_DEPTH,
  RAISED_BY, REF, SEC_IDS, SEV_RANK, SEVERITIES, T,
  WARN_BLOCK_CHARS, ROUTE_STATES, HEADER_FIELDS, checkRunHeader, checkShape, cmpBytes, esc, extractBlock, hasOwn,
  inputProblem, isGatedSeverity, isPlain, loadControls, parseJson, readInput, scanStructure, schemaOf, todayUtc,
} from './hullproof-records-common.mjs';

const TAG = 'hullproof-findings';
const CLASSES = ['finding', 'missing_control', 'hardening_note'];
const TRACE_KINDS = ['entrypoint', 'handoff', 'sink'];

const TRACE = T.array(T.obj({ kind: T.enum(TRACE_KINDS), file: T.path(), line: T.line(), note: T.text(300) }), 1, 12);
const BOUNDARY = T.obj({
  principal: T.text(400), input: T.text(400), intended_control: T.text(400),
  crossed: T.text(400), affected: T.text(400), result: T.text(400),
});
const OWNER_EVIDENCE = T.array(T.obj({
  file: T.path(), hash: T.hash(), hash_kind: T.enum(['git_blob', 'sha256']), date: T.date(), commit: T.sha1(), note: T.text(300),
}), 0, 6);
const LOWERING = T.obj({
  from: T.enum(SEVERITIES),
  to: T.enum(SEVERITIES),
  evidence: T.array(REF, 1, 4),
  reviewer: T.obj({
    type: T.enum(['person', 'agent_session', 'PENDING']),
    name: T.text(60, { opt: true }),
    date: T.date({ opt: true }),
  }),
});
const VERIFIER = 'hullproof-finding-verifier';
const OUTCOME_WORDS = {
  REFUTED: { rule: 'F14', msg: 'REFUTED belongs only on a refuted record' },
  ROUTED: { rule: 'F14', msg: 'ROUTED is never stored, the record becomes a routed record' },
};
const FAIL_VERIFIED_BY = T.obj({
  agent: T.const(VERIFIER), mode: T.const('finding'), outcome: T.enum(['UPHELD', 'ADJUSTED', 'INSUFFICIENT'], { badWords: OUTCOME_WORDS }),
  own_severity: T.enum(SEVERITIES), own_class: T.enum(CLASSES), call: T.int(1, Number.MAX_SAFE_INTEGER, { opt: true }),
});
const ROUTED_VERIFIED_BY = T.obj({
  agent: T.const(VERIFIER), mode: T.const('handoff'), outcome: T.enum(['UPHELD', 'ADJUSTED', 'INSUFFICIENT'], { badWords: OUTCOME_WORDS }),
  call: T.int(1),
});
const REFUTED_VERIFIED_BY = T.obj({
  agent: T.const(VERIFIER), mode: T.enum(['finding', 'handoff']), outcome: T.const('REFUTED'), call: T.int(1),
});

const common = (kind) => ({ fingerprint: T.fingerprint(), kind: T.const(kind), sec_ids: SEC_IDS, title: T.text(160) });

export const RECORD_SPECS = {
  fail: T.obj({
    ...common('fail'),
    class: T.enum(CLASSES),
    gap_in_standard: T.bool(),
    severity: T.enum(SEVERITIES),
    confidence: T.enum(['VERIFIED', 'SUSPECTED']),
    demonstrated: T.bool(),
    root_cause: T.text(120),
    raised_by: RAISED_BY,
    impact_statement: T.text(600),
    remediation: T.obj({ strategy: T.text(800), confirm: T.text(400) }),
    evidence: T.array(REF, 1, 8),
    boundary: { ...BOUNDARY, opt: true },
    trace: { ...TRACE, opt: true },
    absence_search: {
      ...T.obj({ command: T.text(300), files_searched: T.int(0), count: T.int(0), practice: T.enum(['absent', 'present_unsafe']) }), opt: true,
    },
    preventing_layer: { ...T.array(REF, 1, 6), opt: true },
    paths_enumerated: { ...T.obj({ count: T.int(1), method: T.text(400) }), opt: true },
    expiry_condition: T.text(300, { opt: true }),
    owner_evidence: { ...OWNER_EVIDENCE, opt: true },
    lowering: { ...LOWERING, opt: true },
    verified_by: { ...FAIL_VERIFIED_BY, opt: true },
    machine_evidence: { ...MACHINE_EVIDENCE, opt: true },
  }),
  routed: T.obj({
    ...common('routed'),
    state: T.enum(ROUTE_STATES),
    reason: T.text(500),
    owner_action: T.text(500),
    check_card: T.pattern('^CC-[A-Z]+-[0-9]+$', 40, { nullable: true }),
    raised_by: RAISED_BY,
    boundary: BOUNDARY,
    trace: { ...TRACE, opt: true },
    verified_by: { ...ROUTED_VERIFIED_BY, opt: true },
  }),
  refuted: T.obj({
    ...common('refuted'),
    claim: T.text(300),
    reason: T.text(500),
    preventing_layer: T.array(REF, 1, 6),
    raised_by: RAISED_BY,
    verified_by: REFUTED_VERIFIED_BY,
  }),
  observation: T.obj({
    ...common('observation'),
    where: T.array(REF, 1, 4),
    note: T.text(400),
    raised_by: RAISED_BY,
  }),
};

export const TOP_SPEC = T.obj({
  schema_version: T.enum(FINDINGS_SCHEMA_VERSIONS),
  report: T.obj({
    ...HEADER_FIELDS,
    incomplete_reason: T.enum(FINDINGS_INCOMPLETE_REASONS, { opt: true }),
    agent_calls: T.int(0),
    budget: T.int(1, Number.MAX_SAFE_INTEGER, { nullable: true }),
  }),
  records: T.array(T.raw(), 0, 500, { maxRule: 'F4' }), // each record is checked against RECORD_SPECS by kind
});

const CLASS_RULES = {
  finding: { need: ['boundary', 'trace'], deny: ['absence_search', 'preventing_layer', 'paths_enumerated', 'expiry_condition'] },
  missing_control: { need: ['absence_search'], deny: ['preventing_layer', 'paths_enumerated', 'expiry_condition'] },
  hardening_note: { need: ['preventing_layer', 'paths_enumerated', 'expiry_condition'], deny: ['absence_search'] },
};

const sortedUnique = (a, cmp) => a.every((x, i) => i === 0 || cmp(a[i - 1], x) < 0);

// Which requirement severities the record names, from the controls map. Empty when there is no map.
function reqSeverities(rec, controls) {
  if (!controls) return [];
  return (rec.sec_ids || []).map((id) => controls.get(id)?.severity).filter(Boolean);
}
const highest = (sevs) => sevs.reduce((a, b) => (SEV_RANK[b] > SEV_RANK[a] ? b : a), sevs[0]);
const oneBelow = (s) => SEVERITIES[Math.min(SEVERITIES.indexOf(s) + 1, SEVERITIES.length - 1)];

// Does this record need an independent check (contract 4.2, verifier outcome rules 2, 3 and 5)? Used by the gate too.
export function needsVerifier(rec, controls, report) {
  if (rec.kind === 'fail') {
    if (rec.class === 'hardening_note' || isGatedSeverity(rec.severity) || report?.profile === 'deep') return true;
    return reqSeverities(rec, controls).some(isGatedSeverity);
  }
  if (rec.kind === 'routed') return reqSeverities(rec, controls).some(isGatedSeverity);
  return false;
}

function checkRecord(rec, i, ctx, state, controls, report) {
  const { c } = ctx;
  const complete = report?.run_status === 'complete';
  const kind = rec.kind;
  const at = (rule, field, msg) => c.error(rule, `${ctx.base} ${field}`.trim(), msg);
  const warn = (rule, field, msg) => c.warn(rule, `${ctx.base} ${field}`.trim(), msg);

  // F8 and F9: fingerprint prefix, sec_ids order, gap flag.
  const ids = rec.sec_ids;
  const sortedIds = ids.every((x, k) => k === 0 || x > ids[k - 1]);
  if (!sortedIds) at('F9', 'sec_ids', 'must be sorted and hold no duplicates');
  const prefix = rec.fingerprint.split(':')[0];
  const wantPrefix = kind === 'observation' ? 'OBS' : (ids[0] ?? 'GAP');
  if (sortedIds && prefix !== wantPrefix) at('F8', 'fingerprint', 'prefix must be the first sec_ids entry, GAP when there is none, or OBS for an observation');
  if (kind === 'routed' && ids.length === 0) at('F9', 'sec_ids', 'needs at least one requirement id on a lead');
  if (kind === 'fail' && rec.gap_in_standard !== (ids.length === 0)) at('F9', 'gap_in_standard', 'must be true exactly when sec_ids is empty');

  // F11 trace shape, for any record that has one.
  if (rec.trace) {
    const tr = rec.trace;
    const first = tr[0].kind, last = tr[tr.length - 1].kind;
    const ok = tr.length === 1
      ? first === 'entrypoint' || first === 'sink'
      : first === 'entrypoint' && last === 'sink' && tr.slice(1, -1).every((x) => x.kind === 'handoff');
    if (!ok) at('F11', 'trace', 'must start with an entrypoint, end with a sink and hold only handoff between');
  }

  if (kind === 'fail') {
    // F10 class rules and lowering shape.
    const rules = CLASS_RULES[rec.class];
    // F20: a rule or check hit stands in for the boundary and trace of a SUSPECTED finding. VERIFIED still needs both.
    const machine = hasOwn(rec, 'machine_evidence');
    if (machine && state.version === SCHEMA_VERSION) at('F20', 'machine_evidence', `needs schema_version ${MACHINE_EVIDENCE_VERSION} or later`);
    const me = machine ? rec.machine_evidence : null;
    if (me) {
      const v12 = state.version === EVIDENCE_KIND_VERSION;
      const has = (k) => hasOwn(me, k);
      if (!v12 && (has('evidence_kind') || has('runs') || has('runs_proven'))) at('F20', 'machine_evidence', `evidence_kind, runs and runs_proven need schema_version ${EVIDENCE_KIND_VERSION}`);
      if (v12 && !has('evidence_kind')) at('F20', 'machine_evidence.evidence_kind', `is required in schema_version ${EVIDENCE_KIND_VERSION}`);
      const sandbox = me.evidence_kind === 'sandbox_test';
      // F21: the run fields belong to a sandbox test, and a sandbox test names both.
      if (sandbox && v12 && !(has('runs') && has('runs_proven'))) at('F21', 'machine_evidence', 'a sandbox_test needs runs and runs_proven');
      if (!sandbox && (has('runs') || has('runs_proven'))) at('F21', 'machine_evidence', 'runs and runs_proven are only for a sandbox_test');
      if (has('runs') && has('runs_proven') && me.runs_proven > me.runs) at('F21', 'machine_evidence.runs_proven', 'is more than runs');
    }
    const waived = machine && rec.class === 'finding' && rec.confidence === 'SUSPECTED';
    for (const f of rules.need) {
      if (hasOwn(rec, f) || waived) continue;
      const verified = f === 'trace' && rec.confidence === 'VERIFIED';
      at(verified ? 'F12' : 'F10', f, `is required for class ${rec.class}${verified ? ' and for a VERIFIED confidence' : ''}`);
    }
    for (const f of rules.deny) if (hasOwn(rec, f)) at('F10', f, `is not allowed for class ${rec.class}`);
    const lw = rec.lowering;
    if (lw) {
      if (lw.to !== rec.severity) at('F10', 'lowering.to', 'must equal severity');
      if (SEV_RANK[lw.from] <= SEV_RANK[lw.to]) at('F10', 'lowering.from', 'must be a higher severity than lowering.to');
      const pending = lw.reviewer.type === 'PENDING';
      for (const f of ['name', 'date']) {
        if (pending && hasOwn(lw.reviewer, f)) at('F10', `lowering.reviewer.${f}`, 'is not allowed when the reviewer is PENDING');
        if (!pending && !hasOwn(lw.reviewer, f)) at('F10', `lowering.reviewer.${f}`, 'is required unless the reviewer is PENDING');
      }
    }
    // F13 owner evidence.
    const oe = rec.owner_evidence || [];
    // 1.2.0: a test the engine ran in the sandbox at least MIN_PROOF_RUNS times, with the flaw shown in every run, stands in for owner evidence.
    const me2 = rec.machine_evidence;
    const shown = state.version === EVIDENCE_KIND_VERSION && me2?.evidence_kind === 'sandbox_test' && Number.isInteger(me2.runs) && me2.runs >= MIN_PROOF_RUNS && me2.runs_proven === me2.runs;
    if (rec.demonstrated && oe.length === 0 && !shown) at('F13', 'demonstrated', 'is true but owner_evidence is empty');
    if (!rec.demonstrated && shown && oe.length === 0) warn('F13', 'demonstrated', `is false although the sandbox test showed the flaw in all ${me2.runs} runs`);
    oe.forEach((e, k) => {
      const want = e.hash_kind === 'git_blob' ? 40 : 64;
      if (e.hash.length !== want) at('F13', `owner_evidence[${k + 1}].hash`, `does not fit hash_kind ${e.hash_kind}`);
      if (e.date > todayUtc()) warn('F13', `owner_evidence[${k + 1}].date`, 'is in the future');
    });
    if (state.fails.has(rec.fingerprint.slice(rec.fingerprint.indexOf(':') + 1))) at('F8', 'fingerprint', 'root cause (path and words) is already used by another fail record');
    state.fails.add(rec.fingerprint.slice(rec.fingerprint.indexOf(':') + 1));
  }

  // F14 verifier consistency.
  const vb = rec.verified_by;
  const needs = needsVerifier(rec, controls, report);
  if (needs && !vb) {
    state.verifierMissing++;
    const always = kind === 'fail' && rec.class === 'hardening_note';
    const msg = 'is required for this record';
    if (always || complete) at('F14', 'verified_by', msg); else warn('F14', 'verified_by', `${msg} (the run is incomplete)`);
  }
  if (vb && kind === 'fail') {
    if (rec.class === 'hardening_note' && vb.outcome === 'INSUFFICIENT') at('F14', 'verified_by.outcome', 'a hardening note needs UPHELD or ADJUSTED');
    const same = vb.own_severity === rec.severity && vb.own_class === rec.class;
    if (vb.outcome === 'UPHELD' && !same) at('F14', 'verified_by', 'UPHELD needs own_severity and own_class equal to the record');
    if (vb.outcome === 'ADJUSTED' && same) warn('F14', 'verified_by', 'ADJUSTED but both own values equal the record');
    if (vb.outcome === 'ADJUSTED' && !rec.lowering && SEV_RANK[vb.own_severity] < SEV_RANK[rec.severity]) warn('F14', 'verified_by', 'ADJUSTED with an own_severity below the record severity and no lowering block (list the disagreement in the report)');
  }

  if (kind === 'fail' && rec.lowering?.from === 'BLOCKER') {
    state.lowered++;
    if (rec.lowering.reviewer.type === 'PENDING') state.pending++;
  }

  // F16 and F17: need the controls file.
  if (!controls) return;
  const unknown = ids.filter((id) => !controls.has(id));
  for (const id of unknown) at('F16', 'sec_ids', `holds an id that is not in the controls file (${esc(id, 20)})`);
  if (kind !== 'fail' || unknown.length) return;
  const sevs = reqSeverities(rec, controls);
  if (sevs.length === 0) return;
  const top = highest(sevs);
  const lw = rec.lowering;
  if (sevs.includes('BLOCKER')) {
    if (rec.class === 'hardening_note') { at('F16', 'class', 'a hardening note may not name a BLOCKER requirement'); return; }
    if (rec.severity !== 'BLOCKER' && rec.severity !== 'CRITICAL') at('F16', 'severity', 'under a BLOCKER requirement only BLOCKER or CRITICAL is allowed');
    if (rec.severity === 'CRITICAL' && !(lw && lw.from === 'BLOCKER' && lw.to === 'CRITICAL')) at('F16', 'lowering', 'CRITICAL under a BLOCKER requirement needs a lowering block from BLOCKER to CRITICAL');
    return;
  }
  if (rec.class === 'finding' && SEV_RANK[rec.severity] < SEV_RANK[top] && !lw) warn('F17', 'severity', 'is below the requirement severity and has no lowering block');
  if (rec.class === 'hardening_note' && rec.severity !== (top === 'LOW' ? 'LOW' : oneBelow(top)) && !lw) warn('F17', 'severity', 'is not exactly one level below the requirement severity');
  if (rec.class === 'missing_control' && SEV_RANK[rec.severity] < SEV_RANK[top] && !(rec.severity === 'MEDIUM' && rec.absence_search?.practice === 'absent')) {
    warn('F17', 'severity', 'is below the requirement severity and the practice is not recorded as absent at MEDIUM');
  }
}

// Validates already parsed JSON. Returns the summary the gate prints.
export function validateDocument(doc, { controls = null, c = new Collector() } = {}) {
  const summary = { records: 0, fail: 0, routed: 0, refuted: 0, observation: 0, verifierMissing: 0, lowered: 0, pending: 0, report: null };
  const state = { fails: new Set(), verifierMissing: 0, lowered: 0, pending: 0, version: isPlain(doc) ? doc.schema_version : null };
  const top = { c, base: 'file' };
  const before = c.errorCount;
  checkShape(TOP_SPEC, doc, '', top);
  if (!isPlain(doc) || !Array.isArray(doc.records) || doc.records.length > 500) return { summary, c, data: null };
  const report = isPlain(doc.report) ? doc.report : null;
  const reportOk = c.errorCount === before;
  if (reportOk) checkRunHeader(report, { c, base: 'report' }, { withBudget: true });
  if (reportOk) summary.report = report;
  // F15 deterministic_only: no model ran, so no agent calls, and every fail record stands on its machine_evidence.
  const deterministic = reportOk && report.incomplete_reason === 'deterministic_only';
  // engine_hunt: the engine ran a hunt, so model calls were made and counted, and no kit verifier ran. Every fail record stands on its machine_evidence.
  const hunted = reportOk && report.incomplete_reason === 'engine_hunt';
  if (hunted && doc.schema_version !== EVIDENCE_KIND_VERSION) c.error('F15', 'report incomplete_reason', `engine_hunt needs schema_version ${EVIDENCE_KIND_VERSION}`);
  if (hunted && !(report.agent_calls >= 1)) c.error('F15', 'report agent_calls', 'must be at least 1 when the run is engine_hunt');
  if (deterministic && doc.schema_version === '1.0.0') c.error('F15', 'report incomplete_reason', `deterministic_only needs schema_version ${MACHINE_EVIDENCE_VERSION} or later`);
  if (deterministic && report.agent_calls !== 0) c.error('F15', 'report agent_calls', 'must be 0 when the run is deterministic_only');

  const fps = [];
  doc.records.forEach((rec, i) => {
    const n = i + 1;
    if (!isPlain(rec)) { c.error('F5', `record ${n}`, 'must be an object'); return; }
    const kind = typeof rec.kind === 'string' && hasOwn(RECORD_SPECS, rec.kind) ? rec.kind : null;
    if (!kind) { c.error('F5', `record ${n}`, 'kind must be fail, routed, refuted or observation'); return; }
    const label = kind === 'fail' && CLASSES.includes(rec.class) ? rec.class : kind;
    const ctx = { c, base: `record ${n} (${label})` };
    const e0 = c.errorCount;
    checkShape(RECORD_SPECS[kind], rec, '', ctx);
    summary.records++; summary[kind]++;
    if (c.errorCount !== e0) return; // cross checks only run on records whose shape is sound
    fps.push([rec.fingerprint, n]);
    checkRecord(rec, i, ctx, state, controls, reportOk ? report : null);
    if ((deterministic || hunted) && kind === 'fail' && !hasOwn(rec, 'machine_evidence')) c.error('F15', `${ctx.base} machine_evidence`, 'is required on every fail record when the run is deterministic_only');
  });
  // F8 order and uniqueness across records (valid fingerprints only).
  for (let k = 1; k < fps.length; k++) {
    const d = cmpBytes(fps[k - 1][0], fps[k][0]);
    if (d === 0) c.error('F8', `record ${fps[k][1]}`, `fingerprint is a duplicate of record ${fps[k - 1][1]}`);
    else if (d > 0) c.error('F8', `record ${fps[k][1]}`, 'is out of order, records are sorted by fingerprint in byte order');
  }
  summary.verifierMissing = state.verifierMissing;
  summary.lowered = state.lowered;
  summary.pending = state.pending;
  return { summary, c, data: doc };
}

// Reads, parses and validates text. Never throws for bad input: problems become collector messages and `fatal`.
export function validateFindingsText(text, { controls = null } = {}) {
  const c = new Collector();
  const empty = { records: 0, fail: 0, routed: 0, refuted: 0, observation: 0, verifierMissing: 0, lowered: 0, pending: 0, report: null };
  let block;
  try { block = extractBlock(text, TAG); } catch (e) {
    c.error('F3', 'file', e instanceof InputError ? `${e.message} (the tag is ${TAG})` : 'the block could not be read');
    return { summary: empty, c, data: null, fatal: true };
  }
  if (block.length > MAX_BLOCK_CHARS) { c.error('F3', 'block', `is longer than ${MAX_BLOCK_CHARS} characters`); return { summary: empty, c, data: null, fatal: true }; }
  if (block.length > WARN_BLOCK_CHARS) c.warn('F3', 'block', `is longer than ${WARN_BLOCK_CHARS} characters`);
  const sc = scanStructure(block, { maxDepth: MAX_DEPTH });
  if (!sc.ok) { c.error('F4', 'block', `is nested deeper than ${MAX_DEPTH} levels`); return { summary: empty, c, data: null, fatal: true }; }
  const p = parseJson(block);
  if (!p.ok) { c.error('F4', 'block', `is not valid JSON${p.position === null ? '' : ` near position ${p.position}`}`); return { summary: empty, c, data: null, fatal: true }; }
  const r = validateDocument(p.value, { controls, c });
  return { ...r, fatal: false };
}

// Reads a file and validates it. `read` problems are reported the same way.
export function validateFindingsFile(path, { controls = null } = {}) {
  let text;
  try { text = readInput(path); } catch (e) {
    const pr = inputProblem(e);
    const c = new Collector();
    c.error(pr.rule, 'file', pr.message);
    return { summary: { records: 0, fail: 0, routed: 0, refuted: 0, observation: 0, verifierMissing: 0, lowered: 0, pending: 0, report: null }, c, data: null, fatal: true, exit: pr.exit };
  }
  return validateFindingsText(text, { controls });
}

export function findingsSchema() {
  const records = {
    type: 'array', maxItems: 500,
    items: { oneOf: Object.values(RECORD_SPECS).map(schemaOf) },
  };
  const top = schemaOf(TOP_SPEC);
  top.properties.records = records;
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://hullproof.invalid/findings.schema.json',
    title: 'Hullproof findings record',
    description: 'The JSON object inside the hullproof-findings block of a <report>.findings.md file. This schema states field names, types and limits only. It cannot state the rules that connect fields (class and kind requirements, fingerprint order and prefix, verifier and lowering rules, report consistency, machine_evidence from schema_version 1.1.0, its evidence_kind and run fields from 1.2.0). validate-findings.mjs checks those.',
    ...top,
  };
}

export function formatReport(res) {
  const s = res.summary;
  const out = [`hullproof findings: records ${s.records} (fail ${s.fail}, routed ${s.routed}, refuted ${s.refuted}, observation ${s.observation}), errors ${res.c.errorCount}, warnings ${res.c.warningCount}`];
  return out;
}

function main(argv) {
  if (argv.length === 1 && argv[0] === '--print-schema') {
    process.stdout.write(`${JSON.stringify(findingsSchema(), null, 2)}\n`);
    return 0;
  }
  const usage = () => { console.error('usage: validate-findings.mjs <file> [--controls security-controls.json] | --print-schema'); return 2; };
  let file = null, controlsPath = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--controls') { controlsPath = argv[++i]; if (!controlsPath) return usage(); }
    else if (argv[i].startsWith('--') || file) return usage();
    else file = argv[i];
  }
  if (!file) return usage();
  let controls = null;
  if (controlsPath) {
    try { controls = loadControls(controlsPath); } catch (e) {
      console.error(`validate-findings: ${e instanceof InputError ? e.message : 'the controls file could not be read'}`);
      return 2;
    }
  }
  const res = validateFindingsFile(file, { controls });
  console.log(formatReport(res)[0]);
  if (!controls) console.log('notice: severity rules skipped, no controls file');
  for (const l of res.c.lines()) console.log(l);
  if (res.exit === 2) return 2;
  return res.c.errorCount > 0 ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(main(process.argv.slice(2)));
