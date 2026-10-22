// Shared code for the Hullproof record validators and the gate. Node built ins only, no network, nothing from an input
// file is ever executed or imported. Run by the owner or by CI, never by an agent.
//
// Input is treated as hostile: files are opened without following links and only when they are regular files, size is
// capped before reading, JSON nesting is checked before parsing, and every message printed about an input is escaped.
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';

export const MAX_BYTES = 1048576;
export const MAX_BLOCK_CHARS = 200000;
export const WARN_BLOCK_CHARS = 150000;
export const MAX_DEPTH = 32;
export const SCHEMA_VERSION = '1.0.0'; // the surface ledger, and the oldest findings version still accepted
// Findings record versions a validator accepts. 1.1.0 adds `machine_evidence` on a fail record and nothing else.
export const MACHINE_EVIDENCE_VERSION = '1.1.0';
// 1.2.0 (kit 0.5.0) adds the evidence kind to `machine_evidence`, the run fields of a sandbox test, and the incomplete reason engine_hunt.
export const EVIDENCE_KIND_VERSION = '1.2.0';
export const FINDINGS_SCHEMA_VERSIONS = [SCHEMA_VERSION, MACHINE_EVIDENCE_VERSION, EVIDENCE_KIND_VERSION];
// What produced a machine record. scanner_rule: a rule of a scanner (Semgrep, Gitleaks, Trivy, OSV). engine_check: a check of the engine
// (map or configuration). hunt_confirmed: a lead a model proposed and the engine confirmed with a deterministic method.
// sandbox_test: a test the engine ran against the app in the proof sandbox.
export const EVIDENCE_KINDS = ['scanner_rule', 'engine_check', 'hunt_confirmed', 'sandbox_test'];
// A sandbox test counts as shown only when it was run at least this many times and showed the flaw every time.
export const MIN_PROOF_RUNS = 3;

export const SEVERITIES = ['BLOCKER', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
export const SEV_RANK = { BLOCKER: 5, CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
export const STAGES = ['LAUNCH', 'GROWTH', 'SCALE'];
export const PROFILES = ['quick', 'standard', 'deep'];
export const SCOPES = ['full', 'partial'];
export const RUN_STATUSES = ['complete', 'incomplete'];
export const INCOMPLETE_REASONS = ['budget_exhausted', 'agent_failure', 'owner_stopped'];
// The findings record (schema 1.1.0) adds one reason the surface ledger does not have: deterministic_only, a run by the
// engine with no model, where no verifier ran by design and every fail record is decided by its machine_evidence.
// Schema 1.2.0 adds engine_hunt: an engine run whose hunt step made model calls (counted in agent_calls) and where still no kit verifier ran.
export const FINDINGS_INCOMPLETE_REASONS = [...INCOMPLETE_REASONS, 'deterministic_only', 'engine_hunt'];
export const ROUTE_STATES = ['NEEDS DASHBOARD', 'NEEDS BUILD', 'NEEDS DYNAMIC TEST', 'ASK OWNER', 'ATTESTATION', 'UNKNOWN'];

// ---------------------------------------------------------------- reading input

export class InputError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

// The rule a reading problem belongs to, and whether it is a usage level problem (exit 2) or a validation error (exit 1).
export function inputProblem(e) {
  const code = e && e.code;
  if (code === 'NOT_FOUND' || code === 'UNREADABLE') return { rule: 'F1', message: e.message, exit: 2 };
  if (code === 'BAD_UTF8') return { rule: 'F2', message: e.message, exit: 1 };
  if (code === 'NOT_REGULAR' || code === 'TOO_BIG') return { rule: 'F1', message: e.message, exit: 1 };
  return { rule: 'F1', message: 'input could not be read', exit: 2 };
}

// Returns the text, or throws an InputError with a fixed message. Never includes path text in the message.
export function readInput(path, { maxBytes = MAX_BYTES } = {}) {
  if (typeof path !== 'string' || path === '' || path.includes('\0')) throw new InputError('UNREADABLE', 'input path is not usable');
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    if (e && e.code === 'ENOENT') throw new InputError('NOT_FOUND', 'input file was not found');
    if (e && (e.code === 'ELOOP' || e.code === 'EMLINK')) throw new InputError('NOT_REGULAR', 'input is not a regular file (links, pipes, devices and folders are refused)');
    throw new InputError('UNREADABLE', 'input file could not be opened');
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new InputError('NOT_REGULAR', 'input is not a regular file (links, pipes, devices and folders are refused)');
    if (st.size > maxBytes) throw new InputError('TOO_BIG', `input is larger than ${maxBytes} bytes`);
    const buf = Buffer.allocUnsafe(st.size);
    let got = 0;
    while (got < st.size) {
      const n = readSync(fd, buf, got, st.size - got, null);
      if (n === 0) break;
      got += n;
    }
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(buf.subarray(0, got)); // strips one leading byte order mark
    } catch {
      throw new InputError('BAD_UTF8', 'input is not valid UTF 8');
    }
  } catch (e) {
    if (e instanceof InputError) throw e;
    throw new InputError('UNREADABLE', 'input file could not be read');
  } finally {
    try { closeSync(fd); } catch { /* nothing to do */ }
  }
}

// Finds the one fenced block whose info string is exactly `tag`. The block closes at the first line that is exactly three backticks.
export function extractBlock(text, tag) {
  const lines = text.split(/\r?\n/);
  const open = new RegExp('^```' + tag.replace(/[^a-z0-9-]/g, '') + '\\s*$');
  const close = /^```\s*$/;
  let at = -1;
  for (let i = 0; i < lines.length; i++) {
    if (!open.test(lines[i])) continue;
    if (at >= 0) throw new InputError('MULTI_BLOCK', 'more than one block with this tag was found');
    at = i;
  }
  if (at < 0) {
    // Name the opening lines that were found (info strings only, never record text), so the fix is one line.
    const seen = [...new Set(lines.filter((l) => /^```/.test(l) && !close.test(l)).map((l) => l.slice(3).trim().replace(/[^A-Za-z0-9_-]/g, '?').slice(0, 30)))].slice(0, 5);
    throw new InputError('NO_BLOCK', `no block with this tag was found${seen.length ? ' (opening fences found: ' + seen.join(', ') + ')' : ' (no opening fence found)'}`);
  }
  let end = -1;
  for (let j = at + 1; j < lines.length; j++) if (close.test(lines[j])) { end = j; break; }
  if (end < 0) throw new InputError('UNCLOSED', 'the block is not closed');
  return lines.slice(at + 1, end).join('\n');
}

// One pass over raw JSON text, with string and escape state. Rejects over deep text before JSON.parse can overflow its stack.
export function scanStructure(text, { maxDepth = MAX_DEPTH } = {}) {
  let depth = 0, max = 0, inStr = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inStr) {
      if (esc) esc = false; else if (c === 92) esc = true; else if (c === 34) inStr = false;
      continue;
    }
    if (c === 34) inStr = true;
    else if (c === 91 || c === 123) { depth++; if (depth > max) max = depth; if (depth > maxDepth) return { depth: max, ok: false }; }
    else if (c === 93 || c === 125) depth--;
  }
  return { depth: max, ok: true };
}

// Never returns the parser message (V8 puts a piece of the input in it). Only the position.
export function parseJson(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (e) {
    const m = /position (\d+)/.exec(String((e && e.message) || ''));
    return { ok: false, position: m ? Number(m[1]) : null };
  }
}

// ---------------------------------------------------------------- text and path helpers

// Controls, format and invisible characters, private use, line and paragraph separators, lone surrogates, tag characters,
// and every space like character except the plain space.
const UNSAFE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}   -   　\u{E0000}-\u{E007F}]/u;
const HAS_VISIBLE = /[^\s\p{Z}\p{Cc}\p{Cf}]/u;

// Returns null when the value is acceptable, or a short reason code: type, length, blank, chars.
export function textProblem(value, max) {
  if (typeof value !== 'string') return 'type';
  if (value.length < 1 || value.length > max) return 'length';
  if (UNSAFE.test(value)) return 'chars';
  if (!HAS_VISIBLE.test(value)) return 'blank';
  return null;
}
export const checkText = (value, max) => textProblem(value, max) === null;

export function isSafePath(p, { allowFolder = false } = {}) {
  if (typeof p !== 'string' || p.length < 1 || p.length > 300) return false;
  if (p.startsWith('/') || p.includes('\\') || p.includes(':') || p.includes('~') || p.includes('\0')) return false;
  if (UNSAFE.test(p)) return false;
  let body = p;
  if (p.endsWith('/')) {
    if (!allowFolder) return false;
    body = p.slice(0, -1);
  }
  if (body === '') return false;
  const segs = body.split('/');
  return segs.every((s) => s !== '' && s !== '..');
}

export const isSha1 = (s) => typeof s === 'string' && /^[0-9a-f]{40}$/.test(s);
export const isSha256 = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
export const isSecId = (s) => typeof s === 'string' && /^SEC-[A-Z]+-[0-9]{3}$/.test(s);
export function isDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}
export const todayUtc = () => new Date().toISOString().slice(0, 10);

// Safe to show in a terminal: unsafe characters become \u{XXXX}, and the value is cut at `max` characters.
export function escapeForTerminal(s, max = 80) {
  const chars = Array.from(String(s));
  const cut = chars.length > max;
  const out = chars.slice(0, max).map((ch) => {
    if (ch === ' ' || !(UNSAFE.test(ch) || /[\s]/u.test(ch))) return ch;
    return `\\u{${ch.codePointAt(0).toString(16).toUpperCase()}}`;
  }).join('');
  return cut ? `${out}...` : out;
}
export const esc = escapeForTerminal;

// Plain comparators. Fingerprints are sorted in byte order, everything else in code unit order.
export const cmpUnits = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
export const cmpBytes = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

// ---------------------------------------------------------------- collector

export class Collector {
  constructor(cap = 100) {
    this.cap = cap;
    this.errors = [];
    this.warnings = [];
    this.errorCount = 0;
    this.warningCount = 0;
  }
  #fmt(tier, rule, where, message) {
    return escapeForTerminal(`${tier} ${rule} ${[where, message].filter(Boolean).join(' ')}`, 300);
  }
  error(rule, where, message) {
    this.errorCount++;
    if (this.errors.length < this.cap) this.errors.push(this.#fmt('E', rule, where, message));
  }
  warn(rule, where, message) {
    this.warningCount++;
    if (this.warnings.length < this.cap) this.warnings.push(this.#fmt('W', rule, where, message));
  }
  // Numbered lines, errors first, with a counted remainder when a cap was hit.
  lines() {
    const out = [];
    let n = 0;
    for (const m of this.errors) out.push(`${++n}. ${m}`);
    if (this.errorCount > this.errors.length) out.push(`   ... and ${this.errorCount - this.errors.length} more errors not shown`);
    for (const m of this.warnings) out.push(`${++n}. ${m}`);
    if (this.warningCount > this.warnings.length) out.push(`   ... and ${this.warningCount - this.warnings.length} more warnings not shown`);
    return out;
  }
}

// ---------------------------------------------------------------- field tables

// One table drives both the checks and --print-schema. A field is required unless it carries opt: true.
export const T = {
  text: (max, extra = {}) => ({ t: 'text', max, ...extra }),
  enum: (values, extra = {}) => ({ t: 'enum', values, ...extra }),
  const: (value) => ({ t: 'const', value }),
  bool: (extra = {}) => ({ t: 'bool', ...extra }),
  int: (min, max = Number.MAX_SAFE_INTEGER, extra = {}) => ({ t: 'int', min, max, ...extra }),
  path: (extra = {}) => ({ t: 'path', ...extra }),
  line: () => ({ t: 'line' }),
  sha1: () => ({ t: 'sha1' }),
  hash: () => ({ t: 'hash' }),
  date: (extra = {}) => ({ t: 'date', ...extra }),
  secid: () => ({ t: 'secid' }),
  agentid: (extra = {}) => ({ t: 'agentid', ...extra }),
  pattern: (re, max, extra = {}) => ({ t: 'pattern', re, max, ...extra }),
  fingerprint: () => ({ t: 'fingerprint' }),
  array: (of, min, max, extra = {}) => ({ t: 'array', of, min, max, ...extra }),
  obj: (fields, extra = {}) => ({ t: 'object', fields, ...extra }),
  map: (key, of, max, extra = {}) => ({ t: 'map', key, of, max, ...extra }),
  raw: (extra = {}) => ({ t: 'raw', ...extra }), // accepted as is, the caller checks it against another table
};

export const RAISED_BY_RE = '^[A-Za-z0-9][A-Za-z0-9 .:_/-]{0,60}$';
export const FINGERPRINT_RE = '^(SEC-[A-Z]+-[0-9]{3}|GAP|OBS):(-|[^\\s:]+):[a-z0-9]+(-[a-z0-9]+){0,15}$';
export const AGENT_RE = '^[a-z][a-z0-9-]{0,30}$';

export const REF = T.obj({ file: T.path(), line: T.line(), note: T.text(300) });
export const RAISED_BY = T.array(T.pattern(RAISED_BY_RE, 61), 1, 6);
export const SEC_IDS = T.array(T.secid(), 0, 12);

// Which deterministic tool or check produced a fail record (findings schema 1.1.0). `config_sha256` is the sha256 of the
// tool's config file, or of the sorted per file sha256 list of a rules folder, and null when the tool ran on its built in
// defaults with no config file.
export const TOOL_RE = '^[a-z][a-z0-9._-]{0,39}$';
export const RULE_ID_RE = '^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$';
export const TOOL_VERSION_RE = '^[A-Za-z0-9][A-Za-z0-9._+-]{0,59}$';
export const MACHINE_EVIDENCE = T.obj({
  tool: T.pattern(TOOL_RE, 40),
  rule_id: T.pattern(RULE_ID_RE, 200),
  tool_version: T.pattern(TOOL_VERSION_RE, 60),
  config_sha256: T.pattern('^[0-9a-f]{64}$', 64, { nullable: true }),
  evidence_kind: T.enum(EVIDENCE_KINDS, { opt: true }),           // 1.2.0, required there
  runs: T.int(1, 20, { opt: true }),                              // 1.2.0, sandbox_test only: how often the test ran
  runs_proven: T.int(0, 20, { opt: true }),                       // 1.2.0, sandbox_test only: in how many of those runs it showed the flaw
});

const PATTERNS = {
  sha1: '^[0-9a-f]{40}$',
  hash: '^([0-9a-f]{40}|[0-9a-f]{64})$',
  date: '^[0-9]{4}-[0-9]{2}-[0-9]{2}$',
  secid: '^SEC-[A-Z]+-[0-9]{3}$',
  agentid: AGENT_RE,
  fingerprint: FINGERPRINT_RE,
};
const compiled = new Map();
const rx = (src) => { if (!compiled.has(src)) compiled.set(src, new RegExp(src)); return compiled.get(src); };

const isPlain = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }

// Checks one value against a field table entry. `ctx` is { c: Collector, base: 'record 3 (fail)' }.
// Structure problems are F5, text F6, path and line F7, fingerprint shape F8, record count caps F4.
export function checkShape(spec, value, path, ctx) {
  const at = (rule, msg) => ctx.c.error(rule, `${ctx.base} ${path}`.trim(), msg);
  switch (spec.t) {
    case 'text': {
      const why = textProblem(value, spec.max);
      if (why === 'type') at('F5', 'must be a string');
      else if (why === 'length') at('F6', `must be 1 to ${spec.max} characters`);
      else if (why) at('F6', 'must hold visible text with no control or hidden characters');
      return;
    }
    case 'enum':
      if (spec.badWords && typeof value === 'string' && has(spec.badWords, value)) { at(spec.badWords[value].rule, spec.badWords[value].msg); return; }
      if (typeof value !== 'string' || !spec.values.includes(value)) at('F5', 'is not one of the allowed values');
      return;
    case 'const':
      if (value !== spec.value) at('F5', 'is not the expected fixed value');
      return;
    case 'bool':
      if (typeof value !== 'boolean') at('F5', 'must be true or false');
      return;
    case 'int':
      if (value === null && spec.nullable) return;
      if (typeof value !== 'number' || !Number.isInteger(value)) at('F5', `must be an integer${spec.nullable ? ' or null' : ''}`);
      else if (value < spec.min || value > spec.max) at('F5', 'is outside the allowed range');
      return;
    case 'path':
      if (typeof value !== 'string') at('F5', 'must be a string');
      else if (!isSafePath(value, { allowFolder: !!spec.allowFolder })) at('F7', 'is not a safe repository relative path');
      return;
    case 'line':
      if (typeof value !== 'number' || !Number.isInteger(value)) at('F5', 'must be an integer');
      else if (value < 1 || value > 10000000) at('F7', 'is not a line number from 1 to 10000000');
      return;
    case 'sha1': case 'hash': case 'secid': case 'agentid':
      if (typeof value !== 'string') at('F5', 'must be a string');
      else if (!rx(PATTERNS[spec.t]).test(value)) at('F5', `does not match the ${spec.t} pattern`);
      return;
    case 'date':
      if (typeof value !== 'string') at('F5', 'must be a string');
      else if (!isDate(value)) at('F5', 'is not a real date written YYYY-MM-DD');
      return;
    case 'pattern':
      if (value === null && spec.nullable) return;
      if (typeof value !== 'string') at('F5', 'must be a string');
      else if (value.length > spec.max || !rx(spec.re).test(value)) at('F5', 'does not match the required pattern');
      return;
    case 'fingerprint':
      if (typeof value !== 'string') at('F5', 'must be a string');
      else if (value.length > 400 || !rx(PATTERNS.fingerprint).test(value)) at('F8', 'is not a valid fingerprint');
      else {
        const p = value.split(':')[1];
        if (p !== '-' && !isSafePath(p)) at('F8', 'fingerprint path is not safe');
      }
      return;
    case 'array': {
      if (!Array.isArray(value)) { at('F5', 'must be an array'); return; }
      if (value.length > spec.max) { at(spec.maxRule || 'F5', `holds more than ${spec.max} entries`); return; }
      if (value.length < spec.min) at('F5', `needs at least ${spec.min} entries`);
      value.forEach((item, i) => checkShape(spec.of, item, `${path}[${i + 1}]`, ctx));
      return;
    }
    case 'map': {
      if (!isPlain(value)) { at('F5', 'must be an object'); return; }
      const keys = Object.keys(value);
      if (keys.length > spec.max) { at('F5', `holds more than ${spec.max} entries`); return; }
      for (const k of keys) {
        if (!isSafePath(k)) at('F7', 'holds a key that is not a safe repository relative path');
        else checkShape(spec.of, value[k], `${path}.${esc(k, 40)}`, ctx);
      }
      return;
    }
    case 'object': {
      if (!isPlain(value)) { at('F5', 'must be an object'); return; }
      for (const k of Object.keys(value)) {
        if (!has(spec.fields, k)) at('F5', `has an unknown key ${esc(k, 40)}`);
      }
      for (const [k, f] of Object.entries(spec.fields)) {
        const sub = path ? `${path}.${k}` : k;
        if (!has(value, k)) { if (!f.opt) ctx.c.error('F5', `${ctx.base} ${sub}`.trim(), 'is required'); continue; }
        checkShape(f, value[k], sub, ctx);
      }
      return;
    }
    case 'raw':
      return;
    default:
      throw new Error('unknown field type');
  }
}

// Every dotted key path in a field table, for the schema match test. Array and map entries use [] and *.
export function specPaths(spec, prefix = '') {
  if (spec.t === 'object') return Object.entries(spec.fields).flatMap(([k, f]) => [`${prefix}${k}`, ...specPaths(f, `${prefix}${k}.`)]);
  if (spec.t === 'array') return specPaths(spec.of, `${prefix.replace(/\.$/, '')}[].`);
  if (spec.t === 'map') return specPaths(spec.of, `${prefix.replace(/\.$/, '')}.*.`);
  if (spec.t === 'raw' && spec.alts) return [...new Set(spec.alts.flatMap((a) => specPaths(a, prefix)))];
  return [];
}

// JSON Schema (draft 2020-12) for a field table. It cannot state the cross field rules, which the validator checks.
export function schemaOf(spec) {
  switch (spec.t) {
    case 'text': return { type: 'string', minLength: 1, maxLength: spec.max };
    case 'enum': return { enum: spec.values };
    case 'const': return { const: spec.value };
    case 'bool': return { type: 'boolean' };
    case 'int': {
      const s = { type: spec.nullable ? ['integer', 'null'] : 'integer', minimum: spec.min };
      if (spec.max !== Number.MAX_SAFE_INTEGER) s.maximum = spec.max;
      return s;
    }
    case 'path': return { type: 'string', minLength: 1, maxLength: 300, description: 'repository relative path, no leading slash, no .. segment, no backslash, colon or ~' };
    case 'line': return { type: 'integer', minimum: 1, maximum: 10000000 };
    case 'sha1': case 'hash': case 'secid': case 'agentid': case 'fingerprint':
      return { type: 'string', pattern: PATTERNS[spec.t] };
    case 'date': return { type: 'string', pattern: PATTERNS.date };
    case 'pattern': return { type: spec.nullable ? ['string', 'null'] : 'string', pattern: spec.re, maxLength: spec.max };
    case 'array': return { type: 'array', items: schemaOf(spec.of), minItems: spec.min, maxItems: spec.max };
    case 'map': return { type: 'object', additionalProperties: schemaOf(spec.of), maxProperties: spec.max };
    case 'object': {
      const out = { type: 'object', additionalProperties: false, properties: {} };
      const req = [];
      for (const [k, f] of Object.entries(spec.fields)) { out.properties[k] = schemaOf(f); if (!f.opt) req.push(k); }
      if (req.length) out.required = req;
      return out;
    }
    case 'raw': return spec.alts ? { oneOf: spec.alts.map(schemaOf) } : { type: 'object' };
    default: throw new Error('unknown field type');
  }
}

// Report and ledger headers share their consistency rules (F15).
export function checkRunHeader(h, ctx, { withBudget }) {
  const c = ctx.c;
  if (h.run_status === 'incomplete' && !has(h, 'incomplete_reason')) c.error('F15', `${ctx.base} incomplete_reason`, 'is required when the run is incomplete');
  if (h.run_status === 'complete' && has(h, 'incomplete_reason')) c.error('F15', `${ctx.base} incomplete_reason`, 'is not allowed when the run is complete');
  if (h.scope === 'partial' && !has(h, 'scope_note')) c.error('F15', `${ctx.base} scope_note`, 'is required when the scope is partial');
  if (h.scope === 'full' && has(h, 'scope_note')) c.error('F15', `${ctx.base} scope_note`, 'is not allowed when the scope is full');
  if (h.tree_clean === false) c.warn('F15', `${ctx.base} tree_clean`, 'is false, the audited tree had uncommitted changes');
  if (withBudget && Number.isInteger(h.budget) && Number.isInteger(h.agent_calls) && h.agent_calls > h.budget) {
    c.warn('F15', `${ctx.base} agent_calls`, 'is more than the budget');
  }
}

// The fields both headers share (the report adds agent_calls and budget).
export const HEADER_FIELDS = {
  commit: T.sha1(),
  tree: T.sha1(),
  tree_clean: T.bool(),
  stage: T.enum(STAGES),
  profile: T.enum(PROFILES),
  scope: T.enum(SCOPES),
  scope_note: T.text(200, { opt: true }),
  run_status: T.enum(RUN_STATUSES),
  incomplete_reason: T.enum(INCOMPLETE_REASONS, { opt: true }),
};

// Reads a controls file (the generated security-controls.json shape) into a Map of id to { severity, authority }.
export function loadControls(path) {
  const text = readInput(path, { maxBytes: 16 * 1048576 });
  let j;
  try { j = JSON.parse(text); } catch { throw new InputError('BAD_CONTROLS', 'the controls file is not valid JSON'); }
  if (!j || !Array.isArray(j.controls)) throw new InputError('BAD_CONTROLS', 'the controls file needs a top level controls array');
  const map = new Map();
  for (const k of j.controls) {
    if (k && typeof k.id === 'string' && SEV_RANK[k.severity]) map.set(k.id, { severity: k.severity, authority: k.authority, prelaunch: !!k.prelaunch });
  }
  return map;
}

export const isGatedSeverity = (s) => s === 'BLOCKER' || s === 'CRITICAL';
export { has as hasOwn, isPlain };
