#!/usr/bin/env node
// Hullproof checklist gate. No dependencies. Reads security-controls.json and a results file, and exits 1 when any
// BLOCKER or CRITICAL control in scope is FAIL or NOT ASSESSED. Prints counts only, never evidence or notes.
//
// It checks the checklist items only. It does not evaluate gate conditions G-1, G-2, G-6, G-7 and G-8 of STANDARD.md
// (stage record, audit report, HIGH findings, scan output, rollback path), so exit code 0 is not a READY verdict.
//
//   node hullproof-gate.mjs --controls docs/hullproof/security-controls.json --results docs/security/reports/PRE-LAUNCH-RESULTS-<date>.md [--scope prelaunch|all]
//
// Results file, any one of:
//   a Markdown table with an ID column and a Result column (the Results table that /hullproof-prelaunch writes, as it is),
//   CSV with a header row (columns ID and Result required), or
//   JSON: an array of {"id","result","notes"} or {"results":[...]}.
// Other columns are ignored, except Notes or Reason (also "evidence"): a NOT APPLICABLE row needs text there.
//
// Rules beyond the result word:
//   PASS (static) settles an item only when the control's authority is repo. For a dashboard or runtime control it is rejected
//   and the item counts as NOT ASSESSED (STANDARD.md, Result states).
//   NOT APPLICABLE settles an item only when the row carries a reason.
//   An ID that appears twice keeps the worse result.
//
// Optional, for the audit records (the findings record and the surface ledger, checked by the two validators in this folder):
//   --findings <report>.findings.md   validate the findings record, then cross check it against the results table
//   --surface <report>.surface-ledger.md   validate the surface ledger, and cross check it against the findings record
// Cross checks (each failure is exit 2): 1 every BLOCKER or CRITICAL row that is FAIL has a fail record that lists it,
// 2 every BLOCKER or CRITICAL id of a fail record reads FAIL in its row, 3 every record that needs a verifier has one in a
// complete run, 4 every routed record that names a BLOCKER or CRITICAL id has a NOT ASSESSED row with the same sub state,
// 5 both files name the same commit and tree and the ledger agrees with the findings record.
// A run that is incomplete, quick, partial, or (with --surface) has a deferred unit cannot support READY: exit 1.
// For a quick or partial run the gated requirements that have no row are counted on one scope line, not listed.
// Exit codes: 0 checklist items settled, 1 open items or a run that cannot support READY, 2 bad input or a cross check failure.
import { pathToFileURL } from 'node:url';
import { ROUTE_STATES, isGatedSeverity, readInput } from './hullproof-records-common.mjs';
import { needsVerifier, validateFindingsFile } from './validate-findings.mjs';
import { validateLedgerFile } from './validate-surface-ledger.mjs';

const GATE_MAX_BYTES = 16 * 1048576;

export function parseCsv(text) {
  const rows = [];
  let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (ch === '"') q = false; else cell += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { row.push(cell); cell = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); cell = '';
      if (row.some((c) => c.trim() !== '')) rows.push(row);
      row = [];
    } else cell += ch;
  }
  row.push(cell);
  if (row.some((c) => c.trim() !== '')) rows.push(row);
  return rows;
}

const NOTE_COLUMNS = ['notes', 'note', 'reason', 'evidence', 'where it is recorded'];

// A Markdown table row to cells. Pipes escaped as \| stay inside the cell.
function mdCells(line) {
  const s = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  return s.split(/(?<!\\)\|/).map((c) => c.replace(/\\\|/g, '|').trim());
}

const clean = (c) => c.replace(/[`*_]/g, '').replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').trim();

// Every Markdown table that has an ID column and a Result column, each as [head, ...rows].
export function parseMarkdownTables(text) {
  const lines = text.split(/\r?\n/);
  const tables = [];
  for (let at = 0; at < lines.length; at++) {
    if (!lines[at].trim().startsWith('|')) continue;
    const head = mdCells(lines[at]).map((c) => clean(c).toLowerCase());
    if (!(head.includes('id') && head.includes('result'))) continue;
    const body = [];
    let k = at + 1;
    for (; k < lines.length && lines[k].trim().startsWith('|'); k++) {
      const cells = mdCells(lines[k]);
      if (cells.every((c) => /^:?-{2,}:?$/.test(c.replace(/\s/g, '')) || c === '')) continue;
      body.push(cells);
    }
    tables.push([head, ...body]);
    at = k;
  }
  return tables;
}

// Returns [id, result, note] per row. note is the text of the first non empty Notes, Reason or Evidence cell, or ''.
export function loadResults(text) {
  const t = text.trim();
  if (t.startsWith('[') || t.startsWith('{')) {
    const j = JSON.parse(t);
    const list = Array.isArray(j) ? j : j.results;
    if (!Array.isArray(list)) throw new Error('JSON results need an array or a "results" array');
    return list.map((r) => [String(r.id ?? r.ID ?? ''), String(r.result ?? r.Result ?? ''),
      String(r.notes ?? r.Notes ?? r.reason ?? r.Reason ?? r.evidence ?? r.Evidence ?? '').trim()]);
  }
  const rowsFrom = (table, md) => {
    const [head, ...body] = table;
    const names = (head || []).map((h) => (md ? h : h.trim().toLowerCase()));
    const [i, r] = [names.indexOf('id'), names.indexOf('result')];
    if (i < 0 || r < 0) throw new Error('the results need a header row with ID and Result columns (Markdown table, CSV or JSON)');
    const noteCols = names.map((n, k) => (NOTE_COLUMNS.includes(n) ? k : -1)).filter((k) => k >= 0);
    const cell = (c, k) => (md ? clean(c[k] || '') : (c[k] || '').trim());
    return body.map((c) => {
      const rawId = cell(c, i);
      const id = (rawId.match(/SEC-[A-Z]+-\d{3}/) || [rawId])[0];
      const note = noteCols.map((k) => cell(c, k)).find((x) => x !== '') || '';
      return [id, cell(c, r), note];
    });
  };
  const tables = /^\s*\|/m.test(t) ? parseMarkdownTables(t) : [];
  if (tables.length > 0) return tables.flatMap((tb) => rowsFrom(tb, true));
  return rowsFrom(parseCsv(t), false);
}

// PASS, PASS (static) and NOT APPLICABLE are settled words. "NOT ASSESSED: NEEDS DYNAMIC TEST" and a blank result are open.
export function normalize(result) {
  const u = result.trim().toUpperCase();
  if (u.startsWith('PASS')) return 'PASS';
  if (u.startsWith('NOT APPLICABLE') || u === 'N/A') return 'NOT APPLICABLE';
  if (u.startsWith('FAIL')) return 'FAIL';
  return 'NOT ASSESSED';
}

export const isStaticPass = (result) => /^\s*PASS\s*\(\s*static\s*\)/i.test(result);

const WORSE = { FAIL: 3, 'NOT ASSESSED': 2, PASS: 1, 'NOT APPLICABLE': 1 };

// The sub state after "NOT ASSESSED:" in a result, or '' when there is none or it is not a known one.
export function subState(raw) {
  const m = /^\s*NOT ASSESSED\s*:\s*(.*)$/i.exec(String(raw));
  if (!m) return '';
  const rest = m[1].trim().toUpperCase();
  return ROUTE_STATES.find((st) => rest.startsWith(st)) || '';
}

// One entry per ID, the worse result winning, as evaluate reads them.
export function collapseRows(rows) {
  const got = new Map();
  let duplicates = 0;
  for (const [id, raw, note = ''] of rows) {
    const entry = { state: normalize(raw), raw, note };
    const old = got.get(id);
    if (old) {
      duplicates++;
      if (WORSE[old.state] > WORSE[entry.state] || (WORSE[old.state] === WORSE[entry.state] && (old.note !== '' || entry.note === ''))) continue;
    }
    got.set(id, entry);
  }
  return { got, duplicates };
}

export function evaluate(controls, rows, scope = 'prelaunch') {
  const { got, duplicates } = collapseRows(rows);
  const counts = { checked: 0, pass: 0, notApplicable: 0, fail: 0, notAssessed: 0, missing: 0, unknownIds: 0, duplicates, passStaticRejected: 0, naWithoutReason: 0 };
  const known = new Set(controls.map((c) => c.id));
  counts.unknownIds = [...got.keys()].filter((id) => id && !known.has(id)).length;
  for (const c of controls) {
    const gated = c.severity === 'BLOCKER' || (c.severity === 'CRITICAL' && (scope === 'all' || c.prelaunch));
    if (!gated) continue;
    counts.checked++;
    const r = got.get(c.id);
    if (r === undefined) { counts.missing++; counts.notAssessed++; continue; }
    if (r.state === 'PASS') {
      if (isStaticPass(r.raw) && c.authority && c.authority !== 'repo') { counts.passStaticRejected++; counts.notAssessed++; } else counts.pass++;
    } else if (r.state === 'NOT APPLICABLE') {
      if (r.note === '') { counts.naWithoutReason++; counts.notAssessed++; } else counts.notApplicable++;
    } else if (r.state === 'FAIL') counts.fail++;
    else counts.notAssessed++;
  }
  return { counts, ok: counts.fail === 0 && counts.notAssessed === 0 };
}

const FLAG_USAGE = 'usage: hullproof-gate.mjs --controls security-controls.json --results results.md|csv|json [--scope prelaunch|all] [--findings <report>.findings.md] [--surface <report>.surface-ledger.md]';

// The four cross checks between the results table and the findings record (check 5 lives in the ledger validator).
export function crossChecks(controlMap, got, findings) {
  const problems = [];
  const gated = (id) => isGatedSeverity(controlMap.get(id)?.severity);
  const failIds = new Set(findings.records.filter((r) => r.kind === 'fail').flatMap((r) => r.sec_ids));
  for (const [id, row] of got) {
    if (gated(id) && row.state === 'FAIL' && !failIds.has(id)) problems.push(`cross check 1: ${id} is FAIL in the results and no fail record lists it`);
  }
  for (const id of [...failIds].sort()) {
    if (gated(id) && got.get(id)?.state !== 'FAIL') problems.push(`cross check 2: ${id} is named by a fail record but its result is not FAIL`);
  }
  const report = findings.report;
  const missing = findings.records.filter((r) => needsVerifier(r, controlMap, report) && !r.verified_by).length;
  if (missing > 0 && report.run_status === 'complete') problems.push(`cross check 3: ${missing} record(s) need a verifier outcome and have none`);
  for (const r of findings.records.filter((x) => x.kind === 'routed')) {
    for (const id of r.sec_ids.filter(gated)) {
      const row = got.get(id);
      if (!row || row.state !== 'NOT ASSESSED' || subState(row.raw) !== r.state) problems.push(`cross check 4: ${id} is named by a routed record (${r.state}) and its result is not NOT ASSESSED with that sub state`);
    }
  }
  return { problems, verifierMissing: missing };
}

function main(argv) {
  const arg = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };
  const [cf, rf, scope] = [arg('--controls'), arg('--results'), arg('--scope', 'prelaunch')];
  const [ff, sf] = [arg('--findings'), arg('--surface')];
  const flagMissingValue = ['--findings', '--surface'].some((f) => argv.includes(f) && !arg(f));
  if (!cf || !rf || !['prelaunch', 'all'].includes(scope) || flagMissingValue) {
    console.error(FLAG_USAGE);
    return 2;
  }
  try {
    const controls = JSON.parse(readInput(cf, { maxBytes: GATE_MAX_BYTES })).controls;
    const rows = loadResults(readInput(rf, { maxBytes: GATE_MAX_BYTES }));
    const { counts: c, ok } = evaluate(controls, rows, scope);
    console.log(`hullproof checklist (${scope}): checked ${c.checked}, pass ${c.pass}, not applicable ${c.notApplicable}, fail ${c.fail}, not assessed ${c.notAssessed} (missing rows ${c.missing}, PASS (static) rejected ${c.passStaticRejected}, NOT APPLICABLE without a reason ${c.naWithoutReason}), duplicate rows ${c.duplicates}, unknown ids ${c.unknownIds}`);
    const records = ff || sf ? auditRecords(controls, rows, ff, sf) : null;
    if (records && records.problems.length) {
      for (const p of records.problems) console.error(`hullproof gate: ${p}`);
      console.log('RESULT: stopped, the audit records or a cross check need attention (exit 2)');
      return 2;
    }
    const reasons = records ? records.reasons : [];
    // A quick or partial run reads only part of the standard, so the gated rows of the rest are missing by design: one line, not one per row.
    if (records && c.missing > 0 && (reasons.includes('quick profile') || reasons.includes('partial scope'))) {
      console.log(`scope: ${c.missing} BLOCKER or CRITICAL requirement(s) lie outside this run's scope and have no row, so this run ends NOT READY`);
    }
    if (!ok) {
      if (reasons.length) console.log(`note: run cannot support READY (${reasons.join(', ')})`);
      console.log('RESULT: NOT READY, open BLOCKER or CRITICAL items');
      return 1;
    }
    if (reasons.length) {
      console.log(`RESULT: run cannot support READY (${reasons.join(', ')})`);
      return 1;
    }
    console.log('RESULT: checklist items settled. Gate conditions G-1, G-2, G-6, G-7 and G-8 are not evaluated by this tool, so this is not a READY verdict.');
    return 0;
  } catch (e) {
    console.error(`hullproof gate: ${e.message}`);
    return 2;
  }
}

// Validates the two record files, prints their counts lines, runs the cross checks. Returns problems and READY blockers.
function auditRecords(controls, rows, ff, sf) {
  const controlMap = new Map(controls.map((k) => [k.id, k]));
  const problems = [];
  let fres = null, sres = null;
  if (ff) {
    fres = validateFindingsFile(ff, { controls: controlMap });
    const s = fres.summary;
    const head = fres.c.errorCount === 0 && s.report ? `, run ${s.report.run_status}, profile ${s.report.profile}, scope ${s.report.scope}` : '';
    console.log(`hullproof findings: records ${s.records} (fail ${s.fail}, routed ${s.routed}, refuted ${s.refuted}, observation ${s.observation}), verifier missing ${s.verifierMissing}, lowered BLOCKER rows ${s.lowered} (reviewer pending ${s.pending}), warnings ${fres.c.warningCount}${head}${sf ? '' : ', surface ledger not supplied'}`);
    if (fres.c.errorCount > 0) for (const l of fres.c.lines()) problems.push(`findings ${l}`);
  }
  if (sf) {
    const useFindings = fres && fres.c.errorCount === 0 && fres.data ? fres.data : null;
    sres = validateLedgerFile(sf, { findings: useFindings });
    const n = sres.counts;
    console.log(`hullproof surface: units ${n.units} (covered ${n.covered}, found ${n.found}, routed ${n.routed}, deferred ${n.deferred}, out of scope ${n.out_of_scope}, not applicable ${n.not_applicable}), warnings ${sres.c.warningCount}${ff ? '' : ', findings record not supplied'}`);
    if (sres.c.errorCount > 0) for (const l of sres.c.lines()) problems.push(`surface ${l}`);
  }
  const reasons = [];
  const headers = [fres && fres.summary.report, sres && sres.counts.ledger].filter(Boolean);
  if (headers.some((h) => h.run_status === 'incomplete')) reasons.push('run incomplete');
  if (headers.some((h) => h.profile === 'quick')) reasons.push('quick profile');
  if (headers.some((h) => h.scope === 'partial')) reasons.push('partial scope');
  if (sres && sres.counts.deferred > 0) reasons.push('deferred units');
  if (problems.length === 0 && fres && fres.data) {
    const { got } = collapseRows(rows);
    problems.push(...crossChecks(controlMap, got, fres.data).problems);
  }
  return { problems, reasons };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(main(process.argv.slice(2)));
