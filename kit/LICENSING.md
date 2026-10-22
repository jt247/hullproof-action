# Licensing

Hullproof free edition uses two licenses, split by what a file is. This page tells you which one covers which path.

Copyright 2026 Rare Phronesis Limited.

## Code: Apache License 2.0

Full text: [LICENSE](LICENSE). The code is everything that runs or configures a tool.

| Path | What it is |
|------|------------|
| `kit/.claude/hooks/` | The read only shell hook |
| `kit/tools/hullproof/` | Scanner rules, helper scripts, the installer and hook adapters, test fixtures, the gitleaks configuration and the tools README |
| `kit/tools/hullproof/ci/` | The release gate (`hullproof-gate.mjs`), the record validators (`validate-findings.mjs` and `validate-surface-ledger.mjs`), their shared module (`hullproof-records-common.mjs`) and their README |
| `kit/docs/hullproof/findings.schema.json`, `kit/docs/hullproof/surface-ledger.schema.json` | The schemas of the two audit record files, written by the validators |
| `kit/editors/` (rule files, skills, agents, enforcement settings and each `TOOL.json`) | Configuration files that Claude Code, Codex, Cursor and the other supported tools read |
| `kit/.claude/agents/`, `kit/.claude/skills/`, `kit/.claude/rules/` | Agent, skill and scoped rule files that configure Claude Code |
| `kit/docs/hullproof/.kit-manifest` | The file list the auditor uses to check the kit |
| `engine/` | The Hullproof Engine, the open edition, with the same terms as the public engine repository: the Apache License 2.0, text in `engine/LICENSE`. It holds no Pro file |
| `pack/` | The upload pack. It holds the kit prompts, tool pages and documentation under the licenses of those files in the tables here |

## Documentation: CC BY-SA 4.0

Statement: [LICENSE-DOCS.md](LICENSE-DOCS.md). Full legal code: [LICENSE-DOCS-CC-BY-SA-4.0.txt](LICENSE-DOCS-CC-BY-SA-4.0.txt). The documentation is everything written to be read.

| Path | What it is |
|------|------------|
| `kit/docs/` except the two schema files in the code table | The standard, the domain documents, the release checklist, REFERENCES.md and the templates |
| `kit/docs/hullproof/security-controls.json` | The free controls file: every free requirement as data that the gate, the validators and other tools read. It repeats requirement text from the documentation, so it carries the documentation's licence |
| `kit/prompts/`, the tool pages `kit/editors/*/README.md` and `kit/editors/README.md` | The audit and install prompts, and the pages that explain each tool |
| `conventions/` | ID format, requirement template, severity rules and source rules |
| `README.md`, `AI-SETUP.md`, `RELEASE-NOTES-0.5.0.md`, `CHANGELOG.md` | Repository text |
| `docs/` | The sample audit report |
| `LICENSING.md`, `SECURITY.md` | These policy pages |

## Not covered by either license

1. `NOTICE.md` is a list of credits and notices for other people's work. It is not licensed content.
2. Third party material keeps its own license. Hullproof cites standards and vendor pages by ID and link, and paraphrases facts. Sources and their licenses where known are in `NOTICE.md` and `kit/docs/hullproof/REFERENCES.md`. Nothing here grants you rights to third party material.
3. Names and trademarks of other organisations belong to their owners.

## Hullproof Pro

The paid edition is a separate package under its own commercial license (LICENSE-PRO.md, inside that package). It is not included in this repository or in the free edition download, and these two licenses do not cover its Pro only files.

Some files exist in both editions, with a fuller version in Pro. The text of such a file that appears in this edition is available to everyone under the licenses above, whatever else the Pro copy holds. Text that appears only in the Pro copy is not covered by these licenses. Files carry no license header, so the tables on this page are the record: a path under `kit/.claude/`, `kit/tools/`, `kit/docs/hullproof/.kit-manifest` or one of the three JSON files in the code table is code, and any other path under `kit/docs/`, `conventions/` or a root document is documentation.

## Sources and names

Hullproof cites other people's standards and documents by ID and link. It restates their points in its own words. OWASP ASVS, MASVS, MASTG and MASWE, the OWASP Cheat Sheet Series, the OWASP Top 10 lists and MDN pages are shared under CC BY-SA licenses. Many Hullproof requirements restate the point of one or more of their items in Hullproof's own words and cite the item by its ID. Other sources (NIST, CISA, vendor documentation, laws and regulator guidance) are cited the same way, and their licenses are listed in `kit/docs/hullproof/REFERENCES.md`. If you believe a passage copies a source, tell us through the contact in [SECURITY.md](SECURITY.md) and we will rewrite it.

Hullproof is an independent project. It is not affiliated with or endorsed by any organisation or vendor it names. Hullproof and the READY labels describe the result of a defined set of checks on one commit. You may say that a project was checked against Hullproof, with the date and the commit. You may not say a project is certified, approved or endorsed by Hullproof, and you may not use the Hullproof name as the name of your own product or service. The Apache License 2.0 does not give you rights to the Hullproof name.

## Support

Ask questions and report problems with the kit as GitHub issues on https://github.com/jt247/hullproof-free/issues. Issues are public, so do not paste secrets or private project details. A security problem goes through [SECURITY.md](SECURITY.md).

## What this means in practice

If you copy the kit into your project, keep `LICENSE`, `LICENSE-DOCS.md`, `LICENSE-DOCS-CC-BY-SA-4.0.txt`, `LICENSING.md` and `NOTICE.md` in your repository. They sit outside `kit/`, so the install command does not copy them. The README install steps put them in `docs/hullproof/licence/`. If you share or adapt the documentation, credit Hullproof and release your adapted text under CC BY-SA 4.0 as the license requires. If this page and the license texts differ, the license texts apply.
