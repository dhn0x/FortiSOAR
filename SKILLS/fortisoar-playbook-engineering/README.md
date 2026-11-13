# FortiSOAR Playbook Engineering — Claude Skill

Created and maintained by **dhaneshwar ([@dhn0x](https://github.com/dhn0x))**.

A Claude skill to design, build, review, debug and upgrade FortiSOAR playbooks following the patterns of Fortinet's SOAR Framework solution pack: layered collections, filtered triggers, a Configuration step first, default branches, pluggable enrichment, approval gates with timeouts, and a severity-ranked review checklist.

## What it covers

- Modes: Design, Build, Review, Debug, Upgrade
- Triggers and loop prevention, step types and export UUIDs
- Variables, Jinja cookbook (`picklist`, `fromIRI`, `json_query`, `resolveRange`…)
- Core patterns: bulk loops, `do_until`, waits, error handling, upsert, linking, approvals, comments, dispatchers, multi-tenant
- Naming conventions, a five-level maturity ladder, a review checklist, a debug procedure and field lessons

## Install

- **Claude.ai / Claude app:** zip this folder and upload it under Settings → Capabilities → Skills.
- **Claude Code:** copy this folder to `~/.claude/skills/fortisoar-playbook-engineering/` (or `.claude/skills/` in a project).

Then ask Claude about any FortiSOAR playbook, trigger, Jinja expression, loop, approval or playbook JSON export.

## Author and license

Copyright (c) 2026 dhaneshwar ([@dhn0x](https://github.com/dhn0x)). Licensed under the [MIT License](LICENSE).

This is a community project and is not an official Fortinet product. FortiSOAR and Fortinet names belong to Fortinet, Inc.
