# AGENTS.md

Cross-tool guidance for AI coding agents working in this repository.

## Quick start (new agents)

**Do these in order. Do NOT skip to reading source code.**

1. Read this file fully — project context, repo layout, conventions.
2. **Go to Vikunja first.** Use the Vikunja MCP tools (`mcp__vikunja__*`) to read the
   relevant project (`vikunja_projects.get`), list all tasks
   (`vikunja_tasks.list`), and understand current status. This is the
   authoritative source for what's been done, what's in progress, and what's
   planned. Understand the full project state from Vikunja before touching
   the codebase.
3. Check `.cursor/rules/` if scoped rule files exist.
4. Check `docs/` for technical specs (protocol, architecture decisions).
5. **Only then** read source code as needed for your specific task.

## What is Dixie Flatline?

Dixie Flatline is an **LLM-driven red team penetration testing tool**. Named
after the legendary construct from William Gibson's *Neuromancer*, it uses large
language models to autonomously plan and execute penetration testing
engagements.

**Architecture:** The framework owns the agentic loop (ReAct: observe → think →
act → observe). The LLM provides reasoning and planning; the framework handles
tool orchestration, Docker sandboxing, state management, and structured output.

**Goals:**

- **Autonomous reconnaissance** — automated target enumeration, service
  discovery, and attack surface mapping
- **LLM-powered exploit planning** — use language models to reason about
  vulnerabilities, chain attack paths, and prioritize targets
- **Red team simulation** — simulate realistic adversary tactics, techniques,
  and procedures (TTPs)
- **Structured reporting** — generate actionable findings with evidence,
  severity ratings, and remediation guidance

**Status:** Phase 1 in progress. Model-agnostic design allows prototyping with
OpenAI/Anthropic while waiting for Wintermute's fine-tuned model.

## Systems of record

| What | Where |
|------|-------|
| Vision, roadmap, project status | Vikunja project "Dixie Flatline" |
| Research findings and analysis | Vikunja task descriptions and comments |
| Task status and ownership | Vikunja tasks |
| Looping AI code review process (Cursor + Vikunja + pytest) | `docs/review-playbook.md` (mirrors Vikunja playbook task) |
| Architecture decisions | `docs/` directory |
| Coding rules and conventions | This file + `.cursor/rules/` |
| Engagement configuration | `example-engagement.yaml` |

Technical documentation that doesn't fit in Vikunja (specs, diagrams,
benchmarks, design docs) goes in `docs/`. Use Vikunja task descriptions and
comments for research findings, status reports, and narrative context. Use
`docs/` for anything an agent or developer needs while reading or writing code.

## Repo layout

```
dixie_flatline/
├── AGENTS.md                    # This file
├── README.md                    # Quick start guide
├── pyproject.toml               # Python project manifest (hatchling)
├── example-engagement.yaml      # Example engagement configuration
├── docker/
│   └── Dockerfile               # Kali-based sandbox with pentesting tools
├── docs/                        # Technical documentation
│   └── review-playbook.md       # Looping code review: Cursor agent + Vikunja + pytest
├── src/dixie/
│   ├── __init__.py
│   ├── cli.py                   # CLI entrypoint (click): engage, tools, report, intel
│   ├── core/
│   │   ├── agent.py             # ReAct agent loop, recon-mode filtering, finding registration
│   │   ├── config.py            # EngagementMode (recon|full), LLM, Sandbox, Agent config
│   │   ├── sandbox.py           # Docker sandbox for isolated tool execution
│   │   ├── recon_policy.py      # Recon-mode blocked tool names (single source of truth)
│   │   └── schema.py            # Data models: ToolResult, Finding, EngagementState, Confidence
│   ├── models/
│   │   └── llm.py               # Model-agnostic LLM interface via LiteLLM
│   ├── intel/
│   │   ├── __init__.py
│   │   ├── collectors/
│   │   │   ├── __init__.py
│   │   │   ├── base.py          # Abstract collector base class
│   │   │   ├── cisa_kev.py      # CISA KEV catalog collector
│   │   │   ├── exploit_intel.py # Exploit Intelligence Platform API
│   │   │   ├── exploitdb.py     # Exploit-DB CSV mirror collector
│   │   │   ├── forums.py        # Underground forum scraper (clearnet + Tor)
│   │   │   ├── full_disclosure.py # Full Disclosure mailing list
│   │   │   ├── nvd.py           # NVD CVE API collector
│   │   │   ├── packetstorm.py   # Packet Storm Security RSS
│   │   │   ├── reddit.py        # Reddit /r/netsec collector (with backoff)
│   │   │   ├── sploitus.py      # Sploitus exploit search API
│   │   │   └── telegram.py      # Telegram public channel scraper
│   │   ├── pipeline.py          # Orchestrates tiered collection + translation
│   │   ├── scheduler.py         # Cron generation, alerting (email/webhook)
│   │   ├── schema.py            # TI data models: ThreatEntry, IntelSource
│   │   ├── store.py             # SQLite store with deduplication
│   │   └── translate.py         # LLM-powered multilingual translation
│   ├── reporting/
│   │   ├── __init__.py          # Public API: EngagementReport, ReportFormat
│   │   ├── mitre.py             # MITRE ATT&CK technique/tactic catalog
│   │   ├── models.py            # EngagementReport, RiskSummary, TimelineEntry
│   │   ├── markdown.py          # Markdown report renderer (OWASP OPTRS-aligned)
│   │   └── json_report.py       # JSON report renderer for machine consumption
│   └── tools/
│       ├── __init__.py          # build_default_registry() — all tools registered
│       ├── base.py              # Tool base class, ToolParameter, ToolRegistry
│       ├── finding.py           # report_finding pseudo-tool (registers findings)
│       ├── nmap.py              # Nmap: port scanning, service detection
│       ├── masscan.py           # Masscan: high-speed subnet port scanning
│       ├── arp_scan.py          # ARP scan: LAN host discovery
│       ├── gobuster.py          # Gobuster: directory brute-forcing
│       ├── nikto.py             # Nikto: web server vulnerability scanning
│       ├── sslscan.py           # SSLScan: SSL/TLS configuration audit
│       ├── testssl.py           # testssl.sh: comprehensive TLS testing
│       ├── enum4linux.py        # enum4linux: SMB/NetBIOS enumeration
│       ├── whatweb.py           # WhatWeb: web technology fingerprinting
│       └── nuclei.py            # Nuclei: template-based vulnerability scanning
├── configs/
│   ├── dixie_pentest_sft.yaml   # SFT training config
│   └── recon_local_network.yaml # Example recon-mode engagement config
└── tests/
    ├── test_config.py           # Configuration loading tests
    ├── test_forums.py           # Forum scraper, translator, scheduler tests
    ├── test_intel.py            # Intel store and schema tests
    ├── test_passive_scan.py     # Recon mode, finding tool, new tool plugins
    ├── test_recon_policy.py     # Recon blocklist / Vikunja-aligned agent policy tests
    ├── test_reporting.py        # MITRE catalog, report models, MD/JSON renderers
    ├── test_schema.py           # Data model tests
    ├── test_sandbox.py          # Docker sandbox timeout and exit-code behavior
    └── test_tools.py            # Tool command building and output parsing tests
```

## Prerequisites

| Dependency | Required by | Install |
|-----------|-------------|---------|
| Python 3.11+ | Running dixie | system package manager |
| Docker | Sandbox execution | system package manager |
| pytest | Tests | `pip install -e ".[dev]"` |

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Build sandbox image
docker build -t dixie-sandbox:latest docker/
```

## Coding conventions

- **Language**: Python 3.11+, type hints everywhere
- **Data models**: Pydantic v2 for all structured data
- **LLM access**: LiteLLM for multi-provider support — never import
  `openai` or `anthropic` directly
- **Tool plugins**: subclass `Tool` in `src/dixie/tools/`, implement
  `build_command()` and `parse_output()`. All tool output must be structured
  JSON.
- **Config**: engagement parameters go in YAML config files and `config.py`.
  No hardcoded targets, limits, or model names in operational code.
- **Error handling**: no bare `except`, no `sys.exit()` in library code.
  Use structured error returns.
- **Sandbox**: all pentesting tool execution goes through `Sandbox`. The
  `run_local()` method exists for development only.

## Testing

**Test-driven development is required.** When building new functionality, write
tests as part of the same change — not as a follow-up task. Specifically:

- **New tools**: add tests for `build_command()` (various parameter combos)
  and `parse_output()` (real-world output samples, empty output, edge cases).
- **New features**: add tests covering success paths, error paths, and edge
  cases.
- **Bug fixes**: add a regression test that would have caught the bug before
  applying the fix.
- **Run the test suite** before considering a change complete. All tests must
  pass.

```bash
source .venv/bin/activate
pytest -v
```

A PR or change that adds functionality without corresponding tests is
incomplete.

## Automated code review loop

For the repeatable **cursor-review → Vikunja → tests → fix** workflow (including
`CURSOR_REVIEW_*` env flags and how to define “done” when the model still emits
warnings), follow **`docs/review-playbook.md`**. The same content exists as a
Vikunja task on **Dixie Flatline** for cross-project reference; keep the doc and
task in sync when you change the process.

## Vikunja project management

Keep Vikunja accurate **as you work**, not after being asked.

- **Before starting work**: check if a relevant task exists. If not, create one
  and mark it in progress (`vikunja_tasks.update` with a comment, or use a
  label to indicate in-progress state).
- **While working**: if scope changes or you discover sub-tasks, update the task
  description or create related tasks.
- **After completing work**: mark the task done (`vikunja_tasks.update` with
  `done: true`). If the work produced decisions, trade-offs, or research worth
  preserving, add a comment to the task.
- **If you create new files or components**: make sure the task description
  reflects what was actually built, not just what was planned.
- **Never backfill** a batch of tasks after the fact. Each piece of work should
  have a task created before or at the start of that work.

The user should be able to open Vikunja at any time and see an accurate picture
of what's done, what's in progress, and what's next.

### Vikunja MCP server quirks

The Vikunja MCP server
([democratize-technology/vikunja-mcp](https://github.com/democratize-technology/vikunja-mcp))
has a few sharp edges around partial updates. Treat
`vikunja_projects.update` and `vikunja_tasks.bulk-update` as **full replace,
not partial patch**.

- **`vikunja_projects.update` requires `title`.** Calling `update` with only
  `id` + `description` (or any other subset that omits `title`) returns
  `Invalid Data`. Always include the existing `title` even when you don't
  intend to change it.
- **`vikunja_projects.update` resets `parent_project_id` to `0` if you don't
  pass `parentProjectId`.** A child project will silently become a top-level
  project. Always pass `parentProjectId` when updating any field on a child
  project — fetch the current parent first if you don't already know it.
- **`vikunja_tasks.bulk-update` wipes other fields.** Calling
  `bulk-update` with `field: "done"`, `value: true` clears `description` and
  `priority` on every targeted task. Either:
  - Re-apply lost fields with per-task single `update` calls afterward
    (single `update` correctly preserves omitted fields, including `done`),
    or
  - Avoid `bulk-update` entirely and use parallel single `update` calls.

All three are the same root cause: the server sends a partial PATCH that
Vikunja treats as a full object replace, so omitted fields get cleared.
Upstream tracking:

- [#44](https://github.com/democratize-technology/vikunja-mcp/issues/44) —
  `vikunja_projects.update` requires `title`
- [#45](https://github.com/democratize-technology/vikunja-mcp/issues/45) —
  `vikunja_projects.update` resets `parent_project_id`
- [#46](https://github.com/democratize-technology/vikunja-mcp/issues/46) —
  `vikunja_tasks.bulk-update` wipes other fields
- [#37](https://github.com/democratize-technology/vikunja-mcp/issues/37) —
  same family on the **task-update** path (silent project moves; `labels`
  ignored on `create`)

## Cursor tools and workarounds

### Recovering chat history after moving a workspace folder

Cursor binds each chat (composer) to a specific workspace folder path via an
embedded `workspaceIdentifier` stored inside
`~/.config/Cursor/User/globalStorage/state.vscdb`. If the workspace folder is
moved on disk (e.g. `~/work/foo` → `~/work/team/foo`), Cursor treats the new
path as a brand-new workspace and the previous chats vanish from the sidebar.
The chats are **not deleted** — they're just orphaned to the old path.

Use the `migrate-cursor-chat` helper to rewrite the binding so the chats
reappear under the new workspace:

https://github.com/beardfaceguy/agentic_tools_misc/tree/main/migrate-cursor-chat

Workflow when this happens:

1. Open the new workspace path in Cursor once so it gets registered under
   `~/.config/Cursor/User/workspaceStorage/`, then **fully quit Cursor**
   (the script refuses to run if Cursor still has the SQLite DB open).
2. Dry-run to see what would be migrated:

   ```bash
   python3 migrate-cursor-chat.py --dry-run \
       <old-workspace-path> <new-workspace-path>
   ```

3. Apply for real (drop `--dry-run`). The script:
   - Makes a timestamped backup of `state.vscdb`.
   - Updates `composer.composerHeaders` (the sidebar list) and
     `composerData:<chat-id>` (per-chat record) for every chat tied to the
     old path.
   - Copies the per-chat folders under
     `~/.cursor/projects/<old-encoded-path>/agent-transcripts/` to the new
     project dir so past chats remain citeable from new agent sessions.
4. Reopen Cursor at the new path. The chats appear in the sidebar.

The helper is Linux-focused (paths under `~/.config/Cursor/`); see the repo
README for macOS/Windows path adjustments and recovery instructions.

When an agent encounters a user reporting "my chat history disappeared after
I moved my project folder" or similar, point them at this script rather than
trying to reconstruct sessions by hand.

## Review checklist

When reviewing or producing a diff:

- **Tools**: new tool plugins must subclass `Tool`, implement both methods,
  and include tests with real output samples.
- **Config**: no hardcoded values. Targets, limits, model names go in config.
- **LLM**: all model access through LiteLLM. No provider-specific imports.
- **Sandbox**: tool execution must go through `Sandbox`, not `subprocess`.
- **Error handling**: no bare excepts, no panics, no `sys.exit()` in library code.
- **Tests**: new functionality must include tests in the same change.
- **Dependencies**: flag new package additions for confirmation.
