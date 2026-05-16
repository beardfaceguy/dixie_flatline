# Playbook: Looping code reviews (Cursor + Vikunja + pytest)

This document mirrors the canonical Vikunja task **“Playbook: Looping code reviews (Cursor + Vikunja + pytest)”** in the **Dixie Flatline** project so agents and humans can follow the process from the repo. Other projects can copy the workflow and adapt the script paths.

## Purpose

Repeatable **review → track → test → fix** loop using the Cursor Agent CLI, a local review script, Vikunja for engineering notes, and pytest. Use this playbook in **Dixie Flatline** or clone the pattern for other repos.

## Prerequisites

- `scripts/cursor-review.sh` (or equivalent) invoking `agent` in `--mode=ask`, writing optional findings to a log.
- A **Vikunja project** as source of truth for task status (e.g. **Dixie Flatline** + child **Phase 1** for feature work).
- Tests required by project policy (here: new behavior ships with tests in the same change).

## The loop

1. **Run review (clean slate for this round)**

   ```bash
   CURSOR_REVIEW_FRESH_FINDINGS_LOG=1 ./scripts/cursor-review.sh --working
   ```

   Fresh log avoids stale `[BLOCKER]` lines affecting `CURSOR_REVIEW_BLOCK_CUMULATIVE` and keeps each pass comparable.

2. **Triage output**

   - **FAIL / [BLOCKER]**: must fix before considering the round done.
   - **[WARNING] / [NIT]**: fix if cheap and aligned with product policy; otherwise document intentional tradeoff in Vikunja or in code comments.
   - **PASS**: no blockers; the model may still emit warnings (that is normal).

3. **Log in Vikunja**

   - Create a task per review *round* or per theme (e.g. “cursor-review: masscan + LLM tool JSON”).
   - Paste a short summary: what the review claimed, what you changed, test commands run, and links/paths if useful.
   - Use **comments** on that task for follow-up passes so history stays in one place.

4. **For each fix**

   - Prefer **regression tests first** (or in the same commit) for anything that could come back.
   - Run `pytest -q` (or project standard) after edits.
   - Keep changes scoped; avoid drive-by refactors.

5. **Re-run review**

   Repeat from step 1 until you accept the outcome. **“Done”** here means **PASS with no blockers**, not necessarily zero lines of feedback.

## Blocking CI / pre-commit (optional)

- `CURSOR_REVIEW_BLOCK=1` — exit non-zero when **this pass** is FAIL.
- `CURSOR_REVIEW_BLOCK_CUMULATIVE=1` — also fail if the findings log still contains `[BLOCKER]` from an older run (unless the log was truncated for this run).
- Prefer **fresh log** in CI for deterministic verdicts, or document that cumulative mode needs log hygiene.

## Multi-pass / privacy note

Multi-pass mode appends prior findings into the agent prompt. Do not put secrets in the findings log; avoid multi-pass if policy forbids sending that text to the model provider.

## Adapting to another project

1. Copy or adapt `cursor-review.sh` (workspace root, scope flags, model env).
2. Create a Vikunja **parent project** for the repo and optional **child project** for phases.
3. Point your **AGENTS.md** (or README) at Vikunja as the live tracker (and keep “tests with changes” rule).
4. Run the same loop: **review → Vikunja note → tests → fix → re-review**.

## What we used on Dixie Flatline (reference)

- Findings logged under **Phase 1** with titles like `cursor-review round: …`.
- Regression coverage concentrated in `tests/test_review_regressions.py` plus targeted tests next to the feature (intel, tools, etc.).
- Iteration until `cursor-review` reported **PASS**; remaining warnings treated as policy nits unless the team decides otherwise.
