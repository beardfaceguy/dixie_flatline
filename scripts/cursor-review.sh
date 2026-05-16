#!/usr/bin/env bash
#
# AI code review using the Cursor Agent CLI (`agent`).
#
# Inspired by scripts/cursor-review.sh in other Wintermute repos, but without
# any PR comment dataset or external fetch step — only the local tree / git
# diff you ask for.
#
# Behavior:
#   - Skips cleanly if `agent` is not installed (CI-friendly).
#   - Runs with `--mode=ask` (read-only for the agent).
#   - Uses workspace = repo root so AGENTS.md and .cursor/rules are in scope.
#   - Override model: CURSOR_REVIEW_MODEL or --model.
#   - For pre-commit style blocking: CURSOR_REVIEW_BLOCK=1 on BLOCKER findings.
#   - Bypass entirely: CURSOR_REVIEW_SKIP=1
#
set -u

for p in "$HOME/.local/bin" "/usr/local/bin"; do
  [[ ":$PATH:" != *":$p:"* ]] && [[ -d "$p" ]] && export PATH="$p:$PATH"
done

usage() {
  sed -n '1,200p' <<'USAGE_EOF' >&2
Usage: cursor-review.sh [options]

Run a code review by piping a prompt + scope (git diff or file snapshot) to:

  agent -p --trust --mode=ask --output-format text

Diff review (git repository; pick at one style — default --staged):
  --staged            git diff --cached (index vs HEAD)
  --unstaged          git diff (worktree vs index)
  --working           git diff HEAD (all local changes vs last commit)
  --since REF         git diff REF...HEAD (commits on current branch not in REF)
  --merge-base REF    like --since but uses merge-base(HEAD, REF) as left side

  --paths PATH        Limit git diff to PATH (repeatable; git pathspec)

Snapshot review (no unified diff — raw text bundled up to a byte cap):
  --repo-index        Tracked file listing (+ optional --paths filters);
                      high-level layout / convention review.
  --read PATH         Include file contents for PATH (file or directory);
                      repeatable. Descends directories; skips huge/binary files.

General:
  --workspace DIR     Repo root (default: git toplevel, else parent of scripts/)
  --model MODEL     agent --model (else CURSOR_REVIEW_MODEL)
  --max-bytes N     Max UTF-8 bytes of scope (diff/snapshot; default 200000)
  -h, --help        This message

Environment: CURSOR_REVIEW_SKIP, CURSOR_REVIEW_MODEL, CURSOR_REVIEW_MAX_BYTES,
             CURSOR_REVIEW_BLOCK (=1 to exit 1 on [BLOCKER] after review)

Examples:
  cursor-review.sh
  cursor-review.sh --working --paths src/dixie/core
  cursor-review.sh --since origin/main
  cursor-review.sh --repo-index
  cursor-review.sh --read src/dixie/cli.py --read tests/test_tools.py
USAGE_EOF
}

if [[ "${CURSOR_REVIEW_SKIP:-0}" == "1" ]]; then
  echo "cursor-review: skipped (CURSOR_REVIEW_SKIP=1)"
  exit 0
fi

DIFF_MODE="staged"
SINCE_REF=""
MERGE_BASE_REF=""
PATHSPECS=()
SNAPSHOT=""
READ_PATHS=()
DIFF_EXPLICIT=0
WORKSPACE=""
MODEL_OVERRIDE=""
MAX_BYTES="${CURSOR_REVIEW_MAX_BYTES:-200000}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --staged)
      DIFF_MODE="staged"
      DIFF_EXPLICIT=1
      shift
      ;;
    --unstaged)
      DIFF_MODE="unstaged"
      DIFF_EXPLICIT=1
      shift
      ;;
    --working)
      DIFF_MODE="working"
      DIFF_EXPLICIT=1
      shift
      ;;
    --since)
      [[ $# -ge 2 ]] || { echo "cursor-review: --since requires REF" >&2; exit 2; }
      SINCE_REF="$2"
      DIFF_MODE="since"
      DIFF_EXPLICIT=1
      shift 2
      ;;
    --merge-base)
      [[ $# -ge 2 ]] || { echo "cursor-review: --merge-base requires REF" >&2; exit 2; }
      MERGE_BASE_REF="$2"
      DIFF_MODE="merge_base"
      DIFF_EXPLICIT=1
      shift 2
      ;;
    --paths)
      [[ $# -ge 2 ]] || { echo "cursor-review: --paths requires PATH" >&2; exit 2; }
      PATHSPECS+=("$2")
      shift 2
      ;;
    --repo-index)
      SNAPSHOT="repo_index"
      shift
      ;;
    --read)
      [[ $# -ge 2 ]] || { echo "cursor-review: --read requires PATH" >&2; exit 2; }
      READ_PATHS+=("$2")
      shift 2
      ;;
    --workspace)
      [[ $# -ge 2 ]] || { echo "cursor-review: --workspace requires DIR" >&2; exit 2; }
      WORKSPACE="$2"
      shift 2
      ;;
    --model)
      [[ $# -ge 2 ]] || { echo "cursor-review: --model requires MODEL" >&2; exit 2; }
      MODEL_OVERRIDE="$2"
      shift 2
      ;;
    --max-bytes)
      [[ $# -ge 2 ]] || { echo "cursor-review: --max-bytes requires N" >&2; exit 2; }
      MAX_BYTES="$2"
      shift 2
      ;;
    *)
      echo "cursor-review: unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ ! "$MAX_BYTES" =~ ^[1-9][0-9]*$ ]]; then
  echo "cursor-review: --max-bytes / CURSOR_REVIEW_MAX_BYTES must be a positive integer (got: ${MAX_BYTES})" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "$WORKSPACE" ]]; then
  WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
  if git -C "$WORKSPACE" rev-parse --show-toplevel >/dev/null 2>&1; then
    WORKSPACE="$(git -C "$WORKSPACE" rev-parse --show-toplevel)"
  fi
fi

if ! command -v agent >/dev/null 2>&1; then
  echo "cursor-review: agent CLI not found — skipping AI review."
  echo ""
  echo "  Install:  curl -fsSo /tmp/cursor-install.sh https://cursor.com/install"
  echo "  Then:     bash /tmp/cursor-install.sh && agent login"
  echo ""
  exit 0
fi

IS_GIT=0
if git -C "$WORKSPACE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  IS_GIT=1
fi

if [[ ${#READ_PATHS[@]} -gt 0 ]]; then
  if [[ "$SNAPSHOT" == "repo_index" ]]; then
    echo "cursor-review: use either --repo-index or --read, not both." >&2
    exit 2
  fi
  SNAPSHOT="read_files"
fi

if [[ -n "$SNAPSHOT" && "$DIFF_EXPLICIT" -eq 1 ]]; then
  echo "cursor-review: snapshot modes (--repo-index / --read) do not combine with diff flags." >&2
  exit 2
fi

SCOPE_DESC=""
CONTENT=""

_git_diff_or_exit() {
  local stderr_out rc
  stderr_out="$(mktemp)"
  CONTENT="$(git -C "$WORKSPACE" "$@" 2>"$stderr_out")"
  rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "cursor-review: git failed (exit $rc) for: git -C [...] $*" >&2
    cat "$stderr_out" >&2
    rm -f "$stderr_out"
    exit 1
  fi
  rm -f "$stderr_out"
}

build_git_diff() {
  local -a ps=()
  if [[ ${#PATHSPECS[@]} -gt 0 ]]; then
    ps=(-- "${PATHSPECS[@]}")
  fi
  case "$DIFF_MODE" in
    staged)
      SCOPE_DESC="staged diff (index vs HEAD)"
      _git_diff_or_exit diff --cached --no-color "${ps[@]}"
      ;;
    unstaged)
      SCOPE_DESC="unstaged diff (worktree vs index)"
      _git_diff_or_exit diff --no-color "${ps[@]}"
      ;;
    working)
      SCOPE_DESC="local changes vs HEAD (staged + unstaged)"
      _git_diff_or_exit diff HEAD --no-color "${ps[@]}"
      ;;
    since)
      SCOPE_DESC="branch changes vs $SINCE_REF (three-dot)"
      _git_diff_or_exit diff --no-color "$SINCE_REF"...HEAD "${ps[@]}"
      ;;
    merge_base)
      local base stderr_out rc
      stderr_out="$(mktemp)"
      base="$(git -C "$WORKSPACE" merge-base HEAD "$MERGE_BASE_REF" 2>"$stderr_out")"
      rc=$?
      if [[ $rc -ne 0 ]] || [[ -z "$base" ]]; then
        echo "cursor-review: could not compute merge-base HEAD $MERGE_BASE_REF" >&2
        cat "$stderr_out" >&2
        rm -f "$stderr_out"
        exit 1
      fi
      rm -f "$stderr_out"
      SCOPE_DESC="diff from merge-base(HEAD, $MERGE_BASE_REF) to HEAD"
      _git_diff_or_exit diff --no-color "$base"..HEAD "${ps[@]}"
      ;;
  esac
}

build_repo_index() {
  local -a ps=()
  if [[ ${#PATHSPECS[@]} -gt 0 ]]; then
    ps=(-- "${PATHSPECS[@]}")
    SCOPE_DESC="repository file index under: ${PATHSPECS[*]}"
  else
    SCOPE_DESC="full repository tracked file index"
  fi
  local list stderr_out tmp_list rc
  if [[ "$IS_GIT" -eq 1 ]]; then
    stderr_out="$(mktemp)"
    list="$(git -C "$WORKSPACE" ls-files "${ps[@]}" 2>"$stderr_out")"
    rc=$?
    if [[ $rc -ne 0 ]]; then
      echo "cursor-review: git ls-files failed:" >&2
      cat "$stderr_out" >&2
      rm -f "$stderr_out"
      exit 1
    fi
    rm -f "$stderr_out"
  else
    echo "cursor-review: --repo-index without git; listing files under $WORKSPACE" >&2
    stderr_out="$(mktemp)"
    tmp_list="$(mktemp)"
    (
      set -o pipefail
      find "$WORKSPACE" -type f \
        ! -path '*/.git/*' ! -path '*/.venv/*' ! -path '*/__pycache__/*' \
        ! -path '*/node_modules/*' ! -path '*/.ruff_cache/*' 2>"$stderr_out" \
        | sed "s|^$WORKSPACE/||" \
        | LC_ALL=C sort >"$tmp_list"
    )
    rc=$?
    if [[ $rc -ne 0 ]]; then
      echo "cursor-review: find | sort failed:" >&2
      cat "$stderr_out" >&2
      rm -f "$stderr_out" "$tmp_list"
      exit 1
    fi
    rm -f "$stderr_out"
    list="$(cat "$tmp_list")"
    rm -f "$tmp_list"
  fi
  CONTENT="$(cat <<IDX
--- tracked paths (one per line) ---
$list
--- end index ---
IDX
)"
}

# Bundle text files for --read using Python for safety caps.
build_read_snapshot() {
  SCOPE_DESC="file snapshot: ${READ_PATHS[*]}"
  CONTENT="$(env -u PYTHONPATH python3 - "$WORKSPACE" "$MAX_BYTES" "${READ_PATHS[@]}" <<'PY'
import os, sys

workspace = os.path.abspath(sys.argv[1])
max_total = int(sys.argv[2])
paths = sys.argv[3:]
per_file_cap = min(120_000, max_total // max(1, len(paths)))

def under_root(p: str) -> bool:
    try:
        abs_p = os.path.realpath(p)
        root_real = os.path.realpath(workspace)
        common = os.path.commonpath([abs_p, root_real])
    except ValueError:
        return False
    return common == root_real

def utf8_len(s: str) -> int:
    return len(s.encode("utf-8"))

out: list[str] = []
total = 0

def add_fragment(text: str) -> bool:
    """Append text if under UTF-8 byte budget; return False if budget exhausted."""
    global total
    b = utf8_len(text)
    if total + b > max_total:
        return False
    out.append(text)
    total += b
    return True

def emit(path: str, body: str) -> None:
    block = f"\n--- file: {path} ---\n{body}"
    if not add_fragment(block):
        add_fragment(f"\n--- truncated: {path} (budget exhausted) ---\n")
        raise SystemExit(0)

def read_file(rel: str) -> None:
    abs_f = os.path.join(workspace, rel)
    if not under_root(abs_f):
        add_fragment(f"\n--- skip (outside workspace): {rel} ---\n")
        return
    if not os.path.isfile(abs_f):
        add_fragment(f"\n--- missing: {rel} ---\n")
        return
    try:
        with open(abs_f, "rb") as f:
            raw = f.read(per_file_cap + 1)
    except OSError as e:
        add_fragment(f"\n--- unreadable {rel}: {e} ---\n")
        return
    if len(raw) > per_file_cap:
        raw = raw[:per_file_cap]
        suffix = "\n... [truncated per file cap] ...\n"
    else:
        suffix = ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            add_fragment(f"\n--- skip binary: {rel} ---\n")
            return
    emit(rel, text + suffix)

def walk(rel: str) -> None:
    abs_p = os.path.join(workspace, rel)
    if not under_root(abs_p):
        add_fragment(f"\n--- skip (outside workspace): {rel} ---\n")
        return
    if os.path.isfile(abs_p):
        read_file(rel)
        return
    if not os.path.isdir(abs_p):
        add_fragment(f"\n--- not found: {rel} ---\n")
        return
    for root, dirs, files in os.walk(abs_p):
        dirs[:] = [d for d in dirs if d not in (".git", ".venv", "__pycache__", "node_modules", ".ruff_cache")]
        for name in sorted(files):
            fp = os.path.join(root, name)
            rp = os.path.relpath(fp, workspace)
            read_file(rp)
            if total >= max_total:
                return

os.chdir(workspace)
try:
    for p in paths:
        rp = os.path.relpath(os.path.abspath(os.path.join(workspace, p)), workspace)
        if rp.startswith(".."):
            print(f"\n--- skip (outside workspace): {p} ---\n", file=sys.stderr)
            continue
        walk(rp)
except SystemExit:
    pass
sys.stdout.write("".join(out))
PY
)"
}

if [[ -n "$SNAPSHOT" ]]; then
  case "$SNAPSHOT" in
    repo_index) build_repo_index ;;
    read_files) build_read_snapshot ;;
  esac
else
  if [[ "$IS_GIT" -ne 1 ]]; then
    echo "cursor-review: not a git worktree — use --repo-index or --read PATH." >&2
    exit 1
  fi
  build_git_diff
fi

if [[ -z "$CONTENT" ]]; then
  echo "cursor-review: nothing to review (empty scope)."
  exit 0
fi

CONTENT_UTF8_BYTES="$(printf '%s' "$CONTENT" | python3 -c "import sys; print(len(sys.stdin.buffer.read()))")"
if [[ "$CONTENT_UTF8_BYTES" -gt "$MAX_BYTES" ]]; then
  echo "cursor-review: scope is ${CONTENT_UTF8_BYTES} UTF-8 bytes (limit ${MAX_BYTES}) — refusing to send. Raise CURSOR_REVIEW_MAX_BYTES or narrow --paths." >&2
  exit 1
fi

REVIEW_MODEL="${MODEL_OVERRIDE:-${CURSOR_REVIEW_MODEL:-}}"
if [[ -n "$REVIEW_MODEL" ]]; then
  MODEL_LABEL="$REVIEW_MODEL"
else
  MODEL_LABEL="$(
    agent about --format json 2>/dev/null \
      | python3 -c "import sys, json
try:
    print(json.load(sys.stdin).get('model') or 'unknown')
except Exception:
    print('unknown')
"
  )"
fi

PROMPT=$(cat <<EOF
You are reviewing code for the Dixie Flatline repository (LLM-driven red team
framework). Scope: $SCOPE_DESC.

Follow AGENTS.md (coding conventions, testing requirements, sandbox rules) and
the review checklist there:

- Tools: Tool subclasses with build_command + parse_output; structured JSON;
  tests with realistic samples.
- Config: no hardcoded targets/limits/model names in operational code.
- LLM: LiteLLM only — no direct openai/anthropic imports.
- Sandbox: execution via Sandbox, not raw subprocess in tool paths.
- Error handling: no bare except; no sys.exit in library code.
- Tests: new/changed behavior covered in the same change.
- Flag new dependencies.

For each issue, output exactly one line:
[BLOCKER] \`file:line\` — description
[WARNING] \`file:line\` — description
[NIT] \`file:line\` — description

Output ONLY issue lines (no headers, summary, or commentary). If there are no
issues, output nothing.

--- scope content ---
EOF
)

echo "cursor-review: workspace=$WORKSPACE"
echo "cursor-review: model = $MODEL_LABEL"

AGENT_STDERR="$(mktemp)"
OUT=$(
  printf '%s\n%s\n' "$PROMPT" "$CONTENT" \
    | agent -p \
        --trust \
        --mode=ask \
        --output-format text \
        --workspace "$WORKSPACE" \
        ${REVIEW_MODEL:+--model "$REVIEW_MODEL"} \
        2>"$AGENT_STDERR"
)
STATUS=$?
if [[ -s "$AGENT_STDERR" ]]; then
  echo "cursor-review: agent stderr:" >&2
  cat "$AGENT_STDERR" >&2
fi
rm -f "$AGENT_STDERR"

RESULT=$(python3 -c "
import sys, textwrap, re

lines = sys.stdin.read().strip().splitlines()

buckets = {'BLOCKER': [], 'WARNING': [], 'NIT': []}
# Allow optional list markers / indentation before [SEVERITY]
tag_re = re.compile(
    r'^[ \t]*(?:[-*+]\s+|\d+\.\s+)?\[(BLOCKER|WARNING|NIT)\]\s*(.*)'
)

for raw in lines:
    raw = raw.strip()
    m = tag_re.match(raw)
    if m:
        buckets[m.group(1)].append(m.group(2))

def fmt_issue(text):
    if ' — ' in text:
        ref, _, body = text.partition(' — ')
        out = [ref + ' —']
        out.extend(textwrap.wrap(body, width=76,
                   initial_indent='    ', subsequent_indent='    '))
        return '\n'.join(out)
    return textwrap.fill(text, width=80)

sections = []
for label, key in [('Blockers', 'BLOCKER'), ('Warnings', 'WARNING'), ('Nits', 'NIT')]:
    items = buckets[key]
    if not items:
        continue
    sections.append('## ' + label)
    for item in items:
        sections.append('')
        sections.append('- ' + fmt_issue(item))
    sections.append('')

verdict = 'FAIL' if buckets['BLOCKER'] else 'PASS'
counts = []
for key in ('BLOCKER', 'WARNING', 'NIT'):
    n = len(buckets[key])
    if n:
        counts.append(f'{n} {key.lower()}' + ('s' if n != 1 else ''))
summary = ', '.join(counts) if counts else 'no issues found'

sections.append('## Summary')
sections.append(f'{verdict}: {summary}')
sections.append('')
sections.append(verdict)

print('\n'.join(sections))
" <<< "$OUT")

echo
echo "──────── Cursor AI review ────────"
echo "$RESULT"
echo "──────────────────────────────────"

if [[ $STATUS -ne 0 ]]; then
  echo "cursor-review: agent CLI exited $STATUS — not treating as FAIL."
  exit 0
fi

VERDICT=$(echo "$RESULT" | grep -oE '^(PASS|FAIL)$' | tail -1)
if [[ "$VERDICT" == "FAIL" ]]; then
  if [[ "${CURSOR_REVIEW_BLOCK:-0}" == "1" ]]; then
    echo "cursor-review: FAIL — exiting 1 (CURSOR_REVIEW_BLOCK=1)."
    exit 1
  fi
  echo "cursor-review: FAIL — warning only. Set CURSOR_REVIEW_BLOCK=1 to enforce."
fi

exit 0
