"""JSON and Markdown rendering for model bakeoff results."""

from __future__ import annotations

from .models import BakeoffReport


def render_markdown(report: BakeoffReport) -> str:
    """Render a concise comparison while retaining detailed check failures."""
    lines = [
        f"# Dixie Model Bakeoff: {report.suite_name}",
        "",
        f"Suite version: **{report.suite_version}**  ",
        f"Started: **{report.started_at.isoformat()}**",
        "",
        "## Ranking",
        "",
        "| Rank | Candidate | Model | Score | Checks | Tokens | Cost | Time |",
        "|---:|---|---|---:|---:|---:|---:|---:|",
    ]
    for rank, result in enumerate(report.ranked_results(), start=1):
        lines.append(
            "| "
            f"{rank} | `{result.candidate_id}` | `{result.model}` | "
            f"{result.score:.1%} | {result.passed_checks}/{result.total_checks} | "
            f"{result.total_tokens} | ${result.total_cost_usd:.4f} | "
            f"{result.elapsed_seconds:.2f}s |"
        )

    for result in report.ranked_results():
        lines.extend(["", f"## {result.candidate_id}", ""])
        for scenario in result.scenarios:
            lines.append(
                f"### {scenario.scenario_id} — {scenario.score:.1%} "
                f"({scenario.passed_checks}/{scenario.total_checks})"
            )
            failures = [
                check
                for turn in scenario.turns
                for check in turn.checks
                if not check.passed
            ]
            if failures:
                for failure in failures:
                    lines.append(f"- **FAIL `{failure.name}`**: {failure.detail}")
            else:
                lines.append("- All deterministic checks passed.")
            lines.append("")

    lines.extend(
        [
            "## Interpretation limits",
            "",
            "- Scores measure only the deterministic checks encoded in the suite.",
            "- Run every candidate with identical prompts, budgets, and tool schemas.",
            "- Repeat stochastic endpoint runs and report pass@1/pass@3 before selection.",
            "- Compare infrastructure latency and cost at the same context and concurrency.",
            "",
        ]
    )
    return "\n".join(lines)
