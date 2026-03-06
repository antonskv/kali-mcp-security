"""Structured text formatting for tool results."""

from datetime import datetime, timezone


def format_header(tool_name: str, target: str, extra: str = "") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"{'═' * 60}",
        f"  {tool_name.upper()} SCAN RESULTS",
        f"{'═' * 60}",
        f"  Target  : {target}",
        f"  Time    : {ts}",
    ]
    if extra:
        lines.append(f"  Options : {extra}")
    lines.append(f"{'─' * 60}")
    return "\n".join(lines)


def format_footer(rc: int, note: str = "") -> str:
    status = "COMPLETED" if rc == 0 else f"EXITED (code {rc})"
    lines = [
        f"{'─' * 60}",
        f"  Status: {status}",
    ]
    if note:
        lines.append(f"  Note  : {note}")
    lines.append(f"{'═' * 60}")
    return "\n".join(lines)


def format_error(tool_name: str, error: str) -> str:
    return (
        f"{'═' * 60}\n"
        f"  {tool_name.upper()} — ERROR\n"
        f"{'═' * 60}\n"
        f"  {error}\n"
        f"{'═' * 60}"
    )


def truncate_output(text: str, max_lines: int = 500) -> str:
    """Truncate output to prevent overwhelming the LLM context."""
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    kept = lines[:max_lines]
    kept.append(f"\n... [TRUNCATED — {len(lines) - max_lines} more lines] ...")
    return "\n".join(kept)