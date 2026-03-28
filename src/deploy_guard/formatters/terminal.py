"""Rich terminal output with colors and formatting."""

import sys
from ..models import Issue, RISK_ORDER, DECISION_ORDER, final_decision, deduplicate

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"

RISK_COLORS = {
    "critical": f"{BOLD}{RED}",
    "high": f"{RED}",
    "medium": f"{YELLOW}",
    "low": f"{CYAN}",
}

DECISION_ICONS = {
    "BLOCK": f"{RED}⛔{RESET}",
    "WARN": f"{YELLOW}⚠️ {RESET}",
    "REQUIRE_OVERRIDE": f"{MAGENTA}🔒{RESET}",
    "ALLOW": f"{GREEN}✅{RESET}",
}


def _supports_color() -> bool:
    """Check if the terminal supports color."""
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return "TERM" in __import__("os").environ
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _strip_ansi(text: str) -> str:
    """Remove ANSI codes for non-color terminals."""
    import re
    return re.sub(r'\033\[[0-9;]*m', '', text)


def print_report(issues: list[Issue], path: str, use_color: bool = True):
    """Print a rich formatted security report to stdout."""
    if not _supports_color():
        use_color = False

    issues = deduplicate(issues)
    issues.sort(
        key=lambda x: (RISK_ORDER.get(x.risk_level, 0), DECISION_ORDER.get(x.decision, 0)),
        reverse=True
    )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in issues:
        counts[i.risk_level] = counts.get(i.risk_level, 0) + 1

    decision = final_decision(issues)

    # Decision banner
    if decision == "block":
        banner_color = BG_RED if use_color else ""
        decision_text = "⛔ BLOCKED"
    elif decision == "warn":
        banner_color = BG_YELLOW if use_color else ""
        decision_text = "⚠️  WARNING"
    else:
        banner_color = BG_GREEN if use_color else ""
        decision_text = "✅ PASSED"

    r = RESET if use_color else ""
    b = BOLD if use_color else ""
    d = DIM if use_color else ""

    print()
    print(f"  {banner_color}{b} DEPLOY GUARD — Security Report {r}")
    print(f"  {b}{'═' * 60}{r}")
    print(f"  {d}Target:{r}  {path}")
    print(f"  {d}Issues:{r}  {len(issues)}")

    # Colored counts
    crit_c = RISK_COLORS["critical"] if use_color else ""
    high_c = RISK_COLORS["high"] if use_color else ""
    med_c = RISK_COLORS["medium"] if use_color else ""
    low_c = RISK_COLORS["low"] if use_color else ""
    print(f"  {crit_c}● Critical: {counts['critical']}{r}  "
          f"{high_c}● High: {counts['high']}{r}  "
          f"{med_c}● Medium: {counts['medium']}{r}  "
          f"{low_c}● Low: {counts['low']}{r}")

    print(f"  {b}Decision: {decision_text}{r}")
    print(f"  {b}{'═' * 60}{r}")
    print()

    if not issues:
        g = GREEN if use_color else ""
        print(f"  {g}✅ No issues found. Deploy can proceed.{r}")
        print()
        return

    # Group issues by file
    by_file: dict[str, list[Issue]] = {}
    for issue in issues:
        by_file.setdefault(issue.file, []).append(issue)

    for filepath, file_issues in by_file.items():
        print(f"  {b}📄 {filepath}{r}")
        for issue in file_issues:
            rc = RISK_COLORS.get(issue.risk_level, "") if use_color else ""
            icon = DECISION_ICONS.get(issue.decision, "❓") if use_color else issue.decision
            line_info = f"L{issue.line}" if issue.line > 0 else ""

            print(f"    {icon} {rc}[{issue.risk_level.upper()}]{r} {issue.type}")
            if line_info:
                print(f"      {d}Line:{r} {line_info}")
            print(f"      {d}Issue:{r} {issue.message}")
            print(f"      {d}Fix:{r}   {issue.suggestion}")

            if issue.revoke_required:
                warn_c = RED if use_color else ""
                print(f"      {warn_c}⚡ ACTION: Revoke this credential immediately{r}")
            if issue.notify_dpo:
                info_c = MAGENTA if use_color else ""
                print(f"      {info_c}📋 LGPD: Notify DPO. Evaluate ANPD notification (Art. 48){r}")
            print()

    # Summary stats
    print(f"  {b}{'─' * 60}{r}")
    if any(i.revoke_required for i in issues):
        warn_c = RED if use_color else ""
        print(f"  {warn_c}{b}⚡ CREDENTIALS TO REVOKE: "
              f"{sum(1 for i in issues if i.revoke_required)}{r}")
    if any(i.notify_dpo for i in issues):
        info_c = MAGENTA if use_color else ""
        print(f"  {info_c}{b}📋 DPO NOTIFICATIONS REQUIRED: "
              f"{sum(1 for i in issues if i.notify_dpo)}{r}")
    print()
