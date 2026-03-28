"""Git history scanning for leaked secrets."""

import re
import subprocess
import sys
from pathlib import Path

from .models import Issue
from .scanner import DeployGuard


def scan_git_history(n_commits: int, guard: "DeployGuard") -> list[Issue]:
    """Escaneia os últimos N commits do git history em busca de vazamentos."""
    issues: list[Issue] = []

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            print("[Deploy Guard] Aviso: não está em um repositório git. --history ignorado.",
                  file=sys.stderr)
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("[Deploy Guard] Aviso: git não encontrado. --history ignorado.", file=sys.stderr)
        return []

    print(f"[Deploy Guard] Escaneando últimos {n_commits} commits no histórico...",
          file=sys.stderr)

    try:
        result = subprocess.run(
            ["git", "log", f"-{n_commits}", "-p", "--no-merges",
             "--diff-filter=ACRM", "--unified=0"],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="ignore"
        )
    except subprocess.TimeoutExpired:
        print("[Deploy Guard] Timeout no git log. Tente menos commits.", file=sys.stderr)
        return []

    if not result.stdout:
        return []

    current_file = "(git history)"
    current_commit = ""
    commit_re = re.compile(r'^commit ([0-9a-f]{7,40})', re.IGNORECASE)
    file_re = re.compile(r'^\+\+\+ b/(.+)$')
    added_line_re = re.compile(r'^\+(?!\+\+)(.*)$')

    added_lines_buffer: list[str] = []

    def flush_buffer():
        nonlocal current_file, current_commit
        if not added_lines_buffer:
            return
        label = f"{current_file} [commit {current_commit[:7]}]"
        sub = DeployGuard(target=guard.target, strict_lgpd=guard.strict_lgpd)
        sub._scan_secrets(added_lines_buffer, label)
        sub._scan_lgpd(added_lines_buffer, label,
                       Path(current_file).suffix.lower(),
                       "\n".join(added_lines_buffer))
        for issue in sub.issues:
            issue.message = f"[GIT HISTORY] {issue.message}"
            issue.suggestion = (
                f"{issue.suggestion} "
                f"Commit: {current_commit[:7]}. "
                "Se já foi publicado, revogar a credencial mesmo após remover do history."
            )
        issues.extend(sub.issues)
        added_lines_buffer.clear()

    for raw_line in result.stdout.splitlines():
        m_commit = commit_re.match(raw_line)
        if m_commit:
            flush_buffer()
            current_commit = m_commit.group(1)
            continue

        m_file = file_re.match(raw_line)
        if m_file:
            flush_buffer()
            current_file = m_file.group(1)
            continue

        m_add = added_line_re.match(raw_line)
        if m_add:
            added_lines_buffer.append(m_add.group(1))

    flush_buffer()

    # Deduplicar
    seen_msgs: set[str] = set()
    unique: list[Issue] = []
    for issue in issues:
        key = f"{issue.type}|{issue.message[:60]}"
        if key not in seen_msgs:
            seen_msgs.add(key)
            unique.append(issue)

    return unique
