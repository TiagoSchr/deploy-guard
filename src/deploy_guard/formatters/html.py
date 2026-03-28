"""HTML report generator for Deploy Guard."""

import html as html_lib
from datetime import datetime, timezone

from ..models import Issue, RISK_ORDER, DECISION_ORDER, final_decision, deduplicate


def html_report(issues: list[Issue], path: str) -> str:
    """Generate a standalone HTML security report."""
    issues = deduplicate(issues)
    issues.sort(
        key=lambda x: (RISK_ORDER.get(x.risk_level, 0), DECISION_ORDER.get(x.decision, 0)),
        reverse=True,
    )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in issues:
        counts[i.risk_level] = counts.get(i.risk_level, 0) + 1

    decision = final_decision(issues)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    decision_class = {"block": "blocked", "warn": "warning", "allow": "passed"}
    decision_label = {"block": "⛔ BLOCKED", "warn": "⚠️ WARNING", "allow": "✅ PASSED"}

    risk_color = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
    }

    # Build issue rows
    issue_rows = []
    for issue in issues:
        esc = html_lib.escape
        rev_badge = ('<span class="badge badge-revoke">REVOKE</span>'
                     if issue.revoke_required else "")
        dpo_badge = ('<span class="badge badge-dpo">DPO</span>'
                     if issue.notify_dpo else "")

        issue_rows.append(f"""
        <tr class="risk-{issue.risk_level}">
          <td><span class="risk-dot" style="background:{risk_color.get(issue.risk_level, '#666')}"></span>
              {esc(issue.risk_level.upper())}</td>
          <td><span class="decision-tag decision-{issue.decision.lower()}">{esc(issue.decision)}</span></td>
          <td>{esc(issue.type)}</td>
          <td class="file-cell">{esc(issue.file)}{f' <span class="line-num">L{issue.line}</span>' if issue.line > 0 else ''}</td>
          <td>{esc(issue.message)}</td>
          <td>{esc(issue.suggestion)} {rev_badge} {dpo_badge}</td>
        </tr>""")

    rows_html = "\n".join(issue_rows) if issue_rows else """
        <tr><td colspan="6" class="no-issues">✅ No security issues found. Deploy can proceed.</td></tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Deploy Guard — Security Report</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-dim: #8b949e;
    --red: #f85149; --orange: #d29922; --green: #3fb950; --blue: #58a6ff;
    --purple: #bc8cff;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.5;
    padding: 2rem; max-width: 1400px; margin: 0 auto;
  }}
  .header {{ margin-bottom: 2rem; }}
  .header h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
  .header h1 span {{ color: var(--blue); }}
  .meta {{ color: var(--text-dim); font-size: 0.85rem; }}

  .summary {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
  }}
  .stat-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem; text-align: center;
  }}
  .stat-card .number {{ font-size: 2rem; font-weight: 700; }}
  .stat-card .label {{ color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase; }}

  .decision-banner {{
    padding: 1rem 1.5rem; border-radius: 8px; font-size: 1.2rem;
    font-weight: 700; text-align: center; margin-bottom: 2rem;
  }}
  .decision-banner.blocked {{ background: rgba(248,81,73,0.15); border: 2px solid var(--red); color: var(--red); }}
  .decision-banner.warning {{ background: rgba(210,153,34,0.15); border: 2px solid var(--orange); color: var(--orange); }}
  .decision-banner.passed {{ background: rgba(63,185,80,0.15); border: 2px solid var(--green); color: var(--green); }}

  table {{
    width: 100%; border-collapse: collapse; background: var(--surface);
    border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
  }}
  th {{
    background: #1c2128; color: var(--text-dim); font-size: 0.75rem;
    text-transform: uppercase; letter-spacing: 0.05em; padding: 0.75rem 1rem;
    text-align: left; border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 0.75rem 1rem; border-bottom: 1px solid var(--border);
    font-size: 0.85rem; vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover {{ background: rgba(255,255,255,0.02); }}

  .risk-dot {{
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    margin-right: 4px; vertical-align: middle;
  }}
  .decision-tag {{
    display: inline-block; padding: 2px 8px; border-radius: 12px;
    font-size: 0.7rem; font-weight: 600;
  }}
  .decision-block {{ background: rgba(248,81,73,0.2); color: var(--red); }}
  .decision-warn {{ background: rgba(210,153,34,0.2); color: var(--orange); }}
  .decision-require_override {{ background: rgba(188,140,255,0.2); color: var(--purple); }}
  .decision-allow {{ background: rgba(63,185,80,0.2); color: var(--green); }}

  .file-cell {{ font-family: monospace; font-size: 0.8rem; }}
  .line-num {{ color: var(--text-dim); }}

  .badge {{
    display: inline-block; padding: 1px 6px; border-radius: 8px;
    font-size: 0.65rem; font-weight: 700; margin-left: 4px;
  }}
  .badge-revoke {{ background: var(--red); color: white; }}
  .badge-dpo {{ background: var(--purple); color: white; }}

  .no-issues {{ text-align: center; padding: 3rem; color: var(--green); font-size: 1.2rem; }}

  .footer {{
    margin-top: 2rem; text-align: center; color: var(--text-dim);
    font-size: 0.75rem;
  }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ <span>Deploy Guard</span> — Security Report</h1>
  <p class="meta">Target: <strong>{html_lib.escape(path)}</strong> · Generated: {now}</p>
</div>

<div class="decision-banner {decision_class.get(decision, 'passed')}">
  {decision_label.get(decision, '✅ PASSED')}
</div>

<div class="summary">
  <div class="stat-card">
    <div class="number">{len(issues)}</div>
    <div class="label">Total Issues</div>
  </div>
  <div class="stat-card">
    <div class="number" style="color:{risk_color['critical']}">{counts['critical']}</div>
    <div class="label">Critical</div>
  </div>
  <div class="stat-card">
    <div class="number" style="color:{risk_color['high']}">{counts['high']}</div>
    <div class="label">High</div>
  </div>
  <div class="stat-card">
    <div class="number" style="color:{risk_color['medium']}">{counts['medium']}</div>
    <div class="label">Medium</div>
  </div>
  <div class="stat-card">
    <div class="number" style="color:{risk_color['low']}">{counts['low']}</div>
    <div class="label">Low</div>
  </div>
</div>

<table>
  <thead>
    <tr>
      <th>Risk</th>
      <th>Decision</th>
      <th>Type</th>
      <th>File</th>
      <th>Issue</th>
      <th>Fix</th>
    </tr>
  </thead>
  <tbody>
    {rows_html}
  </tbody>
</table>

<div class="footer">
  Deploy Guard v1.0.0 · LGPD Compliance Scanner · {now}
</div>
</body>
</html>"""
