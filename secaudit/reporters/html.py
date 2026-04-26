"""Standalone HTML report rendering."""

from __future__ import annotations

from collections import Counter

from jinja2 import Environment, select_autoescape

from .. import __version__
from ..models import AuditDiff, AuditReport
from ..scoring import top_issues


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SecAudit Report · {{ report.host }}</title>
  <style>
    :root {
      --bg: #060a0d;
      --panel: #0d1418;
      --panel-2: #101b21;
      --text: #d7f9e7;
      --muted: #7db9a2;
      --line: #173028;
      --pass: #14d18b;
      --warn: #ffcc4d;
      --fail: #ff5f6d;
      --info: #67c1ff;
      --accent: #21f3a6;
      --shadow: rgba(0, 0, 0, 0.35);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "JetBrains Mono", "Fira Code", monospace;
      background:
        radial-gradient(circle at top left, rgba(33,243,166,0.12), transparent 35%),
        linear-gradient(180deg, #040608 0%, var(--bg) 100%);
      color: var(--text);
      min-height: 100vh;
    }
    .wrap {
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 24px 0 48px;
    }
    .hero, .card, details {
      background: linear-gradient(180deg, rgba(13,20,24,0.96), rgba(8,12,15,0.96));
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 14px 36px var(--shadow);
    }
    .hero {
      padding: 24px;
      margin-bottom: 24px;
    }
    .hero h1 { margin: 0 0 10px; color: var(--accent); }
    .hero p { margin: 0; color: var(--muted); line-height: 1.6; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { padding: 18px; }
    .card h2, .section-title { margin: 0 0 14px; color: var(--accent); }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.95rem; }
    th, td { border-bottom: 1px solid var(--line); padding: 12px 10px; text-align: left; vertical-align: top; }
    th { color: var(--muted); font-size: 0.84rem; text-transform: uppercase; letter-spacing: 0.08em; }
    .badge { display: inline-flex; align-items: center; gap: 8px; padding: 7px 12px; border-radius: 999px; border: 1px solid var(--line); margin-right: 8px; margin-bottom: 8px; }
    .pass { color: var(--pass); }
    .warn { color: var(--warn); }
    .fail { color: var(--fail); }
    .info { color: var(--info); }
    details { margin-bottom: 14px; overflow: hidden; }
    summary { cursor: pointer; list-style: none; padding: 16px 18px; display: flex; justify-content: space-between; }
    summary::-webkit-details-marker { display: none; }
    .module-body { padding: 0 18px 18px; }
    .footer { margin-top: 24px; color: var(--muted); font-size: 0.88rem; text-align: center; }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>SecAudit v{{ version }}</h1>
      <p>
        Standalone security audit report for <strong>{{ report.target }}</strong><br />
        Generated {{ report.generated_at }} · Duration {{ "%.2f"|format(report.duration_seconds) }}s
      </p>
    </section>

    <section class="grid">
      <article class="card">
        <h2>Summary</h2>
        <div class="badge pass">PASS · {{ report.counts["PASS"] }}</div>
        <div class="badge warn">WARN · {{ report.counts["WARN"] }}</div>
        <div class="badge fail">FAIL · {{ report.counts["FAIL"] }}</div>
        <div class="badge info">INFO · {{ report.counts["INFO"] }}</div>
        <p><strong>Score:</strong> {{ report.score }}/100 · {{ report.grade }}</p>
      </article>
      <article class="card">
        <h2>Severity Distribution</h2>
        {% for severity, count in severity_counts.items() %}
          <div class="badge {{ 'fail' if severity in ('critical', 'high') else 'warn' if severity in ('medium', 'low') else 'info' }}">{{ severity|upper }} · {{ count }}</div>
        {% endfor %}
      </article>
    </section>

    <section class="card" style="margin-bottom: 24px;">
      <h2 class="section-title">Top Issues</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Module</th>
            <th>Check</th>
            <th>Summary</th>
          </tr>
        </thead>
        <tbody>
          {% for issue in issues %}
          <tr>
            <td>{{ issue.severity|upper }}</td>
            <td>{{ issue.module }}</td>
            <td>{{ issue.name }}</td>
            <td>{{ issue.summary }}</td>
          </tr>
          {% else %}
          <tr>
            <td colspan="4">No FAIL or WARN findings were recorded.</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>

    {% if diff %}
    <section class="card" style="margin-bottom: 24px;">
      <h2 class="section-title">Comparison</h2>
      <p>Score: {{ diff.score_before }} → {{ diff.score_after }} · Grade: {{ diff.grade_before }} → {{ diff.grade_after }}</p>
      <p>Added: {{ diff.added|length }} · Changed: {{ diff.changed|length }} · Removed: {{ diff.removed|length }}</p>
    </section>
    {% endif %}

    <section>
      <h2 class="section-title">Modules</h2>
      {% for module in report.modules %}
      <details>
        <summary>
          <strong>{{ module.name }}</strong>
          <span>{{ module.status }} · {{ "%.2f"|format(module.duration_seconds) }}s</span>
        </summary>
        <div class="module-body">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Severity</th>
                <th>Check</th>
                <th>Summary</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {% for result in module.results %}
              <tr>
                <td>{{ result.status }}</td>
                <td>{{ result.severity|upper }}</td>
                <td>{{ result.name }}</td>
                <td>{{ result.summary }}</td>
                <td>{{ result.details }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </details>
      {% endfor %}
    </section>

    <div class="footer">
      Generated by SecAudit {{ version }}
    </div>
  </div>
</body>
</html>
"""


def render_html_report(report: AuditReport, diff: AuditDiff | None = None) -> str:
    """Render a standalone HTML report."""

    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = env.from_string(HTML_TEMPLATE)
    severity_counts = Counter(
        result.severity
        for result in report.results
        if result.status in {"FAIL", "WARN", "INFO"}
    )
    return template.render(
        version=__version__,
        report=report,
        diff=diff,
        issues=top_issues(report.results),
        severity_counts=dict(severity_counts),
    )
