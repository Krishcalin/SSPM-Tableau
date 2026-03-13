"""Report generation — JSON and HTML outputs."""

import json
from dataclasses import asdict

from jinja2 import Template

from .models import ScanResult, Severity, Status


def generate_json_report(result: ScanResult, path: str):
    with open(path, "w") as f:
        json.dump(asdict(result), f, indent=2, default=str)
    print(f"  ├─ JSON report: {path}")


def generate_html_report(result: ScanResult, path: str):
    template = Template(HTML_TEMPLATE)
    html = template.render(
        result=result,
        findings=result.findings,
        Severity=Severity,
        Status=Status,
    )
    with open(path, "w") as f:
        f.write(html)
    print(f"  ├─ HTML report: {path}")


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Tableau Cloud SSPM Report</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0e17; --surface: #111827; --border: rgba(255,255,255,0.06);
    --text: #e2e8f0; --muted: rgba(255,255,255,0.4);
    --pass: #22c55e; --fail: #ef4444; --warn: #eab308;
    --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #3b82f6;
    --accent: #6366f1;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; line-height: 1.6; }
  .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
  .mono { font-family: 'JetBrains Mono', monospace; }
  .header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid var(--border); }
  .header h1 { font-size: 22px; font-weight: 700; }
  .header .meta { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .header .score-box { text-align: center; }
  .header .score-value { font-size: 48px; font-weight: 700; }
  .header .score-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; }
  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 32px; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; }
  .stat .value { font-size: 28px; font-weight: 700; }
  .stat .label { font-size: 11px; color: var(--muted); margin-top: 2px; text-transform: uppercase; letter-spacing: 0.08em; }
  .category { margin-bottom: 28px; }
  .category-header { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; padding: 10px 14px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }
  .category-header h2 { font-size: 14px; font-weight: 600; flex: 1; }
  .category-score { font-size: 14px; font-weight: 700; }
  .finding { display: grid; grid-template-columns: 72px 70px 1fr 80px; align-items: start; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--border); font-size: 13px; }
  .finding:hover { background: rgba(255,255,255,0.02); }
  .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-align: center; letter-spacing: 0.04em; }
  .badge-pass { background: rgba(34,197,94,0.12); color: var(--pass); }
  .badge-fail { background: rgba(239,68,68,0.12); color: var(--fail); }
  .badge-warn { background: rgba(234,179,8,0.12); color: var(--warn); }
  .badge-error { background: rgba(239,68,68,0.12); color: var(--fail); }
  .badge-skip { background: rgba(107,114,128,0.12); color: var(--muted); }
  .sev-critical { color: var(--critical); } .sev-high { color: var(--high); }
  .sev-medium { color: var(--medium); } .sev-low { color: var(--low); }
  .finding-name { font-weight: 600; }
  .finding-details { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .finding-remediation { font-size: 12px; color: rgba(99,102,241,0.8); margin-top: 6px; padding: 8px 10px; background: rgba(99,102,241,0.06); border-radius: 6px; border: 1px solid rgba(99,102,241,0.1); }
  .finding-evidence { font-size: 11px; color: var(--muted); margin-top: 6px; }
  .evidence-item { padding: 2px 0; }
  .score-pass { color: var(--pass); } .score-warn { color: var(--warn); }
  .score-fail { color: var(--fail); } .score-critical { color: #ff2d55; }
  @media print { body { background: #fff; color: #1a1a1a; } .stat { border: 1px solid #ddd; } .finding { border-color: #eee; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1 class="mono">🛡️ Tableau Cloud SSPM Report</h1>
      <div class="meta mono">
        Server: {{ result.server }} &nbsp;|&nbsp; Site: {{ result.site }}<br>
        Scan: {{ result.scan_time }} &nbsp;|&nbsp; ID: {{ result.scan_id }}
      </div>
    </div>
    <div class="score-box mono">
      <div class="score-value {% if result.score >= 85 %}score-pass{% elif result.score >= 65 %}score-warn{% elif result.score >= 40 %}score-fail{% else %}score-critical{% endif %}">{{ result.score }}</div>
      <div class="score-label">Posture Score</div>
    </div>
  </div>
  <div class="stats">
    <div class="stat"><div class="value mono" style="color:var(--text)">{{ result.total_checks }}</div><div class="label mono">Total Checks</div></div>
    <div class="stat"><div class="value mono" style="color:var(--pass)">{{ result.passed }}</div><div class="label mono">Passed</div></div>
    <div class="stat"><div class="value mono" style="color:var(--fail)">{{ result.failed }}</div><div class="label mono">Failed</div></div>
    <div class="stat"><div class="value mono" style="color:var(--warn)">{{ result.warnings }}</div><div class="label mono">Warnings</div></div>
    <div class="stat"><div class="value mono" style="color:var(--muted)">{{ result.skipped }}</div><div class="label mono">Skipped</div></div>
  </div>
  {% set ns = namespace(current_cat='') %}
  {% for f in findings %}
    {% if f.category != ns.current_cat %}
      {% set ns.current_cat = f.category %}
      {% if not loop.first %}</div>{% endif %}
      <div class="category">
        <div class="category-header">
          <h2>{{ f.category }}</h2>
          {% if f.category in result.category_scores %}
            {% set cs = result.category_scores[f.category] %}
            <span class="category-score mono {% if cs >= 85 %}score-pass{% elif cs >= 65 %}score-warn{% elif cs >= 40 %}score-fail{% else %}score-critical{% endif %}">{{ cs }}%</span>
          {% endif %}
        </div>
    {% endif %}
    <div class="finding">
      <div><span class="badge badge-{{ f.status }} mono">{{ f.status | upper }}</span></div>
      <div class="mono" style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.04em;">
        <span class="sev-{{ f.severity }}">{{ f.severity }}</span>
      </div>
      <div>
        <div class="finding-name">{{ f.check_id }}: {{ f.name }}</div>
        <div class="finding-details">{{ f.details }}</div>
        {% if f.status != 'pass' %}
        <div class="finding-remediation">💡 {{ f.remediation }}</div>
        {% endif %}
        {% if f.evidence %}
        <div class="finding-evidence">
          {% for e in f.evidence[:5] %}
          <div class="evidence-item mono">→ {{ e }}</div>
          {% endfor %}
          {% if f.evidence | length > 5 %}
          <div class="evidence-item mono" style="color:rgba(255,255,255,0.25)">... and {{ f.evidence | length - 5 }} more</div>
          {% endif %}
        </div>
        {% endif %}
      </div>
      <div></div>
    </div>
  {% endfor %}
  </div>
  <div style="margin-top:40px; padding-top:20px; border-top:1px solid var(--border); font-size:11px; color:var(--muted); text-align:center;" class="mono">
    Generated by Tableau Cloud SSPM Scanner &nbsp;|&nbsp; {{ result.scan_time }}
  </div>
</div>
</body>
</html>"""
