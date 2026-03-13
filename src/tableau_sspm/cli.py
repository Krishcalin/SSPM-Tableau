"""CLI entrypoint for Tableau Cloud SSPM Scanner."""

import argparse
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone

from .models import ScanResult, Severity, Status
from .collector import TableauCollector
from .checks import SecurityChecks
from .scoring import calculate_score
from .report import generate_json_report, generate_html_report


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Tableau Cloud SSPM — SaaS Security Posture Management Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tableau-sspm --server https://prod-apsoutheast-a.online.tableau.com \\
               --site mysite --token-name pat --token-secret s3cret

  TABLEAU_SERVER=... TABLEAU_SITE=... tableau-sspm --json-only
        """,
    )
    parser.add_argument("--server", default=os.getenv("TABLEAU_SERVER"),
                        help="Tableau Cloud server URL (env: TABLEAU_SERVER)")
    parser.add_argument("--site", default=os.getenv("TABLEAU_SITE"),
                        help="Tableau Cloud site content URL (env: TABLEAU_SITE)")
    parser.add_argument("--token-name", default=os.getenv("TABLEAU_TOKEN_NAME"),
                        help="Personal Access Token name (env: TABLEAU_TOKEN_NAME)")
    parser.add_argument("--token-secret", default=os.getenv("TABLEAU_TOKEN_SECRET"),
                        help="Personal Access Token secret (env: TABLEAU_TOKEN_SECRET)")
    parser.add_argument("--output-dir", default="./sspm_output",
                        help="Output directory for reports (default: ./sspm_output)")
    parser.add_argument("--json-only", action="store_true",
                        help="Skip HTML report, output JSON only")
    parser.add_argument("--min-score", type=float, default=0,
                        help="Minimum passing score (exit 1 if below)")
    return parser.parse_args(argv)


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║           Tableau Cloud SSPM Scanner                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Missing credentials. Provide via CLI args or env vars:      ║
║                                                              ║
║  tableau-sspm \\                                              ║
║    --server  https://your-pod.online.tableau.com \\           ║
║    --site    your-site-name \\                                ║
║    --token-name  your-pat-name \\                             ║
║    --token-secret your-pat-secret                            ║
║                                                              ║
║  Or set environment variables:                               ║
║    TABLEAU_SERVER, TABLEAU_SITE,                             ║
║    TABLEAU_TOKEN_NAME, TABLEAU_TOKEN_SECRET                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


def main(argv=None):
    args = parse_args(argv)

    if not all([args.server, args.site, args.token_name, args.token_secret]):
        print_banner()
        sys.exit(1)

    scan_id = f"SSPM-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    scan_time = datetime.now(timezone.utc).isoformat()

    print(f"\n{'─' * 60}")
    print(f"  Tableau Cloud SSPM Scanner")
    print(f"  Scan ID: {scan_id}")
    print(f"{'─' * 60}\n")

    # ── Phase 1: Collect ───────────────────────────────────────
    print("▸ Phase 1: Data Collection")
    collector = TableauCollector(args.server, args.site, args.token_name, args.token_secret)
    try:
        collector.connect()
        data = collector.collect_all()
    except Exception as e:
        print(f"\n  ✗ Connection failed: {e}")
        sys.exit(1)
    finally:
        collector.disconnect()

    # ── Phase 2: Analyze ───────────────────────────────────────
    print("▸ Phase 2: Security Assessment")
    checks = SecurityChecks(data)
    findings = checks.run_all()

    # ── Phase 3: Score & Report ────────────────────────────────
    print("▸ Phase 3: Scoring & Reporting")
    overall_score, cat_scores = calculate_score(findings)

    result = ScanResult(
        scan_id=scan_id,
        scan_time=scan_time,
        server=args.server,
        site=args.site,
        total_checks=len(findings),
        passed=sum(1 for f in findings if f.status == Status.PASS),
        failed=sum(1 for f in findings if f.status == Status.FAIL),
        warnings=sum(1 for f in findings if f.status == Status.WARN),
        errors=sum(1 for f in findings if f.status == Status.ERROR),
        skipped=sum(1 for f in findings if f.status == Status.SKIP),
        score=overall_score,
        findings=[asdict(f) for f in findings],
        category_scores=cat_scores,
        raw_stats={
            "users": len(data.get("users", [])),
            "groups": len(data.get("groups", [])),
            "projects": len(data.get("projects", [])),
            "datasources": len(data.get("datasources", [])),
            "workbooks": len(data.get("workbooks", [])),
            "flows": len(data.get("flows", [])),
        },
    )

    # Output
    os.makedirs(args.output_dir, exist_ok=True)
    json_path = os.path.join(args.output_dir, f"{scan_id}.json")
    generate_json_report(result, json_path)

    if not args.json_only:
        html_path = os.path.join(args.output_dir, f"{scan_id}.html")
        generate_html_report(result, html_path)

    # ── Summary ────────────────────────────────────────────────
    score_color = "\033[32m" if overall_score >= 85 else "\033[33m" if overall_score >= 65 else "\033[31m"
    reset = "\033[0m"
    print(f"\n{'─' * 60}")
    print(f"  POSTURE SCORE: {score_color}{overall_score}{reset} / 100")
    print(f"{'─' * 60}")
    print(f"  Passed:   {result.passed}")
    print(f"  Failed:   {result.failed}")
    print(f"  Warnings: {result.warnings}")
    print(f"  Skipped:  {result.skipped}")
    print(f"{'─' * 60}")
    for cat, sc in cat_scores.items():
        c = "\033[32m" if sc >= 85 else "\033[33m" if sc >= 65 else "\033[31m"
        print(f"  {cat}: {c}{sc}%{reset}")
    print(f"{'─' * 60}\n")

    # Exit codes
    critical_fails = sum(
        1 for f in findings
        if f.severity == Severity.CRITICAL and f.status == Status.FAIL
    )
    if critical_fails > 0:
        print(f"  ⚠  {critical_fails} CRITICAL finding(s) — exit code 1\n")
        sys.exit(1)
    if args.min_score and overall_score < args.min_score:
        print(f"  ⚠  Score {overall_score} below minimum {args.min_score} — exit code 1\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
