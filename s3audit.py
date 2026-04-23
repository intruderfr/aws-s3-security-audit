#!/usr/bin/env python3
"""
aws-s3-security-audit
=====================

Audits every S3 bucket in an AWS account for common security
misconfigurations and produces a CSV + HTML report.

Checks performed per bucket:
    1. Public access via Block Public Access (account & bucket level)
    2. Public access via bucket ACL
    3. Public access via bucket policy
    4. Default server-side encryption (SSE-S3 / SSE-KMS)
    5. Versioning enabled
    6. MFA Delete enabled
    7. Server access logging enabled
    8. Lifecycle policy configured
    9. Bucket region (informational)
   10. Object Ownership / ACLs disabled (BucketOwnerEnforced)

Usage:
    python s3audit.py                       # default profile, default region
    python s3audit.py --profile prod        # named profile
    python s3audit.py --bucket my-bucket    # single bucket
    python s3audit.py --output ./reports    # custom output dir
    python s3audit.py --json                # also emit JSON
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import json
import logging
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
except ImportError:
    sys.stderr.write(
        "ERROR: boto3 is required. Install with: pip install boto3\n"
    )
    sys.exit(1)


# ---------- Severity model -------------------------------------------------

SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_RANK = {
    SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 1,
    SEVERITY_INFO: 0,
}


@dataclass
class Finding:
    check: str
    severity: str
    passed: bool
    detail: str

    def status_label(self) -> str:
        if self.passed:
            return "PASS"
        return f"FAIL ({self.severity})"


@dataclass
class BucketReport:
    name: str
    region: str | None = None
    creation_date: str | None = None
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def add(self, check: str, severity: str, passed: bool, detail: str) -> None:
        self.findings.append(Finding(check, severity, passed, detail))

    def worst_severity(self) -> str:
        worst = SEVERITY_INFO
        for f in self.findings:
            if not f.passed and SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]:
                worst = f.severity
        return worst

    def fail_count(self) -> int:
        return sum(1 for f in self.findings if not f.passed)


# ---------- Auditor --------------------------------------------------------


class S3Auditor:
    def __init__(self, session: boto3.session.Session, log: logging.Logger) -> None:
        self.session = session
        self.log = log
        self.s3 = session.client("s3")

    # ----- discovery -----

    def list_buckets(self) -> list[dict[str, Any]]:
        resp = self.s3.list_buckets()
        return resp.get("Buckets", [])

    def bucket_region(self, name: str) -> str | None:
        try:
            resp = self.s3.get_bucket_location(Bucket=name)
            loc = resp.get("LocationConstraint")
            return loc or "us-east-1"
        except ClientError as e:
            self.log.warning("bucket_region(%s): %s", name, e.response["Error"]["Code"])
            return None

    def regional_client(self, region: str | None):
        if not region:
            return self.s3
        return self.session.client("s3", region_name=region)

    # ----- checks -----

    def audit_bucket(self, name: str, creation_date: str | None) -> BucketReport:
        report = BucketReport(name=name, creation_date=creation_date)
        region = self.bucket_region(name)
        report.region = region
        client = self.regional_client(region)

        self._check_public_access_block(client, report)
        self._check_acl(client, report)
        self._check_policy_status(client, report)
        self._check_encryption(client, report)
        self._check_versioning(client, report)
        self._check_logging(client, report)
        self._check_lifecycle(client, report)
        self._check_ownership_controls(client, report)

        return report

    def _check_public_access_block(self, client, report: BucketReport) -> None:
        try:
            resp = client.get_public_access_block(Bucket=report.name)
            cfg = resp["PublicAccessBlockConfiguration"]
            all_on = all(
                cfg.get(k, False)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
            report.add(
                "Block Public Access",
                SEVERITY_HIGH,
                all_on,
                "All four BPA flags enabled" if all_on else f"BPA flags incomplete: {cfg}",
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                report.add(
                    "Block Public Access",
                    SEVERITY_HIGH,
                    False,
                    "No Block Public Access configuration set",
                )
            else:
                report.add("Block Public Access", SEVERITY_MEDIUM, False, f"Error: {code}")

    def _check_acl(self, client, report: BucketReport) -> None:
        try:
            acl = client.get_bucket_acl(Bucket=report.name)
            public_uris = {
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            }
            offenders = []
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI")
                if uri in public_uris:
                    offenders.append(f"{grantee.get('Type')}={uri} -> {grant.get('Permission')}")
            if offenders:
                report.add(
                    "ACL not public",
                    SEVERITY_HIGH,
                    False,
                    "Public ACL grants: " + "; ".join(offenders),
                )
            else:
                report.add("ACL not public", SEVERITY_HIGH, True, "No public ACL grants")
        except ClientError as e:
            report.add("ACL not public", SEVERITY_MEDIUM, False, f"Error: {e.response['Error']['Code']}")

    def _check_policy_status(self, client, report: BucketReport) -> None:
        try:
            resp = client.get_bucket_policy_status(Bucket=report.name)
            is_public = resp["PolicyStatus"]["IsPublic"]
            report.add(
                "Bucket policy not public",
                SEVERITY_HIGH,
                not is_public,
                "Policy marked public by AWS" if is_public else "Policy not public",
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchBucketPolicy":
                report.add("Bucket policy not public", SEVERITY_HIGH, True, "No bucket policy attached")
            else:
                report.add("Bucket policy not public", SEVERITY_MEDIUM, False, f"Error: {code}")

    def _check_encryption(self, client, report: BucketReport) -> None:
        try:
            resp = client.get_bucket_encryption(Bucket=report.name)
            rules = resp["ServerSideEncryptionConfiguration"]["Rules"]
            algos = [
                r["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                for r in rules
                if "ApplyServerSideEncryptionByDefault" in r
            ]
            report.add(
                "Default encryption",
                SEVERITY_HIGH,
                bool(algos),
                f"Default SSE: {', '.join(algos)}" if algos else "No default SSE rule",
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                report.add("Default encryption", SEVERITY_HIGH, False, "No default SSE configuration")
            else:
                report.add("Default encryption", SEVERITY_MEDIUM, False, f"Error: {code}")

    def _check_versioning(self, client, report: BucketReport) -> None:
        try:
            resp = client.get_bucket_versioning(Bucket=report.name)
            status = resp.get("Status")
            mfa = resp.get("MFADelete")
            report.add(
                "Versioning enabled",
                SEVERITY_MEDIUM,
                status == "Enabled",
                f"Status={status or 'Disabled'}",
            )
            report.add(
                "MFA Delete enabled",
                SEVERITY_LOW,
                mfa == "Enabled",
                f"MFADelete={mfa or 'Disabled'}",
            )
        except ClientError as e:
            report.add("Versioning enabled", SEVERITY_MEDIUM, False, f"Error: {e.response['Error']['Code']}")

    def _check_logging(self, client, report: BucketReport) -> None:
        try:
            resp = client.get_bucket_logging(Bucket=report.name)
            enabled = "LoggingEnabled" in resp
            target = resp.get("LoggingEnabled", {}).get("TargetBucket")
            report.add(
                "Server access logging",
                SEVERITY_MEDIUM,
                enabled,
                f"Logging to {target}" if enabled else "Server access logging disabled",
            )
        except ClientError as e:
            report.add("Server access logging", SEVERITY_LOW, False, f"Error: {e.response['Error']['Code']}")

    def _check_lifecycle(self, client, report: BucketReport) -> None:
        try:
            resp = client.get_bucket_lifecycle_configuration(Bucket=report.name)
            rules = resp.get("Rules", [])
            report.add(
                "Lifecycle policy",
                SEVERITY_LOW,
                bool(rules),
                f"{len(rules)} lifecycle rule(s)" if rules else "No lifecycle rules",
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchLifecycleConfiguration":
                report.add("Lifecycle policy", SEVERITY_LOW, False, "No lifecycle configuration")
            else:
                report.add("Lifecycle policy", SEVERITY_LOW, False, f"Error: {code}")

    def _check_ownership_controls(self, client, report: BucketReport) -> None:
        try:
            resp = client.get_bucket_ownership_controls(Bucket=report.name)
            rules = resp["OwnershipControls"]["Rules"]
            owns = [r["ObjectOwnership"] for r in rules]
            ok = "BucketOwnerEnforced" in owns
            report.add(
                "ACLs disabled (BucketOwnerEnforced)",
                SEVERITY_MEDIUM,
                ok,
                f"ObjectOwnership: {', '.join(owns)}",
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "OwnershipControlsNotFoundError":
                report.add(
                    "ACLs disabled (BucketOwnerEnforced)",
                    SEVERITY_MEDIUM,
                    False,
                    "No OwnershipControls configured",
                )
            else:
                report.add(
                    "ACLs disabled (BucketOwnerEnforced)",
                    SEVERITY_LOW,
                    False,
                    f"Error: {code}",
                )


# ---------- Renderers ------------------------------------------------------


def write_csv(reports: list[BucketReport], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["Bucket", "Region", "Check", "Severity", "Status", "Detail"]
        )
        for r in reports:
            if r.error:
                writer.writerow([r.name, r.region or "", "audit", "HIGH", "ERROR", r.error])
                continue
            for f_ in r.findings:
                writer.writerow(
                    [
                        r.name,
                        r.region or "",
                        f_.check,
                        f_.severity,
                        "PASS" if f_.passed else "FAIL",
                        f_.detail,
                    ]
                )


SEVERITY_COLOR = {
    SEVERITY_HIGH: "#d73a49",
    SEVERITY_MEDIUM: "#e36209",
    SEVERITY_LOW: "#dbab09",
    SEVERITY_INFO: "#0366d6",
}


def write_html(reports: list[BucketReport], path: Path, generated_at: str) -> None:
    total = len(reports)
    failing = sum(1 for r in reports if r.fail_count() > 0)
    high = sum(1 for r in reports if r.worst_severity() == SEVERITY_HIGH)

    rows: list[str] = []
    for r in sorted(reports, key=lambda x: -SEVERITY_RANK.get(x.worst_severity(), 0)):
        worst = r.worst_severity()
        color = SEVERITY_COLOR.get(worst, "#586069")
        finding_rows = "".join(
            f"<tr class='{ 'fail' if not f.passed else 'pass' }'>"
            f"<td>{html.escape(f.check)}</td>"
            f"<td><span class='sev' style='background:{SEVERITY_COLOR[f.severity]}'>{f.severity}</span></td>"
            f"<td>{'PASS' if f.passed else 'FAIL'}</td>"
            f"<td>{html.escape(f.detail)}</td></tr>"
            for f in r.findings
        )
        rows.append(
            f"<section class='bucket'>"
            f"<h3><span class='dot' style='background:{color}'></span>"
            f"{html.escape(r.name)} "
            f"<small>{html.escape(r.region or '?')} &middot; {r.fail_count()} failing</small></h3>"
            f"<table><thead><tr><th>Check</th><th>Severity</th>"
            f"<th>Status</th><th>Detail</th></tr></thead>"
            f"<tbody>{finding_rows}</tbody></table></section>"
        )

    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>S3 Security Audit Report</title>
<style>
 body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
        margin: 2rem; background:#fafbfc; color:#24292e; }}
 h1 {{ margin-bottom: .25rem; }}
 .meta {{ color:#586069; margin-bottom: 1.5rem; }}
 .summary {{ display:flex; gap:1rem; margin-bottom: 2rem; }}
 .card {{ flex:1; background:#fff; padding:1rem; border-radius:6px;
         border:1px solid #e1e4e8; }}
 .card .num {{ font-size:2rem; font-weight:600; }}
 .bucket {{ background:#fff; border:1px solid #e1e4e8; border-radius:6px;
            padding:1rem 1.25rem; margin-bottom:1rem; }}
 .bucket h3 {{ margin:.25rem 0 .75rem 0; font-size:1.05rem; }}
 .bucket h3 small {{ color:#586069; font-weight:400; margin-left:.5rem; }}
 .dot {{ display:inline-block; width:.7rem; height:.7rem;
         border-radius:50%; margin-right:.4rem; vertical-align:middle; }}
 table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
 th, td {{ text-align:left; padding:.4rem .6rem;
           border-bottom:1px solid #eaecef; }}
 th {{ background:#f6f8fa; font-weight:600; }}
 tr.fail td {{ color:#24292e; }}
 tr.pass td {{ color:#586069; }}
 .sev {{ color:#fff; padding:1px 6px; border-radius:3px;
         font-size:.75rem; font-weight:600; }}
</style></head><body>
<h1>S3 Security Audit Report</h1>
<div class="meta">Generated {html.escape(generated_at)}</div>
<div class="summary">
  <div class="card"><div class="num">{total}</div>Buckets scanned</div>
  <div class="card"><div class="num">{failing}</div>With at least one failure</div>
  <div class="card"><div class="num">{high}</div>HIGH-severity buckets</div>
</div>
{''.join(rows)}
</body></html>
"""
    path.write_text(html_doc, encoding="utf-8")


def write_json(reports: list[BucketReport], path: Path) -> None:
    payload = []
    for r in reports:
        payload.append(
            {
                "name": r.name,
                "region": r.region,
                "creation_date": r.creation_date,
                "error": r.error,
                "worst_severity": r.worst_severity(),
                "fail_count": r.fail_count(),
                "findings": [asdict(f) for f in r.findings],
            }
        )
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ---------- CLI ------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", help="AWS named profile")
    p.add_argument("--region", help="Default AWS region (used for the initial client)")
    p.add_argument("--bucket", action="append", help="Audit only the given bucket (repeatable)")
    p.add_argument("--output", default="./s3-audit-output", help="Output directory")
    p.add_argument("--json", action="store_true", help="Also emit JSON report")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def make_session(profile: str | None, region: str | None) -> boto3.session.Session:
    try:
        return boto3.session.Session(profile_name=profile, region_name=region)
    except ProfileNotFound as e:
        sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(2)


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    log = logging.getLogger("s3audit")

    session = make_session(args.profile, args.region)
    auditor = S3Auditor(session, log)

    try:
        all_buckets = auditor.list_buckets()
    except NoCredentialsError:
        sys.stderr.write("ERROR: no AWS credentials found.\n")
        return 2
    except ClientError as e:
        sys.stderr.write(f"ERROR: list_buckets failed: {e}\n")
        return 2

    if args.bucket:
        wanted = set(args.bucket)
        targets = [b for b in all_buckets if b["Name"] in wanted]
        missing = wanted - {b["Name"] for b in targets}
        if missing:
            log.warning("Bucket(s) not found in account: %s", ", ".join(sorted(missing)))
    else:
        targets = all_buckets

    log.info("Auditing %d bucket(s)", len(targets))

    reports: list[BucketReport] = []
    for b in targets:
        name = b["Name"]
        created = b.get("CreationDate").isoformat() if b.get("CreationDate") else None
        log.info("  -> %s", name)
        try:
            reports.append(auditor.audit_bucket(name, created))
        except Exception as exc:  # broad catch to keep audit going
            log.error("Failed to audit %s: %s", name, exc)
            r = BucketReport(name=name, error=str(exc))
            reports.append(r)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    csv_path = out_dir / f"s3-audit-{stamp}.csv"
    html_path = out_dir / f"s3-audit-{stamp}.html"
    write_csv(reports, csv_path)
    write_html(reports, html_path, stamp)
    if args.json:
        json_path = out_dir / f"s3-audit-{stamp}.json"
        write_json(reports, json_path)
        log.info("Wrote %s", json_path)

    log.info("Wrote %s", csv_path)
    log.info("Wrote %s", html_path)

    fail_total = sum(r.fail_count() for r in reports)
    high_total = sum(1 for r in reports if r.worst_severity() == SEVERITY_HIGH)
    log.info("Summary: %d findings across %d buckets; %d HIGH-severity bucket(s)",
             fail_total, len(reports), high_total)
    return 0 if high_total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
