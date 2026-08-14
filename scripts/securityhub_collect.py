#!/usr/bin/env python3
"""Export AWS Security Hub/CSPM findings as Jira-ready JSON.

The collector is read-only.  It uses the Security Hub ``get_findings`` API,
which is also the API used for CSPM control findings.  Credentials and
secrets are never written to the output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import boto3
except ImportError:  # pragma: no cover - gives a useful CLI error
    boto3 = None


SEVERITIES = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
STATUSES = {"NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"}


def _value(obj: Any, *keys: str, default: Any = None) -> Any:
    for key in keys:
        if isinstance(obj, dict) and obj.get(key) is not None:
            return obj[key]
    return default


def _finding_key(finding: dict[str, Any], account_id: str, region: str) -> str:
    """Return a stable key suitable for deduplication in a later Jira step."""
    product = _value(
        finding.get("ProductFields", {}), "aws/securityhub/ProductName", default=""
    )
    identity = {
        "account_id": account_id,
        "region": region,
        "product": product,
        "id": finding.get("Id", ""),
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _recommendation_text(finding: dict[str, Any]) -> Any:
    remediation = finding.get("Remediation")
    if not isinstance(remediation, dict):
        return None
    recommendation = remediation.get("Recommendation")
    if not isinstance(recommendation, dict):
        return None
    return recommendation.get("Text")


def normalize_finding(
    finding: dict[str, Any], account_id: str, region: str
) -> dict[str, Any]:
    severity = _value(finding.get("Severity", {}), "Label", default="UNKNOWN")
    workflow = _value(finding.get("Workflow", {}), "Status", default="UNKNOWN")
    resources = finding.get("Resources") or []
    return {
        "key": _finding_key(finding, account_id, region),
        "id": finding.get("Id"),
        "product_arn": finding.get("ProductArn"),
        "product_name": _value(
            finding.get("ProductFields", {}), "aws/securityhub/ProductName"
        ),
        "control_id": _value(
            finding.get("ProductFields", {}), "ControlId", "aws/securityhub/ControlId"
        ),
        "title": finding.get("Title"),
        "description": finding.get("Description"),
        "remediation": _recommendation_text(finding),
        "severity": str(severity).upper(),
        "status": str(workflow).upper(),
        "compliance": finding.get("Compliance", {}),
        "account_id": account_id,
        "region": region,
        "resource_ids": [r.get("Id") for r in resources if r.get("Id")],
        "resource_types": [r.get("Type") for r in resources if r.get("Type")],
        "created_at": finding.get("CreatedAt"),
        "updated_at": finding.get("UpdatedAt"),
        "generator_id": finding.get("GeneratorId"),
        "aws_console_url": (
            f"https://{region}.console.aws.amazon.com/securityhub/home"
            f"?region={region}#/findings?search=Id%3D{finding.get('Id', '')}"
        ),
    }


def collect_findings(
    client: Any,
    account_id: str,
    region: str,
    severities: set[str] | None = None,
    statuses: set[str] | None = None,
    max_findings: int | None = None,
) -> list[dict[str, Any]]:
    filters: dict[str, list[dict[str, Any]]] = {}
    if severities:
        filters["SeverityLabel"] = [
            {"Value": value, "Comparison": "EQUALS"} for value in sorted(severities)
        ]
    if statuses:
        filters["WorkflowStatus"] = [
            {"Value": value, "Comparison": "EQUALS"} for value in sorted(statuses)
        ]

    findings: list[dict[str, Any]] = []
    request: dict[str, Any] = {"MaxResults": 100}
    if filters:
        request["Filters"] = filters
    while True:
        response = client.get_findings(**request)
        findings.extend(
            normalize_finding(item, account_id, region)
            for item in response.get("Findings", [])
        )
        if max_findings and len(findings) >= max_findings:
            return findings[:max_findings]
        token = response.get("NextToken")
        if not token:
            return findings
        request["NextToken"] = token


def collect(
    region: str,
    profile: str | None,
    severities: set[str] | None,
    statuses: set[str] | None,
    max_findings: int | None,
) -> dict[str, Any]:
    if boto3 is None:
        raise RuntimeError(
            "boto3 is required; install it with: python -m pip install boto3"
        )
    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("securityhub", region_name=region)
    identity = session.client("sts", region_name=region).get_caller_identity()
    account_id = identity["Account"]
    try:
        hub = client.describe_hub()
    except client.exceptions.ResourceNotFoundException:
        hub = None
    return {
        "schema_version": 1,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "region": region,
        "hub": hub,
        "findings": collect_findings(
            client, account_id, region, severities, statuses, max_findings
        ),
    }


def _csv_values(value: str | None, allowed: set[str], name: str) -> set[str] | None:
    if not value:
        return None
    values = {item.strip().upper() for item in value.split(",") if item.strip()}
    invalid = values - allowed
    if invalid:
        raise ValueError(f"invalid {name}: {', '.join(sorted(invalid))}")
    return values


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--region", default=None, help="AWS region (default: SDK/config region)"
    )
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--severity", help="comma-separated severity labels")
    parser.add_argument("--status", help="comma-separated workflow statuses")
    parser.add_argument("--max-findings", type=int, help="maximum findings to export")
    parser.add_argument(
        "--output", type=Path, default=Path("securityhub-findings.json")
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        severities = _csv_values(args.severity, SEVERITIES, "severity")
        statuses = _csv_values(args.status, STATUSES, "status")
        if args.max_findings is not None and args.max_findings < 1:
            raise ValueError("--max-findings must be positive")
        if boto3 is None:
            raise RuntimeError(
                "boto3 is required; install it with: python -m pip install boto3"
            )
        region = args.region or boto3.Session(profile_name=args.profile).region_name
        if not region:
            raise ValueError("no region configured; pass --region")
        result = collect(region, args.profile, severities, statuses, args.max_findings)
        args.output.write_text(
            json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
        )
        print(f"Wrote {len(result['findings'])} findings to {args.output}")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
