# Security Hub/CSPM collector

This read-only script exports AWS Security Hub findings, including CSPM
control findings, to JSON for review or a later Jira importer.

```bash
python -m pip install -r scripts/requirements.txt
aws sso login --profile my-sandbox
python scripts/securityhub_collect.py \
  --profile my-sandbox --region us-east-1 \
  --severity HIGH,CRITICAL --status NEW \
  --output securityhub-findings.json
```

Required permissions are `securityhub:DescribeHub`,
`securityhub:GetFindings`, and `sts:GetCallerIdentity`. The script does not
create, update, or resolve findings. Use a read-only/sandbox role first.

The output includes a stable `key` per finding (account, region, product, and
finding ID), which is intended for idempotent Jira creation later.
