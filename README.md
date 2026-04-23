# aws-s3-security-audit

A small, dependency-light Python tool that audits every S3 bucket in an AWS
account for common security misconfigurations and produces both a CSV
spreadsheet and a self-contained HTML report.

It uses only the AWS SDK (`boto3`) and the Python standard library — no
extra heavyweight frameworks, no infrastructure, no API keys to manage
beyond your normal AWS credentials.

## What it checks

For every accessible bucket the auditor evaluates:

| Check | Severity | Why it matters |
|-------|----------|----------------|
| Block Public Access (all four flags) | HIGH | The single most important S3 hardening setting. |
| Bucket ACL is not public | HIGH | Legacy AllUsers / AuthenticatedUsers grants leak data. |
| Bucket policy is not public | HIGH | Policies that grant `*` principal expose buckets. |
| Default server-side encryption | HIGH | Encryption-at-rest baseline (SSE-S3 / SSE-KMS). |
| Versioning enabled | MEDIUM | Required for ransomware recovery and audit trails. |
| Server access logging | MEDIUM | Required for forensic investigation and many compliance regimes. |
| Object Ownership = BucketOwnerEnforced (ACLs disabled) | MEDIUM | AWS' current best-practice ownership model. |
| MFA Delete enabled | LOW | Extra protection on versioned buckets against accidental deletion. |
| Lifecycle policy configured | LOW | Cost hygiene and data-retention controls. |

Each finding is tagged with severity and a short detail string so it can be
sorted, filtered, or piped into a ticketing system.

## Install

Requires Python 3.9+.

```bash
git clone https://github.com/intruderfr/aws-s3-security-audit.git
cd aws-s3-security-audit
pip install -r requirements.txt
```

You also need AWS credentials in the environment, in `~/.aws/credentials`,
via an instance/role profile, or via SSO. The IAM principal needs read-only
S3 permissions — the [`AmazonS3ReadOnlyAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonS3ReadOnlyAccess.html)
managed policy is sufficient.

## Usage

```bash
# Audit every bucket in the default account/profile
python s3audit.py

# Use a named profile and a custom output directory
python s3audit.py --profile prod --output ./reports

# Audit only one or two specific buckets
python s3audit.py --bucket my-app-prod --bucket my-app-stage

# Also emit a machine-readable JSON report
python s3audit.py --json
```

The tool writes three files (CSV always, HTML always, JSON when
`--json` is passed) into the output directory. Each filename is
timestamped:

```
s3-audit-output/
  s3-audit-20260423-103045Z.csv
  s3-audit-20260423-103045Z.html
  s3-audit-20260423-103045Z.json    # only with --json
```

The exit code is `0` if no HIGH-severity bucket was found, `1` if any
HIGH-severity finding exists, and `2` for credential / API errors —
making it straightforward to wire into CI.

## Sample CI usage

```yaml
- name: S3 security audit
  run: |
    pip install -r requirements.txt
    python s3audit.py --output ./reports --json
- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: s3-audit
    path: ./reports/
```

## Required IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketOwnershipControls"
      ],
      "Resource": "*"
    }
  ]
}
```

## Notes & limitations

- This is a configuration audit, not an object-level scan. It will not
  detect a single private bucket containing a publicly readable object.
- Bucket policies that grant access to specific external accounts are
  *not* flagged as public — by AWS' definition they aren't. Pair this
  with IAM Access Analyzer for cross-account exposure.
- The tool is intentionally read-only. It will never modify a bucket.

## License

MIT — see [LICENSE](LICENSE).

## Author

Aslam Ahamed — Head of IT @ Prestige One Developments, Dubai
[LinkedIn](https://www.linkedin.com/in/aslam-ahamed/)
