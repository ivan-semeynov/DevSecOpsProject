from typing import Any, Dict, List, Optional
import json

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Terraform Validator Service")


# ---------- Модели ----------

class TerraformResource(BaseModel):
    type: str
    name: str
    config: Dict[str, Any] = {}


class TerraformCode(BaseModel):
    resources: List[TerraformResource] = []


class Violation(BaseModel):
    rule: str
    severity: str
    message: str
    resource: Optional[str] = None
    scenario: Optional[str] = None
    fix: Optional[str] = None


class ValidateRequest(BaseModel):
    terraform_code: TerraformCode


class ValidateResponse(BaseModel):
    is_valid: bool
    total_violations: int
    violations: List[Violation]


# ---------- Логика валидации ----------

def parse_iam_policy(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return {}
    return {}


def validate_s3_bucket(res: TerraformResource) -> List[Violation]:
    violations: List[Violation] = []
    cfg = res.config or {}

    acl = cfg.get("acl")
    if acl in ("public-read", "public-read-write"):
        violations.append(
            Violation(
                rule="s3_public_acl",
                severity="CRITICAL",
                message=f"S3 bucket '{res.name}' has public ACL '{acl}'",
                resource=res.name,
                scenario="scenario_1",
                fix="Set acl to 'private' and use bucket policies with least privilege.",
            )
        )

    if "public_access_block_configuration" not in cfg:
        violations.append(
            Violation(
                rule="s3_missing_public_access_block",
                severity="HIGH",
                message=f"S3 bucket '{res.name}' has no public_access_block_configuration",
                resource=res.name,
                scenario="scenario_1",
                fix="Add public_access_block_configuration to block public access.",
            )
        )

    return violations


def check_iam_statement(stmt: Dict[str, Any], res_name: str) -> List[Violation]:
    violations: List[Violation] = []
    action = stmt.get("Action")
    resource = stmt.get("Resource")

    if action == "*" or (isinstance(action, list) and "*" in action):
        violations.append(
            Violation(
                rule="iam_wildcard_action",
                severity="CRITICAL",
                message=f"IAM policy on '{res_name}' uses Action *",
                resource=res_name,
                scenario="scenario_2",
                fix="Replace Action '*' with a minimal set of required actions.",
            )
        )

    if resource == "*" or (isinstance(resource, list) and "*" in resource):
        violations.append(
            Violation(
                rule="iam_wildcard_resource",
                severity="CRITICAL",
                message=f"IAM policy on '{res_name}' uses Resource *",
                resource=res_name,
                scenario="scenario_2",
                fix="Scope the Resource to specific ARNs instead of '*'.",
            )
        )

    return violations


def validate_iam(res: TerraformResource) -> List[Violation]:
    violations: List[Violation] = []
    cfg = res.config or {}

    policy_raw = cfg.get("policy")
    policy = parse_iam_policy(policy_raw)

    if policy:
        stmts = policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for st in stmts:
            violations.extend(check_iam_statement(st, res.name))

    managed_arns = cfg.get("managed_policy_arns") or []
    if isinstance(managed_arns, str):
        managed_arns = [managed_arns]

    for arn in managed_arns:
        if "AdministratorAccess" in arn:
            violations.append(
                Violation(
                    rule="iam_dangerous_managed_policy",
                    severity="CRITICAL",
                    message=f"Role '{res.name}' uses AdministratorAccess",
                    resource=res.name,
                    scenario="scenario_2",
                    fix="Replace AdministratorAccess with a least-privilege policy.",
                )
            )
        if "AmazonS3FullAccess" in arn:
            violations.append(
                Violation(
                    rule="iam_dangerous_managed_policy",
                    severity="HIGH",
                    message=f"Role '{res.name}' uses AmazonS3FullAccess",
                    resource=res.name,
                    scenario="scenario_2",
                    fix="Limit S3 access to specific buckets and actions.",
                )
            )

    return violations


def validate_terraform_code(code: TerraformCode) -> List[Violation]:
    violations: List[Violation] = []
    for res in code.resources:
        if res.type == "aws_s3_bucket":
            violations.extend(validate_s3_bucket(res))
        elif res.type.startswith("aws_iam_"):
            violations.extend(validate_iam(res))
    return violations


# ---------- Endpoint'ы ----------

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "terraform-validator"}


@app.get("/api/v1/rules/s3")
def get_s3_rules():
    return {
        "rules": [
            {
                "id": "s3_public_acl",
                "description": "S3 buckets must not be public",
            },
            {
                "id": "s3_public_access_block_required",
                "description": "S3 buckets must enable public_access_block_configuration",
            },
        ]
    }


@app.post("/api/v1/validate", response_model=ValidateResponse)
def validate(req: ValidateRequest):
    violations = validate_terraform_code(req.terraform_code)
    is_valid = len(violations) == 0
    return ValidateResponse(
        is_valid=is_valid,
        total_violations=len(violations),
        violations=violations,
    )
