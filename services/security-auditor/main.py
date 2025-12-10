from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Security Auditor Service")


# ---------- Модели ----------

class TerraformResource(BaseModel):
    type: str
    name: str
    config: Dict[str, Any] = {}


class TerraformCode(BaseModel):
    resources: List[TerraformResource] = []


class SecretFinding(BaseModel):
    id: str
    severity: str
    message: str
    match: Optional[str] = None
    path: Optional[str] = None
    scenario: Optional[str] = None


class SecretScanResult(BaseModel):
    total_findings: int
    findings: List[SecretFinding] = []


class Violation(BaseModel):
    rule: str
    severity: str
    message: str
    resource: Optional[str] = None
    scenario: Optional[str] = None
    fix: Optional[str] = None


class ValidationResult(BaseModel):
    is_valid: bool
    total_violations: int
    violations: List[Violation] = []


class AuditRequest(BaseModel):
    terraform_code: TerraformCode
    secret_scan: SecretScanResult
    validation_result: ValidationResult


class AuditSummary(BaseModel):
    risk_level: str
    total_violations: int
    scenario_violations: Dict[str, int]


class AuditResponse(BaseModel):
    summary: AuditSummary
    violations: List[Violation]
    recommendations: List[str]
    

# ---------- Логика аудита ----------

def severity_weight(sev: str) -> int:
    mapping = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    return mapping.get(sev.upper(), 2)


def compute_risk_level(max_weight: int) -> str:
    if max_weight >= 4:
        return "CRITICAL"
    if max_weight == 3:
        return "HIGH"
    if max_weight == 2:
        return "MEDIUM"
    return "LOW"


def run_audit(req: AuditRequest) -> AuditResponse:
    all_violations: List[Violation] = list(req.validation_result.violations)

    # преобразуем секреты в "виртуальные" нарушения
    for f in req.secret_scan.findings:
        all_violations.append(
            Violation(
                rule=f"id:{f.id}",
                severity=f.severity,
                message=f.message,
                resource=f.path,
                scenario=f.scenario,
                fix=None,
            )
        )

    scenario_violations: Dict[str, int] = {"scenario_1": 0, "scenario_2": 0}
    max_weight = 0

    for v in all_violations:
        if v.scenario in scenario_violations:
            scenario_violations[v.scenario] += 1
        max_weight = max(max_weight, severity_weight(v.severity))

    risk_level = compute_risk_level(max_weight)

    summary = AuditSummary(
        risk_level=risk_level,
        total_violations=len(all_violations),
        scenario_violations=scenario_violations,
    )

    recommendations: List[str] = []
    if scenario_violations["scenario_1"] > 0:
        recommendations.append(
            "Review S3 buckets: disable public ACLs, enable public access block, use least-privilege bucket policies."
        )
    if scenario_violations["scenario_2"] > 0:
        recommendations.append(
            "Refactor IAM roles and policies to remove wildcards and dangerous managed policies."
        )
    if req.secret_scan.total_findings > 0:
        recommendations.append(
            "Rotate exposed secrets and move them into a proper secrets manager."
        )
    if not recommendations:
        recommendations.append(
            "No critical findings detected. Continue following security best practices."
        )

    return AuditResponse(
        summary=summary,
        violations=all_violations,
        recommendations=recommendations,
    )


# ---------- Endpoint'ы ----------

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "security-auditor"}


@app.get("/api/v1/patterns")
def patterns():
    return {
        "scenarios": {
            "scenario_1": "Public S3 buckets / missing public access block",
            "scenario_2": "Excessive IAM permissions",
        }
    }


@app.post("/api/v1/audit", response_model=AuditResponse)
def audit(req: AuditRequest):
    return run_audit(req)
