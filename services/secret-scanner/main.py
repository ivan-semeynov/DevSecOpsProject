from typing import Any, Dict, List, Optional
import json
import re

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Secret Scanner Service")


# ---------- Модели ----------

class TerraformResource(BaseModel):
    type: str
    name: str
    config: Dict[str, Any] = {}


class TerraformCode(BaseModel):
    resources: List[TerraformResource] = []


class ScanRequest(BaseModel):
    terraform_code: TerraformCode


class SecretFinding(BaseModel):
    id: str
    severity: str
    message: str
    match: Optional[str] = None
    path: Optional[str] = None
    scenario: Optional[str] = None


class ScanResponse(BaseModel):
    total_findings: int
    findings: List[SecretFinding]


# ---------- Паттерны поиска ----------

PATTERNS: Dict[str, Dict[str, Any]] = {
    "aws_access_key": {
        "regex": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "message": "Possible AWS Access Key ID detected",
    },
    "aws_secret_key": {
        "regex": r"(?i)aws_secret_access_key",
        "severity": "CRITICAL",
        "message": "Possible AWS secret key reference",
    },
    "s3_public_acl": {
        "regex": r'acl\s*=\s*"(public-read|public-read-write)"',
        "severity": "CRITICAL",
        "message": "S3 bucket with public ACL",
        "scenario": "scenario_1",
    },
    "iam_wildcard_action": {
        "regex": r'"Action"\s*:\s*"\*"',
        "severity": "CRITICAL",
        "message": "IAM policy with wildcard Action",
        "scenario": "scenario_2",
    },
    "iam_wildcard_resource": {
        "regex": r'"Resource"\s*:\s*"\*"',
        "severity": "CRITICAL",
        "message": "IAM policy with wildcard Resource",
        "scenario": "scenario_2",
    },
}


# ---------- Endpoint'ы ----------

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "secret-scanner"}


@app.get("/api/v1/patterns")
def get_patterns():
    return {
        "patterns": [
            {"id": pid, "regex": data["regex"], "severity": data["severity"]}
            for pid, data in PATTERNS.items()
        ]
    }


@app.post("/api/v1/scan/secrets", response_model=ScanResponse)
def scan_secrets(req: ScanRequest):
    # Превращаем структуру в строку и ищем паттерны
    raw = json.dumps(req.terraform_code.dict(), ensure_ascii=False)
    findings: List[SecretFinding] = []

    for pid, meta in PATTERNS.items():
        for m in re.finditer(meta["regex"], raw):
            findings.append(
                SecretFinding(
                    id=pid,
                    severity=meta["severity"],
                    message=meta["message"],
                    match=m.group(0),
                    path="raw",
                    scenario=meta.get("scenario"),
                )
            )

    return ScanResponse(total_findings=len(findings), findings=findings)
