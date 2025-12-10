import os
import json
import uuid
from typing import Any, Dict, List, Optional

import requests
import boto3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Policy Manager Service")


# ---------- Модели ----------

class TerraformResource(BaseModel):
    type: str
    name: str
    config: Dict[str, Any] = {}


class TerraformCode(BaseModel):
    resources: List[TerraformResource] = []


class TerraformValidationRequest(BaseModel):
    terraform_code: TerraformCode
    pipeline_id: Optional[str] = None
    repository_url: Optional[str] = None


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


class AuditSummary(BaseModel):
    risk_level: str
    total_violations: int
    scenario_violations: Dict[str, int]


class AuditResult(BaseModel):
    summary: AuditSummary
    violations: List[Violation]
    recommendations: List[str] = []


class ValidationResponse(BaseModel):
    approved: bool
    pipeline_id: Optional[str]
    summary: AuditSummary
    violations: List[Violation]


# ---------- Конфиг / S3-клиент ----------

SECRET_SCANNER_URL = os.getenv("SECRET_SCANNER_URL", "http://secret-scanner:8000")
TERRAFORM_VALIDATOR_URL = os.getenv("TERRAFORM_VALIDATOR_URL", "http://terraform-validator:8000")
SECURITY_AUDITOR_URL = os.getenv("SECURITY_AUDITOR_URL", "http://security-auditor:8000")

S3_ENDPOINT = os.getenv("S3_ENDPOINT", "http://minio:9000")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "admin")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "password123")
S3_BUCKET = os.getenv("S3_BUCKET", "security-results")

s3_client = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
    region_name="us-east-1",
)


# ---------- Вспомогательные функции ----------

def call_service(method: str, url: str, body: Dict[str, Any]) -> Dict[str, Any]:
    resp = requests.request(method, url, json=body, timeout=20)
    resp.raise_for_status()
    return resp.json()


def ensure_bucket_exists():
    resp = s3_client.list_buckets()
    existing = [b["Name"] for b in resp.get("Buckets", [])]
    if S3_BUCKET not in existing:
        s3_client.create_bucket(Bucket=S3_BUCKET)


def store_result_in_s3(pipeline_id: Optional[str], data: Dict[str, Any]) -> None:
    ensure_bucket_exists()
    key = f"{pipeline_id or 'no-pipeline'}/{uuid.uuid4().hex}.json"
    body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    s3_client.put_object(Bucket=S3_BUCKET, Key=key, Body=body)


# ---------- Endpoint'ы ----------

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "policy-manager"}


@app.get("/api/v1/policies/s3")
def get_s3_policies():
    return {
        "rules": [
            {
                "id": "s3_public_acl",
                "description": "S3 buckets must not use public-read or public-read-write ACL",
                "severity": "CRITICAL",
            },
            {
                "id": "s3_public_access_block_required",
                "description": "S3 buckets must enable public_access_block_configuration",
                "severity": "HIGH",
            },
        ]
    }


@app.get("/api/v1/policies/iac")
def get_iac_policies():
    return {
        "rules": [
            {
                "id": "iam_wildcard_action",
                "description": "IAM policies must not use Action: \"*\"",
                "severity": "CRITICAL",
            },
            {
                "id": "iam_wildcard_resource",
                "description": "IAM policies must not use Resource: \"*\"",
                "severity": "CRITICAL",
            },
            {
                "id": "iam_dangerous_managed_policies",
                "description": "Avoid AdministratorAccess and AmazonS3FullAccess",
                "severity": "HIGH",
            },
        ]
    }


@app.get("/api/v1/services/status")
def services_status():
    services = {
        "secret_scanner": f"{SECRET_SCANNER_URL}/api/v1/health",
        "terraform_validator": f"{TERRAFORM_VALIDATOR_URL}/api/v1/health",
        "security_auditor": f"{SECURITY_AUDITOR_URL}/api/v1/health",
    }
    result: Dict[str, Any] = {}
    for name, url in services.items():
        try:
            r = requests.get(url, timeout=5)
            r.raise_for_status()
            result[name] = {"status": "ok", "detail": r.json()}
        except Exception as e:
            result[name] = {"status": "down", "detail": str(e)}
    return result


@app.post("/api/v1/validate/terraform", response_model=ValidationResponse)
def validate_terraform(req: TerraformValidationRequest):
    tf_dict = req.terraform_code.dict()

    # безопасность по умолчанию: если что-то не так с сервисами → 503 → деплой блокируется
    try:
        # 1) Secret Scanner
        secret_json = call_service(
            "POST",
            f"{SECRET_SCANNER_URL}/api/v1/scan/secrets",
            {"terraform_code": tf_dict},
        )
        secret_scan = SecretScanResult(**secret_json)

        # 2) Terraform Validator
        validator_json = call_service(
            "POST",
            f"{TERRAFORM_VALIDATOR_URL}/api/v1/validate",
            {"terraform_code": tf_dict},
        )
        validation_result = ValidationResult(**validator_json)

        # 3) Security Auditor
        audit_payload = {
            "terraform_code": tf_dict,
            "secret_scan": secret_scan.dict(),
            "validation_result": validation_result.dict(),
        }
        audit_json = call_service(
            "POST",
            f"{SECURITY_AUDITOR_URL}/api/v1/audit",
            audit_payload,
        )
        audit_result = AuditResult(**audit_json)
    except Exception as e:
        # Любая ошибка в security-пути → деплой блокируем
        raise HTTPException(status_code=503, detail=f"Security validation failed: {e}")

    # Решение: LOW/MEDIUM → пропускаем, HIGH/CRITICAL → блокируем
    approved = audit_result.summary.risk_level in ("LOW", "MEDIUM")

    response = ValidationResponse(
        approved=approved,
        pipeline_id=req.pipeline_id,
        summary=audit_result.summary,
        violations=audit_result.violations,
    )

    # Логируем результат в MinIO (ошибка логирования не ломает ответ)
    try:
        store_result_in_s3(req.pipeline_id, response.dict())
    except Exception as e:
        print(f"[policy-manager] Failed to store result in MinIO: {e}")

    return response
