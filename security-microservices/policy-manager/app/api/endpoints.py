from fastapi import APIRouter, HTTPException
import requests
from models.schemas import TerraformValidationRequest, ValidationResult

router = APIRouter()

# Конфигурация сервисов
SERVICES = {
    "secret_scanner": "http://localhost:8001",
    "terraform_validator": "http://localhost:8002", 
    "security_auditor": "http://localhost:8003"
}

@router.get("/policies/s3")
def get_s3_policies():
    """(1) Какие правила для S3?"""
    return {
        "rules": {
            "acl": "S3 должен быть 'private'",
            "encryption": "required"
        }
    }

@router.get("/policies/iac")
def get_iac_policies():
    """(2) Все политики S3 и IAM"""
    return {
        "s3_policies": {"acl": "private"},
        "iam_policies": {"forbidden_roles": ["admin", "editor"]}
    }

@router.post("/validate/terraform", response_model=ValidationResult)
async def validate_terraform(request: TerraformValidationRequest):
    """Главный endpoint для проверки Terraform кода"""
    try:
        # 1. Проверка секретов
        secret_scan = requests.post(
            f"{SERVICES['secret_scanner']}/api/v1/scan/secrets",
            json={"code": request.terraform_code}
        ).json()

        # 2. Валидация Terraform
        terraform_check = requests.post(
            f"{SERVICES['terraform_validator']}/api/v1/validate",
            json={"terraform_code": request.terraform_code}
        ).json()

        # 3. Финальный аудит
        security_audit = requests.post(
            f"{SERVICES['security_auditor']}/api/v1/audit",
            json={
                "secret_scan": secret_scan,
                "terraform_validation": terraform_check
            }
        ).json()

        approved = (
            not secret_scan.get("secrets_found", True) and
            terraform_check.get("valid", False) and
            security_audit.get("overall_status") == "PASS"
        )

        return ValidationResult(
            approved=approved,
            secret_scan=secret_scan,
            terraform_validation=terraform_check,
            security_audit=security_audit
        )

    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail="Сервис безопасности недоступен")

@router.get("/health")
def health_check():
    return {"status": "healthy", "service": "policy-manager"}

@router.get("/services/status")
def get_services_status():
    status = {}
    for service_name, service_url in SERVICES.items():
        try:
            response = requests.get(f"{service_url}/api/v1/health", timeout=5)
            status[service_name] = "healthy" if response.status_code == 200 else "unhealthy"
        except:
            status[service_name] = "unreachable"
    return {"services_status": status}