from fastapi import FastAPI, HTTPException
import requests
import json

app = FastAPI(title="Policy Manager")

# Храним правила безопасности
SECURITY_RULES = {
    "s3_buckets": {
        "acl": "private",  # S3 должен быть private
        "encryption": "required"
    },
    "iam_roles": {
        "max_privileges": ["readonly", "viewer"],
        "forbidden_roles": ["admin", "editor"]
    }
}

@app.get("/")
def read_root():
    return {"service": "Policy Manager", "status": "running"}

@app.get("/policies/s3")
def get_s3_policies():
    """Возвращает правила для S3 (1) Какие правила для S3?"""
    return {
        "rules": SECURITY_RULES["s3_buckets"],
        "description": "S3 должен быть 'private'"
    }

@app.get("/policies/iac")
def get_iac_policies():
    """Возвращает все политики для инфраструктуры (2) Все политики S3 и IAM"""
    return {
        "s3_policies": SECURITY_RULES["s3_buckets"],
        "iam_policies": SECURITY_RULES["iam_roles"]
    }

@app.post("/validate/terraform")
async def validate_terraform(terraform_code: dict):
    """Проверяет Terraform код через другие сервисы"""
    
    # 1. Проверяем секреты в коде
    secret_check = requests.post(
        "http://secret-scanner:8001/scan/secrets",
        json={"code": terraform_code}
    )
    
    # 2. Проверяем валидность Terraform
    terraform_check = requests.post(
        "http://terraform-validator:8002/validate",
        json={"terraform_code": terraform_code}
    )
    
    # 3. Получаем финальный аудит
    audit_result = requests.post(
        "http://security-auditor:8003/audit",
        json={
            "secret_scan": secret_check.json(),
            "terraform_validation": terraform_check.json()
        }
    )
    
    return {
        "policy_check": "completed",
        "secret_scan": secret_check.json(),
        "terraform_validation": terraform_check.json(),
        "final_audit": audit_result.json()
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}