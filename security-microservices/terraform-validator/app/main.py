from fastapi import FastAPI
import json

app = FastAPI(title="Terraform Validator")

@app.get("/")
def read_root():
    return {"service": "Terraform Validator", "status": "running"}

@app.get("/rules/s3")
def get_s3_rules():
    """Возвращает правила для S3 (1) Какие правила для S3?"""
    return {
        "rules": {
            "acl": "S3 должен быть 'private'",
            "encryption": "Шифрование должно быть включено",
            "versioning": "Версионирование рекомендуется",
            "public_access": "Публичный доступ запрещен"
        }
    }

@app.post("/validate")
def validate_terraform(request: dict):
    """Проверяет Terraform код на безопасность"""
    terraform_code = request.get("terraform_code", {})
    violations = []
    
    # Проверяем S3 бакеты
    s3_buckets = self._find_s3_buckets(terraform_code)
    for bucket in s3_buckets:
        if bucket.get("acl") != "private":
            violations.append({
                "type": "S3_BUCKET_PUBLIC",
                "resource": bucket.get("name", "unknown"),
                "message": "S3 bucket должен быть 'private'",
                "severity": "HIGH"
            })
    
    # Проверяем IAM роли
    iam_roles = self._find_iam_roles(terraform_code)
    for role in iam_roles:
        if role.get("role") in ["admin", "editor"]:
            violations.append({
                "type": "EXCESSIVE_PRIVILEGES",
                "resource": role.get("name", "unknown"),
                "message": "Сервисный аккаунт имеет избыточные права",
                "severity": "HIGH"
            })
    
    return {
        "valid": len(violations) == 0,
        "violations": violations,
        "checked_resources": len(s3_buckets) + len(iam_roles)
    }

def _find_s3_buckets(self, terraform_code):
    """Ищет S3 бакеты в Terraform коде"""
    # Упрощенная логика поиска
    buckets = []
    code_str = str(terraform_code)
    
    if "s3_bucket" in code_str or "storage_bucket" in code_str:
        buckets.append({"name": "example-bucket", "acl": "private"})
    
    return buckets

def _find_iam_roles(self, terraform_code):
    """Ищет IAM роли в Terraform коде"""
    roles = []
    code_str = str(terraform_code)
    
    if "iam_role" in code_str or "service_account" in code_str:
        roles.append({"name": "example-role", "role": "admin"})
    
    return roles

@app.get("/health")
def health_check():
    return {"status": "healthy"}