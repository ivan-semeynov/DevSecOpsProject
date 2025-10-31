from fastapi import APIRouter
from models.schemas import ValidationRequest, ValidationResponse
from services.terraform_parser import TerraformParser

router = APIRouter()
terraform_parser = TerraformParser()

@router.get("/rules/s3")
def get_s3_rules():
    """(1) Какие правила для S3?"""
    return {
        "rules": {
            "acl": "S3 должен быть 'private'",
            "encryption": "required",
            "public_access": "forbidden"
        },
        "description": "S3 должен быть 'private'"
    }

@router.post("/validate", response_model=ValidationResponse)
def validate_terraform(request: ValidationRequest):
    """Проверка Terraform кода на безопасность"""
    terraform_code = request.terraform_code
    
    # Используем сервис для парсинга
    s3_buckets = terraform_parser.find_s3_buckets(terraform_code)
    iam_roles = terraform_parser.find_iam_roles(terraform_code)
    
    violations = []
    
    # Проверяем S3 бакеты
    for bucket in s3_buckets:
        if bucket.get("acl") != "private":
            violations.append({
                "type": "S3_BUCKET_PUBLIC",
                "resource": bucket.get("name", "unknown"),
                "message": "S3 bucket должен быть 'private'",
                "severity": "HIGH",
                "scenario": "INTEGRITY_THREAT"
            })
    
    # Проверяем IAM роли
    for role in iam_roles:
        if role.get("role") in ["admin", "editor"]:
            violations.append({
                "type": "EXCESSIVE_PRIVILEGES",
                "resource": role.get("name", "unknown"),
                "message": "Сервисный аккаунт имеет избыточные права",
                "severity": "HIGH", 
                "scenario": "CONFIDENTIALITY_THREAT"
            })
    
    return ValidationResponse(
        valid=len(violations) == 0,
        violations=violations,
        checked_resources=len(s3_buckets) + len(iam_roles)
    )

@router.get("/health")
def health_check():
    return {"status": "healthy", "service": "terraform-validator"}