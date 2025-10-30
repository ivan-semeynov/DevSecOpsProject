from fastapi import FastAPI
import requests

app = FastAPI(title="Security Auditor")

@app.get("/")
def read_root():
    return {"service": "Security Auditor", "status": "running"}

@app.get("/patterns")
def get_audit_patterns():
    """Возвращает паттерны для аудита (1) Какие паттерны секретов?"""
    return {
        "audit_patterns": {
            "aws_keys": "Проверка AWS ключей доступа",
            "s3_public": "Проверка публичных S3 бакетов",
            "iam_privileges": "Проверка прав IAM ролей"
        }
    }

@app.post("/audit")
def perform_security_audit(request: dict):
    """Выполняет финальный аудит безопасности (3) Отправка статуса проверки"""
    secret_scan = request.get("secret_scan", {})
    terraform_validation = request.get("terraform_validation", {})
    
    # Анализируем результаты
    critical_issues = []
    
    # Проверяем найденные секреты
    if secret_scan.get("secrets_found", False):
        critical_issues.append({
            "issue": "SECRETS_IN_CODE",
            "description": "В коде обнаружены секретные ключи",
            "severity": "CRITICAL"
        })
    
    # Проверяем нарушения в Terraform
    terraform_violations = terraform_validation.get("violations", [])
    for violation in terraform_violations:
        if violation.get("severity") == "HIGH":
            critical_issues.append({
                "issue": violation.get("type"),
                "description": violation.get("message"),
                "severity": "HIGH"
            })
    
    # Формируем финальный статус
    audit_passed = len(critical_issues) == 0
    
    return {
        "audit_completed": True,
        "overall_status": "PASS" if audit_passed else "FAIL",
        "critical_issues": critical_issues,
        "summary": {
            "total_issues": len(critical_issues),
            "secrets_found": secret_scan.get("secrets_found", False),
            "terraform_violations": len(terraform_violations)
        }
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}