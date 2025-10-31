from fastapi import APIRouter
from models.schemas import AuditRequest, AuditResponse
from services.audit_engine import AuditEngine

router = APIRouter()
audit_engine = AuditEngine()

@router.get("/patterns")
def get_audit_patterns():
    """(1) Какие паттерны секретов?"""
    return {
        "audit_patterns": {
            "aws_keys": "Проверка AWS ключей доступа",
            "s3_public": "Проверка публичных S3 бакетов",
            "iam_privileges": "Проверка прав IAM ролей"
        }
    }

@router.post("/audit", response_model=AuditResponse)
def perform_security_audit(request: AuditRequest):
    """(3) Отправка статуса проверки - финальный аудит"""
    
    # Используем сервис для анализа
    critical_issues = audit_engine.analyze_security_issues(
        request.secret_scan,
        request.terraform_validation
    )
    
    # Финальный вердикт
    audit_passed = len(critical_issues) == 0
    
    return AuditResponse(
        audit_completed=True,
        overall_status="PASS" if audit_passed else "FAIL",
        critical_issues=critical_issues,
        summary={
            "total_issues": len(critical_issues),
            "secrets_found": request.secret_scan.get("secrets_found", False),
            "terraform_violations": len(request.terraform_validation.get("violations", [])),
            "compliance_level": "HIGH" if audit_passed else "LOW"
        }
    )

@router.get("/health")
def health_check():
    return {"status": "healthy", "service": "security-auditor"}