from fastapi import APIRouter
import re
from models.schemas import ScanRequest, ScanResponse

router = APIRouter()

SECRET_PATTERNS = {
    "aws_access_key": r'AKIA[0-9A-Z]{16}',
    "aws_secret_key": r'[A-Za-z0-9+/]{40}',
    "yandex_cloud_key": r'YCAJ[0-9A-Za-z\\-_]{38,50}'
}

@router.get("/patterns")
def get_secret_patterns():
    """(1) Какие паттерны секретов?"""
    return {"secret_patterns": SECRET_PATTERNS}

@router.post("/scan/secrets", response_model=ScanResponse)
def scan_for_secrets(request: ScanRequest):
    """Сканирование кода на наличие секретов"""
    code_text = str(request.code)
    found_secrets = {}
    
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, code_text, re.IGNORECASE)
        if matches:
            found_secrets[secret_type] = {
                "count": len(matches),
                "examples": matches[:2],
                "severity": "HIGH" if "key" in secret_type else "MEDIUM"
            }
    
    return ScanResponse(
        secrets_found=len(found_secrets) > 0,
        details=found_secrets,
        scan_status="completed"
    )

@router.get("/health")
def health_check():
    return {"status": "healthy", "service": "secret-scanner"}