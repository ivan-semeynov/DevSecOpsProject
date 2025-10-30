from fastapi import FastAPI
import re

app = FastAPI(title="Secret Scanner")

# Регулярные выражения для поиска секретов (2) Regex для AWS ключей
SECRET_PATTERNS = {
    "aws_access_key": r'AKIA[0-9A-Z]{16}',
    "aws_secret_key": r'[A-Za-z0-9+/]{40}',
    "yandex_cloud_key": r'YCAJ[0-9A-Za-z\\-_]{38,50}',
    "password_in_code": r'password\s*=\s*["\']([^"\']+)["\']'
}

@app.get("/")
def read_root():
    return {"service": "Secret Scanner", "status": "running"}

@app.get("/patterns")
def get_secret_patterns():
    """Возвращает паттерны для поиска секретов (1) Какие паттерны секретов?"""
    return {
        "secret_patterns": SECRET_PATTERNS,
        "description": "Regex для AWS ключей и других секретов"
    }

@app.post("/scan/secrets")
def scan_for_secrets(request: dict):
    """Сканирует код на наличие секретов"""
    code_text = str(request.get("code", {}))
    found_secrets = {}
    
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, code_text)
        if matches:
            found_secrets[secret_type] = {
                "count": len(matches),
                "examples": matches[:3]  # Показываем только 3 примера
            }
    
    return {
        "secrets_found": len(found_secrets) > 0,
        "details": found_secrets,
        "scan_status": "completed"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}