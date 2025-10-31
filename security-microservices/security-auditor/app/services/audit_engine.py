class AuditEngine:
    def analyze_security_issues(self, secret_scan, terraform_validation):
        """Анализ результатов безопасности"""
        critical_issues = []
        
        # Анализ найденных секретов
        if secret_scan.get("secrets_found", False):
            details = secret_scan.get("details", {})
            for secret_type, info in details.items():
                if info.get("severity") == "HIGH":
                    critical_issues.append({
                        "issue": f"EXPOSED_{secret_type.upper()}",
                        "description": f"Обнаружен {secret_type} в коде",
                        "severity": "CRITICAL",
                        "scenario": "CONFIDENTIALITY_THREAT"
                    })
        
        # Анализ нарушений в Terraform
        terraform_violations = terraform_validation.get("violations", [])
        for violation in terraform_violations:
            if violation.get("severity") == "HIGH":
                critical_issues.append({
                    "issue": violation.get("type"),
                    "description": violation.get("message"),
                    "severity": "HIGH",
                    "scenario": violation.get("scenario", "UNKNOWN")
                })
        
        return critical_issues