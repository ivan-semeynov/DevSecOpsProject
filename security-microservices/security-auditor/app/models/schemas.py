from pydantic import BaseModel
from typing import Dict, Any, List

class AuditRequest(BaseModel):
    secret_scan: Dict[str, Any]
    terraform_validation: Dict[str, Any]

class AuditResponse(BaseModel):
    audit_completed: bool
    overall_status: str
    critical_issues: List[Dict[str, Any]]
    summary: Dict[str, Any]