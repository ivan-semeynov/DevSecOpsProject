from pydantic import BaseModel
from typing import Dict, Any, List

class TerraformValidationRequest(BaseModel):
    terraform_code: Dict[str, Any]

class ValidationResult(BaseModel):
    approved: bool
    secret_scan: Dict[str, Any]
    terraform_validation: Dict[str, Any]
    security_audit: Dict[str, Any]