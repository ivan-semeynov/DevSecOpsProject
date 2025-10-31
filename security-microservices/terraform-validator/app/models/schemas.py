from pydantic import BaseModel
from typing import Dict, Any, List

class ValidationRequest(BaseModel):
    terraform_code: Dict[str, Any]

class ValidationResponse(BaseModel):
    valid: bool
    violations: List[Dict[str, Any]]
    checked_resources: int