from pydantic import BaseModel
from typing import Dict, Any

class ScanRequest(BaseModel):
    code: Dict[str, Any]

class ScanResponse(BaseModel):
    secrets_found: bool
    details: Dict[str, Any]
    scan_status: str