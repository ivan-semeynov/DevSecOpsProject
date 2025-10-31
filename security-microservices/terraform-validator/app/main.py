from fastapi import FastAPI
from api.endpoints import router as api_router

app = FastAPI(title="Terraform Validator", version="1.0.0")
app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {"service": "Terraform Validator", "status": "running"}