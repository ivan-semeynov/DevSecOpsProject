from fastapi import FastAPI
from api.endpoints import router as api_router

app = FastAPI(title="Policy Manager", version="1.0.0")

# Подключаем роутер
app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {"service": "Policy Manager", "status": "runni   ng"}