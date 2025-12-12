set -euo pipefail

# ---------- Настройки ----------
TF_ROOT="${TF_ROOT:-infra/terraform}"
POLICY_MANAGER_URL="${POLICY_MANAGER_URL:-http://localhost:8000}"
COMPOSE_UP="${COMPOSE_UP:-0}"      # 1 = поднимать docker-compose автоматически
DO_APPLY="${DO_APPLY:-0}"          # 1 = делать terraform apply если approved=true

TF_IMAGE="${TF_IMAGE:-hashicorp/terraform:1.9.8}"

# Для Windows + Git Bash
export MSYS_NO_PATHCONV=1

# MinIO creds (для учебного стенда из docker-compose)
MINIO_ACCESS_KEY="${MINIO_ACCESS_KEY:-admin}"
MINIO_SECRET_KEY="${MINIO_SECRET_KEY:-password123}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://host.docker.internal:9000}"

# Экспортим в TF_VAR_* чтобы terraform подхватил переменные
export TF_VAR_minio_access_key="$MINIO_ACCESS_KEY"
export TF_VAR_minio_secret_key="$MINIO_SECRET_KEY"
export TF_VAR_minio_endpoint="$MINIO_ENDPOINT"

# ---------- Хелперы ----------
need_cmd () {
  command -v "$1" >/dev/null 2>&1 || { echo "❌ Требуется команда: $1"; exit 1; }
}

docker_tf () {
  # Запускает terraform внутри контейнера в папке TF_ROOT
  docker run --rm -i \
    -v "$(pwd -W)/${TF_ROOT}:/workspace" \
    -w /workspace \
    -e TF_VAR_minio_access_key \
    -e TF_VAR_minio_secret_key \
    -e TF_VAR_minio_endpoint \
    "$TF_IMAGE" "$@"
}

# ---------- Проверки окружения ----------
need_cmd docker
need_cmd python
need_cmd curl

if [ ! -d "$TF_ROOT" ]; then
  echo "❌ Не найдена папка TF_ROOT=$TF_ROOT"
  exit 1
fi

if [ ! -f "$TF_ROOT/main.tf" ]; then
  echo "❌ Не найден $TF_ROOT/main.tf"
  exit 1
fi

if [ ! -f "tools/tfplan_to_security_payload.py" ]; then
  echo "❌ Не найден tools/tfplan_to_security_payload.py"
  exit 1
fi

# ---------- (Опционально) поднять compose ----------
if [ "$COMPOSE_UP" = "1" ]; then
  echo "[+] Starting services via docker compose..."
  docker compose up -d --build
fi

echo "[+] Health check Policy Manager..."
curl -sS "$POLICY_MANAGER_URL/api/v1/health" >/dev/null

# ---------- Terraform: init/plan/show ----------
echo "[+] Terraform init (docker)..."
docker_tf init -backend=false >/dev/null

echo "[+] Terraform plan (docker)..."
docker_tf plan -out=tfplan >/dev/null

echo "[+] Terraform show -json (docker)..."
docker_tf show -json tfplan > "$TF_ROOT/tfplan.json"

# ---------- Payload ----------
echo "[+] Building payload.json..."
python tools/tfplan_to_security_payload.py "$TF_ROOT/tfplan.json" > payload.json

# ---------- Call Policy Manager ----------
echo "[+] Calling Policy Manager..."
HTTP_CODE=$(curl -sS -o response.json -w "%{http_code}" \
  -X POST "$POLICY_MANAGER_URL/api/v1/validate/terraform" \
  -H "Content-Type: application/json" \
  --data-binary @payload.json)

echo "[+] Policy Manager HTTP code: $HTTP_CODE"
echo "[+] Response saved to response.json"

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "❌ Security gate failed: HTTP $HTTP_CODE"
  cat response.json || true
  exit 1
fi

APPROVED=$(python - <<'PY'
import json
data = json.load(open("response.json", encoding="utf-8"))
print(str(data.get("approved")).lower())
PY
)

RISK=$(python - <<'PY'
import json
data = json.load(open("response.json", encoding="utf-8"))
print(data.get("summary", {}).get("risk_level"))
PY
)

echo "[+] approved=$APPROVED risk_level=$RISK"

if [ "$APPROVED" != "true" ]; then
  echo "❌ BLOCKED: Security violations found. Terraform apply will NOT run."
  echo "   Посмотри details в response.json"
  exit 1
fi

echo "✅ APPROVED: Security gate passed."

# ---------- Apply (опционально) ----------
if [ "$DO_APPLY" = "1" ]; then
  echo "[+] Running terraform apply (docker)..."
  docker_tf apply -auto-approve
  echo "✅ Apply done."
else
  echo "[i] DO_APPLY=0, пропускаю terraform apply."
fi
EOF