#!/usr/bin/env python
import json
import os
import sys
from typing import Any, Dict, List, Tuple


def collect_resources(module: Dict[str, Any], acc: List[Dict[str, Any]]) -> None:
    for res in module.get("resources", []):
        acc.append(res)
    for child in module.get("child_modules", []):
        collect_resources(child, acc)


def normalize_resources(tf_resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Приводим ресурсы из terraform show -json к формату:
    {type, name, config}
    + "приклеиваем" public access block к aws_s3_bucket, если он задан отдельным ресурсом
    """
    buckets: Dict[Tuple[str, str], Dict[str, Any]] = {}  # key=(type,name) -> normalized bucket
    pab_by_bucket_name: Dict[str, Dict[str, Any]] = {}   # key=bucket name -> pab values

    normalized: List[Dict[str, Any]] = []

    # 1) Сначала соберём public access block ресурсы
    for r in tf_resources:
        if r.get("type") == "aws_s3_bucket_public_access_block":
            values = r.get("values", {}) or {}
            # values.bucket может быть bucket id/arn, но часто совпадает с именем бакета
            # Для учебного стенда будем пытаться сопоставить по строке bucket.
            bucket_ref = values.get("bucket")
            if isinstance(bucket_ref, str) and bucket_ref:
                pab_by_bucket_name[bucket_ref] = values

    # 2) Теперь нормализуем ресурсы и “приклеим” PAB к bucket, если сможем
    for r in tf_resources:
        r_type = r.get("type")
        r_name = r.get("name")
        values = r.get("values", {}) or {}

        item = {
            "type": r_type,
            "name": r_name,
            "config": values,
        }

        # Если это bucket — попробуем добавить public_access_block_configuration
        if r_type == "aws_s3_bucket":
            # в values.bucket обычно строка имени бакета
            bucket_name = values.get("bucket")
            if isinstance(bucket_name, str) and bucket_name in pab_by_bucket_name:
                pab = pab_by_bucket_name[bucket_name]
                item["config"]["public_access_block_configuration"] = {
                    "block_public_acls": pab.get("block_public_acls", True),
                    "ignore_public_acls": pab.get("ignore_public_acls", True),
                    "block_public_policy": pab.get("block_public_policy", True),
                    "restrict_public_buckets": pab.get("restrict_public_buckets", True),
                }

            buckets[(r_type, r_name)] = item

        normalized.append(item)

    return normalized


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: tfplan_to_security_payload.py <tfplan.json>", file=sys.stderr)
        sys.exit(1)

    tfplan_path = sys.argv[1]
    with open(tfplan_path, "r", encoding="utf-8") as f:
        plan = json.load(f)

    raw_resources: List[Dict[str, Any]] = []
    root_module = plan.get("planned_values", {}).get("root_module", {}) or {}
    collect_resources(root_module, raw_resources)

    resources = normalize_resources(raw_resources)

    pipeline_id = os.getenv("CI_PIPELINE_ID") or os.getenv("GITHUB_RUN_ID") or "local_run"
    repository_url = os.getenv("CI_PROJECT_URL") or (
        (os.getenv("GITHUB_SERVER_URL", "") + "/" + os.getenv("GITHUB_REPOSITORY", "")).strip("/")
    ) or "local_repo"

    payload = {
        "terraform_code": {"resources": resources},
        "pipeline_id": pipeline_id,
        "repository_url": repository_url,
    }

    json.dump(payload, sys.stdout)


if __name__ == "__main__":
    main()
