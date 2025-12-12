#!/usr/bin/env python
import json
import os
import sys
from typing import Any, Dict, List


def collect_resources(module: Dict[str, Any], acc: List[Dict[str, Any]]) -> None:
    for res in module.get("resources", []):
        acc.append(res)
    for child in module.get("child_modules", []):
        collect_resources(child, acc)


def to_public_access_block_cfg(pab_values: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "block_public_acls": pab_values.get("block_public_acls", True),
        "ignore_public_acls": pab_values.get("ignore_public_acls", True),
        "block_public_policy": pab_values.get("block_public_policy", True),
        "restrict_public_buckets": pab_values.get("restrict_public_buckets", True),
    }


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: tfplan_to_security_payload.py <tfplan.json>", file=sys.stderr)
        sys.exit(1)

    tfplan_path = sys.argv[1]
    with open(tfplan_path, "r", encoding="utf-8") as f:
        plan = json.load(f)

    raw: List[Dict[str, Any]] = []
    root_module = plan.get("planned_values", {}).get("root_module", {}) or {}
    collect_resources(root_module, raw)

    # Соберём PublicAccessBlock ресурсы:
    # 1) по имени terraform-ресурса (самый надёжный матч)
    pab_by_name: Dict[str, Dict[str, Any]] = {}
    # 2) по values.bucket (запасной матч)
    pab_by_bucket_value: Dict[str, Dict[str, Any]] = {}

    for r in raw:
        if r.get("type") == "aws_s3_bucket_public_access_block":
            name = r.get("name")
            values = r.get("values", {}) or {}
            if isinstance(name, str) and name:
                pab_by_name[name] = values
            b = values.get("bucket")
            if isinstance(b, str) and b:
                pab_by_bucket_value[b] = values

    normalized: List[Dict[str, Any]] = []

    for r in raw:
        r_type = r.get("type")
        r_name = r.get("name")
        values = r.get("values", {}) or {}

        item = {"type": r_type, "name": r_name, "config": values}

        if r_type == "aws_s3_bucket" and isinstance(r_name, str):
            # 1) Склейка по имени ресурса (bucket.safe_logs ↔ pab.safe_logs)
            if r_name in pab_by_name:
                item["config"]["public_access_block_configuration"] = to_public_access_block_cfg(
                    pab_by_name[r_name]
                )
            else:
                # 2) запасной вариант: по строке bucket в values
                bucket_name = values.get("bucket")
                if isinstance(bucket_name, str) and bucket_name in pab_by_bucket_value:
                    item["config"]["public_access_block_configuration"] = to_public_access_block_cfg(
                        pab_by_bucket_value[bucket_name]
                    )

        normalized.append(item)

    pipeline_id = os.getenv("CI_PIPELINE_ID") or os.getenv("GITHUB_RUN_ID") or "local_run"
    repo_url = (
        os.getenv("CI_PROJECT_URL")
        or (os.getenv("GITHUB_SERVER_URL", "") + "/" + os.getenv("GITHUB_REPOSITORY", "")).strip("/")
        or "local_repo"
    )

    payload = {
        "terraform_code": {"resources": normalized},
        "pipeline_id": pipeline_id,
        "repository_url": repo_url,
    }

    json.dump(payload, sys.stdout)


if __name__ == "__main__":
    main()
