#!/usr/bin/env python
import json
import os
import sys
from typing import Any, Dict, List


def collect_resources(module: Dict[str, Any], acc: List[Dict[str, Any]]) -> None:
    for res in module.get("resources", []):
        acc.append(
            {
                "type": res.get("type"),
                "name": res.get("name"),
                "config": res.get("values", {}),
            }
        )
    for child in module.get("child_modules", []):
        collect_resources(child, acc)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: tfplan_to_security_payload.py <tfplan.json>", file=sys.stderr)
        sys.exit(1)

    tfplan_path = sys.argv[1]
    with open(tfplan_path, "r", encoding="utf-8") as f:
        plan = json.load(f)

    resources: List[Dict[str, Any]] = []
    root_module = plan.get("planned_values", {}).get("root_module", {})
    collect_resources(root_module, resources)

    pipeline_id = os.getenv("CI_PIPELINE_ID") or "local_run"
    repository_url = os.getenv("CI_PROJECT_URL") or "local_repo"

    payload = {
        "terraform_code": {
            "resources": resources,
        },
        "pipeline_id": pipeline_id,
        "repository_url": repository_url,
    }

    json.dump(payload, sys.stdout)


if __name__ == "__main__":
    main()
