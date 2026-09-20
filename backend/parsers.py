import re
import json


def parse_nuclei_output(raw_output: str):
    pattern = (
        r"\[(CVE-\d{4}-\d{4,})\]\s+"
        r"\[([^\]]+)\]\s+"
        r"\[(critical|high|medium|low|info)\]\s+"
        r"(.+)"
    )

    match = re.search(pattern, raw_output, re.IGNORECASE)

    if not match:
        return None

    return {
        "cve_id": match.group(1).upper(),
        "protocol": match.group(2).lower(),
        "severity": match.group(3).lower(),
        "target": match.group(4).strip()
    }


def parse_nuclei_json(raw_output: str):
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return None

    classification = data.get("info", {}).get("classification", {})

    cve_ids = classification.get("cve-id", [])
    cwe_ids = classification.get("cwe-id", [])

    if isinstance(cve_ids, str):
        cve_id = cve_ids
    else:
        cve_id = cve_ids[0] if cve_ids else None

    if isinstance(cwe_ids, str):
        cwe_id = cwe_ids
    else:
        cwe_id = cwe_ids[0] if cwe_ids else None

    return {
        "title": data.get("info", {}).get("name"),
        "severity": data.get("info", {}).get("severity"),
        "target": data.get("matched-at"),
        "template_id": data.get("template-id"),
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "protocol": data.get("type"),
    }


def parse_nuclei_jsonl(raw_output: str):
    results = []

    for line in raw_output.splitlines():
        line = line.strip()

        if not line:
            continue

        parsed = parse_nuclei_json(line)

        if parsed:
            parsed["evidence"] = line
            results.append(parsed)

    return results

