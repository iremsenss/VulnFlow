import re
import json
import xml.etree.ElementTree as ET


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
        "cvss_score": classification.get("cvss-score"),
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


def parse_nmap_xml(raw_output: str):
    try:
        root = ET.fromstring(raw_output)
    except ET.ParseError:
        return None

    hosts = []

    for host in root.findall("host"):
        address = host.find("address")

        if address is None:
            continue

        ip_address = address.get("addr")
        hostname_element = host.find("./hostnames/hostname")

        hostname = (
            hostname_element.get("name")
            if hostname_element is not None
            else None
        )
        
        
        ports = []

        for port in host.findall("./ports/port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            
            ports.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": state.get("state"),
                "service": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None
            })

        hosts.append({
            "ip": ip_address,
            "hostname": hostname,
            "ports": ports
        })

        return hosts