import json
import datetime

def generate_sarif(findings, pkg_name="unknown"):
    """Convert dashboard findings into SARIF 2.1.0 format."""
    sarif_log = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "WgpArch Security Dashboard",
                    "version": "1.2.0",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    # Map findings to SARIF results
    for severity, title, description, color in findings:
        rule_id = "WGP-UNKNOWN"
        if "[" in title and "]" in title:
            rule_id = title.split("[")[1].split("]")[0]
            
        sarif_log["runs"][0]["results"].append({
            "ruleId": rule_id,
            "level": "error" if "CRITICAL" in severity else "warning" if "WARNING" in severity else "note",
            "message": {
                "text": f"{title}: {description}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f"PKGBUILD ({pkg_name})"
                    }
                }
            }]
        })

    return json.dumps(sarif_log, indent=2)
