#!/usr/bin/env python3
import json
import logging
import sys
import re

def ingest_json_from_stdin() -> dict:
    json_obj = json.load(sys.stdin)
    return json_obj

def format_json_for_glsd(json_dict: dict) -> dict:
    output_dict = dict(version="3.0.0", vulnerabilities=list())
    
    if json_dict["runs"]:
        for vuln in json_dict["runs"]:
            for id in range(0, len(vuln["results"])):
                rule = vuln["results"][id]["ruleIndex"]
                artifact = vuln["results"][id]["locations"][0]["physicalLocation"]
                vname = vuln["tool"]["driver"]["rules"][rule]["name"]
                message = vuln["results"][id]["message"]
                description = vuln["tool"]["driver"]["rules"][rule]["help"]["markdown"]
                bfix = re.split("Best practices for prevention", description)
                pfix = re.split('How to prevent', description)

                if 'type' not in vuln:
                    gitlab_vuln_dict = dict()
                    gitlab_vuln_dict["id"] = vuln["results"][id]["fingerprints"]["0"]
                    gitlab_vuln_dict["category"] = "sast"
                    gitlab_vuln_dict["scanner"] = dict(id="snyk", name="Snyk Code")
                    gitlab_vuln_dict["name"] = vname
                    gitlab_vuln_dict["message"] = vname
                    gitlab_vuln_dict["description"] = description

                    gitlab_vuln_dict["cve"] = ""
                    if 'cwe' in vuln["tool"]["driver"]["rules"][rule]["properties"]:
                        for cwenum in range (0, len(vuln["tool"]["driver"]["rules"][rule]["properties"]["cwe"])):
                            gitlab_vuln_dict["cwe"] = vuln["tool"]["driver"]["rules"][rule]["properties"]["cwe"][cwenum]
                            cweId = gitlab_vuln_dict["cwe"].split("-")
                            gitlab_vuln_dict["identifiers"] = [
                            {
                                "type": "Snyk Code",
                                "name": gitlab_vuln_dict["cwe"],
                                "value": gitlab_vuln_dict["cwe"],
                                "url": "https://cwe.mitre.org/data/definitions/" + cweId[1] + ".html",
                            }
                            ]
                    else:
                        gitlab_vuln_dict["cwe"] = ""
                        gitlab_vuln_dict["identifiers"] = [
                        {
                            "type": "Snyk Code",
                            "name": vuln["results"][id]["ruleId"],
                            "value": vuln["results"][id]["ruleId"],
                        }
                        ]
                    gitlab_vuln_dict["location"] = {
                            "file": artifact["artifactLocation"]["uri"],
                            "start_line": artifact["region"]["startLine"],
                            "end_line": artifact["region"]["endLine"]
                    }
                    if vuln["results"][id]["level"] == "error":
                        gitlab_vuln_dict["severity"] = "High"
                    elif vuln["results"][id]["level"] == "warning":
                        gitlab_vuln_dict["severity"] = "Medium"
                    else:
                        gitlab_vuln_dict["severity"] = "Low"
                    
                    if len(bfix) > 1:
                        gitlab_vuln_dict["solution"] = bfix[1]
                    elif len(pfix) > 1:
                        gitlab_vuln_dict["solution"] = pfix[1]
                    else:
                        gitlab_vuln_dict["solution"] = message["text"]

                    output_dict["vulnerabilities"].append(gitlab_vuln_dict)

    return output_dict

def output_json_file(json_dict: dict) -> str:
    filename = f"snyk-gl-code-scanning.json"
    with open(filename, "w") as output_file:
        output_file.write(json.dumps(json_dict, indent=4))
    return filename


def main() -> None:
    json_obj = ingest_json_from_stdin()
    formatted_json = format_json_for_glsd(json_dict=json_obj)
    output_filename = output_json_file(formatted_json)
    logging.basicConfig(level=logging.INFO)
    logging.info(output_filename)
    return None


if __name__ == "__main__":
    main()
