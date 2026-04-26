"""Snyk mock data generator."""

import random
from typing import Any

from generators import (
    generate_email,
    generate_uuid,
    now_iso,
    weighted_choice,
)

_ORGS = ["my-org", "acme-corp", "security-team"]
_PACKAGES = [
    ("lodash", "4.17.15", "npm"),
    ("log4j-core", "2.14.1", "maven"),
    ("django", "3.2.4", "pip"),
    ("rails", "6.0.3", "rubygems"),
    ("express", "4.17.1", "npm"),
    ("spring-core", "5.3.20", "maven"),
]
_PROJECTS = [
    "frontend-app",
    "backend-api",
    "microservice-auth",
    "data-pipeline",
    "mobile-app",
]

_ISSUE_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "high_prototype_pollution": (
        {
            "issueType": "vuln",
            "pkgName": "lodash",
            "pkgVersions": ["4.17.15"],
            "issueData": {
                "id": "SNYK-JS-LODASH-608086",
                "title": "Prototype Pollution",
                "severity": "high",
                "cvssScore": 7.4,
                "description": "lodash is vulnerable to prototype pollution via the `merge`, `mergeWith`, and `defaultsDeep` functions.",
                "cve": "CVE-2020-8203",
                "cwe": ["CWE-400"],
                "fixedIn": ["4.17.21"],
                "isPatchable": False,
                "isUpgradable": True,
                "language": "js",
            },
        },
        0.40,
    ),
    "medium_license": (
        {
            "issueType": "license",
            "pkgName": "react",
            "pkgVersions": ["16.14.0"],
            "issueData": {
                "id": f"snyk:lic:npm:react:MIT",
                "title": "MIT license",
                "severity": "medium",
                "license": "MIT",
                "description": "MIT licensed package — review if compliant with your open source policy.",
            },
        },
        0.30,
    ),
    "critical_log4shell": (
        {
            "issueType": "vuln",
            "pkgName": "log4j-core",
            "pkgVersions": ["2.14.1"],
            "issueData": {
                "id": "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720",
                "title": "Remote Code Execution (RCE)",
                "severity": "critical",
                "cvssScore": 10.0,
                "description": "Affected versions of this package are vulnerable to Remote Code Execution (RCE) via the LDAP JNDI parser.",
                "cve": "CVE-2021-44228",
                "cwe": ["CWE-917"],
                "fixedIn": ["2.15.0"],
                "isPatchable": False,
                "isUpgradable": True,
                "language": "java",
            },
        },
        0.20,
    ),
    "low_informational": (
        {
            "issueType": "vuln",
            "pkgName": "express",
            "pkgVersions": ["4.17.1"],
            "issueData": {
                "id": "SNYK-JS-EXPRESS-2963889",
                "title": "Information Exposure",
                "severity": "low",
                "cvssScore": 3.1,
                "description": "Information exposure through sent data.",
                "cve": "CVE-2022-24999",
                "cwe": ["CWE-209"],
                "fixedIn": ["4.18.2"],
                "isPatchable": False,
                "isUpgradable": True,
                "language": "js",
            },
        },
        0.10,
    ),
}


def _generate_issue() -> dict[str, Any]:
    template = weighted_choice(_ISSUE_TEMPLATES)
    project = random.choice(_PROJECTS)
    org = random.choice(_ORGS)
    issue_id = generate_uuid()

    return {
        "id": issue_id,
        "url": f"https://snyk.io/vuln/{template['issueData']['id']}",
        "title": template["issueData"]["title"],
        "type": template["issueType"],
        "package": template["pkgName"],
        "version": random.choice(template["pkgVersions"]),
        "severity": template["issueData"]["severity"],
        "language": template["issueData"].get("language", "unknown"),
        "packageManager": "npm",
        "priorityScore": random.randint(400, 1000),
        "priority": {"score": random.randint(400, 1000), "factors": []},
        "issueData": template["issueData"],
        "isPatched": False,
        "isIgnored": False,
        "fixInfo": {
            "isPatchable": template["issueData"].get("isPatchable", False),
            "isUpgradable": template["issueData"].get("isUpgradable", False),
            "nearestFixedInVersion": random.choice(template["issueData"].get("fixedIn", [""])),
        },
        "links": {"paths": f"https://app.snyk.io/org/{org}/project/{project}"},
        "introducedDate": now_iso(),
        "project": {
            "id": generate_uuid(),
            "name": project,
        },
    }


def get_issues_response(org: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    count = min(limit, 100)
    issues = [_generate_issue() for _ in range(count)]
    # Real Snyk v1 /org/{id}/issues returns the array under 'issues'. Some
    # internal Snyk endpoints and older docs use 'results'. We expose both
    # keys to keep every parser happy.
    return {
        "issues": issues,
        "results": issues,
        "total": count + random.randint(0, 200),
        "limit": limit,
        "offset": offset,
    }


def get_issues_response_jsonapi(
    org: str | None = None, limit: int = 100, starting_after: str | None = None
) -> dict[str, Any]:
    """Snyk REST API (JSON:API) shape for /rest/orgs/{id}/issues.

    Observo's Snyk source calls the newer REST API rather than v1. The shape
    is JSON:API: a top-level 'data' array of resource objects, each with
    'id', 'type', and 'attributes'. 'No issue data found in Snyk response'
    happens when the parser doesn't see this 'data' key.
    """
    count = min(limit, 100)
    raw = [_generate_issue() for _ in range(count)]
    data = []
    for issue in raw:
        sev = issue["severity"]
        data.append({
            "id": issue["id"],
            "type": "issue",
            "attributes": {
                "key": issue["issueData"]["id"],
                "title": issue["title"],
                "type": "package_vulnerability" if issue["type"] == "vuln" else "license",
                "status": "open",
                "effective_severity_level": sev,
                "ignored": issue["isIgnored"],
                "created_at": issue["introducedDate"],
                "updated_at": issue["introducedDate"],
                "coordinates": [{
                    "remedies": [],
                    "representations": [{
                        "dependency": {
                            "package_name": issue["package"],
                            "package_version": issue["version"],
                        }
                    }],
                }],
                "problems": [{
                    "id": issue["issueData"]["id"],
                    "source": "SNYK",
                    "type": "vulnerability",
                    "url": issue["url"],
                }],
                "risk": {"score": {"value": issue["priorityScore"]}},
            },
            "relationships": {
                "organization": {"data": {"id": generate_uuid(), "type": "organization"}},
                "scan_item": {"data": {"id": issue["project"]["id"], "type": "project"}},
            },
        })
    return {
        "jsonapi": {"version": "1.0"},
        "data": data,
        "links": {
            "self": f"/rest/orgs/{org or 'my-org'}/issues",
        },
    }


def get_projects_response(org: str | None = None) -> dict[str, Any]:
    projects = []
    for project_name in _PROJECTS:
        projects.append(
            {
                "id": generate_uuid(),
                "name": project_name,
                "created": now_iso(),
                "origin": random.choice(["github", "gitlab", "cli"]),
                "type": random.choice(["npm", "maven", "pip", "rubygems"]),
                "readOnly": False,
                "testFrequency": "daily",
                "totalDependencies": random.randint(50, 500),
                "issueCountsBySeverity": {
                    "low": random.randint(0, 20),
                    "medium": random.randint(0, 15),
                    "high": random.randint(0, 10),
                    "critical": random.randint(0, 3),
                },
                "remoteRepoUrl": f"https://github.com/example/{project_name}.git",
                "lastTestedDate": now_iso(),
                "isMonitored": True,
                "tags": [],
            }
        )
    return {"org": {"id": generate_uuid(), "name": org or random.choice(_ORGS)}, "projects": projects}


def get_audit_logs_response(org: str | None = None, limit: int = 100, page: int = 1) -> list[dict[str, Any]]:
    count = min(limit, 100)
    events = []
    actions = [
        ("api.scan", "API scan initiated"),
        ("project.import", "Project imported from SCM"),
        ("user.invite", "User invited to org"),
        ("project.settings.update", "Project settings updated"),
        ("org.policy.update", "Organization policy updated"),
    ]
    for _ in range(count):
        action, description = random.choice(actions)
        events.append(
            {
                "groupId": generate_uuid(),
                "orgId": generate_uuid(),
                "userId": generate_uuid(),
                "projectId": generate_uuid(),
                "event": action,
                "content": {"description": description},
                "created": now_iso(),
            }
        )
    return events
