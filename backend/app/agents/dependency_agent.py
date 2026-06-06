"""Dependency analysis agent - CVE checking, license compliance, outdated packages."""

import re
from typing import Any, Dict, List

import httpx
import structlog
from langchain.tools import StructuredTool
from pydantic import BaseModel, Field

from app.config import settings

logger = structlog.get_logger(__name__)


# ─── Input schemas ────────────────────────────────────────────────────────────


class DepsInput(BaseModel):
    diff_content: str = Field(description="Git diff content to parse for dependency changes")


class CVEInput(BaseModel):
    package: str = Field(description="Package name")
    version: str = Field(description="Package version")
    ecosystem: str = Field(description="Ecosystem: PyPI, npm, Go, Maven, etc")


class LicenseInput(BaseModel):
    deps: str = Field(description="JSON string of dependencies list [{name, version, license}]")


class OutdatedInput(BaseModel):
    deps: str = Field(description="JSON string of deps [{name, version}]")
    ecosystem: str = Field(description="Package ecosystem: PyPI, npm, etc")


# ─── Tool implementations ────────────────────────────────────────────────────


def parse_dependency_files(diff_content: str) -> Dict[str, Any]:
    """Parse dependency files changed in the diff."""
    deps = []
    current_file = None

    for line in diff_content.split("\n"):
        if line.startswith("diff --git") or line.startswith("+++ b/"):
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()

        if not line.startswith("+") or line.startswith("+++"):
            continue

        content = line[1:].strip()

        # requirements.txt format: package==1.2.3 or package>=1.2.3
        if current_file and ("requirements" in current_file or current_file.endswith(".txt")):
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([><=!]+)\s*([0-9][^\s;#]*)", content)
            if match:
                deps.append({
                    "name": match.group(1),
                    "operator": match.group(2),
                    "version": match.group(3).split(",")[0],
                    "ecosystem": "PyPI",
                    "file": current_file,
                })

        # package.json format
        elif current_file and "package.json" in current_file:
            match = re.match(r'"([a-zA-Z0-9_\-@/\.]+)":\s*"[\^~]?([0-9][^"]*)"', content)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(2),
                    "ecosystem": "npm",
                    "file": current_file,
                })

        # go.mod format
        elif current_file and "go.mod" in current_file:
            match = re.match(r"require\s+([^\s]+)\s+v([0-9][^\s]*)", content)
            if not match:
                match = re.match(r"\s+([^\s]+)\s+v([0-9][^\s]*)", content)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(2),
                    "ecosystem": "Go",
                    "file": current_file,
                })

        # Pipfile format
        elif current_file and "Pipfile" in current_file:
            match = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(2).replace("*", "latest"),
                    "ecosystem": "PyPI",
                    "file": current_file,
                })

    return {"dependencies": deps, "count": len(deps)}


async def check_cve_database(package: str, version: str, ecosystem: str) -> Dict[str, Any]:
    """Query OSV.dev for CVEs affecting a package version."""
    url = f"{settings.OSV_API_URL}/query"
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                return {
                    "package": package,
                    "version": version,
                    "vulnerabilities": [
                        {
                            "id": v.get("id"),
                            "summary": v.get("summary", ""),
                            "severity": _map_osv_severity(v),
                            "aliases": v.get("aliases", []),
                            "published": v.get("published", ""),
                            "modified": v.get("modified", ""),
                        }
                        for v in vulns
                    ],
                    "vulnerable": len(vulns) > 0,
                }
            else:
                return {"package": package, "version": version, "error": f"OSV API error: {response.status_code}", "vulnerable": False}
    except Exception as exc:
        logger.warning("cve_check.failed", package=package, error=str(exc))
        return {"package": package, "version": version, "error": str(exc), "vulnerable": False}


def _map_osv_severity(vuln: Dict[str, Any]) -> str:
    """Map OSV severity to our severity scale."""
    severity_data = vuln.get("severity", [])
    if not severity_data:
        return "unknown"
    for s in severity_data:
        score_type = s.get("type", "")
        score = s.get("score", "")
        if "CVSS" in score_type:
            try:
                # CVSS v3 score text like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                # Extract base score from ranges
                if "9" in score[:3] or "10" in score[:4]:
                    return "critical"
                elif "7" in score[:3] or "8" in score[:3]:
                    return "high"
                elif "4" in score[:3] or "5" in score[:3] or "6" in score[:3]:
                    return "medium"
                else:
                    return "low"
            except Exception:
                pass
    return "medium"


KNOWN_LICENSE_CONFLICTS = {
    "GPL-2.0": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"],
    "GPL-3.0": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"],
    "AGPL-3.0": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "GPL-2.0", "GPL-3.0"],
    "LGPL-2.1": [],
    "LGPL-3.0": [],
}

RESTRICTIVE_LICENSES = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0", "Commons Clause"]


def check_license_compatibility(deps: str) -> Dict[str, Any]:
    """Check license compatibility across dependencies."""
    import json

    try:
        dep_list = json.loads(deps)
    except Exception:
        return {"error": "Invalid JSON", "issues": []}

    issues = []
    restrictive_found = []

    for dep in dep_list:
        license_id = dep.get("license", "Unknown")
        name = dep.get("name", "unknown")

        if license_id in RESTRICTIVE_LICENSES:
            restrictive_found.append({"package": name, "license": license_id})
            issues.append({
                "package": name,
                "license": license_id,
                "issue": f"{license_id} is a restrictive copyleft license",
                "severity": "high" if "AGPL" in license_id else "medium",
            })

        if license_id == "Unknown":
            issues.append({
                "package": name,
                "license": license_id,
                "issue": "License unknown - manual review required",
                "severity": "low",
            })

    return {
        "total_deps": len(dep_list),
        "restrictive_licenses": restrictive_found,
        "issues": issues,
        "has_issues": len(issues) > 0,
    }


def find_outdated_packages(deps: str, ecosystem: str) -> Dict[str, Any]:
    """Identify packages that appear significantly outdated based on version patterns."""
    import json

    try:
        dep_list = json.loads(deps)
    except Exception:
        return {"error": "Invalid JSON", "outdated": []}

    outdated = []
    for dep in dep_list:
        version = dep.get("version", "0.0.0")
        name = dep.get("name", "unknown")

        # Heuristic: very old major versions are suspicious
        try:
            major = int(version.split(".")[0])
            if major == 0:
                outdated.append({
                    "package": name,
                    "version": version,
                    "reason": "Pre-1.0 version - may be unstable",
                    "severity": "low",
                })
        except (ValueError, IndexError):
            pass

    return {"outdated_candidates": outdated, "ecosystem": ecosystem}


# ─── LangChain tools ─────────────────────────────────────────────────────────

DEPENDENCY_TOOLS = [
    StructuredTool(
        name="parse_dependency_files",
        description="Parse dependency files in the diff to extract package names and versions",
        func=parse_dependency_files,
        args_schema=DepsInput,
    ),
    StructuredTool(
        name="check_license_compatibility",
        description="Check license compatibility for a list of dependencies",
        func=check_license_compatibility,
        args_schema=LicenseInput,
    ),
    StructuredTool(
        name="find_outdated_packages",
        description="Find potentially outdated packages based on version heuristics",
        func=find_outdated_packages,
        args_schema=OutdatedInput,
    ),
]


async def run_dependency_agent(
    pr_data: Dict[str, Any],
    diff_content: str,
) -> List[Dict[str, Any]]:
    """Run dependency analysis and return findings."""
    pr_id = str(pr_data.get("pr_id", ""))
    findings = []

    # Parse deps from diff
    dep_result = parse_dependency_files(diff_content)
    deps = dep_result.get("dependencies", [])

    if not deps:
        logger.info("dependency_agent.no_deps_found", pr_id=pr_id)
        return []

    logger.info("dependency_agent.found_deps", count=len(deps), pr_id=pr_id)

    # Check CVEs for each dependency
    for dep in deps[:20]:  # Limit to avoid rate limiting
        cve_result = await check_cve_database(
            dep["name"], dep["version"], dep.get("ecosystem", "PyPI")
        )

        if cve_result.get("vulnerable"):
            for vuln in cve_result.get("vulnerabilities", []):
                findings.append({
                    "severity": vuln.get("severity", "high"),
                    "category": "dependency",
                    "agent_type": "dependency",
                    "title": f"CVE in {dep['name']} {dep['version']}: {vuln.get('id', 'Unknown')}",
                    "description": (
                        f"Package {dep['name']} version {dep['version']} has a known vulnerability: "
                        f"{vuln.get('summary', 'No summary available')}. "
                        f"CVE ID: {vuln.get('id')}. Aliases: {', '.join(vuln.get('aliases', []))}"
                    ),
                    "file_path": dep.get("file", "requirements.txt"),
                    "line_start": None,
                    "line_end": None,
                    "code_snippet": f"{dep['name']}=={dep['version']}",
                    "suggestion": f"Upgrade {dep['name']} to a version that patches {vuln.get('id')}",
                    "confidence_score": 0.95,
                    "pr_id": pr_id,
                })

    # Check for outdated patterns
    import json
    outdated = find_outdated_packages(json.dumps(deps), "mixed")
    for pkg in outdated.get("outdated_candidates", []):
        findings.append({
            "severity": pkg["severity"],
            "category": "dependency",
            "agent_type": "dependency",
            "title": f"Potentially outdated: {pkg['package']} {pkg['version']}",
            "description": pkg["reason"],
            "file_path": "dependency file",
            "line_start": None,
            "line_end": None,
            "code_snippet": f"{pkg['package']}=={pkg['version']}",
            "suggestion": "Consider upgrading to the latest stable version",
            "confidence_score": 0.6,
            "pr_id": pr_id,
        })

    logger.info("dependency_agent.complete", findings_count=len(findings), pr_id=pr_id)
    return findings
