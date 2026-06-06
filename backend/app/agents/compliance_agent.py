"""Compliance agent: GDPR, SOC2 CC controls."""

import re
from typing import Any, Dict, List

import structlog
from langchain.tools import StructuredTool
from pydantic import BaseModel, Field

from app.config import settings

logger = structlog.get_logger(__name__)


class CodeInput(BaseModel):
    code: str = Field(description="Source code to analyze for compliance issues")


# ─── SOC2 CC Control mapping ─────────────────────────────────────────────────

SOC2_CONTROLS = {
    "CC6.1": "Logical and Physical Access Controls",
    "CC6.2": "New Data Subjects Access",
    "CC6.3": "Role-Based Access",
    "CC6.7": "Transmission of Confidential Information",
    "CC7.1": "System Monitoring",
    "CC7.2": "Security Event Monitoring",
    "CC8.1": "Change Management",
    "CC9.1": "Risk Mitigation",
    "A1.1": "Availability Commitments",
    "PI1.1": "Processing Integrity",
}

# ─── GDPR PII patterns ────────────────────────────────────────────────────────

PII_FIELDS = [
    "email", "phone", "address", "ssn", "social_security", "passport",
    "credit_card", "date_of_birth", "dob", "first_name", "last_name",
    "full_name", "ip_address", "user_id", "username", "national_id",
    "tax_id", "bank_account", "health_record", "medical",
]


def check_gdpr_patterns(code: str) -> Dict[str, Any]:
    """Check for GDPR compliance issues: PII logging, missing consent checks."""
    issues = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        line_lower = line.lower()

        # Check for PII in log statements
        is_log_statement = any(
            kw in line_lower for kw in ["logger.", "logging.", "log.", "print(", "console.log"]
        )
        if is_log_statement:
            for pii_field in PII_FIELDS:
                if pii_field in line_lower:
                    issues.append({
                        "line": i,
                        "type": "pii_logging",
                        "severity": "high",
                        "field": pii_field,
                        "code": line.strip(),
                        "description": f"PII field '{pii_field}' may be logged in plain text",
                        "gdpr_article": "Article 5(1)(f) - Data integrity and confidentiality",
                        "soc2_control": "CC6.7",
                        "suggestion": "Redact or mask PII before logging. Use structured logging with field-level masking.",
                    })

        # Check for data stored without encryption indicators
        for pii_field in PII_FIELDS:
            if f"store_{pii_field}" in line_lower or f"save_{pii_field}" in line_lower:
                if "encrypt" not in line_lower and "hash" not in line_lower:
                    issues.append({
                        "line": i,
                        "type": "unencrypted_pii_storage",
                        "severity": "high",
                        "field": pii_field,
                        "code": line.strip(),
                        "description": f"PII '{pii_field}' may be stored without encryption",
                        "gdpr_article": "Article 32 - Security of processing",
                        "soc2_control": "CC6.1",
                        "suggestion": "Encrypt PII at rest using AES-256 or equivalent",
                    })

        # Check for missing consent checks on data processing
        if any(f in line_lower for f in ["user_data", "personal_data", "process_data"]):
            if "consent" not in line_lower and "gdpr" not in line_lower:
                issues.append({
                    "line": i,
                    "type": "missing_consent_check",
                    "severity": "medium",
                    "code": line.strip(),
                    "description": "Data processing operation without visible consent verification",
                    "gdpr_article": "Article 6 - Lawfulness of processing",
                    "soc2_control": "PI1.1",
                    "suggestion": "Add explicit consent check before processing personal data",
                })

        # Check for data transfer patterns
        if re.search(r"requests\.(post|put|patch)\s*\(.*(?:user|person|customer)", line_lower):
            issues.append({
                "line": i,
                "type": "data_transfer",
                "severity": "medium",
                "code": line.strip(),
                "description": "Data transfer to external service may require GDPR Data Processing Agreement",
                "gdpr_article": "Article 28 - Processor",
                "soc2_control": "CC9.1",
                "suggestion": "Ensure DPA exists with external processor and data minimization is applied",
            })

    return {"gdpr_issues": issues, "count": len(issues)}


def check_soc2_controls(code: str) -> Dict[str, Any]:
    """Check for SOC2 CC control violations."""
    violations = []
    lines = code.split("\n")

    # CC6.1 - Access Controls
    access_patterns = [
        (r"if\s+True\s*:", "Hardcoded True condition bypasses access control", "CC6.1", "critical"),
        (r"skip_auth\s*=\s*True|bypass_auth\s*=\s*True", "Auth bypass flag", "CC6.1", "critical"),
        (r"superuser\s*=\s*True.*hardcoded|is_staff\s*=\s*True.*hardcoded",
         "Hardcoded privilege escalation", "CC6.3", "high"),
    ]

    # CC7.1 - System Monitoring (missing logging)
    monitoring_patterns = [
        (r"def\s+(?:login|authenticate|logout|delete|update_role)\s*\(",
         "Critical operation may lack audit logging", "CC7.2", "medium"),
    ]

    # CC8.1 - Change Management
    change_patterns = [
        (r"alter\s+table\s+\w+\s+drop\s+column|DROP\s+TABLE",
         "Destructive DDL operation without migration safety", "CC8.1", "high"),
    ]

    all_patterns = access_patterns + monitoring_patterns + change_patterns

    for i, line in enumerate(lines, 1):
        for pattern, description, control_id, severity in all_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                violations.append({
                    "line": i,
                    "control_id": control_id,
                    "control_name": SOC2_CONTROLS.get(control_id, "Unknown"),
                    "severity": severity,
                    "description": description,
                    "code": line.strip(),
                    "suggestion": f"Review {control_id}: {SOC2_CONTROLS.get(control_id)} requirements",
                })

    # Check for missing audit logging in sensitive operations
    sensitive_ops = ["delete", "update_user", "change_role", "reset_password", "transfer"]
    for i, line in enumerate(lines, 1):
        for op in sensitive_ops:
            if re.search(rf"def\s+{op}\s*\(", line, re.IGNORECASE):
                # Look in surrounding lines for logging
                context = "\n".join(lines[max(0, i):min(len(lines), i + 10)])
                if not any(kw in context.lower() for kw in ["logger.", "logging.", "audit_log"]):
                    violations.append({
                        "line": i,
                        "control_id": "CC7.2",
                        "control_name": SOC2_CONTROLS["CC7.2"],
                        "severity": "medium",
                        "description": f"Sensitive operation '{op}' may lack audit logging",
                        "code": line.strip(),
                        "suggestion": "Add audit log entry recording who performed this action and when",
                    })

    return {"soc2_violations": violations, "count": len(violations)}


def check_data_retention(code: str) -> Dict[str, Any]:
    """Check for data retention policy issues."""
    issues = []
    lines = code.split("\n")

    retention_patterns = [
        (r"created_at.*datetime\.now\(\)", "Data stored without retention timestamp - add expires_at"),
        (r"store.*forever|keep.*permanently|never.*delete", "Data may be stored indefinitely"),
        (r"SELECT \* FROM.*(?:users|customers|patients)", "Broad data fetch without date range filter"),
    ]

    for i, line in enumerate(lines, 1):
        for pattern, description in retention_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append({
                    "line": i,
                    "description": description,
                    "severity": "low",
                    "code": line.strip(),
                    "gdpr_article": "Article 5(1)(e) - Storage limitation",
                    "suggestion": "Implement data retention policy with automatic deletion after defined period",
                })

    return {"retention_issues": issues, "count": len(issues)}


def check_audit_logging(code: str) -> Dict[str, Any]:
    """Check for missing audit logging in critical operations."""
    missing_audit_logs = []
    lines = code.split("\n")

    critical_functions = [
        "login", "logout", "register", "delete_user", "update_permissions",
        "change_password", "reset_password", "transfer", "payment", "refund",
        "admin", "approve", "reject",
    ]

    for i, line in enumerate(lines, 1):
        for func_name in critical_functions:
            if re.search(rf"def\s+{func_name}\s*\(", line, re.IGNORECASE):
                # Check next 15 lines for audit log
                context_end = min(len(lines), i + 15)
                context = "\n".join(lines[i:context_end])
                if not any(kw in context.lower() for kw in
                           ["audit", "logger", "logging.info", "log_event", "track"]):
                    missing_audit_logs.append({
                        "line": i,
                        "function": func_name,
                        "severity": "medium",
                        "code": line.strip(),
                        "soc2_control": "CC7.2",
                        "description": f"Function '{func_name}' lacks audit logging",
                        "suggestion": "Add structured audit log entry with user, action, timestamp, and result",
                    })

    return {"missing_audit_logs": missing_audit_logs, "count": len(missing_audit_logs)}


COMPLIANCE_TOOLS = [
    StructuredTool(
        name="check_gdpr_patterns",
        description="Check for GDPR violations: PII logging, missing consent, unencrypted storage",
        func=check_gdpr_patterns,
        args_schema=CodeInput,
    ),
    StructuredTool(
        name="check_soc2_controls",
        description="Check for SOC2 CC control violations in code",
        func=check_soc2_controls,
        args_schema=CodeInput,
    ),
    StructuredTool(
        name="check_data_retention",
        description="Check for data retention policy compliance issues",
        func=check_data_retention,
        args_schema=CodeInput,
    ),
    StructuredTool(
        name="check_audit_logging",
        description="Check for missing audit logging in critical operations",
        func=check_audit_logging,
        args_schema=CodeInput,
    ),
]


async def run_compliance_agent(
    pr_data: Dict[str, Any],
    diff_content: str,
) -> List[Dict[str, Any]]:
    """Run compliance checks and return structured findings."""
    pr_id = str(pr_data.get("pr_id", ""))
    findings = []

    # Extract added code lines from diff
    added_code = "\n".join(
        line[1:] for line in diff_content.split("\n")
        if line.startswith("+") and not line.startswith("+++")
    )

    if not added_code.strip():
        return []

    # Run all compliance checks
    gdpr_result = check_gdpr_patterns(added_code)
    for issue in gdpr_result.get("gdpr_issues", []):
        findings.append({
            "severity": issue["severity"],
            "category": "compliance",
            "agent_type": "compliance",
            "title": f"GDPR: {issue.get('description', 'Compliance issue')}",
            "description": (
                f"{issue['description']}. "
                f"GDPR {issue.get('gdpr_article', '')}. "
                f"SOC2 Control: {issue.get('soc2_control', '')}"
            ),
            "file_path": "unknown",
            "line_start": issue.get("line"),
            "line_end": issue.get("line"),
            "code_snippet": issue.get("code", ""),
            "suggestion": issue.get("suggestion", ""),
            "confidence_score": 0.75,
            "owasp_category": None,
            "pr_id": pr_id,
        })

    soc2_result = check_soc2_controls(added_code)
    for violation in soc2_result.get("soc2_violations", []):
        findings.append({
            "severity": violation["severity"],
            "category": "compliance",
            "agent_type": "compliance",
            "title": f"SOC2 {violation['control_id']}: {violation['description']}",
            "description": (
                f"SOC2 Control {violation['control_id']} ({violation['control_name']}): "
                f"{violation['description']}"
            ),
            "file_path": "unknown",
            "line_start": violation.get("line"),
            "line_end": violation.get("line"),
            "code_snippet": violation.get("code", ""),
            "suggestion": violation.get("suggestion", ""),
            "confidence_score": 0.7,
            "pr_id": pr_id,
        })

    audit_result = check_audit_logging(added_code)
    for item in audit_result.get("missing_audit_logs", []):
        findings.append({
            "severity": item["severity"],
            "category": "compliance",
            "agent_type": "compliance",
            "title": f"Missing Audit Log: {item['function']}",
            "description": item["description"],
            "file_path": "unknown",
            "line_start": item.get("line"),
            "line_end": item.get("line"),
            "code_snippet": item.get("code", ""),
            "suggestion": item.get("suggestion", ""),
            "confidence_score": 0.65,
            "pr_id": pr_id,
        })

    logger.info("compliance_agent.complete", findings_count=len(findings), pr_id=pr_id)
    return findings
