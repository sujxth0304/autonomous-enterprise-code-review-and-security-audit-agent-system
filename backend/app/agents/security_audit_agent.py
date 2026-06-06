"""Security audit agent covering OWASP Top 10."""

import re
from typing import Any, Dict, List

import structlog
from langchain.agents import AgentExecutor, create_react_agent
from langchain.prompts import PromptTemplate
from langchain.tools import StructuredTool
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel, Field

from app.config import settings

logger = structlog.get_logger(__name__)


# ─── Input schemas ────────────────────────────────────────────────────────────


class CodeChunkInput(BaseModel):
    code: str = Field(description="Code chunk to analyze for security vulnerabilities")


class DiffInput(BaseModel):
    diff: str = Field(description="Git diff content to scan for exposed secrets")


class AuthInput(BaseModel):
    code: str = Field(description="Code to analyze for authentication/authorization patterns")


class InjectionInput(BaseModel):
    code: str = Field(description="Code to analyze for injection vulnerabilities")


class CryptoInput(BaseModel):
    code: str = Field(description="Code to analyze for cryptographic usage issues")


# ─── OWASP Tool implementations ──────────────────────────────────────────────


def check_owasp_top10(code: str) -> Dict[str, Any]:
    """Check code for OWASP Top 10 2021 vulnerabilities."""
    findings = []

    owasp_checks = {
        "A01:2021-Broken Access Control": [
            (r"is_admin\s*=\s*True", "Hardcoded admin privilege escalation"),
            (r"role\s*=\s*['\"]admin['\"]", "Hardcoded admin role assignment"),
            (r"\.all\(\).*filter.*user", "Potential IDOR - missing user ownership filter"),
            (r"request\.user.*or.*None", "Auth bypass pattern"),
        ],
        "A02:2021-Cryptographic Failures": [
            (r"DES\b|3DES\b|RC4\b|MD2\b", "Broken encryption algorithm"),
            (r"key\s*=\s*['\"][a-zA-Z0-9]{1,16}['\"]", "Hardcoded short encryption key"),
            (r"ssl_verify\s*=\s*False|verify\s*=\s*False", "SSL certificate verification disabled"),
            (r"http://(?!localhost)", "Non-TLS HTTP connection in code"),
        ],
        "A03:2021-Injection": [
            (r"f['\"].*SELECT.*WHERE.*{", "SQL injection via f-string"),
            (r"['\"]SELECT.*['\"] \+\s*\w", "SQL injection via concatenation"),
            (r"cursor\.execute\s*\([^)]*%[^)]*\)", "SQL injection via % formatting"),
            (r"\.raw\s*\(.*\+", "Raw SQL with string concatenation"),
            (r"shell\s*=\s*True", "Command injection via shell=True"),
        ],
        "A04:2021-Insecure Design": [
            (r"TODO.*security|FIXME.*auth|HACK.*login", "Security TODO left in code"),
        ],
        "A05:2021-Security Misconfiguration": [
            (r"DEBUG\s*=\s*True", "Debug mode enabled in production code"),
            (r"SECRET_KEY\s*=\s*['\"][^'\"]{1,20}['\"]", "Short/weak secret key"),
            (r"ALLOWED_HOSTS\s*=\s*\[?\s*['\*]\s*", "Wildcard ALLOWED_HOSTS"),
            (r"CORS_ORIGIN_ALLOW_ALL\s*=\s*True", "CORS allows all origins"),
        ],
        "A06:2021-Vulnerable and Outdated Components": [],  # Handled by dependency agent
        "A07:2021-Identification and Authentication Failures": [
            (r"password\s*==\s*['\"][^'\"]+['\"]", "Hardcoded password comparison"),
            (r"token\s*=\s*['\"][a-zA-Z0-9]{10,}['\"]", "Hardcoded token"),
            (r"remember_me.*lifetime.*days.*3[0-9]{2,}", "Excessive session lifetime"),
        ],
        "A08:2021-Software and Data Integrity Failures": [
            (r"pickle\.loads?\s*\(", "Unsafe deserialization with pickle"),
            (r"yaml\.load\s*\([^,)]*\)", "Unsafe YAML load without Loader"),
            (r"marshal\.loads?\s*\(", "Unsafe marshal deserialization"),
        ],
        "A09:2021-Security Logging and Monitoring Failures": [
            (r"except.*pass", "Exception silently swallowed - no logging"),
            (r"except.*:\s*\n\s*pass", "Exception handler with just pass"),
        ],
        "A10:2021-Server-Side Request Forgery": [
            (r"requests\.get\s*\(\s*\w+\s*\)", "Unvalidated URL in HTTP request - potential SSRF"),
            (r"urllib\.request\.urlopen\s*\(\s*\w+", "Unvalidated URL fetch - potential SSRF"),
        ],
    }

    for owasp_id, patterns in owasp_checks.items():
        for pattern, description in patterns:
            for i, line in enumerate(code.split("\n"), 1):
                if re.search(pattern, line):
                    findings.append({
                        "owasp": owasp_id,
                        "line": i,
                        "code": line.strip(),
                        "description": description,
                        "pattern": pattern,
                    })

    return {"findings": findings, "owasp_categories_hit": list({f["owasp"] for f in findings})}


def scan_for_secrets(diff: str) -> Dict[str, Any]:
    """Scan diff for accidentally exposed secrets and credentials."""
    findings = []

    secret_patterns = [
        (r"(?i)api[_-]?key\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
         "API Key", "critical"),
        (r"(?i)secret[_-]?key\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
         "Secret Key", "critical"),
        (r"(?i)password\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
         "Hardcoded Password", "critical"),
        (r"(?i)token\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]",
         "Access Token", "high"),
        (r"sk-[a-zA-Z0-9]{48}",
         "OpenAI API Key", "critical"),
        (r"sk-ant-api[a-zA-Z0-9_\-]{40,}",
         "Anthropic API Key", "critical"),
        (r"ghp_[a-zA-Z0-9]{36}",
         "GitHub Personal Access Token", "critical"),
        (r"(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*['\"]?([A-Z0-9]{20})['\"]?",
         "AWS Access Key ID", "critical"),
        (r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9/+]{40})['\"]?",
         "AWS Secret Access Key", "critical"),
        (r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
         "Private Key", "critical"),
        (r"(?i)database[_-]?url\s*[:=]\s*['\"]?(postgres|mysql|mongodb)://[^'\"]+['\"]?",
         "Database URL with credentials", "high"),
        (r"(?i)jdbc:[a-z]+://[^@]+:[^@]+@",
         "JDBC connection string with password", "high"),
    ]

    for i, line in enumerate(diff.split("\n"), 1):
        if not line.startswith("+"):  # Only check added lines
            continue
        for pattern, secret_type, severity in secret_patterns:
            match = re.search(pattern, line)
            if match:
                # Check if it's likely a placeholder
                matched_value = match.group(0)
                if any(placeholder in matched_value.lower()
                       for placeholder in ["your_", "example", "changeme", "placeholder",
                                           "xxx", "...", "redacted"]):
                    continue
                findings.append({
                    "line": i,
                    "secret_type": secret_type,
                    "severity": severity,
                    "code": line.strip()[:100] + "..." if len(line) > 100 else line.strip(),
                    "recommendation": f"Remove hardcoded {secret_type} and use environment variables",
                })

    return {"secrets_found": len(findings), "findings": findings}


def check_auth_patterns(code: str) -> Dict[str, Any]:
    """Analyze authentication and authorization patterns."""
    findings = []
    lines = code.split("\n")

    auth_issues = [
        (r"if\s+user\.is_authenticated\s*==\s*True", "Explicit True comparison is fragile"),
        (r"@app\.route.*methods.*['\"](PUT|DELETE|PATCH)['\"].*\n(?!.*@login_required)",
         "Mutable endpoint may lack authentication"),
        (r"JWT.*none.*algorithm|algorithm.*none", "JWT 'none' algorithm vulnerability"),
        (r"\.decode\(.*verify\s*=\s*False", "JWT signature verification disabled"),
        (r"bcrypt\.checkpw|verify.*password.*plain", "Raw password comparison instead of hash"),
        (r"session\[.*\]\s*=\s*True.*admin", "Session-based admin escalation"),
        (r"@require.*admin.*@require.*login", "Decorator order may bypass auth"),
    ]

    for i, line in enumerate(lines, 1):
        for pattern, issue in auth_issues:
            if re.search(pattern, line):
                findings.append({
                    "line": i,
                    "issue": issue,
                    "code": line.strip(),
                    "severity": "high",
                })

    return {"auth_issues": findings, "count": len(findings)}


def check_injection_vectors(code: str) -> Dict[str, Any]:
    """Check for various injection vulnerabilities."""
    findings = []
    lines = code.split("\n")

    injection_patterns = [
        # SQL Injection
        (r"execute\s*\(\s*['\"]SELECT.*%s|execute\s*\(\s*f['\"]SELECT", "sql", "critical",
         "SQL Injection via string formatting"),
        # Command Injection
        (r"os\.system\s*\(.*\+|subprocess.*shell.*True.*\+", "command", "critical",
         "Command Injection via string concatenation"),
        # LDAP Injection
        (r"ldap.*search.*\+\s*\w|ldap.*filter.*f['\"]", "ldap", "high",
         "LDAP Injection risk"),
        # XPath Injection
        (r"xpath.*\+\s*\w|etree.*find.*\+", "xpath", "high",
         "XPath Injection risk"),
        # Template Injection
        (r"render_template_string\s*\(.*request\.|jinja2\.Template\s*\(.*request\.",
         "template", "critical", "Server-side Template Injection (SSTI)"),
        # NoSQL Injection
        (r"collection\.find\s*\(\s*\{[^}]*request\.", "nosql", "high",
         "NoSQL Injection via unsanitized input"),
        # Path Traversal
        (r"open\s*\(\s*.*request\.|open\s*\(\s*os\.path\.join.*request\.",
         "path_traversal", "high", "Path Traversal via user input"),
    ]

    for i, line in enumerate(lines, 1):
        for pattern, injection_type, severity, description in injection_patterns:
            if re.search(pattern, line):
                findings.append({
                    "line": i,
                    "injection_type": injection_type,
                    "severity": severity,
                    "description": description,
                    "code": line.strip(),
                })

    return {"injection_findings": findings, "types_found": list({f["injection_type"] for f in findings})}


def check_crypto_usage(code: str) -> Dict[str, Any]:
    """Analyze cryptographic usage for weaknesses."""
    findings = []
    lines = code.split("\n")

    crypto_checks = [
        (r"MD5|md5\s*\(|hashlib\.md5", "high", "MD5 is cryptographically broken", "CWE-327"),
        (r"SHA1|sha1\s*\(|hashlib\.sha1", "medium", "SHA-1 is weak for security purposes", "CWE-327"),
        (r"DES\b|3DES\b|Cipher\.DES|TripleDES", "critical", "DES/3DES is broken encryption", "CWE-327"),
        (r"RC4|ARC4|arcfour", "critical", "RC4 stream cipher is broken", "CWE-327"),
        (r"ECB\b|MODE_ECB", "high", "ECB mode leaks data patterns", "CWE-327"),
        (r"random\.(random|randint|choice|shuffle)", "medium",
         "random module is not cryptographically secure", "CWE-338"),
        (r"iv\s*=\s*b?['\"]?[0]{8,}", "high", "Zero/static IV weakens encryption", "CWE-330"),
        (r"key_size\s*=\s*[0-9]{1,3}[^0-9]|bits\s*=\s*[0-9]{1,3}[^0-9]", "medium",
         "Small key size may be insufficient", "CWE-326"),
    ]

    for i, line in enumerate(lines, 1):
        for pattern, severity, description, cwe in crypto_checks:
            if re.search(pattern, line):
                findings.append({
                    "line": i,
                    "severity": severity,
                    "description": description,
                    "cwe": cwe,
                    "code": line.strip(),
                })

    return {"crypto_findings": findings, "count": len(findings)}


# ─── LangChain tools ─────────────────────────────────────────────────────────

SECURITY_TOOLS = [
    StructuredTool(
        name="check_owasp_top10",
        description="Check code for OWASP Top 10 2021 security vulnerabilities",
        func=check_owasp_top10,
        args_schema=CodeChunkInput,
    ),
    StructuredTool(
        name="scan_for_secrets",
        description="Scan diff for accidentally exposed secrets, API keys, and credentials",
        func=scan_for_secrets,
        args_schema=DiffInput,
    ),
    StructuredTool(
        name="check_auth_patterns",
        description="Analyze authentication and authorization patterns for security issues",
        func=check_auth_patterns,
        args_schema=AuthInput,
    ),
    StructuredTool(
        name="check_injection_vectors",
        description="Check for SQL, command, template, and other injection vulnerabilities",
        func=check_injection_vectors,
        args_schema=InjectionInput,
    ),
    StructuredTool(
        name="check_crypto_usage",
        description="Analyze cryptographic usage for weak algorithms and poor key management",
        func=check_crypto_usage,
        args_schema=CryptoInput,
    ),
]

SECURITY_PROMPT = PromptTemplate.from_template("""You are a senior security engineer performing a security audit on a GitHub Pull Request.

Your task is to identify security vulnerabilities covering OWASP Top 10 2021:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection (SQL, Command, LDAP, XSS, SSTI)
- A04: Insecure Design
- A05: Security Misconfiguration
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery (SSRF)

PR Information:
- Repository: {repo}
- PR Number: {pr_number}

Diff Content:
{diff_content}

Use the tools systematically:
1. First scan for secrets in the diff
2. Check OWASP Top 10 patterns in added code
3. Analyze auth patterns
4. Check injection vectors
5. Review crypto usage

For each finding output a JSON object:
{{
  "severity": "critical|high|medium|low|info",
  "category": "security",
  "owasp_category": "A01:2021-...",
  "cwe_id": "CWE-XXX",
  "title": "Short title",
  "description": "Detailed explanation of the vulnerability",
  "file_path": "path/to/file.py",
  "line_start": 42,
  "line_end": 42,
  "code_snippet": "vulnerable code",
  "suggestion": "How to remediate",
  "confidence_score": 0.9
}}

{agent_scratchpad}

Tools: {tools}
Tool names: {tool_names}""")


async def run_security_audit_agent(
    pr_data: Dict[str, Any],
    diff_content: str,
) -> List[Dict[str, Any]]:
    """Run the security audit agent and return structured findings."""

    if not settings.GEMINI_API_KEY:
        logger.warning("security_audit.no_api_key_using_heuristics")
        return _heuristic_security_scan(pr_data, diff_content)

    try:
        llm = ChatGoogleGenerativeAI(
            model=settings.GEMINI_MODEL,
            temperature=0,
            google_api_key=settings.GEMINI_API_KEY,
        )

        agent = create_react_agent(llm, SECURITY_TOOLS, SECURITY_PROMPT)
        executor = AgentExecutor(
            agent=agent,
            tools=SECURITY_TOOLS,
            max_iterations=settings.MAX_AGENT_STEPS,
            verbose=False,
            handle_parsing_errors=True,
        )

        result = await executor.ainvoke({
            "repo": pr_data.get("repo_full_name", "unknown"),
            "pr_number": pr_data.get("pr_number", 0),
            "diff_content": diff_content[:10000],
        })

        from app.agents.static_analysis_agent import _parse_agent_findings
        return _parse_agent_findings(result.get("output", ""), "security_audit", pr_data)

    except Exception as exc:
        logger.error("security_audit.agent_error", error=str(exc))
        return _heuristic_security_scan(pr_data, diff_content)


def _heuristic_security_scan(
    pr_data: Dict[str, Any], diff_content: str
) -> List[Dict[str, Any]]:
    """Fallback heuristic security scan."""
    findings = []
    pr_id = str(pr_data.get("pr_id", ""))

    # Run all tools on diff
    secrets_result = scan_for_secrets(diff_content)
    for secret in secrets_result.get("findings", []):
        findings.append({
            "severity": secret["severity"],
            "category": "security",
            "agent_type": "security_audit",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "title": f"Exposed {secret['secret_type']}",
            "description": f"Hardcoded {secret['secret_type']} found in diff at line {secret['line']}",
            "file_path": "unknown",
            "line_start": secret["line"],
            "line_end": secret["line"],
            "code_snippet": secret["code"],
            "suggestion": secret["recommendation"],
            "confidence_score": 0.95,
            "pr_id": pr_id,
        })

    added_code = "\n".join(
        line[1:] for line in diff_content.split("\n") if line.startswith("+")
    )

    owasp_result = check_owasp_top10(added_code)
    for finding in owasp_result.get("findings", []):
        findings.append({
            "severity": "high",
            "category": "security",
            "agent_type": "security_audit",
            "owasp_category": finding["owasp"],
            "title": finding["description"],
            "description": f"OWASP {finding['owasp']}: {finding['description']} at line {finding['line']}",
            "file_path": "unknown",
            "line_start": finding["line"],
            "line_end": finding["line"],
            "code_snippet": finding["code"],
            "suggestion": "Review and remediate per OWASP guidelines",
            "confidence_score": 0.8,
            "pr_id": pr_id,
        })

    crypto_result = check_crypto_usage(added_code)
    for finding in crypto_result.get("crypto_findings", []):
        findings.append({
            "severity": finding["severity"],
            "category": "security",
            "agent_type": "security_audit",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "cwe_id": finding["cwe"],
            "title": finding["description"],
            "description": finding["description"],
            "file_path": "unknown",
            "line_start": finding["line"],
            "line_end": finding["line"],
            "code_snippet": finding["code"],
            "suggestion": "Replace with modern, secure cryptographic algorithm",
            "confidence_score": 0.9,
            "pr_id": pr_id,
        })

    return findings
