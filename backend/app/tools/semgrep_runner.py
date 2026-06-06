"""Semgrep runner for automated static analysis."""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)


async def run_semgrep_scan(
    files: Dict[str, str],  # {filename: content}
    rules_path: str = "auto",
    timeout_seconds: int = 120,
) -> List[Dict[str, Any]]:
    """
    Run Semgrep static analysis on provided code files.

    Args:
        files: Dictionary mapping filenames to their content
        rules_path: Semgrep rules path or "auto" for default rules
        timeout_seconds: Maximum scan duration

    Returns:
        List of finding dictionaries
    """
    if not files:
        return []

    # Write files to temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        file_paths = []
        for filename, content in files.items():
            # Sanitize path to prevent path traversal
            safe_name = Path(filename).name
            file_path = os.path.join(tmpdir, safe_name)
            with open(file_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(content)
            file_paths.append(file_path)

        return await _execute_semgrep(tmpdir, rules_path, timeout_seconds)


async def _execute_semgrep(
    scan_dir: str,
    rules_path: str,
    timeout_seconds: int,
) -> List[Dict[str, Any]]:
    """Execute semgrep and parse results."""
    cmd = [
        "semgrep",
        "scan",
        "--json",
        "--quiet",
        "--no-rewrite-rule-ids",
    ]

    if rules_path == "auto":
        cmd.extend(["--config", "auto"])
    elif rules_path:
        cmd.extend(["--config", rules_path])
    else:
        cmd.extend(["--config", "p/security-audit", "--config", "p/python"])

    cmd.append(scan_dir)

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=scan_dir,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
        except asyncio.TimeoutError:
            process.kill()
            logger.warning("semgrep.timeout", timeout=timeout_seconds)
            return []

        if process.returncode not in (0, 1):  # 1 = findings found, 0 = clean
            logger.error("semgrep.error", returncode=process.returncode, stderr=stderr.decode()[:500])
            return []

        return _parse_semgrep_output(stdout.decode())

    except FileNotFoundError:
        logger.warning("semgrep.not_installed", hint="Install with: pip install semgrep")
        return []
    except Exception as exc:
        logger.error("semgrep.unexpected_error", error=str(exc))
        return []


def _parse_semgrep_output(output: str) -> List[Dict[str, Any]]:
    """Parse Semgrep JSON output into structured findings."""
    findings = []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.warning("semgrep.json_parse_error", output=output[:200])
        return []

    results = data.get("results", [])

    for result in results:
        severity_map = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "info",
            "CRITICAL": "critical",
        }

        semgrep_severity = result.get("extra", {}).get("severity", "WARNING").upper()
        severity = severity_map.get(semgrep_severity, "medium")

        # Override with metadata severity if available
        metadata = result.get("extra", {}).get("metadata", {})
        if metadata.get("severity"):
            severity = metadata["severity"].lower()

        finding = {
            "rule_id": result.get("check_id", "unknown"),
            "severity": severity,
            "category": "static_analysis",
            "agent_type": "static_analysis",
            "title": result.get("extra", {}).get("message", "Semgrep finding"),
            "description": (
                result.get("extra", {}).get("message", "")
                + ("\n\nReference: " + metadata.get("references", [""])[0]
                   if metadata.get("references") else "")
            ),
            "file_path": result.get("path", ""),
            "line_start": result.get("start", {}).get("line"),
            "line_end": result.get("end", {}).get("line"),
            "code_snippet": result.get("extra", {}).get("lines", ""),
            "suggestion": metadata.get("fix", "See Semgrep rule for remediation"),
            "confidence_score": _map_semgrep_confidence(metadata.get("confidence", "MEDIUM")),
            "cwe_id": _extract_cwe(metadata),
            "owasp_category": metadata.get("owasp", [""])[0] if metadata.get("owasp") else None,
        }
        findings.append(finding)

    logger.info("semgrep.parsed", finding_count=len(findings))
    return findings


def _map_semgrep_confidence(confidence: str) -> float:
    """Map Semgrep confidence level to numeric score."""
    mapping = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}
    return mapping.get(confidence.upper(), 0.7)


def _extract_cwe(metadata: Dict[str, Any]) -> Optional[str]:
    """Extract CWE identifier from Semgrep metadata."""
    cwe_list = metadata.get("cwe", [])
    if cwe_list and isinstance(cwe_list, list):
        return cwe_list[0]
    elif isinstance(cwe_list, str):
        return cwe_list
    return None


def check_semgrep_installed() -> bool:
    """Check if semgrep is installed and accessible."""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
