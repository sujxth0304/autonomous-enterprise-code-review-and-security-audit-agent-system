"""AST-based code analysis utilities: chunking, language detection, complexity."""

import re
from typing import Any, Dict, List, Optional, Tuple


def detect_language_from_path(file_path: str) -> str:
    """Detect programming language from file extension."""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".cpp": "cpp",
        ".c": "c",
        ".rs": "rust",
        ".kt": "kotlin",
        ".swift": "swift",
        ".sh": "bash",
        ".sql": "sql",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".tf": "terraform",
        ".json": "json",
        ".md": "markdown",
        ".html": "html",
        ".css": "css",
    }
    for ext, lang in ext_map.items():
        if file_path.endswith(ext):
            return lang
    return "unknown"


def chunk_diff_by_file(diff_content: str) -> List[Dict[str, Any]]:
    """
    Split a unified diff into per-file chunks.

    Returns list of {file_path, language, diff_chunk, added_lines, removed_lines}
    """
    chunks = []
    current_file = None
    current_chunk = []
    added = 0
    removed = 0

    for line in diff_content.split("\n"):
        if line.startswith("diff --git "):
            if current_file and current_chunk:
                chunks.append({
                    "file_path": current_file,
                    "language": detect_language_from_path(current_file),
                    "diff_chunk": "\n".join(current_chunk),
                    "added_lines": added,
                    "removed_lines": removed,
                })
            current_chunk = [line]
            added = 0
            removed = 0
            # Extract filename from "diff --git a/foo.py b/foo.py"
            parts = line.split(" b/")
            current_file = parts[-1] if parts else None
        elif line.startswith("+++ b/"):
            current_file = line[6:].strip()
            current_chunk.append(line)
        elif line.startswith("--- ") or line.startswith("+++ "):
            current_chunk.append(line)
        else:
            if current_file:
                current_chunk.append(line)
                if line.startswith("+") and not line.startswith("+++"):
                    added += 1
                elif line.startswith("-") and not line.startswith("---"):
                    removed += 1

    if current_file and current_chunk:
        chunks.append({
            "file_path": current_file,
            "language": detect_language_from_path(current_file),
            "diff_chunk": "\n".join(current_chunk),
            "added_lines": added,
            "removed_lines": removed,
        })

    return chunks


def extract_code_from_diff(diff_chunk: str, include_context: bool = True) -> str:
    """Extract just the code lines from a diff chunk (strip +/- markers)."""
    lines = []
    for line in diff_chunk.split("\n"):
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            lines.append(line[1:])
        elif line.startswith("-"):
            if include_context:
                lines.append(line[1:])
        elif not line.startswith("\\"):
            lines.append(line)
    return "\n".join(lines)


def chunk_code_for_embedding(
    code: str,
    file_path: str,
    chunk_size: int = 50,
    overlap: int = 10,
) -> List[Dict[str, Any]]:
    """
    Split code into overlapping chunks suitable for embedding.

    Args:
        code: Source code string
        file_path: File path (used for language detection)
        chunk_size: Lines per chunk
        overlap: Lines to overlap between chunks

    Returns:
        List of {content, line_start, line_end, chunk_index, symbols}
    """
    lines = code.split("\n")
    chunks = []
    chunk_index = 0

    stride = max(1, chunk_size - overlap)
    for start in range(0, len(lines), stride):
        end = min(start + chunk_size, len(lines))
        chunk_lines = lines[start:end]
        content = "\n".join(chunk_lines)

        if not content.strip():
            continue

        symbols = extract_symbols(content, detect_language_from_path(file_path))

        chunks.append({
            "content": content,
            "line_start": start + 1,
            "line_end": end,
            "chunk_index": chunk_index,
            "symbols": symbols,
        })
        chunk_index += 1

        if end >= len(lines):
            break

    return chunks


def extract_symbols(code: str, language: str) -> List[str]:
    """Extract function and class names from code for symbol-based search."""
    symbols = []

    if language == "python":
        patterns = [
            r"def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
            r"class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:\(]",
            r"async\s+def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
        ]
    elif language in ("javascript", "typescript"):
        patterns = [
            r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
            r"const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:async\s+)?\(",
            r"class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[{\(]",
            r"([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(?:async\s+)?function",
        ]
    elif language == "go":
        patterns = [
            r"func\s+(?:\([^)]+\)\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
            r"type\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+struct",
        ]
    elif language == "java":
        patterns = [
            r"(?:public|private|protected|static).*\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
            r"class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*",
            r"interface\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*",
        ]
    else:
        patterns = [r"(?:def|function|func|class)\s+([a-zA-Z_][a-zA-Z0-9_]*)"]

    for pattern in patterns:
        matches = re.findall(pattern, code)
        symbols.extend(matches)

    # Deduplicate while preserving order
    seen = set()
    unique_symbols = []
    for s in symbols:
        if s not in seen and len(s) > 2:  # Skip very short symbols
            seen.add(s)
            unique_symbols.append(s)

    return unique_symbols[:20]  # Limit to 20 symbols per chunk


def calculate_diff_statistics(diff_content: str) -> Dict[str, Any]:
    """Calculate statistics about a diff."""
    file_chunks = chunk_diff_by_file(diff_content)

    stats = {
        "total_files": len(file_chunks),
        "total_additions": sum(c["added_lines"] for c in file_chunks),
        "total_removals": sum(c["removed_lines"] for c in file_chunks),
        "files_by_language": {},
        "files": [],
    }

    for chunk in file_chunks:
        lang = chunk["language"]
        stats["files_by_language"][lang] = stats["files_by_language"].get(lang, 0) + 1
        stats["files"].append({
            "path": chunk["file_path"],
            "language": lang,
            "additions": chunk["added_lines"],
            "removals": chunk["removed_lines"],
        })

    return stats


def find_sensitive_file_changes(file_paths: List[str]) -> List[Dict[str, str]]:
    """Identify which changed files are security-sensitive."""
    sensitive_patterns = {
        "auth": "Authentication/Authorization module",
        "security": "Security configuration",
        "crypto": "Cryptographic code",
        "payment": "Payment processing",
        "billing": "Billing system",
        "admin": "Admin interface",
        "config": "Application configuration",
        "settings": "Application settings",
        "secret": "Secrets/credentials",
        "password": "Password handling",
        "token": "Token management",
        "jwt": "JWT implementation",
        "oauth": "OAuth flow",
        ".env": "Environment variables",
        "migration": "Database migration",
        "schema": "Database schema",
        "permission": "Permission system",
        "role": "Role management",
    }

    flagged = []
    for path in file_paths:
        path_lower = path.lower()
        for pattern, description in sensitive_patterns.items():
            if pattern in path_lower:
                flagged.append({
                    "file_path": path,
                    "reason": description,
                    "pattern": pattern,
                })
                break

    return flagged
