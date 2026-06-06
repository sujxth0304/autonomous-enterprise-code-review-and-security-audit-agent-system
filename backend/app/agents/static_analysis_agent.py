"""Static analysis agent using Claude with ReAct pattern."""

import ast
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


# ─── Tool input schemas ──────────────────────────────────────────────────────


class SemgrepInput(BaseModel):
    code: str = Field(description="Source code to analyze")
    language: str = Field(description="Programming language (python, javascript, go, etc)")


class ASTInput(BaseModel):
    code: str = Field(description="Python source code to parse into AST")


class ComplexityInput(BaseModel):
    code: str = Field(description="Source code to analyze for cyclomatic complexity")


class LanguageInput(BaseModel):
    file_path: str = Field(description="File path to detect language from")


# ─── Tool implementations ────────────────────────────────────────────────────


def run_semgrep(code: str, language: str) -> Dict[str, Any]:
    """
    Analyze code with pattern-based static analysis rules.
    Returns findings with severity, message, and line numbers.
    """
    findings = []
    lines = code.split("\n")

    patterns = {
        "python": [
            (r"eval\s*\(", "high", "Use of eval() is dangerous - can execute arbitrary code", "CWE-95"),
            (r"exec\s*\(", "high", "Use of exec() allows arbitrary code execution", "CWE-95"),
            (r"pickle\.loads?\s*\(", "high", "Deserialization with pickle is unsafe", "CWE-502"),
            (r"subprocess\.call\s*\(.*shell\s*=\s*True", "high", "Shell injection risk with shell=True", "CWE-78"),
            (r"os\.system\s*\(", "medium", "Use subprocess instead of os.system", "CWE-78"),
            (r"hashlib\.md5\s*\(", "medium", "MD5 is cryptographically weak", "CWE-327"),
            (r"hashlib\.sha1\s*\(", "low", "SHA1 is considered weak for cryptographic use", "CWE-327"),
            (r"random\.(random|randint|choice)\s*\(", "low", "Use secrets module for cryptographic randomness", "CWE-338"),
            (r"assert\s+", "low", "Assertions can be disabled with -O flag", "CWE-617"),
            (r"open\s*\(.*['\"]w['\"]", "info", "File write operation - verify path sanitization", "CWE-22"),
        ],
        "javascript": [
            (r"eval\s*\(", "high", "eval() is dangerous and should be avoided", "CWE-95"),
            (r"innerHTML\s*=", "high", "innerHTML assignment can lead to XSS", "CWE-79"),
            (r"document\.write\s*\(", "high", "document.write() is vulnerable to XSS", "CWE-79"),
            (r"setTimeout\s*\(['\"]", "medium", "String-based setTimeout is like eval", "CWE-95"),
            (r"dangerouslySetInnerHTML", "high", "dangerouslySetInnerHTML bypasses XSS protection", "CWE-79"),
            (r"Math\.random\s*\(", "low", "Math.random() is not cryptographically secure", "CWE-338"),
        ],
        "sql": [
            (r"f['\"]SELECT.*\{", "critical", "SQL injection via f-string formatting", "CWE-89"),
            (r"['\"]SELECT.*['\"] \+", "critical", "SQL injection via string concatenation", "CWE-89"),
            (r"% .* FROM", "high", "Potential SQL injection via % formatting", "CWE-89"),
        ],
    }

    lang_patterns = patterns.get(language.lower(), [])
    # Also check for SQL patterns in all languages
    sql_patterns = patterns.get("sql", [])

    for i, line in enumerate(lines, 1):
        for pattern, severity, message, cwe in lang_patterns + sql_patterns:
            if re.search(pattern, line):
                findings.append({
                    "line": i,
                    "severity": severity,
                    "message": message,
                    "cwe": cwe,
                    "code": line.strip(),
                    "rule": pattern,
                })

    return {"findings": findings, "total": len(findings), "language": language}


def parse_ast(code: str) -> Dict[str, Any]:
    """Parse Python AST and return structure summary."""
    try:
        tree = ast.parse(code)
        functions = []
        classes = []
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    "name": node.name,
                    "line": node.lineno,
                    "args": [a.arg for a in node.args.args],
                    "decorator_count": len(node.decorator_list),
                })
            elif isinstance(node, ast.ClassDef):
                classes.append({"name": node.name, "line": node.lineno})
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                else:
                    imports.append(node.module or "")

        return {
            "functions": functions,
            "classes": classes,
            "imports": imports,
            "total_lines": len(code.split("\n")),
        }
    except SyntaxError as e:
        return {"error": f"Syntax error: {e}", "functions": [], "classes": [], "imports": []}


def check_code_complexity(code: str) -> Dict[str, Any]:
    """Calculate McCabe cyclomatic complexity for Python code."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"error": "Could not parse code", "complexity": 0}

    class ComplexityVisitor(ast.NodeVisitor):
        def __init__(self):
            self.complexity = 1  # Base complexity
            self.function_complexities = []

        def visit_FunctionDef(self, node):
            func_complexity = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler,
                                       ast.With, ast.Assert, ast.comprehension)):
                    func_complexity += 1
                elif isinstance(child, ast.BoolOp):
                    func_complexity += len(child.values) - 1
            self.function_complexities.append({
                "name": node.name,
                "line": node.lineno,
                "complexity": func_complexity,
            })
            self.complexity += func_complexity - 1
            self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef

    visitor = ComplexityVisitor()
    visitor.visit(tree)

    high_complexity = [f for f in visitor.function_complexities if f["complexity"] > 10]

    return {
        "total_complexity": visitor.complexity,
        "function_complexities": visitor.function_complexities,
        "high_complexity_functions": high_complexity,
        "has_complexity_issues": len(high_complexity) > 0,
    }


def detect_language(file_path: str) -> str:
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
    }
    for ext, lang in ext_map.items():
        if file_path.endswith(ext):
            return lang
    return "unknown"


# ─── LangChain tools ─────────────────────────────────────────────────────────

STATIC_ANALYSIS_TOOLS = [
    StructuredTool(
        name="run_semgrep",
        description="Run pattern-based static analysis on code to find bugs, security issues. Input: code string and language string.",
        func=run_semgrep,
        args_schema=SemgrepInput,
    ),
    StructuredTool(
        name="parse_ast",
        description="Parse Python code into AST and extract functions, classes, imports.",
        func=parse_ast,
        args_schema=ASTInput,
    ),
    StructuredTool(
        name="check_code_complexity",
        description="Calculate cyclomatic complexity of Python code functions.",
        func=check_code_complexity,
        args_schema=ComplexityInput,
    ),
    StructuredTool(
        name="detect_language",
        description="Detect programming language from file path extension.",
        func=detect_language,
        args_schema=LanguageInput,
    ),
]

STATIC_ANALYSIS_PROMPT = PromptTemplate.from_template("""You are a senior software engineer performing static code analysis on a GitHub Pull Request.

Analyze the following diff for:
1. Code quality issues (complexity, maintainability)
2. Common programming errors and anti-patterns
3. Security vulnerabilities (injection, unsafe functions)
4. Style and best practice violations

PR Information:
- Repository: {repo}
- PR Number: {pr_number}
- Files Changed: {files_changed}

Diff Content:
{diff_content}

Use the available tools to:
1. Detect the language of changed files
2. Run semgrep analysis on relevant code sections
3. Check AST structure for Python files
4. Analyze cyclomatic complexity

For each finding, output a JSON object with:
- severity: critical/high/medium/low/info
- category: static_analysis
- title: brief title
- description: detailed explanation
- file_path: affected file
- line_start: starting line number
- line_end: ending line number
- code_snippet: relevant code
- suggestion: how to fix
- confidence_score: 0.0-1.0

{agent_scratchpad}

Available tools: {tools}
Tool names: {tool_names}""")


async def run_static_analysis_agent(
    pr_data: Dict[str, Any],
    diff_content: str,
) -> List[Dict[str, Any]]:
    """Run the static analysis agent and return structured findings."""

    if not settings.GEMINI_API_KEY:
        logger.warning("static_analysis.no_api_key_using_heuristics")
        return _heuristic_static_analysis(pr_data, diff_content)

    try:
        llm = ChatGoogleGenerativeAI(
            model=settings.GEMINI_MODEL,
            temperature=0,
            google_api_key=settings.GEMINI_API_KEY,
        )

        agent = create_react_agent(llm, STATIC_ANALYSIS_TOOLS, STATIC_ANALYSIS_PROMPT)
        executor = AgentExecutor(
            agent=agent,
            tools=STATIC_ANALYSIS_TOOLS,
            max_iterations=settings.MAX_AGENT_STEPS,
            verbose=False,
            handle_parsing_errors=True,
            return_intermediate_steps=True,
        )

        result = await executor.ainvoke({
            "repo": pr_data.get("repo_full_name", "unknown"),
            "pr_number": pr_data.get("pr_number", 0),
            "files_changed": pr_data.get("files_changed", 0),
            "diff_content": diff_content[:8000],  # Truncate for token limits
        })

        return _parse_agent_findings(result.get("output", ""), "static_analysis", pr_data)

    except Exception as exc:
        logger.error("static_analysis.agent_error", error=str(exc))
        return _heuristic_static_analysis(pr_data, diff_content)


def _heuristic_static_analysis(
    pr_data: Dict[str, Any], diff_content: str
) -> List[Dict[str, Any]]:
    """Fallback heuristic analysis when LLM is unavailable."""
    findings = []
    lines = diff_content.split("\n")
    pr_id = str(pr_data.get("pr_id", ""))

    for i, line in enumerate(lines, 1):
        if not line.startswith("+"):
            continue
        code = line[1:]  # Strip leading +

        # Check various patterns
        checks = [
            (r"eval\(", "high", "Dangerous eval() usage", "CWE-95"),
            (r"exec\(", "high", "Dangerous exec() usage", "CWE-95"),
            (r"pickle\.load", "high", "Unsafe deserialization", "CWE-502"),
            (r"os\.system\(", "medium", "Shell command execution", "CWE-78"),
            (r"TODO|FIXME|HACK|XXX", "info", "Unresolved code comment", None),
        ]

        for pattern, severity, message, cwe in checks:
            if re.search(pattern, code):
                findings.append({
                    "severity": severity,
                    "category": "static_analysis",
                    "agent_type": "static_analysis",
                    "title": message,
                    "description": f"Found `{pattern}` pattern at line {i}",
                    "file_path": _extract_file_from_diff(diff_content, i),
                    "line_start": i,
                    "line_end": i,
                    "code_snippet": code.strip(),
                    "suggestion": f"Review and replace the {pattern} usage with a safer alternative",
                    "confidence_score": 0.85,
                    "cwe_id": cwe,
                    "pr_id": pr_id,
                })

    return findings


def _extract_file_from_diff(diff_content: str, target_line: int) -> str:
    """Extract the file path for a given line in a diff."""
    current_file = "unknown"
    for i, line in enumerate(diff_content.split("\n"), 1):
        if line.startswith("diff --git") or line.startswith("+++ b/"):
            if line.startswith("+++ b/"):
                current_file = line[6:]
        if i >= target_line:
            break
    return current_file


def _parse_agent_findings(
    output: str, agent_type: str, pr_data: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Parse agent text output to extract structured findings."""
    import json

    findings = []
    pr_id = str(pr_data.get("pr_id", ""))

    # Try to extract JSON blocks from output
    json_pattern = re.compile(r'\{[^{}]*"severity"[^{}]*\}', re.DOTALL)
    matches = json_pattern.findall(output)

    for match in matches:
        try:
            finding = json.loads(match)
            finding["agent_type"] = agent_type
            finding["pr_id"] = pr_id
            finding.setdefault("category", agent_type)
            finding.setdefault("confidence_score", 0.8)
            findings.append(finding)
        except json.JSONDecodeError:
            continue

    return findings
