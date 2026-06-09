"""TreeSitterParser: AST-based code analysis with LLM fallback.

Parses source code using tree-sitter for Python, JS/TS, Java, Go, Ruby, PHP.
Extracts: function definitions, class definitions, imports, HTTP handlers,
route decorators, middleware, auth decorators, data models, env var references.
Falls back to LLM semantic understanding when AST extraction is insufficient.
"""

import logging
import os
from pathlib import Path
from typing import Any

from src.llm.json_utils import extract_json_from_response

logger = logging.getLogger(__name__)

# Language to file extension mapping
LANGUAGE_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py", ".pyi"},
    "javascript": {".js", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx", ".mts", ".cts"},
    "java": {".java"},
    "go": {".go"},
    "ruby": {".rb", ".rake"},
    "php": {".php", ".phtml"},
}

# Reverse mapping: extension -> language
EXT_TO_LANGUAGE: dict[str, str] = {}
for lang, exts in LANGUAGE_EXTENSIONS.items():
    for ext in exts:
        EXT_TO_LANGUAGE[ext] = lang

# Patterns for security-relevant code extraction
SECURITY_PATTERNS: dict[str, dict[str, list[str]]] = {
    "python": {
        "route_decorators": ["@app.route", "@router.", "@api_view", "@controller", "@blueprint"],
        "auth_decorators": ["@login_required", "@auth_required", "@permission_required", "@jwt_required", "@require_auth"],
        "http_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        "orm_models": ["Model", "Column", "relationship", "ForeignKey", "Mapped"],
        "env_vars": ["os.environ", "os.getenv", "getenv", "ENV["],
        "sql_queries": ["execute(", "raw(", "cursor.execute", ".query("],
        "dangerous_functions": ["eval(", "exec(", "subprocess", "os.system(", "shell=True"],
        "file_operations": ["open(", "file(", "Path(", "read_file"],
        "crypto": ["hashlib", "bcrypt", "jwt.encode", "jwt.decode", "fernet"],
    },
    "javascript": {
        "route_decorators": ["app.get(", "app.post(", "router.get(", "router.post(", "app.use("],
        "auth_decorators": ["authenticate", "authorize", "jwt.verify", "passport.authenticate"],
        "http_methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
        "orm_models": ["Schema", "Model", "sequelize.define", "mongoose.model"],
        "env_vars": ["process.env", "import.meta.env"],
        "sql_queries": ["query(", "raw(", "sequelize.query"],
        "dangerous_functions": ["eval(", "Function(", "child_process", "exec("],
        "file_operations": ["fs.readFile", "fs.writeFile", "createReadStream"],
        "crypto": ["crypto.createHash", "bcrypt", "jsonwebtoken"],
    },
}


class TreeSitterParser:
    """Parses source code using tree-sitter (with LLM fallback) for security analysis.

    Extracts security-relevant structures from codebases:
    - HTTP handlers and route definitions
    - Authentication/authorization decorators
    - Data models and ORM definitions
    - SQL queries and database interactions
    - Dangerous function calls
    - Environment variable references
    - File operations and crypto usage

    Falls back to LLM-based parsing when tree-sitter is unavailable
    or when semantic understanding is needed beyond AST extraction.
    """

    def __init__(self, llm_client: Any | None = None) -> None:
        self.llm = llm_client
        self._parsers: dict[str, Any] = {}
        self._parser_available: bool = False
        self._init_parsers()

    def _init_parsers(self) -> None:
        """Try to initialize tree-sitter parsers for supported languages."""
        try:
            import tree_sitter_python as tspython
            import tree_sitter_javascript as tsjs
            import tree_sitter_typescript as tstypescript
            from tree_sitter import Language, Parser

            self._language_map = {
                "python": Language(tspython.language()),
                "javascript": Language(tsjs.language()),
                "typescript": Language(tstypescript.typescript().language()),
            }
            for lang_name, language in self._language_map.items():
                parser = Parser(language)
                self._parsers[lang_name] = parser
            self._parser_available = True
            logger.info("TreeSitterParser: tree-sitter available for %s", list(self._parsers.keys()))
        except ImportError:
            self._parser_available = False
            logger.info("TreeSitterParser: tree-sitter not available, will use regex + LLM fallback")

    async def parse_codebase(self, repo_path: str | Path) -> dict[str, Any]:
        """Parse an entire codebase directory.

        Args:
            repo_path: Path to the codebase directory.

        Returns:
            Dict with keys: functions, classes, imports, http_handlers,
            auth_decorators, data_models, env_vars, sql_queries,
            dangerous_functions, file_operations, crypto_usage.
        """
        repo_path = Path(repo_path)
        if not repo_path.is_dir():
            logger.error("TreeSitterParser: path is not a directory: %s", repo_path)
            return {}

        results: dict[str, list[dict[str, Any]]] = {
            "functions": [],
            "classes": [],
            "imports": [],
            "http_handlers": [],
            "auth_decorators": [],
            "data_models": [],
            "env_vars": [],
            "sql_queries": [],
            "dangerous_functions": [],
            "file_operations": [],
            "crypto_usage": [],
        }

        source_files = self._find_source_files(repo_path)
        logger.info("TreeSitterParser: found %d source files in %s", len(source_files), repo_path)

        for file_path in source_files:
            try:
                file_results = self._parse_file(file_path, repo_path)
                for key, items in file_results.items():
                    results[key].extend(items)
            except Exception as exc:
                logger.warning("TreeSitterParser: failed to parse %s: %s", file_path, exc)

        # Deduplicate results
        for key in results:
            seen = set()
            deduped = []
            for item in results[key]:
                dedup_key = (item.get("name", ""), item.get("file", ""), item.get("line", 0))
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    deduped.append(item)
            results[key] = deduped

        return results

    def _find_source_files(self, repo_path: Path) -> list[Path]:
        """Find all source files in the repo that we can parse."""
        skip_dirs = {
            "__pycache__", ".git", "node_modules", ".venv", "venv",
            "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
        }
        source_files = []

        for root, dirs, files in os.walk(repo_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

            for fname in files:
                ext = Path(fname).suffix
                if ext in EXT_TO_LANGUAGE:
                    source_files.append(Path(root) / fname)

        return source_files

    def _parse_file(self, file_path: Path, repo_path: Path) -> dict[str, list[dict[str, Any]]]:
        """Parse a single source file for security-relevant structures."""
        relative_path = str(file_path.relative_to(repo_path))
        ext = file_path.suffix
        language = EXT_TO_LANGUAGE.get(ext, "")

        try:
            source_code = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return {}

        if self._parser_available and language in self._parsers:
            return self._parse_with_treesitter(source_code, relative_path, language)
        else:
            return self._parse_with_regex(source_code, relative_path, language)

    def _parse_with_treesitter(
        self, source_code: str, file_path: str, language: str
    ) -> dict[str, list[dict[str, Any]]]:
        """Parse source code using tree-sitter AST analysis."""
        parser = self._parsers.get(language)
        if parser is None:
            return self._parse_with_regex(source_code, file_path, language)

        tree = parser.parse(source_code.encode())
        results: dict[str, list[dict[str, Any]]] = {
            "functions": [], "classes": [], "imports": [],
            "http_handlers": [], "auth_decorators": [], "data_models": [],
            "env_vars": [], "sql_queries": [], "dangerous_functions": [],
            "file_operations": [], "crypto_usage": [],
        }

        lines = source_code.splitlines()
        self._walk_tree(tree.root_node, results, file_path, lines)
        return results

    def _walk_tree(
        self, node: Any, results: dict[str, list], file_path: str, lines: list[str]
    ) -> None:
        """Walk the tree-sitter AST and extract security-relevant nodes."""
        if node.type == "function_definition":
            name = self._get_child_text(node, "identifier", lines)
            results["functions"].append({
                "name": name,
                "file": file_path,
                "line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
            })

        elif node.type == "class_definition":
            name = self._get_child_text(node, "identifier", lines)
            results["classes"].append({
                "name": name,
                "file": file_path,
                "line": node.start_point[0] + 1,
            })

        elif node.type == "import_statement" or node.type == "import_from_statement":
            import_text = lines[node.start_point[0]] if node.start_point[0] < len(lines) else ""
            results["imports"].append({
                "text": import_text.strip(),
                "file": file_path,
                "line": node.start_point[0] + 1,
            })

        # Recurse into children
        for child in node.children:
            self._walk_tree(child, results, file_path, lines)

    def _get_child_text(self, node: Any, child_type: str, lines: list[str]) -> str:
        """Get text of a child node by type."""
        for child in node.children:
            if child.type == child_type:
                return lines[child.start_point[0]][child.start_point[1]:child.end_point[1]]
        return ""

    def _parse_with_regex(
        self, source_code: str, file_path: str, language: str
    ) -> dict[str, list[dict[str, Any]]]:
        """Fallback regex-based parsing when tree-sitter is unavailable."""
        import re

        results: dict[str, list[dict[str, Any]]] = {
            "functions": [], "classes": [], "imports": [],
            "http_handlers": [], "auth_decorators": [], "data_models": [],
            "env_vars": [], "sql_queries": [], "dangerous_functions": [],
            "file_operations": [], "crypto_usage": [],
        }

        patterns = SECURITY_PATTERNS.get(language, SECURITY_PATTERNS.get("python", {}))
        lines = source_code.splitlines()

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Function definitions
            func_match = re.match(r"def\s+(\w+)\s*\(", stripped)
            if func_match:
                results["functions"].append({
                    "name": func_match.group(1),
                    "file": file_path,
                    "line": line_num,
                })

            # Class definitions
            class_match = re.match(r"class\s+(\w+)", stripped)
            if class_match:
                results["classes"].append({
                    "name": class_match.group(1),
                    "file": file_path,
                    "line": line_num,
                })

            # Security patterns
            for category, keywords in patterns.items():
                for keyword in keywords:
                    if keyword in line:
                        results[category].append({
                            "pattern": keyword,
                            "line_text": stripped[:200],
                            "file": file_path,
                            "line": line_num,
                        })
                        break  # One match per category per line

        return results

    async def parse_with_llm_fallback(self, source_code: str, file_path: str) -> dict[str, Any]:
        """Use LLM to parse source code when AST extraction is insufficient.

        Called when tree-sitter can't fully understand semantics, e.g.,
        dynamic route registration, implicit auth flows, etc.
        """
        if not self.llm:
            return {}

        prompt = f"""Analyze this source code for security-relevant structures. Extract:
- HTTP endpoints and their methods (GET, POST, etc.)
- Authentication/authorization checks
- Data models and validation
- SQL queries and database interactions
- Dangerous function calls (eval, exec, shell, etc.)
- Environment variable usage
- File operations
- Cryptographic operations

Source file: {file_path}

```python
{source_code[:8000]}
```

Respond with a JSON object with keys: http_handlers, auth_decorators, data_models,
sql_queries, dangerous_functions, env_vars, file_operations, crypto_usage.
Each value should be a list of objects with 'name', 'line', and 'description' keys."""

        try:
            response = await self.llm.generate(prompt, task_type="reasoning", max_tokens=2048)
            result = extract_json_from_response(response)
            if isinstance(result, dict):
                return result
        except Exception as exc:
            logger.warning("TreeSitterParser: LLM fallback failed for %s: %s", file_path, exc)

        return {}