"""
response_analyzer.py
--------------------
Analyzes HTTP responses (or simulated responses) to detect evidence of
SQL Injection vulnerability.

Detection techniques implemented:
  • SQL error message fingerprinting
  • Response-difference analysis  (normal vs injected)
  • Time-based delay detection
  • Boolean condition inference
  • Content-length anomaly detection
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

import logging

logger = logging.getLogger(__name__)


# ── Enumerations ──────────────────────────────────────────────────────────

class InjectionType(str, Enum):
    AUTH_BYPASS = "Authentication Bypass"
    DATA_EXTRACTION = "Database Data Extraction"
    DB_INFO = "Database Information Disclosure"
    TIME_BASED = "Time-Based Blind Injection"
    BOOLEAN_BASED = "Boolean-Based Blind Injection"
    ERROR_BASED = "Error-Based Injection"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DATA_MODIFICATION = "Database Record Modification"
    DATA_DELETION = "Record Deletion"
    DATA_INSERTION = "Malicious Data Insertion"
    TABLE_DROP = "Table Drop"


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ── Known SQL error signatures ────────────────────────────────────────────

SQL_ERROR_SIGNATURES: List[Tuple[str, str]] = [
    # (pattern, database hint)
    (r"SQL syntax.*?MySQL", "MySQL"),
    (r"Warning.*?\Wmysqli?_", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"check the manual that corresponds to your (MySQL|MariaDB)", "MySQL/MariaDB"),
    (r"mysql_fetch", "MySQL"),

    (r"ORA-\d{5}", "Oracle"),
    (r"Oracle.*?Driver", "Oracle"),
    (r"quoted string not properly terminated", "Oracle"),

    (r"PostgreSQL.*?ERROR", "PostgreSQL"),
    (r"pg_query\(\)", "PostgreSQL"),
    (r"pg_exec\(\)", "PostgreSQL"),

    (r"Microsoft.*?ODBC.*?SQL Server", "MSSQL"),
    (r"\bSQLServer\b", "MSSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"Microsoft.*?SQL.*?Native Client error", "MSSQL"),

    (r"SQLite.*?error", "SQLite"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"unrecognized token", "SQLite"),
    (r"near \".*?\": syntax error", "SQLite"),

    (r"SQL syntax error", "Generic"),
    (r"unclosed quotation mark", "Generic"),
    (r"syntax error at or near", "Generic"),
    (r"SQL command not properly ended", "Generic"),
    (r"SQLSTATE\[", "Generic"),
    (r"Dynamic SQL Error", "Generic"),
    (r"Syntax error in.*?query.*?expression", "Generic"),
]


# ── Analysis result ───────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    """Result of analysing a single injected response."""
    vulnerable: bool = False
    injection_types: List[InjectionType] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    database_hint: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.SAFE
    payload_used: str = ""
    endpoint: str = ""
    parameter: str = ""
    response_time: float = 0.0
    status_code: int = 0

    def add(self, itype: InjectionType, evidence: str) -> None:
        if itype not in self.injection_types:
            self.injection_types.append(itype)
        self.evidence.append(evidence)
        self.vulnerable = True

    def compute_risk(self) -> RiskLevel:
        """Derive the risk level from detected injection types."""
        if not self.vulnerable:
            self.risk_level = RiskLevel.SAFE
            return self.risk_level

        types = set(self.injection_types)
        critical_types = {
            InjectionType.DATA_MODIFICATION,
            InjectionType.DATA_DELETION,
            InjectionType.TABLE_DROP,
            InjectionType.PRIVILEGE_ESCALATION,
            InjectionType.DATA_INSERTION,
        }
        high_types = {
            InjectionType.DATA_EXTRACTION,
            InjectionType.DB_INFO,
        }
        medium_types = {
            InjectionType.AUTH_BYPASS,
            InjectionType.ERROR_BASED,
        }

        if types & critical_types:
            self.risk_level = RiskLevel.CRITICAL
        elif types & high_types:
            self.risk_level = RiskLevel.HIGH
        elif types & medium_types:
            self.risk_level = RiskLevel.MEDIUM
        else:
            self.risk_level = RiskLevel.LOW

        return self.risk_level


# ── Response Analyzer ─────────────────────────────────────────────────────

class ResponseAnalyzer:
    """Compare baseline and injected HTTP responses to detect SQL injection."""

    def __init__(self):
        self._compiled_errors = [
            (re.compile(pat, re.IGNORECASE), db) for pat, db in SQL_ERROR_SIGNATURES
        ]

    # ── Primary analysis entry-point ──────────────────────────────────

    def analyze(
        self,
        *,
        baseline_body: str,
        baseline_status: int,
        baseline_time: float,
        injected_body: str,
        injected_status: int,
        injected_time: float,
        payload: str,
        endpoint: str = "",
        parameter: str = "",
        category: str = "",
    ) -> AnalysisResult:
        """
        Compare baseline (normal) and injected responses to detect
        injection indicators.
        """
        result = AnalysisResult(
            payload_used=payload,
            endpoint=endpoint,
            parameter=parameter,
            response_time=injected_time,
            status_code=injected_status,
        )

        # 1. SQL error fingerprinting
        self._check_sql_errors(injected_body, result)

        # 2. Authentication bypass detection
        self._check_auth_bypass(baseline_body, baseline_status, injected_body, injected_status, payload, category, result)

        # 3. Union-based data extraction detection
        self._check_union_extraction(baseline_body, injected_body, payload, category, result)

        # 4. Time-based blind detection
        self._check_time_based(baseline_time, injected_time, payload, category, result)

        # 5. Boolean-based blind detection
        self._check_boolean_based(baseline_body, injected_body, payload, category, result)

        # 6. Destructive-capability detection (simulation)
        self._check_destructive_capabilities(baseline_body, injected_body, baseline_status, injected_status, payload, category, result)

        # Compute final risk
        result.compute_risk()
        return result

    # ── Individual detection methods ──────────────────────────────────

    def _check_sql_errors(self, body: str, result: AnalysisResult) -> None:
        """Look for SQL error messages in the response body."""
        for regex, db_hint in self._compiled_errors:
            m = regex.search(body)
            if m:
                result.add(
                    InjectionType.ERROR_BASED,
                    f"SQL error detected ({db_hint}): {m.group()[:120]}",
                )
                result.database_hint = db_hint
                break  # one error is enough

    def _check_auth_bypass(
        self,
        baseline_body: str,
        baseline_status: int,
        injected_body: str,
        injected_status: int,
        payload: str,
        category: str,
        result: AnalysisResult,
    ) -> None:
        """Detect authentication bypass via response comparison."""
        if category and "bypass" not in category.lower() and "authentication" not in category.lower():
            return

        bypass_indicators = [
            "login successful",
            "welcome",
            "dashboard",
            "logged in",
            "authenticated",
            "session",
            "token",
            "redirect",
            "success",
        ]

        # Baseline should fail (invalid credentials)
        baseline_lower = baseline_body.lower()
        injected_lower = injected_body.lower()

        baseline_failed = any(
            w in baseline_lower for w in ["invalid", "fail", "error", "incorrect", "denied", "wrong"]
        ) or baseline_status in (401, 403)

        injected_succeeded = any(w in injected_lower for w in bypass_indicators) or injected_status == 200

        # If the baseline failed but injected succeeded → bypass
        if baseline_failed and injected_succeeded and injected_lower != baseline_lower:
            result.add(
                InjectionType.AUTH_BYPASS,
                f"Authentication bypassed – baseline indicated failure, injected response indicates success. Payload: {payload}",
            )

        # Also detect if response body is significantly different and positive
        if len(injected_body) > len(baseline_body) * 1.5 and injected_status == 200:
            result.add(
                InjectionType.AUTH_BYPASS,
                "Response body significantly larger after injection, suggesting bypass.",
            )

    def _check_union_extraction(
        self,
        baseline_body: str,
        injected_body: str,
        payload: str,
        category: str,
        result: AnalysisResult,
    ) -> None:
        """Detect UNION-based data extraction."""
        if "union" not in payload.lower():
            return

        # If injected body is longer or contains new information
        extra = len(injected_body) - len(baseline_body)

        if extra > 20:
            result.add(
                InjectionType.DATA_EXTRACTION,
                f"UNION injection returned {extra} extra bytes – data extraction likely possible.",
            )

        # Check for schema keywords in response
        schema_keywords = ["information_schema", "table_name", "column_name", "sqlite_master"]
        for kw in schema_keywords:
            if kw in injected_body.lower():
                result.add(
                    InjectionType.DB_INFO,
                    f"Database schema information ({kw}) leaked in response.",
                )
                break

        # Check for data patterns (username, password, email, etc.)
        data_patterns = [r"\badmin\b", r"password", r"@\w+\.\w+", r"user(name)?"]
        for pat in data_patterns:
            if re.search(pat, injected_body, re.IGNORECASE) and not re.search(pat, baseline_body, re.IGNORECASE):
                result.add(
                    InjectionType.DATA_EXTRACTION,
                    f"Potential sensitive data pattern detected in UNION response: {pat}",
                )
                break

    def _check_time_based(
        self,
        baseline_time: float,
        injected_time: float,
        payload: str,
        category: str,
        result: AnalysisResult,
    ) -> None:
        """Detect time-based blind injection from response delay."""
        if "sleep" not in payload.lower() and "waitfor" not in payload.lower() and "benchmark" not in payload.lower():
            return

        delay = injected_time - baseline_time
        if delay >= 2.5:  # generous threshold
            result.add(
                InjectionType.TIME_BASED,
                f"Response delayed by {delay:.1f}s (baseline {baseline_time:.1f}s), indicating time-based blind injection.",
            )

    def _check_boolean_based(
        self,
        baseline_body: str,
        injected_body: str,
        payload: str,
        category: str,
        result: AnalysisResult,
    ) -> None:
        """Detect boolean-based blind injection from body differences."""
        if "boolean" not in (category or "").lower():
            # Also match common boolean payloads
            if "AND 1=1" not in payload and "AND 1=2" not in payload:
                return

        # If TRUE-condition response differs from FALSE-condition baseline
        if injected_body != baseline_body:
            len_diff = abs(len(injected_body) - len(baseline_body))
            if len_diff > 0:
                result.add(
                    InjectionType.BOOLEAN_BASED,
                    f"Boolean payload caused response change ({len_diff} byte diff), confirming boolean-based blind injection.",
                )

    def _check_destructive_capabilities(
        self,
        baseline_body: str,
        injected_body: str,
        baseline_status: int,
        injected_status: int,
        payload: str,
        category: str,
        result: AnalysisResult,
    ) -> None:
        """
        Determine whether destructive operations (UPDATE/DELETE/DROP/INSERT)
        *could* be injected based on response indicators.

        The bot does NOT execute destructive queries — it infers capability
        from query-chaining indicators.
        """
        payload_lower = payload.lower()

        # Check if the endpoint already showed some vulnerability
        # (indicating unsanitized input reaches SQL)
        sql_vuln_present = result.vulnerable

        # Stacked-query / chaining indicator
        has_semicolon = ";" in payload
        # If the server didn't error on a semicolon-chained payload,
        # it likely supports stacked queries.
        server_accepted = injected_status not in (400, 500, 422)
        no_sql_error = not any(
            regex.search(injected_body) for regex, _ in self._compiled_errors
        )

        chaining_likely = has_semicolon and server_accepted and no_sql_error

        if "update" in payload_lower and (chaining_likely or sql_vuln_present):
            if "role" in payload_lower or "admin" in payload_lower or "privilege" in payload_lower or "is_admin" in payload_lower:
                result.add(
                    InjectionType.PRIVILEGE_ESCALATION,
                    f"UPDATE-based privilege escalation appears possible (stacked queries accepted). Payload: {payload}",
                )
            else:
                result.add(
                    InjectionType.DATA_MODIFICATION,
                    f"UPDATE-based data modification appears possible. Payload: {payload}",
                )

        if "delete" in payload_lower and (chaining_likely or sql_vuln_present):
            result.add(
                InjectionType.DATA_DELETION,
                f"DELETE-based data deletion appears possible. Payload: {payload}",
            )

        if "drop" in payload_lower and (chaining_likely or sql_vuln_present):
            result.add(
                InjectionType.TABLE_DROP,
                f"DROP TABLE appears possible – schema destruction risk. Payload: {payload}",
            )

        if "insert" in payload_lower and (chaining_likely or sql_vuln_present):
            result.add(
                InjectionType.DATA_INSERTION,
                f"INSERT-based malicious data injection appears possible. Payload: {payload}",
            )


# ── Static-analysis response analyzer (for code scanning without live server) ──

class StaticCodeAnalyzer:
    """
    Analyze source code (without running a server) to detect patterns
    that indicate SQL injection vulnerability.
    """

    # Patterns that suggest unsafe SQL construction
    UNSAFE_SQL_PATTERNS = [
        (re.compile(r"""f["'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP).*?\{.*?\}""", re.IGNORECASE | re.DOTALL),
         "f-string SQL query with variable interpolation"),
        (re.compile(r"""["'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP).*?%s""", re.IGNORECASE),
         "%-format SQL query with parameter substitution"),
        (re.compile(r"""["'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP).*?["']\s*\+\s*\w+""", re.IGNORECASE),
         "String concatenation in SQL query"),
        (re.compile(r"""["'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP).*?["']\s*%\s*\(""", re.IGNORECASE),
         "%-tuple formatting in SQL query"),
        (re.compile(r"""\.format\(.*?\).*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)""", re.IGNORECASE),
         ".format() used in SQL query"),
        (re.compile(r"""(?:execute|query|raw)\s*\(\s*f?["'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)""", re.IGNORECASE),
         "Direct execution of constructed SQL query"),
        (re.compile(r"""cursor\.execute\s*\(\s*(?:f["']|["'].*?\+|["'].*?%|.*?\.format)""", re.IGNORECASE),
         "cursor.execute() with unsafe query construction"),
    ]

    # Patterns that suggest safe parameterized queries
    SAFE_SQL_PATTERNS = [
        re.compile(r"""cursor\.execute\s*\(\s*["'][^"']*\?[^"']*["']\s*,""", re.IGNORECASE),  # ? params
        re.compile(r"""cursor\.execute\s*\(\s*["'][^"']*%s[^"']*["']\s*,\s*\(""", re.IGNORECASE),  # %s tuple
        re.compile(r"""\.filter\s*\(""", re.IGNORECASE),  # ORM filter
        re.compile(r"""\.objects\.\w+\(""", re.IGNORECASE),  # Django ORM
    ]

    def analyze_file(self, filepath: str) -> List[Dict]:
        """
        Scan a single file for unsafe SQL patterns.
        Returns list of findings.
        """
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
                lines = content.splitlines()
        except OSError:
            return findings

        for regex, description in self.UNSAFE_SQL_PATTERNS:
            for m in regex.finditer(content):
                line_no = content[: m.start()].count("\n") + 1
                line_text = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                findings.append({
                    "file": filepath,
                    "line": line_no,
                    "code": line_text,
                    "issue": description,
                    "severity": "HIGH",
                })

        return findings

    def analyze_directory(self, directory: str) -> List[Dict]:
        """Scan an entire directory tree for unsafe SQL patterns."""
        import os
        all_findings = []
        for dirpath, _, filenames in os.walk(directory):
            for fname in filenames:
                if fname.endswith((".py", ".js", ".ts", ".php")):
                    full = os.path.join(dirpath, fname)
                    all_findings.extend(self.analyze_file(full))
        return all_findings
