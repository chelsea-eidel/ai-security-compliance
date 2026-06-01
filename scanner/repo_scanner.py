"""Main scanner that orchestrates all detection tools against a repository."""

from __future__ import annotations

import os
import re
import subprocess
import logging
from pathlib import Path
from typing import Optional

import yaml

from scanner.finding import Finding, Severity

# Parsers are imported defensively so the package stays importable while they
# are still being built. A tool whose parser is missing is skipped with a
# warning rather than crashing the whole scan.
try:
    from scanner.parsers.semgrep_parser import SemgrepParser
except ImportError:
    SemgrepParser = None  # type: ignore[assignment]
try:
    from scanner.parsers.trivy_parser import TrivyParser
except ImportError:
    TrivyParser = None  # type: ignore[assignment]
try:
    from scanner.parsers.secrets_parser import SecretsParser
except ImportError:
    SecretsParser = None  # type: ignore[assignment]
try:
    from scanner.parsers.config_parser import ConfigComplianceParser
except ImportError:
    ConfigComplianceParser = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class RepoScanner:
    """Scans a single repository for security compliance issues."""

    def __init__(self, rules_path: str, settings: dict):
        with open(rules_path) as f:
            self.rules = yaml.safe_load(f)
        self.settings = settings
        self.parsers = {}
        if SemgrepParser is not None:
            self.parsers["semgrep"] = SemgrepParser()
        if TrivyParser is not None:
            self.parsers["trivy"] = TrivyParser()
        if SecretsParser is not None:
            self.parsers["gitleaks"] = SecretsParser()
        self.config_parser = (
            ConfigComplianceParser(self.rules) if ConfigComplianceParser is not None else None
        )

    def scan(
        self,
        repo_path: str,
        repo_name: str = "",
        file_filter: Optional[list[str]] = None,
    ) -> list[Finding]:
        """Run all enabled scans and return unified findings.

        file_filter: optional list of paths (absolute or repo-relative) to
        restrict the returned findings to. The tools still run across the full
        repo — the filter is applied post-hoc — so this is correct but not yet
        a speed optimization. True per-file tool invocation is a future change
        that belongs in each parser's scan method.
        """
        repo_path = os.path.abspath(repo_path)
        if not repo_name:
            repo_name = os.path.basename(repo_path)

        findings: list[Finding] = []
        scan_cfg = self.settings.get("scan", {}).get("tools", {})

        if scan_cfg.get("semgrep", True):
            findings.extend(self._run_semgrep(repo_path, repo_name))

        if scan_cfg.get("trivy", True):
            findings.extend(self._run_trivy(repo_path, repo_name))

        if scan_cfg.get("gitleaks", True):
            findings.extend(self._run_gitleaks(repo_path, repo_name))

        if scan_cfg.get("custom_rules", True):
            findings.extend(self._run_custom_rules(repo_path, repo_name))

        # Filter by minimum severity
        min_sev = self.settings.get("scan", {}).get("min_severity", "medium")
        threshold = Severity.from_str(min_sev)
        findings = [f for f in findings if f.severity >= threshold]

        if file_filter is not None:
            findings = self._filter_to_files(findings, repo_path, file_filter)

        # Attach remediation metadata from rules
        self._attach_remediation_info(findings)

        logger.info(f"[{repo_name}] Found {len(findings)} issues above {min_sev} severity")
        return findings

    @staticmethod
    def _filter_to_files(
        findings: list[Finding], repo_path: str, file_filter: list[str]
    ) -> list[Finding]:
        normalized = {
            os.path.normpath(p if os.path.isabs(p) else os.path.join(repo_path, p))
            for p in file_filter
        }

        def matches(f: Finding) -> bool:
            fp = f.file_path
            abs_fp = fp if os.path.isabs(fp) else os.path.join(repo_path, fp)
            return os.path.normpath(abs_fp) in normalized

        return [f for f in findings if matches(f)]

    def _run_semgrep(self, repo_path: str, repo_name: str) -> list[Finding]:
        if "semgrep" not in self.parsers:
            logger.warning("semgrep parser not available, skipping")
            return []
        logger.info(f"[{repo_name}] Running Semgrep...")
        try:
            result = subprocess.run(
                [
                    "semgrep", "scan",
                    "--config", "auto",
                    "--json",
                    "--quiet",
                    repo_path,
                ],
                capture_output=True, text=True, timeout=300,
            )
            return self.parsers["semgrep"].parse(result.stdout, repo_name)
        except FileNotFoundError:
            logger.warning("semgrep not installed, skipping")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"[{repo_name}] semgrep timed out")
            return []

    def _run_trivy(self, repo_path: str, repo_name: str) -> list[Finding]:
        if "trivy" not in self.parsers:
            logger.warning("trivy parser not available, skipping")
            return []
        logger.info(f"[{repo_name}] Running Trivy...")
        try:
            result = subprocess.run(
                [
                    "trivy", "fs",
                    "--format", "json",
                    "--quiet",
                    repo_path,
                ],
                capture_output=True, text=True, timeout=300,
            )
            return self.parsers["trivy"].parse(result.stdout, repo_name)
        except FileNotFoundError:
            logger.warning("trivy not installed, skipping")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"[{repo_name}] trivy timed out")
            return []

    def _run_gitleaks(self, repo_path: str, repo_name: str) -> list[Finding]:
        if "gitleaks" not in self.parsers:
            logger.warning("gitleaks parser not available, skipping")
            return []
        logger.info(f"[{repo_name}] Running Gitleaks...")
        try:
            result = subprocess.run(
                [
                    "gitleaks", "detect",
                    "--source", repo_path,
                    "--report-format", "json",
                    "--report-path", "/dev/stdout",
                    "--no-banner",
                ],
                capture_output=True, text=True, timeout=300,
            )
            return self.parsers["gitleaks"].parse(result.stdout, repo_name)
        except FileNotFoundError:
            logger.warning("gitleaks not installed, skipping")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"[{repo_name}] gitleaks timed out")
            return []

    def _run_custom_rules(self, repo_path: str, repo_name: str) -> list[Finding]:
        """Run pattern-based custom compliance rules from compliance_rules.yaml."""
        if self.config_parser is None:
            logger.warning("custom-rules parser not available, skipping")
            return []
        logger.info(f"[{repo_name}] Running custom compliance rules...")
        return self.config_parser.scan(repo_path, repo_name)

    def _attach_remediation_info(self, findings: list[Finding]):
        """Enrich findings with remediation strategy from rules config."""
        rule_map = {}
        for category in self.rules.get("categories", {}).values():
            for rule in category.get("rules", []):
                rule_map[rule["id"]] = rule

        for finding in findings:
            rule = rule_map.get(finding.rule_id)
            if rule and "remediation" in rule:
                finding.remediation_strategy = rule["remediation"].get("strategy", "")
                finding.ai_assisted = rule["remediation"].get("ai_assisted", False)
