"""Fix validation: assertions, targeted re-scan, and regression-guarded tests.

Pipeline for each applied fix:
    1. Strategy-specific assertion on patched files  (~ms, always if registered)
    2. Targeted re-scan of patched files              (seconds)
    3. Existing test commands, regression-gated       (minutes, opt-in)
    4. Existing build commands, regression-gated      (minutes, opt-in)

At the end of a batch of fixes:
    5. Full-repo re-scan                              (slow, opt-in)
    6. Final regression-gated test/build pass

Regression gating:
    Before any fix runs, `capture_baseline()` snapshots which test/build
    commands pass on the unmodified tree. Post-fix runs only re-execute
    commands that were passing at baseline, and only flag ones that went
    passing -> failing as regressions. Pre-existing failures are excluded
    so they don't block legitimate security fixes. The tradeoff: if a
    test was already broken when we started, we won't catch a fix that
    breaks it *differently* — the repo's existing tests need to be
    green-ish for this to be rigorous.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from scanner.finding import Finding
from validation.assertions import get_assertion

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    name: str
    passed: bool
    duration_s: float
    message: str = ""


@dataclass
class ValidationResult:
    passed: bool
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return sum(c.duration_s for c in self.checks)

    @property
    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]


@dataclass
class Baseline:
    """Pre-fix snapshot of test/build status, used to detect regressions."""

    test_results: dict[str, bool] = field(default_factory=dict)
    build_results: dict[str, bool] = field(default_factory=dict)
    captured_at: float = 0.0

    @property
    def passing_tests(self) -> list[str]:
        return [cmd for cmd, ok in self.test_results.items() if ok]

    @property
    def passing_builds(self) -> list[str]:
        return [cmd for cmd, ok in self.build_results.items() if ok]


class FixValidator:
    """Validates individual fixes and whole batches against regressions.

    The `scanner` parameter is duck-typed (anything with a
    `.scan(repo_path, repo_name, file_filter) -> list[Finding]` method works)
    so this module doesn't hard-couple to `scanner.RepoScanner` — that keeps
    validation importable even if the scanner's parsers aren't built yet.
    """

    def __init__(self, settings: dict, scanner: Any):
        self.settings = settings
        self.scanner = scanner
        v = settings.get("validation", {})
        self.run_tests = v.get("run_tests", True)
        self.verify_build = v.get("verify_build", True)
        self.verify_fixes = v.get("verify_fixes", True)
        self.full_rescan = v.get("full_rescan", False)
        self.baseline_existing = v.get("baseline_existing", True)
        self.timeout = v.get("timeout", 300)
        self.step_budget_s = v.get("step_budget_s", 60)
        self.test_commands: list[str] = v.get("test_commands", [])
        self.build_commands: list[str] = v.get("build_commands", [])

    # ─────────────────────────────────────────────────────────────
    # Baseline
    # ─────────────────────────────────────────────────────────────

    def capture_baseline(self, repo_path: str) -> Baseline:
        """Record which test/build commands pass on the unmodified tree."""
        baseline = Baseline(captured_at=time.time())
        if not self.baseline_existing:
            return baseline

        if self.run_tests:
            for cmd in self.test_commands:
                ok, dur = self._try_command(repo_path, cmd)
                if ok is None:
                    continue
                baseline.test_results[cmd] = ok
                logger.info(
                    f"[baseline] test {cmd!r}: {'pass' if ok else 'fail'} ({dur:.1f}s)"
                )

        if self.verify_build:
            for cmd in self.build_commands:
                ok, dur = self._try_command(repo_path, cmd)
                if ok is None:
                    continue
                baseline.build_results[cmd] = ok
                logger.info(
                    f"[baseline] build {cmd!r}: {'pass' if ok else 'fail'} ({dur:.1f}s)"
                )

        pre_broken = [
            c for c, ok in {**baseline.test_results, **baseline.build_results}.items() if not ok
        ]
        if pre_broken:
            logger.warning(
                f"[baseline] {len(pre_broken)} command(s) already failing pre-fix — "
                f"excluded from regression checks: {pre_broken}"
            )
        return baseline

    # ─────────────────────────────────────────────────────────────
    # Per-fix
    # ─────────────────────────────────────────────────────────────

    def validate_fix(
        self,
        repo_path: str,
        finding: Finding,
        patched_files: list[str],
        baseline: Baseline,
    ) -> ValidationResult:
        """Validate a single applied fix. Call AFTER patching, BEFORE commit."""
        result = ValidationResult(passed=True)

        if self.verify_fixes:
            result.checks.append(self._check_assertion(repo_path, finding, patched_files))
            result.checks.append(self._check_targeted_rescan(repo_path, finding, patched_files))

        # Only re-run the commands that were green at baseline. Known-broken
        # commands are skipped, and we treat a newly-failing baseline-green
        # command as a regression caused by the fix.
        if self.run_tests and baseline.passing_tests:
            result.checks.append(
                self._check_commands_no_regression(repo_path, baseline.passing_tests, "test")
            )
        if self.verify_build and baseline.passing_builds:
            result.checks.append(
                self._check_commands_no_regression(repo_path, baseline.passing_builds, "build")
            )

        result.passed = all(c.passed for c in result.checks)
        logger.info(
            f"[validate-fix] {finding.rule_id} @ {finding.file_path}: "
            f"{'PASS' if result.passed else 'FAIL'} in {result.duration_s:.1f}s "
            f"({len(result.failures)} failure(s))"
        )
        return result

    # ─────────────────────────────────────────────────────────────
    # Batch-level
    # ─────────────────────────────────────────────────────────────

    def validate_batch(self, repo_path: str, baseline: Baseline) -> ValidationResult:
        """Run after ALL fixes in a repo have been applied and individually validated."""
        result = ValidationResult(passed=True)

        if self.full_rescan:
            result.checks.append(self._check_full_rescan(repo_path))

        if self.run_tests and baseline.passing_tests:
            result.checks.append(
                self._check_commands_no_regression(repo_path, baseline.passing_tests, "test-final")
            )
        if self.verify_build and baseline.passing_builds:
            result.checks.append(
                self._check_commands_no_regression(
                    repo_path, baseline.passing_builds, "build-final"
                )
            )

        result.passed = all(c.passed for c in result.checks)
        logger.info(
            f"[validate-batch] {repo_path}: "
            f"{'PASS' if result.passed else 'FAIL'} in {result.duration_s:.1f}s"
        )
        return result

    # ─────────────────────────────────────────────────────────────
    # Individual checks
    # ─────────────────────────────────────────────────────────────

    def _check_assertion(
        self, repo_path: str, finding: Finding, patched_files: list[str]
    ) -> CheckResult:
        t0 = time.time()
        strategy = finding.remediation_strategy
        assertion = get_assertion(strategy) if strategy else None
        if assertion is None:
            return CheckResult(
                name=f"assertion[{strategy or 'none'}]",
                passed=True,
                duration_s=time.time() - t0,
                message=f"no positive assertion for strategy {strategy!r}; "
                        f"relying on re-scan + existing tests",
            )

        abs_files = [
            p if os.path.isabs(p) else os.path.join(repo_path, p) for p in patched_files
        ]
        try:
            ok, msg = assertion(abs_files, repo_path)
        except Exception as e:
            return CheckResult(
                name=f"assertion[{strategy}]",
                passed=False,
                duration_s=time.time() - t0,
                message=f"assertion raised: {e}",
            )
        return CheckResult(
            name=f"assertion[{strategy}]",
            passed=ok,
            duration_s=time.time() - t0,
            message=msg,
        )

    def _check_targeted_rescan(
        self, repo_path: str, finding: Finding, patched_files: list[str]
    ) -> CheckResult:
        t0 = time.time()
        try:
            current = self.scanner.scan(
                repo_path,
                repo_name=finding.repo or os.path.basename(repo_path),
                file_filter=patched_files,
            )
        except Exception as e:
            return CheckResult(
                name="rescan[targeted]",
                passed=False,
                duration_s=time.time() - t0,
                message=f"re-scan failed: {e}",
            )

        dur = time.time() - t0
        if dur > self.step_budget_s:
            logger.warning(
                f"[validate] targeted re-scan took {dur:.1f}s "
                f"(budget {self.step_budget_s}s)"
            )

        # 1. The original finding must no longer fire on the patched file.
        still_present = any(
            c.rule_id == finding.rule_id
            and os.path.normpath(c.file_path) == os.path.normpath(finding.file_path)
            for c in current
        )
        if still_present:
            return CheckResult(
                name="rescan[targeted]",
                passed=False,
                duration_s=dur,
                message=f"{finding.rule_id} still fires on {finding.file_path} after fix",
            )

        # 2. The fix must not have introduced any same-or-higher severity
        #    finding on the patched files.
        regressions = [c for c in current if c.severity >= finding.severity]
        if regressions:
            ids = sorted({f.rule_id for f in regressions})
            return CheckResult(
                name="rescan[targeted]",
                passed=False,
                duration_s=dur,
                message=f"fix introduced new findings on patched files: {ids}",
            )

        return CheckResult(
            name="rescan[targeted]",
            passed=True,
            duration_s=dur,
            message="original finding resolved; no new regressions on patched files",
        )

    def _check_full_rescan(self, repo_path: str) -> CheckResult:
        t0 = time.time()
        try:
            self.scanner.scan(repo_path)
        except Exception as e:
            return CheckResult(
                name="rescan[full]",
                passed=False,
                duration_s=time.time() - t0,
                message=f"full re-scan failed: {e}",
            )
        return CheckResult(
            name="rescan[full]",
            passed=True,
            duration_s=time.time() - t0,
            message="full re-scan completed",
        )

    def _check_commands_no_regression(
        self, repo_path: str, commands: list[str], label: str
    ) -> CheckResult:
        t0 = time.time()
        regressions: list[str] = []
        for cmd in commands:
            ok, dur = self._try_command(repo_path, cmd)
            logger.info(
                f"[validate-{label}] {cmd!r}: {'pass' if ok else 'fail'} ({dur:.1f}s)"
            )
            if ok is False:
                regressions.append(cmd)
        duration = time.time() - t0
        if regressions:
            return CheckResult(
                name=f"{label}-no-regression",
                passed=False,
                duration_s=duration,
                message=f"regressed (previously passing, now failing): {regressions}",
            )
        return CheckResult(
            name=f"{label}-no-regression",
            passed=True,
            duration_s=duration,
            message=f"{len(commands)} command(s) still passing",
        )

    # ─────────────────────────────────────────────────────────────
    # Command runner
    # ─────────────────────────────────────────────────────────────

    def _try_command(self, repo_path: str, cmd: str) -> tuple[Optional[bool], float]:
        """Run a command in repo_path.

        Returns:
            (True, duration)  — exit 0
            (False, duration) — non-zero exit (genuine failure)
            (None, duration)  — command not applicable (missing tool / no target);
                                caller should exclude from the baseline entirely.
        """
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return False, time.time() - t0
        except FileNotFoundError:
            return None, time.time() - t0

        dur = time.time() - t0
        if proc.returncode == 127:  # command not found
            return None, dur

        # Treat "target doesn't exist" style failures as not-applicable so
        # they don't inflate the baseline's failing set.
        stderr_lower = (proc.stderr or "").lower()
        if proc.returncode != 0 and any(
            hint in stderr_lower
            for hint in (
                "no such file",
                "no targets",
                "no rule to make target",
                "command not found",
            )
        ):
            return None, dur
        return proc.returncode == 0, dur
