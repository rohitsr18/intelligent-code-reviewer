"""Parallel Multi-File Review Engine & Sub-2s Fast-Path Triage.

Eliminates CodeRabbit latency bottlenecks and multi-minute async wait times.
Concurrently reviews multiple modified files in parallel using bounded worker
pools, and fast-paths documentation, trivial patches, and non-logic updates
through deterministic local heuristics in milliseconds.
"""

import asyncio
import os
import re
import time
from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from app.reviewer.models import (
    ReviewAnalysisResult,
    ReviewFinding,
    FindingCategory,
    FindingSeverity,
    GrowthTip,
)
from app.reviewer.engine import BaseReviewEngine, get_review_engine
from app.reviewer.diff_pruner import DiffPruner


class FileDiffUnit(BaseModel):
    filename: str
    diff_content: str
    language: str
    line_count: int
    is_fast_path: bool = False
    fast_path_reason: Optional[str] = None


class BatchReviewEngine:
    """Orchestrates concurrent multi-file reviews and fast-path triage."""

    DOC_EXTENSIONS = {".md", ".markdown", ".rst", ".txt", ".adoc", ".docs"}
    LANGUAGE_MAP = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
        ".rs": "rust",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".c": "c",
        ".cs": "csharp",
        ".rb": "ruby",
        ".php": "php",
        ".sql": "sql",
        ".html": "html",
        ".css": "css",
        ".json": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".toml": "toml",
        ".sh": "bash",
        ".bash": "bash",
    }

    def __init__(
        self,
        engine: Optional[BaseReviewEngine] = None,
        max_concurrency: int = 5,
    ) -> None:
        self.engine = engine or get_review_engine()
        self.max_concurrency = max_concurrency
        self.pruner = DiffPruner()

    def detect_language(self, filename: str) -> str:
        """Determines programming language based on file extension."""
        _, ext = os.path.splitext(filename.lower())
        return self.LANGUAGE_MAP.get(ext, "python")

    def classify_file_unit(self, filename: str, content: str) -> Tuple[bool, Optional[str]]:
        """Determines if a file qualifies for sub-2s fast-path evaluation."""
        _, ext = os.path.splitext(filename.lower())

        # 1. Documentation fast-path
        if ext in self.DOC_EXTENSIONS:
            return True, f"Documentation file ({ext})"

        # 2. Config & static markup fast-path
        if ext in {".json", ".yaml", ".yml", ".toml", ".ini", ".env.example"}:
            added_lines = [l for l in content.splitlines() if l.startswith("+") and not l.startswith("+++")]
            if len(added_lines) <= 20:
                return True, f"Lightweight configuration edit ({len(added_lines)} lines)"

        # 3. Micro patches (< 4 lines changed without control flow/keywords)
        added_lines = [l for l in content.splitlines() if l.startswith("+") and not l.startswith("+++")]
        if len(added_lines) <= 3:
            raw_text = " ".join(added_lines).lower()
            risk_keywords = ["eval", "exec", "password", "token", "key", "secret", "auth", "admin", "delete"]
            if not any(kw in raw_text for kw in risk_keywords):
                return True, f"Micro patch ({len(added_lines)} added lines)"

        return False, None

    def split_diff_into_units(self, raw_diff: str) -> List[FileDiffUnit]:
        """Parses a multi-file unified git diff into individual FileDiffUnits."""
        if not raw_diff or not raw_diff.strip():
            return []

        # First prune generated lockfiles and vendor blobs
        prune_res = self.pruner.prune_diff(raw_diff)
        clean_diff = prune_res.clean_diff if prune_res.clean_diff else raw_diff

        lines = clean_diff.splitlines()
        chunks: List[Tuple[str, List[str]]] = []
        current_file: Optional[str] = None
        current_lines: List[str] = []

        header_re = re.compile(r"^diff --git a/(.*?) b/(.*)$")
        alt_re = re.compile(r"^\+\+\+ b/(.*)$")

        for line in lines:
            m = header_re.match(line)
            if m:
                if current_file is not None:
                    chunks.append((current_file, current_lines))
                current_file = m.group(2)
                current_lines = [line]
                continue

            if current_file is None:
                alt_m = alt_re.match(line)
                if alt_m:
                    current_file = alt_m.group(1)
                    current_lines = [line]
                    continue

            current_lines.append(line)

        if current_file is not None and current_lines:
            chunks.append((current_file, current_lines))

        # Fallback if no git diff header found (treat as single file)
        if not chunks:
            chunks.append(("unknown.py", lines))

        units: List[FileDiffUnit] = []
        for fname, flines in chunks:
            fcontent = "\n".join(flines)
            is_fast, reason = self.classify_file_unit(fname, fcontent)
            units.append(
                FileDiffUnit(
                    filename=fname,
                    diff_content=fcontent,
                    language=self.detect_language(fname),
                    line_count=len(flines),
                    is_fast_path=is_fast,
                    fast_path_reason=reason,
                )
            )

        return units

    async def _evaluate_fast_path(self, unit: FileDiffUnit) -> ReviewAnalysisResult:
        """Deterministic sub-2s local heuristic evaluation for docs and minor edits."""
        start_time = time.time()
        findings: List[ReviewFinding] = []
        lines = unit.diff_content.splitlines()

        for idx, line in enumerate(lines, start=1):
            if line.startswith("+") and not line.startswith("+++"):
                stripped = line[1:].strip()
                # Check for empty markdown links [text]()
                if "[" in stripped and "](" in stripped and "]()" in stripped:
                    findings.append(
                        ReviewFinding(
                            category=FindingCategory.MAINTAINABILITY,
                            severity=FindingSeverity.LOW,
                            title="Empty Markdown Link Target",
                            description="Markdown hyperlink contains an empty URL destination.",
                            line_start=idx,
                            suggested_fix=stripped.replace("]()", "](https://example.com)"),
                            rule_id="DOC-001",
                        )
                    )

        latency_ms = (time.time() - start_time) * 1000
        overall_score = 98 if not findings else 88

        return ReviewAnalysisResult(
            overall_score=overall_score,
            summary=f"Fast-path heuristic evaluation completed for {unit.filename} ({unit.fast_path_reason or 'Trivial patch'}).",
            category_scores={
                "bugs": 100,
                "architecture": 95,
                "security": 100,
                "performance": 100,
                "maintainability": 95,
            },
            findings=findings,
            growth_tips=[],
            model_used="fast-path-heuristic-engine",
            evaluation_latency_ms=round(latency_ms, 2),
            total_files_reviewed=1,
            fast_path_files_count=1,
            parallel_speedup_factor=1.0,
        )

    async def review_file_unit(
        self,
        unit: FileDiffUnit,
        semaphore: asyncio.Semaphore,
        rules: Optional[List[str]] = None,
        min_severity: Optional[str] = "low",
    ) -> ReviewAnalysisResult:
        """Evaluates a single file diff unit with concurrency management."""
        if unit.is_fast_path:
            return await self._evaluate_fast_path(unit)

        async with semaphore:
            res = await self.engine.analyze(
                code=unit.diff_content,
                language=unit.language,
                filename=unit.filename,
                rules=rules,
                min_severity=min_severity,
            )
            # Prefix finding titles with filename if multiple files are reviewed
            for f in res.findings:
                if unit.filename and not f.title.startswith(f"[{unit.filename}]"):
                    f.title = f"[{unit.filename}] {f.title}"
            return res

    def aggregate_batch_results(
        self,
        results: List[Tuple[FileDiffUnit, ReviewAnalysisResult]],
        total_wall_time_ms: float,
    ) -> ReviewAnalysisResult:
        """Combines multiple per-file reviews into a unified PR review report."""
        if not results:
            return ReviewAnalysisResult(
                overall_score=100,
                summary="No reviewable files in diff.",
                category_scores={},
                findings=[],
                model_used="batch-coordinator",
                evaluation_latency_ms=0.0,
            )

        if len(results) == 1:
            unit, single_res = results[0]
            single_res.total_files_reviewed = 1
            single_res.fast_path_files_count = 1 if unit.is_fast_path else 0
            single_res.parallel_speedup_factor = 1.0
            single_res.evaluation_latency_ms = round(total_wall_time_ms, 2)
            return single_res

        all_findings: List[ReviewFinding] = []
        all_style_nits: List[ReviewFinding] = []
        seen_tips = set()
        all_tips: List[GrowthTip] = []
        category_totals: Dict[str, List[int]] = {}
        cumulative_latency_ms = 0.0
        fast_path_count = 0

        for unit, res in results:
            if unit.is_fast_path:
                fast_path_count += 1
            cumulative_latency_ms += res.evaluation_latency_ms
            all_findings.extend(res.findings)
            all_style_nits.extend(res.style_nits)

            for tip in res.growth_tips:
                if tip.topic not in seen_tips:
                    seen_tips.add(tip.topic)
                    all_tips.append(tip)

            for cat, val in res.category_scores.items():
                category_totals.setdefault(cat, []).append(val)

        # Average category scores across files
        merged_scores = {
            cat: int(sum(vals) / len(vals)) for cat, vals in category_totals.items()
        }

        # Calculate composite overall score
        all_scores = [res.overall_score for _, res in results]
        overall_score = int(sum(all_scores) / len(all_scores)) if all_scores else 90

        # Sort findings by severity (critical first)
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        all_findings.sort(
            key=lambda x: severity_order.get(x.severity.value, 0),
            reverse=True,
        )

        # Compute parallel speedup factor
        speedup = (
            round(cumulative_latency_ms / max(total_wall_time_ms, 1.0), 2)
            if cumulative_latency_ms > 0
            else 1.0
        )

        summary = (
            f"Parallel multi-file review completed across {len(results)} files "
            f"({fast_path_count} fast-pathed, {len(all_findings)} issues identified). "
            f"Achieved ~{speedup}x concurrent throughput speedup."
        )

        return ReviewAnalysisResult(
            overall_score=overall_score,
            summary=summary,
            category_scores=merged_scores,
            findings=all_findings,
            style_nits=all_style_nits,
            noise_reduction_applied=(len(all_style_nits) > 0),
            growth_tips=all_tips,
            model_used=f"parallel-batch-coordinator (x{len(results)} files)",
            evaluation_latency_ms=round(total_wall_time_ms, 2),
            total_files_reviewed=len(results),
            fast_path_files_count=fast_path_count,
            parallel_speedup_factor=speedup,
        )

    async def analyze_diff_parallel(
        self,
        raw_diff: str,
        rules: Optional[List[str]] = None,
        min_severity: Optional[str] = "low",
    ) -> ReviewAnalysisResult:
        """Main entrypoint: parses, triages, reviews in parallel, and aggregates results."""
        start_time = time.time()
        units = self.split_diff_into_units(raw_diff)

        if not units:
            return ReviewAnalysisResult(
                overall_score=100,
                summary="Empty or non-code diff submitted.",
                evaluation_latency_ms=0.0,
            )

        semaphore = asyncio.Semaphore(self.max_concurrency)

        # Concurrently review each file
        async def _run_unit(u: FileDiffUnit) -> Tuple[FileDiffUnit, ReviewAnalysisResult]:
            res = await self.review_file_unit(u, semaphore, rules=rules, min_severity=min_severity)
            return u, res

        tasks = [_run_unit(u) for u in units]
        results = await asyncio.gather(*tasks)

        total_wall_time_ms = (time.time() - start_time) * 1000
        return self.aggregate_batch_results(results, total_wall_time_ms)

