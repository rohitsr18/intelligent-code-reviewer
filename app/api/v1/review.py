import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.v1.models import (
    ReviewSubmissionRequest,
    ReviewSubmissionResponse,
    ReviewDetailResponse,
    RedactionSummary,
    LanguageDetectRequest,
    LanguageDetectResponse,
    DependencyAuditRequest,
    DependencyAuditResponse,
    SASTScanRequest,
    SASTScanResponse,
    TestAuditRequest,
    TestAuditResponse,
    IntentSweepRequest,
    IntentSweepResponse,
    SUPPORTED_LANGUAGES,
)
from app.auth.models import AuthenticatedUser
from app.auth.iap import get_current_user
from app.core.config import get_settings
from app.core.rate_limiter import check_api_rate_limit
from app.security.sanitizer import CodeSanitizer
from app.security.prompt_guard import PromptGuard
from app.reviewer.engine import BaseReviewEngine, get_review_engine
from app.analytics.service import HistoricalLearningService, get_historical_learning_service
from app.storage.service import StorageService, get_storage_service
from app.storage.models import ReviewDocument
from app.reviewer.diff_pruner import DiffPruner
from app.reviewer.batch_engine import BatchReviewEngine
from app.reviewer.language_detector import LanguageDetector
from app.reviewer.dependency_auditor import DependencyAuditor
from app.reviewer.sast_scanner import SASTScanner
from app.reviewer.test_auditor import TestHealthAuditor
from app.reviewer.intent_sweeper import IntentArtifactSweeper

router = APIRouter(prefix="/review", tags=["Review"])

# In-memory submission store for fast fallback
_review_store: Dict[str, Dict[str, Any]] = {}


def get_sanitizer() -> CodeSanitizer:
    settings = get_settings()
    return CodeSanitizer(
        entropy_threshold=settings.entropy_threshold,
        scan_secrets=settings.secret_scanning_enabled,
        scan_pii=settings.pii_redaction_enabled,
    )


def get_prompt_guard() -> PromptGuard:
    return PromptGuard()


@router.post(
    "/submit",
    response_model=ReviewSubmissionResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(check_api_rate_limit)],
)
async def submit_code_for_review(
    submission: ReviewSubmissionRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    sanitizer: CodeSanitizer = Depends(get_sanitizer),
    guard: PromptGuard = Depends(get_prompt_guard),
    engine: BaseReviewEngine = Depends(get_review_engine),
    learning_service: HistoricalLearningService = Depends(get_historical_learning_service),
    storage_service: StorageService = Depends(get_storage_service),
) -> ReviewSubmissionResponse:
    settings = get_settings()

    # Payload size and line limit checks
    code_bytes = len(submission.code.encode("utf-8"))
    if code_bytes > settings.max_code_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Code payload ({code_bytes} bytes) exceeds limit of {settings.max_code_size_bytes} bytes",
        )

    code_lines = len(submission.code.splitlines())
    if code_lines > settings.max_code_lines:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Code length ({code_lines} lines) exceeds limit of {settings.max_code_lines} lines",
        )

    # 0. Intelligent Diff Pruning & Token Optimization
    pruner = DiffPruner()
    prune_res = pruner.prune_diff(submission.code)
    code_to_review = prune_res.clean_diff if prune_res.clean_diff else submission.code
    pruning_summary = {
        "pruned_files_count": prune_res.pruned_files_count,
        "reviewed_files_count": prune_res.reviewed_files_count,
        "tokens_saved_estimate": prune_res.estimated_tokens_saved,
        "reduction_percentage": prune_res.reduction_percentage,
        "pruned_files": [p.model_dump() for p in prune_res.pruned_files],
    } if prune_res.pruned_files_count > 0 else None

    # 1. Automatic Language Detection from extension or code syntax
    detector = LanguageDetector()
    detect_res = detector.detect(code_to_review, filename=submission.filename)
    effective_language = (
        detect_res.detected_language
        if submission.language in ("auto", "", None)
        else submission.language
    )

    # 2. Scrub credentials and PII
    sanitization_result = sanitizer.sanitize(code_to_review)

    # 3. Guard against prompt injection and isolate boundaries
    guard_result = guard.inspect_and_wrap(
        code=sanitization_result.sanitized_code,
        language=effective_language,
        context=submission.context or "",
    )

    review_id = str(uuid.uuid4())
    submitted_at = datetime.now(timezone.utc)

    # Determine status flag
    if not guard_result.is_safe:
        review_status = "flagged_risk"
    elif sanitization_result.has_secrets or sanitization_result.has_pii:
        review_status = "sanitized"
    else:
        review_status = "accepted"

    redaction_summaries = [
        RedactionSummary(
            secret_type=r.secret_type,
            redaction_token=r.redaction_token,
            line_number=r.line_number,
        )
        for r in sanitization_result.redactions
    ]

    # 4. Retrieve matching team rules from BigQuery historical engine
    active_rules = await learning_service.get_enrichment_rules(language=effective_language)
    prompt_rules = learning_service.format_rules_for_prompt(active_rules)

    # 4.5 Dependency & License Auditing
    dep_auditor = DependencyAuditor()
    dep_audit_res = dep_auditor.audit_dependencies(
        code_or_diff=submission.code,
        filename=submission.filename,
    )
    dep_findings = dep_audit_res.to_review_findings()

    # 4.6 AST-based Static Application Security Testing (SAST) Scanner
    sast_scanner = SASTScanner()
    sast_res = sast_scanner.scan(
        code=code_to_review,
        language=effective_language,
        filename=submission.filename,
    )
    sast_findings = sast_res.to_review_findings()

    # 4.7 Test Health, Flakiness, and Coverage Auditor
    test_auditor = TestHealthAuditor()
    if "diff --git a/" in submission.code:
        test_audit_res = test_auditor.audit_diff(submission.code)
    else:
        test_audit_res = test_auditor.audit_code(
            code=code_to_review,
            filename=submission.filename,
            language=effective_language,
        )
    test_findings = test_audit_res.to_review_findings()

    # 4.8 PR Intent Verification & Leftover Artifact Sweeper
    intent_sweeper = IntentArtifactSweeper()
    intent_report = intent_sweeper.verify_intent(
        code_or_diff=submission.code,
        context=submission.context,
        filename=submission.filename,
        language=effective_language,
    )
    intent_findings = intent_report.to_review_findings()

    # 5. Analyze code with AI review engine enriched with team rules
    # Multi-file git diffs automatically use parallel batching & sub-2s fast-path triage
    if "diff --git a/" in guard_result.secured_prompt or "\n+++ b/" in guard_result.secured_prompt:
        batch_engine = BatchReviewEngine(engine=engine)
        analysis = await batch_engine.analyze_diff_parallel(
            raw_diff=guard_result.secured_prompt,
            rules=prompt_rules,
            min_severity=submission.min_severity,
        )
    else:
        analysis = await engine.analyze(
            code=guard_result.secured_prompt,
            language=effective_language,
            filename=submission.filename,
            context=submission.context,
            rules=prompt_rules,
            min_severity=submission.min_severity,
        )

    # Inject dependency audit findings & calibrate security score
    if dep_findings and analysis:
        analysis.findings = dep_findings + analysis.findings
        if dep_audit_res.vulnerable_packages_count > 0:
            analysis.category_scores["security"] = max(
                20, analysis.category_scores.get("security", 90) - (dep_audit_res.vulnerable_packages_count * 25)
            )
            analysis.overall_score = max(
                25, analysis.overall_score - (dep_audit_res.vulnerable_packages_count * 15)
            )

    # Inject SAST static vulnerabilities & calibrate security score
    if sast_findings and analysis:
        analysis.findings = sast_findings + analysis.findings
        sec_penalty = (sast_res.critical_count * 30) + (sast_res.high_count * 15) + (sast_res.medium_count * 5)
        if sec_penalty > 0:
            analysis.category_scores["security"] = max(
                10, analysis.category_scores.get("security", 95) - sec_penalty
            )
            analysis.overall_score = max(
                20, analysis.overall_score - int(sec_penalty * 0.6)
            )

    # Inject test health and flakiness findings
    if test_findings and analysis:
        analysis.findings = analysis.findings + test_findings

    # Inject intent verification and artifact sweep findings
    if intent_findings and analysis:
        analysis.findings = analysis.findings + intent_findings

    dep_summary = dep_audit_res.model_dump() if dep_audit_res.is_manifest else None
    sast_summary = {
        "language": sast_res.language,
        "total_findings": sast_res.total_findings,
        "critical_count": sast_res.critical_count,
        "high_count": sast_res.high_count,
        "medium_count": sast_res.medium_count,
        "low_count": sast_res.low_count,
        "findings": [f.model_dump() for f in sast_res.findings],
    } if sast_res.total_findings > 0 else None

    test_audit_summary = {
        "is_test_file": test_audit_res.is_test_file,
        "total_test_cases": test_audit_res.total_test_cases,
        "impacted_test_files": test_audit_res.impacted_test_files,
        "has_missing_coverage": test_audit_res.has_missing_coverage,
        "findings": [f.model_dump() for f in test_audit_res.findings],
    } if (test_audit_res.is_test_file or test_audit_res.findings) else None

    intent_audit_summary = {
        "intent_alignment_score": intent_report.intent_alignment_score,
        "is_aligned": intent_report.is_aligned,
        "scope_drift_detected": intent_report.scope_drift_detected,
        "drift_reasons": intent_report.drift_reasons,
        "unintended_files": intent_report.unintended_files,
        "missing_stated_items": intent_report.missing_stated_items,
        "total_artifacts_count": intent_report.total_artifacts_count,
        "artifact_findings": [f.model_dump() for f in intent_report.artifact_findings],
    } if (intent_report.scope_drift_detected or intent_report.total_artifacts_count > 0) else None

    # 6. Record analytical telemetry in BigQuery
    await learning_service.record_review_event(
        review_id=review_id,
        user_id=user.user_id,
        user_email=user.email,
        language=effective_language,
        filename=submission.filename,
        original_line_count=sanitization_result.original_line_count,
        sanitized_secrets_count=sanitization_result.total_redactions,
        prompt_risk_score=guard_result.risk_score,
        review_status=review_status,
        analysis=analysis,
        rules_applied_count=len(prompt_rules),
    )

    review_doc = ReviewDocument(
        review_id=review_id,
        user_id=user.user_id,
        submitted_by=user.email,
        submitted_at=submitted_at,
        status=review_status,
        filename=submission.filename,
        language=effective_language,
        original_line_count=sanitization_result.original_line_count,
        sanitized_code=sanitization_result.sanitized_code,
        secured_prompt=guard_result.secured_prompt,
        redactions=[r.model_dump() for r in redaction_summaries],
        risk_score=guard_result.risk_score,
        is_safe_prompt=guard_result.is_safe,
        flags=guard_result.flags,
        rules_applied_count=len(prompt_rules),
        pruning_summary=pruning_summary,
        dependency_audit=dep_summary,
        sast_summary=sast_summary,
        test_audit_summary=test_audit_summary,
        intent_audit_summary=intent_audit_summary,
        analysis=analysis.model_dump() if analysis else None,
    )

    await storage_service.save_review(review_doc)

    record = {
        "review_id": review_id,
        "status": review_status,
        "user_id": user.user_id,
        "submitted_by": user.email,
        "submitted_at": submitted_at,
        "filename": submission.filename,
        "language": effective_language,
        "detected_language_confidence": detect_res.confidence,
        "detected_by": detect_res.detected_by,
        "original_line_count": sanitization_result.original_line_count,
        "sanitized_code": sanitization_result.sanitized_code,
        "secured_prompt": guard_result.secured_prompt,
        "redactions": redaction_summaries,
        "risk_score": guard_result.risk_score,
        "is_safe_prompt": guard_result.is_safe,
        "flags": guard_result.flags,
        "rules_applied_count": len(prompt_rules),
        "pruning_summary": pruning_summary,
        "dependency_audit": dep_summary,
        "sast_summary": sast_summary,
        "test_audit_summary": test_audit_summary,
        "intent_audit_summary": intent_audit_summary,
        "analysis": analysis,
    }

    _review_store[review_id] = record

    return ReviewSubmissionResponse(
        review_id=review_id,
        status=review_status,
        original_line_count=sanitization_result.original_line_count,
        redactions_count=sanitization_result.total_redactions,
        redactions=redaction_summaries,
        risk_score=guard_result.risk_score,
        is_safe_prompt=guard_result.is_safe,
        flags=guard_result.flags,
        submitted_by=user.email,
        submitted_at=submitted_at,
        filename=submission.filename,
        language=effective_language,
        detected_language_confidence=detect_res.confidence,
        detected_by=detect_res.detected_by,
        rules_applied_count=len(prompt_rules),
        pruning_summary=pruning_summary,
        dependency_audit=dep_summary,
        sast_summary=sast_summary,
        test_audit_summary=test_audit_summary,
        intent_audit_summary=intent_audit_summary,
        analysis=analysis,
    )


@router.post(
    "/audit-dependencies",
    response_model=DependencyAuditResponse,
    summary="Audit package manifest dependencies for CVEs and copyleft license risks",
)
async def audit_dependencies_endpoint(
    req: DependencyAuditRequest,
    user: AuthenticatedUser = Depends(get_current_user),
) -> DependencyAuditResponse:
    auditor = DependencyAuditor()
    res = auditor.audit_dependencies(req.manifest_content, filename=req.filename)
    return DependencyAuditResponse(
        manifest_type=res.manifest_type,
        is_manifest=res.is_manifest,
        total_dependencies_scanned=res.total_dependencies_scanned,
        vulnerable_packages_count=res.vulnerable_packages_count,
        license_violations_count=res.license_violations_count,
        dependencies=[d.model_dump() for d in res.dependencies],
        findings=[f.model_dump() for f in res.findings],
    )


@router.post(
    "/scan-sast",
    response_model=SASTScanResponse,
    summary="Perform AST and static application security testing (SAST) on code",
)
async def scan_sast_endpoint(
    req: SASTScanRequest,
    user: AuthenticatedUser = Depends(get_current_user),
) -> SASTScanResponse:
    scanner = SASTScanner()
    res = scanner.scan(code=req.code, language=req.language, filename=req.filename)
    return SASTScanResponse(
        language=res.language,
        total_findings=res.total_findings,
        critical_count=res.critical_count,
        high_count=res.high_count,
        medium_count=res.medium_count,
        low_count=res.low_count,
        findings=[f.model_dump() for f in res.findings],
    )


@router.post(
    "/audit-tests",
    response_model=TestAuditResponse,
    summary="Audit test suite health, flakiness, tautologies, and coverage impact",
)
async def audit_tests_endpoint(
    req: TestAuditRequest,
    user: AuthenticatedUser = Depends(get_current_user),
) -> TestAuditResponse:
    auditor = TestHealthAuditor()
    if "diff --git a/" in req.code:
        res = auditor.audit_diff(req.code)
    else:
        res = auditor.audit_code(code=req.code, filename=req.filename, language=req.language)
    return TestAuditResponse(
        is_test_file=res.is_test_file,
        total_test_cases=res.total_test_cases,
        impacted_test_files=res.impacted_test_files,
        has_missing_coverage=res.has_missing_coverage,
        findings=[f.model_dump() for f in res.findings],
    )


@router.post(
    "/sweep-artifacts",
    response_model=IntentSweepResponse,
    summary="Verify PR intent alignment and sweep for leftover debugging artifacts",
)
async def sweep_artifacts_endpoint(
    req: IntentSweepRequest,
    user: AuthenticatedUser = Depends(get_current_user),
) -> IntentSweepResponse:
    sweeper = IntentArtifactSweeper()
    report = sweeper.verify_intent(
        code_or_diff=req.code,
        context=req.context,
        filename=req.filename,
        language=req.language,
    )
    return IntentSweepResponse(
        intent_alignment_score=report.intent_alignment_score,
        is_aligned=report.is_aligned,
        scope_drift_detected=report.scope_drift_detected,
        drift_reasons=report.drift_reasons,
        unintended_files=report.unintended_files,
        missing_stated_items=report.missing_stated_items,
        total_artifacts_count=report.total_artifacts_count,
        artifact_findings=[f.model_dump() for f in report.artifact_findings],
    )


@router.post(
    "/detect-language",
    response_model=LanguageDetectResponse,
    summary="Automatically detect programming language from code and filename",
)
async def detect_language_endpoint(
    req: LanguageDetectRequest,
) -> LanguageDetectResponse:
    detector = LanguageDetector()
    res = detector.detect(req.code, filename=req.filename)
    return LanguageDetectResponse(
        detected_language=res.detected_language,
        confidence=res.confidence,
        detected_by=res.detected_by,
        is_ambiguous=res.is_ambiguous,
        candidate_scores=res.candidate_scores,
        supported_languages=sorted(list(SUPPORTED_LANGUAGES - {"auto"})),
    )


@router.get(
    "/{review_id}",
    response_model=ReviewDetailResponse,
)
async def get_review_submission(
    review_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    storage_service: StorageService = Depends(get_storage_service),
) -> ReviewDetailResponse:
    # First check persistent Firestore
    doc = await storage_service.get_review(review_id)
    if doc:
        if not user.is_reviewer_or_above and user.user_id != doc.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access forbidden: you can only view your own review submissions",
            )
        return ReviewDetailResponse(
            review_id=doc.review_id,
            status=doc.status,
            submitted_by=doc.submitted_by,
            submitted_at=doc.submitted_at,
            filename=doc.filename,
            language=doc.language,
            original_line_count=doc.original_line_count,
            redactions_count=len(doc.redactions),
            sanitized_code=doc.sanitized_code,
            risk_score=doc.risk_score,
            is_safe_prompt=doc.is_safe_prompt,
            flags=doc.flags,
            rules_applied_count=doc.rules_applied_count,
            feedback=doc.feedback.model_dump() if doc.feedback else None,
            session_id=doc.session_id,
            pruning_summary=doc.pruning_summary,
            dependency_audit=doc.dependency_audit,
            sast_summary=doc.sast_summary,
            test_audit_summary=doc.test_audit_summary,
            intent_audit_summary=doc.intent_audit_summary,
            analysis=doc.analysis,
        )

    # In-memory fallback
    record = _review_store.get(review_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review submission '{review_id}' not found",
        )

    if not user.is_reviewer_or_above and user.user_id != record["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: you can only view your own review submissions",
        )

    return ReviewDetailResponse(
        review_id=record["review_id"],
        status=record["status"],
        submitted_by=record["submitted_by"],
        submitted_at=record["submitted_at"],
        filename=record.get("filename"),
        language=record["language"],
        original_line_count=record["original_line_count"],
        redactions_count=len(record.get("redactions", [])),
        sanitized_code=record["sanitized_code"],
        risk_score=record["risk_score"],
        is_safe_prompt=record["is_safe_prompt"],
        flags=record.get("flags", []),
        rules_applied_count=record.get("rules_applied_count", 0),
        pruning_summary=record.get("pruning_summary"),
        dependency_audit=record.get("dependency_audit"),
        sast_summary=record.get("sast_summary"),
        test_audit_summary=record.get("test_audit_summary"),
        intent_audit_summary=record.get("intent_audit_summary"),
        analysis=record.get("analysis"),
    )
