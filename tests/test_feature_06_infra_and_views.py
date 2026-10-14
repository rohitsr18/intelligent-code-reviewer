import os
from unittest.mock import MagicMock
import pytest
from app.analytics.views import (
    VIEW_DEFINITIONS,
    get_rendered_view_sql,
    provision_looker_views,
)


def test_rendered_view_sql_formatting():
    sql = get_rendered_view_sql(
        view_name="vw_developer_scorecard",
        project_id="test-proj",
        dataset_id="test_dataset",
    )
    assert "test-proj.test_dataset.review_events" in sql
    assert "avg_code_score" in sql
    assert "high_severity_defect_density_per_kloc" in sql


def test_code_quality_trends_view_sql():
    sql = get_rendered_view_sql(
        view_name="vw_code_quality_trends",
        project_id="test-proj",
        dataset_id="test_dataset",
    )
    assert "test-proj.test_dataset.review_events" in sql
    assert "review_date" in sql
    assert "daily_avg_score" in sql


def test_recurring_anti_patterns_view_sql():
    sql = get_rendered_view_sql(
        view_name="vw_recurring_anti_patterns",
        project_id="test-proj",
        dataset_id="test_dataset",
    )
    assert "test-proj.test_dataset.historical_rules" in sql
    assert "test-proj.test_dataset.review_events" in sql
    assert "total_enforcements" in sql


def test_get_rendered_view_sql_unknown_view_fails():
    with pytest.raises(ValueError) as exc:
        get_rendered_view_sql("vw_unknown", "proj", "ds")
    assert "is not defined" in str(exc.value)


def test_provision_looker_views_with_mock_client():
    mock_client = MagicMock()
    results = provision_looker_views(
        client=mock_client,
        project_id="my-gcp-project",
        dataset_id="code_reviewer_analytics",
    )
    assert len(results) == 3
    assert all(results.values())
    assert mock_client.create_table.call_count == 3


def test_terraform_files_integrity():
    tf_dir = "terraform"
    assert os.path.isdir(tf_dir)
    expected_files = [
        "main.tf",
        "variables.tf",
        "cloud_run.tf",
        "bigquery.tf",
        "firestore.tf",
        "iam.tf",
        "outputs.tf",
    ]
    for filename in expected_files:
        path = os.path.join(tf_dir, filename)
        assert os.path.isfile(path), f"Missing terraform file: {path}"
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            assert len(content) > 20, f"File {path} is suspiciously empty"


def test_github_actions_workflows_integrity():
    workflows_dir = ".github/workflows"
    assert os.path.isdir(workflows_dir)
    ci_path = os.path.join(workflows_dir, "ci.yml")
    cd_path = os.path.join(workflows_dir, "cd.yml")
    assert os.path.isfile(ci_path)
    assert os.path.isfile(cd_path)

    with open(ci_path, "r", encoding="utf-8") as f:
        ci_text = f.read()
        assert "pytest" in ci_text
        assert "actions/checkout" in ci_text

    with open(cd_path, "r", encoding="utf-8") as f:
        cd_text = f.read()
        assert "deploy-cloudrun" in cd_text
        assert "google-github-actions/auth" in cd_text


def test_docs_integrity():
    docs_dir = "docs"
    assert os.path.isdir(docs_dir)
    looker_doc = os.path.join(docs_dir, "LOOKER_STUDIO_SETUP.md")
    deploy_doc = os.path.join(docs_dir, "DEPLOYMENT_RUNBOOK.md")
    assert os.path.isfile(looker_doc)
    assert os.path.isfile(deploy_doc)
