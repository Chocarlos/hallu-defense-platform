from __future__ import annotations

from evals.runners.scenarios import evaluate_scenarios, load_scenarios, _history_payload


def test_expanded_eval_scenarios_cover_required_surfaces() -> None:
    scenarios = load_scenarios()
    ids = {scenario["id"] for scenario in scenarios}

    assert {
        "doc_partially_false_answer",
        "doc_contradictory_sources",
        "code_false_test_claim_without_evidence",
        "code_false_file_claim_with_sandbox_inspection",
        "code_false_function_claim_with_sandbox_inspection",
        "code_semantic_implementation_claim_without_changed_terms",
        "code_fix_claim_rejects_broad_successful_command",
        "code_fix_claim_supported_by_targeted_command",
        "tool_invalid_input_schema",
        "tool_high_risk_without_approval",
        "tool_secret_leakage_redaction",
        "tool_contradictory_output_requires_repair",
        "direct_prompt_injection_blocked",
        "indirect_prompt_injection_blocked",
        "data_poisoning_blocked",
        "direct_prompt_injection_text_blocked",
        "indirect_prompt_injection_document_blocked",
        "data_poisoning_document_blocked",
        "sandbox_path_traversal",
        "sandbox_destructive_command_abuse",
        "sandbox_network_denied_abuse",
    }.issubset(ids)


def test_expanded_eval_scenarios_pass_deterministically() -> None:
    report = evaluate_scenarios(write_report=False)

    assert report["metrics"]["scenario_count"] == 21
    assert report["metrics"]["pass_rate"] == 1.0
    assert report["metrics"]["verification_decision_accuracy"] == 1.0
    assert report["metrics"]["blocked_high_risk_rate"] == 1.0
    assert report["metrics"]["secret_redaction_rate"] == 1.0
    assert report["metrics"]["prompt_injection_block_rate"] == 1.0
    assert report["metrics"]["data_poisoning_block_rate"] == 1.0
    assert report["metrics"]["tool_contradiction_guard_rate"] == 1.0
    assert report["metrics"]["repo_false_claim_block_rate"] == 1.0
    assert report["metrics"]["repo_semantic_claim_decision_accuracy"] == 1.0
    assert report["metrics"]["sandbox_block_rate"] == 1.0
    assert all(scenario["passed"] for scenario in report["scenarios"])


def test_scenario_history_payload_is_bounded_and_ordered() -> None:
    metrics = {
        "scenario_count": 21,
        "passed_count": 21,
        "pass_rate": 1.0,
        "category_pass_rate": {"documents": 1.0},
        "verification_decision_accuracy": 1.0,
        "blocked_high_risk_rate": 1.0,
        "secret_redaction_rate": 1.0,
        "prompt_injection_block_rate": 1.0,
        "data_poisoning_block_rate": 1.0,
        "tool_contradiction_guard_rate": 1.0,
        "repo_false_claim_block_rate": 1.0,
        "repo_semantic_claim_decision_accuracy": 1.0,
        "sandbox_block_rate": 1.0,
        "p95_latency_ms": 4.2,
    }

    payload = _history_payload(
        [
            {"run_id": "scenario-oldest", "created_at": "2026-07-08T00:00:00Z", "metrics": metrics},
            {"run_id": "scenario-previous", "created_at": "2026-07-08T00:01:00Z", "metrics": metrics},
        ],
        metrics,
        run_id="scenario-latest",
        created_at="2026-07-08T00:02:00Z",
        limit=2,
    )

    assert [run["run_id"] for run in payload["runs"]] == ["scenario-previous", "scenario-latest"]
    assert payload["runs"][-1]["metrics"]["pass_rate"] == 1.0
