"""Confidence calibration across rules, causal inference, patterns, and agents."""

from __future__ import annotations


class ConfidenceEngine:
    """Combines heterogeneous RCA evidence into calibrated confidence."""

    def score(self, *, rule_rca=None, pattern_match=None, anomaly_result=None, causal_result=None, agent_result=None) -> dict:
        rule_rca = rule_rca or {}
        scores = {}

        def _bump(label, weight):
            if not label:
                return
            scores[label] = scores.get(label, 0.0) + float(weight)

        rule_label = rule_rca.get("rca_label", "UNKNOWN")
        rule_score = min(1.0, max(0.0, float(rule_rca.get("confidence_pct", 0)) / 100.0))
        _bump(rule_label, 0.4 * rule_score)

        pattern_similarity = 0.0
        historical_success = 0.5
        if pattern_match:
            pattern_similarity = float(pattern_match.get("similarity", 0.0))
            historical_success = float(pattern_match.get("historical_success", pattern_match.get("confidence", 0.5)))
            _bump(pattern_match.get("root_cause"), 0.2 * pattern_similarity * historical_success)

        anomaly_score = 0.0
        if anomaly_result and anomaly_result.get("is_anomalous"):
            anomaly_score = float(anomaly_result.get("score", 0.0))
            _bump(anomaly_result.get("suggested_root_cause", rule_label), 0.05 * anomaly_score)

        causal_score = 0.0
        if causal_result:
            causal_score = float(causal_result.get("causal_strength", causal_result.get("confidence", 0.0)))
            _bump(causal_result.get("root_cause", rule_label), 0.2 * causal_score)

        agent_consensus = 0.0
        if agent_result:
            top = agent_result.get("top_hypothesis") or {}
            agent_consensus = float(agent_result.get("consensus_score", top.get("confidence", 0.0)))
            _bump(top.get("label", rule_label), 0.15 * agent_consensus)

        final_label = max(scores.items(), key=lambda item: item[1])[0] if scores else rule_label
        ordered = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        winner = ordered[0][1] if ordered else rule_score
        runner_up = ordered[1][1] if len(ordered) > 1 else 0.0
        margin = max(0.0, winner - runner_up)
        uncertainty = round(max(0.0, 1.0 - min(1.0, margin * 2.5)), 4)
        consensus = 1.0 - uncertainty

        calibrated = (
            (winner * 0.55)
            + (historical_success * 0.15)
            + (consensus * 0.2)
            + ((1.0 - min(1.0, anomaly_score)) * 0.1)
        )
        calibrated = round(min(0.99, max(0.2, calibrated)), 4)

        return {
            "final_label": final_label,
            "confidence_score": calibrated,
            "confidence_pct": int(round(calibrated * 100)),
            "uncertainty": uncertainty,
            "consensus": round(consensus, 4),
            "source_scores": {
                "rule_score": round(rule_score, 4),
                "pattern_score": round(pattern_similarity * historical_success, 4),
                "anomaly_score": round(anomaly_score, 4),
                "causal_score": round(causal_score, 4),
                "agent_score": round(agent_consensus, 4),
            },
        }
