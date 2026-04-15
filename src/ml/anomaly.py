"""Anomaly ensemble scaffolding for telecom session signals."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class AnomalyEnsemble:
    """Thin interface for blended anomaly scoring.

    The first iteration is intentionally lightweight: callers can provide any
    detector objects with a ``fit`` and ``decision_function``/``predict_proba``
    style API later without changing the rest of the pipeline.
    """

    detectors: list[object] = field(default_factory=list)

    def fit(self, rows: Iterable[list[float]]) -> "AnomalyEnsemble":
        data = list(rows)
        for detector in self.detectors:
            fit = getattr(detector, "fit", None)
            if callable(fit):
                fit(data)
        return self

    def score_rows(self, rows: Iterable[list[float]]) -> list[float]:
        data = list(rows)
        if not self.detectors:
            return [0.0 for _ in data]

        blended: list[float] = []
        for idx, row in enumerate(data):
            values: list[float] = []
            for detector in self.detectors:
                if hasattr(detector, "decision_function"):
                    result = detector.decision_function([row])
                    values.append(float(result[0]))
                elif hasattr(detector, "predict_proba"):
                    result = detector.predict_proba([row])
                    values.append(float(result[0][-1]))
            blended.append(sum(values) / len(values) if values else 0.0)
        return blended
