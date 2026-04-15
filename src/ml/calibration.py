"""Confidence calibration scaffolding for RCA confidence outputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

try:
    from sklearn.isotonic import IsotonicRegression
except Exception:  # pragma: no cover - dependency may be optional in some envs
    IsotonicRegression = None


@dataclass
class ConfidenceCalibrator:
    """Small wrapper around isotonic calibration for RCA confidence."""

    _model: object | None = None

    def fit(self, scores: Iterable[float], labels: Iterable[int]) -> "ConfidenceCalibrator":
        if IsotonicRegression is None:
            raise RuntimeError("scikit-learn is required for confidence calibration")
        self._model = IsotonicRegression(out_of_bounds="clip")
        self._model.fit(list(scores), list(labels))
        return self

    def predict(self, scores: Iterable[float]) -> list[float]:
        if self._model is None:
            return [float(score) for score in scores]
        return [float(value) for value in self._model.predict(list(scores))]

    def calibrate(self, score: float) -> float:
        return self.predict([score])[0]
