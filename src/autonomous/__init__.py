"""Autonomous RCA orchestration components.

Keep package exports lazy so importing a single autonomous submodule does not
re-enter ``src.autonomous.engine`` during package initialization.
"""

from importlib import import_module

__all__ = [
    "AgentCoordinator",
    "AutonomousRCAEngine",
    "CausalGraphEngine",
    "CausalInferenceEngine",
    "ConfidenceEngine",
    "GraphStore",
    "SyntheticTraceGenerator",
    "TelecomKnowledgeGraph",
    "TimeSeriesIntelligenceEngine",
]

_EXPORT_MAP = {
    "AgentCoordinator": ("src.autonomous.agent_coordinator", "AgentCoordinator"),
    "AutonomousRCAEngine": ("src.autonomous.engine", "AutonomousRCAEngine"),
    "CausalGraphEngine": ("src.autonomous.causal_graph", "CausalGraphEngine"),
    "CausalInferenceEngine": ("src.autonomous.causal_inference", "CausalInferenceEngine"),
    "ConfidenceEngine": ("src.autonomous.confidence_engine", "ConfidenceEngine"),
    "GraphStore": ("src.autonomous.graph_store", "GraphStore"),
    "SyntheticTraceGenerator": ("src.autonomous.synthetic_trace_generator", "SyntheticTraceGenerator"),
    "TelecomKnowledgeGraph": ("src.autonomous.knowledge_graph", "TelecomKnowledgeGraph"),
    "TimeSeriesIntelligenceEngine": ("src.autonomous.timeseries_engine", "TimeSeriesIntelligenceEngine"),
}


def __getattr__(name: str):
    if name not in _EXPORT_MAP:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _EXPORT_MAP[name]
    module = import_module(module_name)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value
