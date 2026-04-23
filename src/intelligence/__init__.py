"""Self-improving RCA intelligence layer.

Keep package exports lazy so importing a single intelligence submodule does not
pull in the learning loop and autonomous engine during package initialization.
"""

from importlib import import_module

__all__ = [
    "KnowledgeBaseDoctor",
    "KnowledgeCompactor",
    "KnowledgeEngine",
    "LearningLoop",
    "SkillExporter",
    "VectorStore",
    "run_learning_cycle",
]

_EXPORT_MAP = {
    "KnowledgeBaseDoctor": ("src.intelligence.knowledge_doctor", "KnowledgeBaseDoctor"),
    "KnowledgeCompactor": ("src.intelligence.compaction_engine", "KnowledgeCompactor"),
    "KnowledgeEngine": ("src.intelligence.knowledge_engine", "KnowledgeEngine"),
    "LearningLoop": ("src.intelligence.learning_loop", "LearningLoop"),
    "SkillExporter": ("src.intelligence.skill_exporter", "SkillExporter"),
    "VectorStore": ("src.intelligence.vector_store", "VectorStore"),
    "run_learning_cycle": ("src.intelligence.learning_loop", "run_learning_cycle"),
}


def __getattr__(name: str):
    if name not in _EXPORT_MAP:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _EXPORT_MAP[name]
    module = import_module(module_name)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value
