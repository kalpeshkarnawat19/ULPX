from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional

class TargetRuntime(Enum):
    VECTOR_REMAP = "vector_remap"
    LOGSTASH = "logstash"
    PYTHON_NATIVE = "python_native"

@dataclass
class FieldMapping:
    raw_field: str
    canonical_field: str
    transformer: Optional[str] = None
    override_applied: bool = False

@dataclass
class CompiledParserSpec:
    spec_id: str
    source_id: str
    version: int
    target_runtime: TargetRuntime
    mappings: List[FieldMapping]
    compiled_code: str
    spec_hash: str
