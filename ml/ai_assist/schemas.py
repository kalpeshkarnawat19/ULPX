from typing import Dict, Any, Set

# Canonical Target Registry (Strict validation to eliminate hallucinated target fields)
CANONICAL_SCHEMA_REGISTRY: Set[str] = {
    "src.ip", "src.port", "src.mac", "src.host",
    "dst.ip", "dst.port", "dst.mac", "dst.host",
    "dest.ip", "dest.port", "dest.mac", "dest.host",
    "event.action", "event.category", "event.outcome", "event.type",
    "user.name", "user.id", "user.domain", "user.email", "user.role",
    "http.request.method", "http.request.url", "http.response.status_code",
    "process.name", "process.pid", "process.parent.pid", "process.command_line",
    "network.protocol", "network.bytes_in", "network.bytes_out", "network.packets",
    "file.path", "file.name", "file.size", "file.hash.sha256"
}

# Strict JSON Schema definition for candidate ParserSpecs
PARSER_CANDIDATE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "candidate_id": {"type": "string"},
        "source_format": {"type": "string"},
        "mapped_fields": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "raw_field": {"type": "string"},
                    "canonical_field": {"type": "string"},
                    "confidence": {"type": "number"},
                    "reasoning": {"type": "string"}
                },
                "required": ["raw_field", "canonical_field", "confidence", "reasoning"]
            }
        },
        "unmapped_fields": {
            "type": "array",
            "items": {"type": "string"}
        }
    },
    "required": ["candidate_id", "source_format", "mapped_fields", "unmapped_fields"]
}
