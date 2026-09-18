import logging
from typing import Dict, Any, List, Optional
from ml.source_profiler.profiler import UnknownSourceProfiler
from ml.semantic_mapper.mapper import SemanticMapper
from ml.ai_assist.assistant import LocalAIAssistant

logger = logging.getLogger(__name__)

class OnboardingOrchestrator:
    """
    Control-plane state machine linking Profiling (Stage 7), 
    Semantic Mapping (Stage 8), and AI Escalation (Stage 9) into a 
    resumable ParserSpec onboarding workflow.
    """
    def __init__(self, profiler: Optional[UnknownSourceProfiler] = None,
                 mapper: Optional[SemanticMapper] = None,
                 ai_assistant: Optional[LocalAIAssistant] = None):
        self.profiler = profiler or UnknownSourceProfiler()
        self.mapper = mapper or SemanticMapper()
        self.ai_assistant = ai_assistant or LocalAIAssistant()

    def run_pipeline(self, source_id: str, log_lines: List[str]) -> Dict[str, Any]:
        """Runs end-to-end ingestion profiling, field mapping, and AI escalation."""
        if not log_lines:
            raise ValueError("log_lines list cannot be empty.")

        # Stage 7: Unknown Source Profiler (expects List[str])
        profile = self.profiler.profile(log_lines)
        
        # Extract profiled fields
        if hasattr(profile, "fields"):
            profiled_fields = profile.fields
        elif isinstance(profile, dict):
            profiled_fields = profile.get("fields", [])
        else:
            profiled_fields = []

        # Extract detected format
        if hasattr(profile, "format"):
            detected_format = str(profile.format)
        elif hasattr(profile, "detected_format"):
            detected_format = str(profile.detected_format)
        elif isinstance(profile, dict):
            detected_format = str(profile.get("format", profile.get("detected_format", "unknown")))
        else:
            detected_format = "unknown"

        # Stage 8: Semantic Mapper
        mapping_result = self.mapper.map_fields(profiled_fields)
        
        auto_accepted = mapping_result.get("auto_accept", []) if isinstance(mapping_result, dict) else getattr(mapping_result, "auto_accept", [])
        human_review = mapping_result.get("human_review", []) if isinstance(mapping_result, dict) else getattr(mapping_result, "human_review", [])
        abstained = mapping_result.get("abstained", []) if isinstance(mapping_result, dict) else getattr(mapping_result, "abstained", [])

        # Stage 9: AI Escalation for fields needing human review or abstained
        escalated_fields = human_review + abstained
        ai_candidate_specs = []

        if escalated_fields:
            log_sample = "\n".join(log_lines[:5])
            ai_spec = self.ai_assistant.propose_mappings(
                candidate_id=f"cand_{source_id}",
                source_format=detected_format,
                unmapped_fields=escalated_fields,
                log_sample=log_sample
            )
            ai_candidate_specs.append(ai_spec)

        # Assemble execution package
        status = "READY_FOR_REVIEW" if escalated_fields else "AUTO_APPROVED"
        
        parser_spec_package = {
            "source_id": source_id,
            "status": status,
            "detected_format": detected_format,
            "deterministic_mappings": auto_accepted,
            "escalated_fields": escalated_fields,
            "ai_candidate_specs": ai_candidate_specs,
            "metadata": {
                "total_fields": len(profiled_fields),
                "auto_accepted_count": len(auto_accepted),
                "escalated_count": len(escalated_fields)
            }
        }

        return parser_spec_package
