import logging
from typing import Dict, Any, Optional, List
from ml.spec_compiler.schemas import CompiledParserSpec

logger = logging.getLogger(__name__)

class SpecDeploymentEngine:
    """
    Manages spec registry publishing, hot-swapping active worker parsers, 
    and maintains atomic rollback capabilities.
    """
    def __init__(self):
        self.active_registry: Dict[str, CompiledParserSpec] = {}
        self.revision_history: Dict[str, List[CompiledParserSpec]] = {}

    def deploy_spec(self, spec: CompiledParserSpec, validation_passed: bool) -> Dict[str, Any]:
        """Deploys a validated spec to the active registry atomically."""
        if not validation_passed:
            raise ValueError(f"Cannot deploy spec {spec.spec_id}: Test bench validation failed.")

        source_id = spec.source_id
        
        # Save previous spec to history for rollback support
        if source_id in self.active_registry:
            if source_id not in self.revision_history:
                self.revision_history[source_id] = []
            self.revision_history[source_id].append(self.active_registry[source_id])

        # Atomic hot-reload update
        self.active_registry[source_id] = spec
        logger.info(f"Successfully hot-reloaded spec {spec.spec_id} for source {source_id}")

        return {
            "status": "DEPLOYED",
            "source_id": source_id,
            "active_spec_id": spec.spec_id,
            "spec_hash": spec.spec_hash,
            "version": spec.version
        }

    def rollback(self, source_id: str) -> Dict[str, Any]:
        """Rolls back the active spec for source_id to the previous revision."""
        if source_id not in self.revision_history or not self.revision_history[source_id]:
            raise KeyError(f"No historical revision available for rollback on source: {source_id}")

        previous_spec = self.revision_history[source_id].pop()
        self.active_registry[source_id] = previous_spec
        logger.warning(f"Rolled back source {source_id} to spec {previous_spec.spec_id}")

        return {
            "status": "ROLLED_BACK",
            "source_id": source_id,
            "active_spec_id": previous_spec.spec_id,
            "spec_hash": previous_spec.spec_hash
        }

    def get_active_spec(self, source_id: str) -> Optional[CompiledParserSpec]:
        """Retrieves currently deployed active parser spec."""
        return self.active_registry.get(source_id)
