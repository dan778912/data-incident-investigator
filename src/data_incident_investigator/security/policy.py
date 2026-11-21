from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel

from data_incident_investigator.domain.diagnostics import (
    TOOL_ARGUMENT_MODELS,
    DiagnosticRequest,
)
from data_incident_investigator.domain.remediation import ApprovalDecision, RemediationPlan


class PolicyViolation(ValueError):
    """Raised when a model proposal crosses an enforceable capability boundary."""


class PolicyGateway:
    def __init__(self, *, max_patch_operations: int = 5) -> None:
        self._max_patch_operations = max_patch_operations
        self._consumed_nonces: set[str] = set()

    def validate_diagnostic_request(self, request: DiagnosticRequest) -> BaseModel:
        argument_model = TOOL_ARGUMENT_MODELS.get(request.tool)
        if argument_model is None:
            raise PolicyViolation(f"diagnostic tool is not allowlisted: {request.tool}")
        try:
            return argument_model.model_validate(request.arguments)
        except ValueError as exc:
            raise PolicyViolation(f"invalid arguments for {request.tool}: {exc}") from exc

    def validate_plan(self, plan: RemediationPlan) -> None:
        if len(plan.operations) > self._max_patch_operations:
            raise PolicyViolation("remediation plan exceeds the operation limit")
        if not plan.citation_ids:
            raise PolicyViolation("remediation plans require at least one supporting citation")
        if plan.plan_hash != plan.calculate_hash():
            raise PolicyViolation("remediation plan hash is invalid")

    def authorize_plan(self, plan: RemediationPlan, decision: ApprovalDecision) -> None:
        self.validate_plan(plan)
        if not decision.approved:
            raise PolicyViolation("the remediation was rejected")
        if decision.plan_id != plan.plan_id:
            raise PolicyViolation("approval references a different remediation plan")
        if decision.plan_hash != plan.plan_hash:
            raise PolicyViolation("approval is stale because the remediation plan changed")
        if decision.source_sha256 != plan.source_sha256:
            raise PolicyViolation("approval is stale because the source artifact changed")
        if decision.expires_at <= datetime.now(UTC):
            raise PolicyViolation("approval has expired")
        nonce = str(decision.nonce)
        if nonce in self._consumed_nonces:
            raise PolicyViolation("approval nonce has already been consumed")
        self._consumed_nonces.add(nonce)
