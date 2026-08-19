"""
models.py
---------
Pydantic schemas used across the API for request validation and response typing.
"""

from typing import Optional, List
from pydantic import BaseModel, Field


class DecoyRequest(BaseModel):
    """Payload for manually requesting a fresh decoy be generated."""
    template_type: str = Field(
        ...,
        description="One of: env_config, db_dump, s3_bucket, ssh_key, admin_creds",
    )
    company_context: Optional[str] = Field(
        default="a mid-size fintech company called NovaPay",
        description="Free-text context to make the decoy feel realistic/contextual.",
    )


class AlertOut(BaseModel):
    id: int
    timestamp: str
    source_ip: str
    user_agent: Optional[str]
    method: str
    path: str
    query_params: Optional[str]
    headers: Optional[str]
    payload: Optional[str]
    decoy_type: Optional[str]
    canary_token: Optional[str]
    severity: str


class StatsOut(BaseModel):
    total_alerts: int
    unique_ips: int
    top_decoys: List[dict]
    top_ips: List[dict]
    canaries_triggered: int
