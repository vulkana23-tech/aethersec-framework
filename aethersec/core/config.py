"""
Configuration parameters for AetherSec.
"""

from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass
class Config:
    request_timeout: float = 10.0
    max_concurrent_requests: int = 20
    user_agent: str = "AetherSec-Defensive-Audit-Engine/1.0"
    enable_timing_analysis: bool = True
    eventual_consistency_threshold_ms: float = 150.0
    max_ast_depth: int = 5
    default_headers: Dict[str, str] = field(
        default_factory=lambda: {
            "Accept": "application/json",
            "User-Agent": "AetherSec-Defensive-Audit-Engine/1.0",
        }
    )


DEFAULT_CONFIG = Config()
