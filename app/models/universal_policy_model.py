from dataclasses import dataclass
from typing import List, Optional

@dataclass
class UniversalPolicy:

    name: str

    source_entities: List[str]
    destination_entities: List[str]

    applications: List[str]
    services: List[str]

    action: str

    log_start: bool
    log_end: bool

    security_profiles: List[str]

    identity_sources: Optional[List[str]]

    description: Optional[str]

    priority: Optional[int]