from typing import Dict, Type

from app.collectors.base import BaseCollector
from app.collectors.palo_alto_api_collector import PaloAltoAPICollector


class CollectorRegistry:
    def __init__(self) -> None:
        self._registry: Dict[str, Type[BaseCollector]] = {
            "palo_alto_api": PaloAltoAPICollector,
        }

    def get_collector_class(self, collector_name: str):
        return self._registry.get(collector_name)