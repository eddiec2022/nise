from abc import ABC, abstractmethod
from typing import Dict


class BaseCollector(ABC):
    @abstractmethod
    def collect(self) -> Dict:
        pass