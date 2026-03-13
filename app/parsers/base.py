from abc import ABC, abstractmethod

from app.models.normalized_firewall_model import FirewallConfig


class BaseParser(ABC):
    @abstractmethod
    def parse(self) -> FirewallConfig:
        pass