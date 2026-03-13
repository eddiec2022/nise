from typing import Dict, Type

from app.parsers.base import BaseParser
from app.parsers.palo_alto_parser import PaloAltoParser


class ParserRegistry:
    def __init__(self) -> None:
        self._registry: Dict[str, Type[BaseParser]] = {
            "palo_alto": PaloAltoParser,
        }

    def get_parser_class(self, parser_name: str) -> Type[BaseParser] | None:
        return self._registry.get(parser_name)