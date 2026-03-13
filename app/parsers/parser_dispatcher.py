from app.models.normalized_firewall_model import FirewallConfig
from app.parsers.parser_registry import ParserRegistry
from app.utils.config_detector import ConfigDetector


class ParserDispatcher:
    def __init__(self) -> None:
        self.detector = ConfigDetector()
        self.registry = ParserRegistry()

    def parse(self, file_path: str) -> tuple[dict, FirewallConfig]:
        detection = self.detector.detect(file_path)

        parser_name = detection.get("parser", "unknown")
        parser_class = self.registry.get_parser_class(parser_name)

        if parser_class is None:
            raise ValueError(
                f"No parser implemented for parser '{parser_name}' "
                f"(vendor={detection.get('vendor')}, config_type={detection.get('config_type')})"
            )

        parser = parser_class(file_path)
        config = parser.parse()

        return detection, config