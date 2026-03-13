from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class TrafficIdentity:
    source_ip: str
    destination_ip: str
    application: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    candidate_applications: List[str] = field(default_factory=list)
    candidate_services: Set[str] = field(default_factory=set)
    inference_confidence: str = "none"

    def has_application_context(self) -> bool:
        return bool(self.application or self.candidate_applications)

    def has_service_context(self) -> bool:
        return bool(self.candidate_services)


class TrafficIdentityBuilder:
    """
    Normalizes troubleshooting input into a consistent traffic identity.

    Supported inputs:
    - application only
    - protocol + port only
    - both application and protocol + port

    Behavior:
    - if application is provided, preserve it
    - if protocol/port is provided, normalize to protocol/port service tokens
    - if application is missing, infer likely applications from protocol/port
    - if application is provided but protocol/port is missing, infer candidate
      services from known application-default ports
    """

    APP_DEFAULT_PORTS = {
        "ssl": {"tcp/443"},
        "web-browsing": {"tcp/80"},
        "dns": {"udp/53", "tcp/53"},
        "ssh": {"tcp/22"},
        "ms-rdp": {"tcp/3389"},
        "smtp": {"tcp/25"},
        "pop3": {"tcp/110"},
        "imap": {"tcp/143"},
        "snmp": {"udp/161"},
        "ping": {"icmp"},
    }

    PORT_TO_APPS = {
        "tcp/22": ["ssh"],
        "tcp/80": ["web-browsing"],
        "tcp/443": ["ssl", "web-browsing"],
        "udp/53": ["dns"],
        "tcp/53": ["dns"],
        "tcp/3389": ["ms-rdp"],
        "tcp/25": ["smtp"],
        "tcp/110": ["pop3"],
        "tcp/143": ["imap"],
        "udp/161": ["snmp"],
    }

    def build(
        self,
        source_ip: str,
        destination_ip: str,
        application: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
    ) -> TrafficIdentity:
        normalized_application = self._normalize_application(application)
        normalized_protocol = self._normalize_protocol(protocol)
        normalized_port = self._normalize_port(port)

        candidate_services = self._build_candidate_services(
            application=normalized_application,
            protocol=normalized_protocol,
            port=normalized_port,
        )

        candidate_applications, confidence = self._infer_candidate_applications(
            application=normalized_application,
            candidate_services=candidate_services,
        )

        return TrafficIdentity(
            source_ip=source_ip,
            destination_ip=destination_ip,
            application=normalized_application,
            protocol=normalized_protocol,
            port=normalized_port,
            candidate_applications=candidate_applications,
            candidate_services=candidate_services,
            inference_confidence=confidence,
        )

    def _normalize_application(self, application: Optional[str]) -> Optional[str]:
        if not application:
            return None

        normalized = application.strip().lower()
        return normalized if normalized else None

    def _normalize_protocol(self, protocol: Optional[str]) -> Optional[str]:
        if not protocol:
            return None

        normalized = protocol.strip().lower()
        if normalized in {"tcp", "udp"}:
            return normalized

        if normalized == "icmp":
            return "icmp"

        return None

    def _normalize_port(self, port: Optional[int]) -> Optional[int]:
        if port is None:
            return None

        try:
            numeric_port = int(port)
        except (TypeError, ValueError):
            return None

        if 1 <= numeric_port <= 65535:
            return numeric_port

        return None

    def _build_candidate_services(
        self,
        application: Optional[str],
        protocol: Optional[str],
        port: Optional[int],
    ) -> Set[str]:
        candidate_services: Set[str] = set()

        if protocol == "icmp":
            candidate_services.add("icmp")

        if protocol in {"tcp", "udp"} and port is not None:
            candidate_services.add(f"{protocol}/{port}")

        if application:
            candidate_services.update(self.APP_DEFAULT_PORTS.get(application, set()))

        return candidate_services

    def _infer_candidate_applications(
        self,
        application: Optional[str],
        candidate_services: Set[str],
    ) -> tuple[List[str], str]:
        if application:
            return [application], "explicit"

        inferred_apps: List[str] = []

        for service in sorted(candidate_services):
            for candidate_app in self.PORT_TO_APPS.get(service, []):
                if candidate_app not in inferred_apps:
                    inferred_apps.append(candidate_app)

        if not inferred_apps:
            return [], "none"

        if len(inferred_apps) == 1:
            return inferred_apps, "high"

        return inferred_apps, "medium"