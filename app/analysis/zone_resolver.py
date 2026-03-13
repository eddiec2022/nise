from typing import Any, Dict, Optional

from app.analysis.route_lookup import RouteLookup
from app.models.normalized_firewall_model import Interface, Scope


class ZoneResolver:
    """
    Resolve IP addresses to zones using forwarding context.

    Resolution order:
    1. Connected subnet match
    2. Static route lookup
    3. Interface → zone mapping
    4. Unknown (future: address object fallback)
    """

    def __init__(self, scope: Scope):
        self.scope = scope
        self.route_lookup = RouteLookup(scope)

    def resolve(self, ip: str) -> Dict[str, Any]:
        """
        Resolve IP to zone using forwarding information.
        """

        route_result = self.route_lookup.lookup(ip)

        if route_result["status"] != "resolved":
            return {
                "status": "unknown",
                "ip": ip,
                "zone": None,
                "method": None,
                "confidence": "low",
                "evidence": route_result.get("evidence", []),
            }

        interface_name = route_result.get("egress_interface")

        iface = self._get_interface(interface_name)

        if iface and iface.zone:
            evidence = list(route_result.get("evidence", []))

            evidence.append(
                f"Interface {iface.name} belongs to zone {iface.zone}"
            )

            return {
                "status": "resolved",
                "ip": ip,
                "zone": iface.zone,
                "method": route_result.get("method"),
                "confidence": route_result.get("confidence", "medium"),
                "egress_interface": iface.name,
                "matched_prefix": route_result.get("matched_prefix"),
                "virtual_router": route_result.get("virtual_router"),
                "route_type": route_result.get("route_type"),
                "evidence": evidence,
            }

        return {
            "status": "unknown",
            "ip": ip,
            "zone": None,
            "method": route_result.get("method"),
            "confidence": "low",
            "egress_interface": interface_name,
            "matched_prefix": route_result.get("matched_prefix"),
            "virtual_router": route_result.get("virtual_router"),
            "route_type": route_result.get("route_type"),
            "evidence": route_result.get("evidence", []),
        }

    def _get_interface(self, interface_name: Optional[str]) -> Optional[Interface]:
        """
        Locate interface object from normalized scope.
        """

        if not interface_name:
            return None

        for iface in self.scope.interfaces:
            if iface.name == interface_name:
                return iface

        return None

    def debug_summary(self) -> Dict[str, Any]:
        """
        Helpful debugging summary.
        """

        return {
            "scope": self.scope.name,
            "interfaces": len(self.scope.interfaces),
            "zones": len(self.scope.zones),
            "routes": len(self.scope.routes),
        }