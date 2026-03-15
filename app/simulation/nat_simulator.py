import ipaddress
import re
from typing import List, Optional

from app.models.nat_model import (
    DestinationTranslation,
    NatRule,
    SourceTranslation,
    SourceTranslationType,
    TranslationResult,
)


class NatSimulator:
    """
    Evaluates an ordered list of NatRule objects against a traffic flow and
    returns a TranslationResult describing any address or port translations
    that apply.

    This engine operates exclusively on the normalized NAT model layer. It
    has no knowledge of vendor-specific config formats, firewall scopes, or
    security policy. It returns translation facts only — which addresses were
    rewritten and why. Downstream engines or vendor behavior layers are
    responsible for deciding which flow identity (pre-NAT or post-NAT) to
    use when evaluating security policy.
    """

    def simulate(
        self,
        nat_rules: List[NatRule],
        source_ip: str,
        destination_ip: str,
        service: str,
        from_zone: str,
        to_zone: str,
    ) -> TranslationResult:
        """
        Evaluate NAT rules in rule_order sequence and return the translation
        outcome for the given flow.

        Rules are sorted by rule_order before evaluation. The first matching
        enabled rule wins; subsequent rules are not evaluated.

        Args:
            nat_rules: Ordered list of NatRule objects to evaluate.
            source_ip: Source IP address of the flow (pre-NAT).
            destination_ip: Destination IP address of the flow (pre-NAT).
            service: Service string of the flow, e.g. "tcp/443" (pre-NAT).
            from_zone: Ingress zone of the flow.
            to_zone: Egress zone of the flow.

        Returns:
            A TranslationResult populated with pre- and post-NAT addresses,
            match details, and explanation steps.
        """
        steps: List[str] = []
        normalized_service = self._normalize_service(service)

        steps.append(
            f"NAT evaluation started: src={source_ip} dst={destination_ip} "
            f"svc={normalized_service} from_zone={from_zone} to_zone={to_zone}"
        )

        ordered_rules = sorted(nat_rules, key=lambda r: r.rule_order)
        steps.append(f"Evaluating {len(ordered_rules)} NAT rule(s) in rule_order sequence.")

        for rule in ordered_rules:
            if not rule.enabled:
                steps.append(f"  Rule '{rule.name}' [order={rule.rule_order}]: skipped (disabled).")
                continue

            match, reason = self._rule_matches(
                rule, source_ip, destination_ip, normalized_service, from_zone, to_zone
            )

            if not match:
                steps.append(f"  Rule '{rule.name}' [order={rule.rule_order}]: no match — {reason}.")
                continue

            steps.append(f"  Rule '{rule.name}' [order={rule.rule_order}]: matched.")
            return self._apply_translations(
                rule=rule,
                source_ip=source_ip,
                destination_ip=destination_ip,
                service=normalized_service,
                steps=steps,
            )

        steps.append("No NAT rule matched. Flow passes without translation.")
        return TranslationResult(
            nat_applied=False,
            matched_rule_name=None,
            source_ip_before=source_ip,
            source_ip_after=source_ip,
            destination_ip_before=destination_ip,
            destination_ip_after=destination_ip,
            service_before=normalized_service,
            service_after=normalized_service,
            source_translation_applied=False,
            destination_translation_applied=False,
            explanation_steps=steps,
        )

    # ------------------------------------------------------------------
    # Rule matching
    # ------------------------------------------------------------------

    def _rule_matches(
        self,
        rule: NatRule,
        source_ip: str,
        destination_ip: str,
        service: str,
        from_zone: str,
        to_zone: str,
    ) -> tuple[bool, str]:
        """
        Check whether a NatRule matches the given flow.

        Returns a (matched, reason) tuple. reason is populated only when
        matched is False and describes which criterion failed.
        """
        if not self._zone_matches(rule.from_zones, from_zone):
            return False, f"from_zone '{from_zone}' not in {rule.from_zones}"

        if not self._zone_matches(rule.to_zones, to_zone):
            return False, f"to_zone '{to_zone}' not in {rule.to_zones}"

        if not self._address_matches(rule.source_addresses, source_ip):
            return False, f"source_ip '{source_ip}' not in source_addresses {rule.source_addresses}"

        if not self._address_matches(rule.destination_addresses, destination_ip):
            return False, f"destination_ip '{destination_ip}' not in destination_addresses {rule.destination_addresses}"

        if not self._service_matches(rule.services, service):
            return False, f"service '{service}' not in services {rule.services}"

        return True, ""

    def _zone_matches(self, rule_zones: List[str], candidate_zone: str) -> bool:
        if not rule_zones:
            return True
        lowered = {z.lower() for z in rule_zones}
        if "any" in lowered:
            return True
        return candidate_zone.lower() in lowered

    def _address_matches(self, rule_addresses: List[str], candidate_ip: str) -> bool:
        if not rule_addresses:
            return True
        lowered = {a.lower() for a in rule_addresses}
        if "any" in lowered:
            return True
        for token in rule_addresses:
            if self._ip_or_subnet_matches(token, candidate_ip):
                return True
        return False

    def _ip_or_subnet_matches(self, token: str, candidate_ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(candidate_ip)
        except ValueError:
            return False
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                return ip_obj in net
            return ip_obj == ipaddress.ip_address(token)
        except ValueError:
            return False

    def _service_matches(self, rule_services: List[str], candidate_service: str) -> bool:
        if not rule_services:
            return True
        lowered = {s.lower() for s in rule_services}
        if "any" in lowered:
            return True
        normalized_candidate = self._normalize_service(candidate_service)
        for token in rule_services:
            if self._normalize_service(token) == normalized_candidate:
                return True
        return False

    def _normalize_service(self, service: str) -> str:
        """
        Normalize a service string to protocol/port format.

        Examples:
            tcp-443  -> tcp/443
            udp/53   -> udp/53
            tcp/80   -> tcp/80
            any      -> any
            icmp     -> icmp
        """
        if not service:
            return ""
        service = service.strip().lower()
        if service in {"any", "icmp", "application-default"}:
            return service
        match = re.fullmatch(r"(tcp|udp)[/-](\d+)", service)
        if match:
            protocol, port = match.groups()
            return f"{protocol}/{port}"
        return service

    # ------------------------------------------------------------------
    # Translation application
    # ------------------------------------------------------------------

    def _apply_translations(
        self,
        rule: NatRule,
        source_ip: str,
        destination_ip: str,
        service: str,
        steps: List[str],
    ) -> TranslationResult:
        """
        Apply source and destination translations defined by the matched rule
        and return a fully populated TranslationResult.
        """
        src_after = source_ip
        dst_after = destination_ip
        svc_after = service
        src_translated = False
        dst_translated = False

        if rule.source_translation is not None:
            src_after, src_translated = self._apply_source_translation(
                rule.source_translation, source_ip, steps
            )

        if rule.destination_translation is not None:
            dst_after, svc_after, dst_translated = self._apply_destination_translation(
                rule.destination_translation, destination_ip, service, steps
            )

        nat_applied = src_translated or dst_translated

        if nat_applied:
            steps.append(
                f"Translation complete: src {source_ip}->{src_after} "
                f"dst {destination_ip}->{dst_after} svc {service}->{svc_after}."
            )
        else:
            steps.append(
                f"Rule '{rule.name}' matched but defines no active translation. "
                "Flow passes unchanged."
            )

        return TranslationResult(
            nat_applied=nat_applied,
            matched_rule_name=rule.name,
            source_ip_before=source_ip,
            source_ip_after=src_after,
            destination_ip_before=destination_ip,
            destination_ip_after=dst_after,
            service_before=service,
            service_after=svc_after,
            source_translation_applied=src_translated,
            destination_translation_applied=dst_translated,
            explanation_steps=steps,
        )

    def _apply_source_translation(
        self,
        st: SourceTranslation,
        source_ip: str,
        steps: List[str],
    ) -> tuple[str, bool]:
        """
        Apply a SourceTranslation and return (translated_ip, was_translated).
        """
        t = st.type

        if t == SourceTranslationType.NONE:
            steps.append("  Source translation type is 'none'. No source change.")
            return source_ip, False

        if t in (
            SourceTranslationType.DYNAMIC_IP,
            SourceTranslationType.STATIC_IP,
        ):
            if not st.translated_addresses:
                steps.append(
                    f"  Source translation type '{t.value}' has no translated_addresses defined. "
                    "No source change."
                )
                return source_ip, False
            translated = st.translated_addresses[0]
            steps.append(
                f"  Source translation ({t.value}): {source_ip} -> {translated}."
            )
            return translated, True

        if t == SourceTranslationType.DYNAMIC_IP_AND_PORT:
            # v1: models source address translation only. Source port
            # allocation (PAT) is not simulated in this version.
            if not st.translated_addresses:
                steps.append(
                    "  Source translation type 'dynamic_ip_and_port' has no "
                    "translated_addresses defined. No source change."
                )
                return source_ip, False
            translated = st.translated_addresses[0]
            steps.append(
                f"  Source translation (dynamic_ip_and_port): {source_ip} -> {translated}. "
                "Note: source port allocation (PAT) is not simulated in this version."
            )
            return translated, True

        if t == SourceTranslationType.INTERFACE_ADDRESS:
            if not st.interface_name:
                steps.append(
                    "  Source translation type 'interface_address' has no interface_name defined. "
                    "No source change."
                )
                return source_ip, False
            steps.append(
                f"  Source translation type 'interface_address' is defined for interface "
                f"'{st.interface_name}', but the actual interface IP is not available in "
                "this simulator (v1). Source address left unchanged. A future version will "
                "resolve interface IPs from the normalized firewall model."
            )
            return source_ip, False

        steps.append(f"  Source translation type '{t.value}' is unrecognized. No source change.")
        return source_ip, False

    def _apply_destination_translation(
        self,
        dt: DestinationTranslation,
        destination_ip: str,
        service: str,
        steps: List[str],
    ) -> tuple[str, str, bool]:
        """
        Apply a DestinationTranslation and return
        (translated_dst_ip, translated_service, was_translated).
        """
        dst_after = destination_ip
        svc_after = service
        translated = False

        if dt.translated_address:
            steps.append(
                f"  Destination translation: {destination_ip} -> {dt.translated_address}."
            )
            dst_after = dt.translated_address
            translated = True

        if dt.translated_port is not None:
            svc_after = self._rewrite_service_port(service, dt.translated_port)
            steps.append(
                f"  Destination port translation: {service} -> {svc_after}."
            )
            translated = True

        if not translated:
            steps.append(
                "  Destination translation defined but no address or port specified. "
                "No destination change."
            )

        return dst_after, svc_after, translated

    def _rewrite_service_port(self, service: str, new_port: int) -> str:
        """
        Replace the port number in a service string with new_port.

        Examples:
            tcp/80  + 8080 -> tcp/8080
            udp/53  + 5353 -> udp/5353
            any     + 80   -> any          (cannot rewrite portless service)
        """
        match = re.fullmatch(r"(tcp|udp)/(\d+)", service)
        if match:
            protocol = match.group(1)
            return f"{protocol}/{new_port}"
        return service
