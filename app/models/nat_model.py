from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SourceTranslationType(str, Enum):
    """Defines the mechanism used to translate the source address of a flow."""
    NONE = "none"
    DYNAMIC_IP = "dynamic_ip"
    DYNAMIC_IP_AND_PORT = "dynamic_ip_and_port"
    STATIC_IP = "static_ip"
    INTERFACE_ADDRESS = "interface_address"


# ---------------------------------------------------------------------------
# Translation sub-models
# ---------------------------------------------------------------------------

class SourceTranslation(BaseModel):
    """
    Describes how the source address (and optionally port) of a flow is
    translated by a NAT rule.

    Attributes:
        type: The translation mechanism. Determines which other fields are
            relevant (e.g. translated_addresses is used for dynamic_ip and
            static_ip; interface_name is used for interface_address).
        translated_addresses: Pool of addresses or a single static address
            that the source is translated to. Used for dynamic_ip,
            dynamic_ip_and_port, and static_ip types.
        interface_name: Egress interface whose IP is used as the translated
            source. Used for interface_address type.
        fallback_behavior: Optional description of fallback behavior when the
            translated address pool is exhausted (e.g. "drop", "none").
    """
    type: SourceTranslationType = SourceTranslationType.NONE
    translated_addresses: List[str] = Field(default_factory=list)
    interface_name: Optional[str] = None
    fallback_behavior: Optional[str] = None


class DestinationTranslation(BaseModel):
    """
    Describes how the destination address (and optionally port) of a flow is
    translated by a NAT rule.

    Attributes:
        translated_address: The address the original destination is rewritten
            to. None indicates no destination address translation.
        translated_port: The port the original destination port is rewritten
            to. None indicates no port translation.
    """
    translated_address: Optional[str] = None
    translated_port: Optional[int] = None


# ---------------------------------------------------------------------------
# Core NAT rule model
# ---------------------------------------------------------------------------

class NatRule(BaseModel):
    """
    Normalized, vendor-neutral representation of a single NAT rule.

    A NatRule defines the match criteria for a flow and the translations to
    apply when the flow matches. It is the canonical unit of NAT policy in
    the NISE model layer.

    Attributes:
        name: Unique name of the NAT rule within its scope.
        enabled: Whether the rule is active. Disabled rules are skipped
            during simulation.
        from_zones: Ingress zones the rule matches on. An empty list or
            ["any"] means any zone.
        to_zones: Egress zones the rule matches on. An empty list or ["any"]
            means any zone.
        source_addresses: Source address objects or CIDR prefixes the rule
            matches on. ["any"] means any source.
        destination_addresses: Destination address objects or CIDR prefixes
            the rule matches on. ["any"] means any destination.
        services: Services (port/protocol combinations) the rule matches on.
            ["any"] means any service.
        source_translation: The source translation to apply when the rule
            matches. None indicates no source translation.
        destination_translation: The destination translation to apply when
            the rule matches. None indicates no destination translation.
        rule_order: Position of the rule in the ordered policy list.
            Lower values are evaluated first.
        description: Human-readable description of the rule's purpose.
        tags: Administrative tags attached to the rule.
    """
    name: str
    enabled: bool = True
    from_zones: List[str] = Field(default_factory=list)
    to_zones: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    source_translation: Optional[SourceTranslation] = None
    destination_translation: Optional[DestinationTranslation] = None
    rule_order: int = 0
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Simulation result models
# ---------------------------------------------------------------------------

class TranslationResult(BaseModel):
    """
    Records the outcome of NAT evaluation for a single flow.

    Produced by the NAT simulation engine after evaluating a flow against
    the ordered NAT rule list. Both pre-NAT and post-NAT identities are
    preserved so that downstream engines (security policy, troubleshooting)
    can reference either identity.

    Attributes:
        nat_applied: True if at least one translation was applied to the flow.
        matched_rule_name: Name of the first NAT rule that matched the flow.
            None if no rule matched.
        source_ip_before: Source IP address before translation.
        source_ip_after: Source IP address after translation. Equals
            source_ip_before when no source translation was applied.
        destination_ip_before: Destination IP address before translation.
        destination_ip_after: Destination IP address after translation.
            Equals destination_ip_before when no destination translation was
            applied.
        service_before: Service (e.g. "tcp/80") before translation.
        service_after: Service after translation. Equals service_before when
            no port translation was applied.
        source_translation_applied: True if source address translation was
            performed.
        destination_translation_applied: True if destination address
            translation was performed.
        explanation_steps: Ordered list of human-readable strings describing
            each evaluation step, suitable for troubleshooting output.
    """
    nat_applied: bool = False
    matched_rule_name: Optional[str] = None
    source_ip_before: Optional[str] = None
    source_ip_after: Optional[str] = None
    destination_ip_before: Optional[str] = None
    destination_ip_after: Optional[str] = None
    service_before: Optional[str] = None
    service_after: Optional[str] = None
    source_translation_applied: bool = False
    destination_translation_applied: bool = False
    explanation_steps: List[str] = Field(default_factory=list)


class FlowIdentityStage(BaseModel):
    """
    Captures the full identity of a flow at each stage of firewall processing.

    NISE tracks three distinct identities for every simulated flow so that
    each engine receives and reports the correct address context:

    - original: The addresses and service as seen arriving at the firewall
      before any processing occurs.
    - post_nat: The addresses and service after NAT translation has been
      applied. This is the identity used for routing and security policy
      lookup on Palo Alto and most stateful firewalls.
    - effective_security_identity: The identity that the security policy
      engine will match against. On most platforms this equals post_nat,
      but the field is kept separate to accommodate platforms with
      different ordering semantics.

    Attributes:
        original: Flow tuple (src_ip, dst_ip, service) as received,
            before NAT. Stored as a free-form string for flexibility
            (e.g. "src=10.0.0.1 dst=8.8.8.8 svc=tcp/443").
        post_nat: Flow tuple after NAT translation has been applied.
        effective_security_identity: Flow tuple used when matching security
            policy rules.
    """
    original: Optional[str] = None
    post_nat: Optional[str] = None
    effective_security_identity: Optional[str] = None
