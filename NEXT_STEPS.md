# NISE Next Steps

## Immediate Next Step

### Automatic IP-to-Zone Resolution

The troubleshooting engine currently requires source and destination zones.

Next enhancement:

Allow engineers to provide only:


source IP
destination IP
application or port/protocol


The system should automatically determine:


source zone
destination zone


This will significantly improve usability in large environments.

Planned implementation:

- create `zone_resolver.py`
- map IP addresses to zones
- use interface/subnet data when available
- fallback to address object analysis

---

# Near-Term Enhancements

## Service Object Resolution

Improve service matching by resolving named service objects.

Capabilities to add:

- service object parsing
- service group support
- protocol/port extraction
- full Palo Alto service semantics

---

## NAT-Aware Troubleshooting

Enhance troubleshooting to consider NAT transformations.

Capabilities:

- pre-NAT vs post-NAT traffic evaluation
- source NAT handling
- destination NAT handling

---

## Routing Awareness

Introduce routing awareness for better path analysis.

Capabilities:

- evaluate routing tables
- determine next-hop zone transitions
- improve attack path accuracy

---

# Mid-Term Development

## Multi-Vendor Support

Add support for additional firewall vendors.

Planned parsers:


Cisco ASA
Fortinet FortiGate
Check Point


---

## Visualization

Introduce graphical visualization capabilities.

Examples:


zone connectivity graphs
attack path diagrams
policy dependency visualization


---

# Long-Term Roadmap

## Cloud Security Visibility

Extend NISE to analyze cloud network security configurations.

Targets:


AWS Security Groups
Azure NSGs
GCP Firewall Rules


---

## Policy Optimization

Introduce advanced policy analysis capabilities.

Examples:


rule shadowing detection
policy cleanup recommendations
least-privilege enforcement


---

## SaaS Platform

Long-term goal is to evolve NISE into a full network security intelligence platform delivered as a service.

Capabilities may include:


continuous configuration analysis
automated security posture monitoring
multi-environment visibility
enterprise dashboards