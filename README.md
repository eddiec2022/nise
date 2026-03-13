# NISE
Network Intelligence & Security Engine

NISE is an analysis engine designed to understand firewall configurations the same way a firewall processes traffic.  
It parses network security configurations, normalizes them into a structured model, and performs security analysis, exposure detection, and connectivity troubleshooting.

The goal of NISE is to provide engineers with fast, accurate insights into firewall behavior without needing to manually inspect rules, routes, and objects.

---

# Current Capabilities

## Configuration Parsing
NISE currently supports Palo Alto Networks firewall configurations.

Supported deployment types:
- Standalone firewalls
- Panorama-managed firewalls

The parser extracts and normalizes:

- zones
- interfaces
- zone bindings
- virtual routers
- static routes
- address objects
- address groups
- service objects
- security policies
- NAT policies

These elements are normalized into a common firewall model used by the analysis engines.

---

# Analysis Engines

## Policy Analysis Engine (PAE)

Analyzes security policies for configuration issues and operational risks.

Findings include:

- duplicate objects
- shadowed rules
- overly permissive rules
- missing rule descriptions
- missing security profiles

The engine produces:

- CSV report
- executive summary
- PDF report

---

## Attack Path Engine (APE)

Builds a zone-level reachability graph using firewall rules.

Capabilities:

- determine reachable zones
- compute blast radius of a zone
- visualize rule-driven attack paths
- identify unintended access paths

APE v1.1 enhancements include:

- validation of zone inputs
- rule-aware zone path tracking
- attack path attribution to specific rules

---

## Critical Asset Exposure Engine

Analyzes whether critical assets are reachable from potentially exposed zones.

Capabilities:

- define critical assets
- determine if assets are reachable through rule paths
- calculate exposure risk scores

Risk scoring considers:

- path length
- rule permissiveness
- exposure level

---

## Connectivity Troubleshooting Engine

Simulates firewall decision logic to determine why traffic is allowed or blocked.

Supported traffic inputs:

- application only
- protocol/port only
- application + protocol/port

The engine evaluates rules in order and provides detailed explanations.

Features:

- rule match simulation
- candidate rule ranking
- closest-match rule suggestions
- mismatch explanations

Example output:


Result: IMPLICIT DENY
Explanation: Zone-level path exists but no rule fully matches traffic identity.
Closest candidate rule: Allow SSH
Failure reason: source address mismatch


---

# Forwarding Intelligence

NISE now includes forwarding-stage analysis similar to firewall routing behavior.

Capabilities:

- route lookup engine
- longest-prefix route matching
- interface resolution
- automatic IP → zone mapping

Zone resolution process:


IP address
↓
Route lookup
↓
Egress interface
↓
Zone binding
↓
Resolved zone


This allows troubleshooting without manually specifying zones.

Example:


NISE resolves:

10.1.1.10 → Public
10.2.2.20 → Internal-VRF1


---

# Project Architecture

The engine is organized into modular analysis components.


app/
├── analysis/
│ ├── exposure_engine.py
│ ├── route_lookup.py
│ ├── troubleshooting_engine.py
│ └── zone_resolver.py
│
├── models/
│ └── normalized_firewall_model.py
│
├── parsers/
│ └── palo_alto_parser.py
│
└── simulation/
└── policy_simulator.py


Core design principles:

- vendor-agnostic normalized firewall model
- modular analysis engines
- rule-aware path analysis
- firewall-like decision logic

---

# Running NISE

## Build Docker image


docker build -t nise .


## Parse configuration


docker run -it --rm -v ${PWD}:/app nise python main.py file sample_config.xml


## Troubleshoot connectivity


docker run -it --rm -v ${PWD}:/app nise python main.py troubleshoot sample_panorama.xml "Apex WH" Public Internal-VRF1 10.1.1.10 10.2.2.20 ssh


---

# Roadmap

Upcoming enhancements:

### NAT Awareness
Incorporate NAT policy evaluation into troubleshooting and exposure analysis.

### Dynamic Route Awareness
Support live route table queries from firewalls (RIB lookup).

### Return Path Analysis
Detect asymmetric routing and return-path failures.

### Multi-Vendor Support
Future support for:

- Cisco ASA
- Fortinet
- Check Point
- Cloud security platforms

### Cloud Security Visibility
Integration with:

- AWS security groups
- Azure NSGs
- cloud firewall policies

---

# Long-Term Vision

NISE aims to evolve into a comprehensive security intelligence platform capable of:

- analyzing large multi-firewall environments
- identifying attack paths automatically
- simulating policy behavior
- providing security posture insights
- assisting engineers with real-time troubleshooting

---

# License

Project currently under active development.