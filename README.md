# NISE
Network Intelligence & Security Engine

NISE is an analysis engine designed to understand firewall configurations the same way a firewall processes traffic.  
It parses network security configurations, normalizes them into a structured model, and performs security analysis, exposure detection, and connectivity troubleshooting.

The goal of NISE is to provide engineers with fast, accurate insights into firewall behavior without needing to manually inspect rules, routes, and objects.

---

# Current Capabilities

## Multi-Vendor Architecture

NISE is designed to support multiple firewall vendors.

Vendor configurations are parsed and translated into a common normalized firewall model.  
All analysis engines operate only on this normalized representation.

This allows NISE to support additional vendors in the future without modifying the analysis engines.

Future vendor support may include:

- Cisco ASA
- Fortinet
- Check Point
- cloud firewall policies

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

## Automatic Connectivity Troubleshooting

NISE supports automatic zone resolution when troubleshooting connectivity.

Engineers can provide only:

- source IP
- destination IP
- application OR protocol/port

NISE automatically determines:

IP
↓
Route lookup
↓
Egress interface
↓
Zone binding
↓
Resolved zone

Example command:

docker run -it --rm -v ${PWD}:/app nise python main.py troubleshoot-auto sample_panorama.xml "Apex WH" 172.16.90.10 8.8.8.8 ssl

Example output:

Resolved source zone: Internal  
Route/Subnet: 172.16.80.0/20

Resolved destination zone: Public  
Route/Subnet: 0.0.0.0/0

Result: ALLOWED  
Matched rule: Streaming Media Web

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

# Future Platform Vision

NISE is designed to evolve beyond a configuration analysis tool into a full **Network Security Intelligence Platform**.

Future platform capabilities will include:

### Network Reasoning Engine

NISE will not only parse configurations but will reason about **how networks behave** by combining:

- routing decisions
- firewall policy evaluation
- NAT transformations
- load balancer decisions
- cloud security controls

This allows NISE to answer complex operational questions such as:

- Why is this application failing?
- What security control is blocking traffic?
- What network path is being used?
- What systems are exposed during an attack?

---

### Network Behavior Simulation

Future versions of NISE will simulate end-to-end network behavior across multiple infrastructure layers.

Example reasoning chain:

Client → Routing → Firewall → NAT → Load Balancer → Server

This will allow engineers to troubleshoot complex environments without manually tracing traffic across devices.

---

### Privacy-Preserving Intelligence

NISE may optionally collect **anonymized operational metrics** to improve analysis accuracy and security recommendations.

Collected data will never include:

- IP addresses
- hostnames
- configuration details
- log contents

Instead, NISE may collect aggregated metrics such as:

- rule counts
- exposure patterns
- troubleshooting mismatch statistics
- blast radius characteristics

This allows NISE to improve its reasoning models while preserving customer privacy.



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

## Roadmap

### Near-term development priorities

- NAT-aware troubleshooting
- service object and service group resolution
- return-path analysis
- dynamic route table support (live firewall RIB queries)
- asymmetric path detection

### Future capabilities:

- multi-vendor firewall support
- cloud security policy analysis
- automated attack path visualization

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
- instead of competing with large players like Tufin, AlgoSec and big name suites, CorNETiQ sets itself apart as being a product above and beyond their capabilities
- grow CorNETiQ into a $555 Million company within the next 18 months by leading the network security intelligence space
---

# License

Project currently under active development.