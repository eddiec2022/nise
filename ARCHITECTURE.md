# NISE Architecture

Separate Data Model from Reasoning Engines (Vendors → Parsers → Normalized Model → Reasoning Engines)
	The Normalized Model must be the center of the system.
	Nothing else should bypass it.

## Core Processing Pipeline


Configuration File / API Snapshot
↓
Parser Layer
↓
Normalized Firewall Model
↓
Analysis Engines
• Security Analyzer
• Policy Simulator
• Exposure Engine (APE)
• Critical Asset Exposure Engine
• Connectivity Troubleshooting Engine
↓
Reports / Intelligence


This pipeline allows NISE to convert vendor-specific firewall configurations into a **vendor-agnostic model**, enabling analysis, simulation, exposure detection, and troubleshooting across multiple platforms.

---

# Parser Layer

Responsible for detecting vendor configuration formats and translating them into the normalized firewall model.

Directory:


app/parsers/


Key components:

- parser_dispatcher.py
- parser_registry.py
- palo_alto_parser.py
- base.py

Capabilities:

- vendor detection
- standalone vs Panorama detection
- object extraction
- policy extraction
- conversion to normalized model

Additional detection utility:


app/utils/config_detector.py


---

# Normalized Firewall Model

Location:


app/models/normalized_firewall_model.py


Core objects:

- FirewallConfig
- Scope
- SecurityRule
- AddressObject
- AddressGroup
- Finding

Purpose:

Provide a **vendor-agnostic representation of firewall configurations** so that all analysis engines operate on the same data structure regardless of vendor.

This model enables:

- cross-vendor policy analysis
- policy simulation
- exposure modeling
- attack path analysis

---

# Security Analyzer

Location:


app/analysis/security_analyzer.py


The analyzer identifies security weaknesses and configuration hygiene issues.

Current detections include:

- overly permissive rules
- missing session-end logging
- missing security profiles
- missing log forwarding
- duplicate address objects
- shadow rules
- missing descriptions
- disabled rules

Output:

- detailed CSV engineering report
- executive PDF report
- estimated remediation effort

---

# Policy Simulator

Location:


app/simulation/policy_simulator.py


Simulates firewall policy behavior to determine how traffic would be processed.

Capabilities:

- rule matching simulation
- address object resolution
- address group resolution
- subnet matching
- application matching
- service matching
- Palo Alto **application-default** semantics
- implicit deny detection

Example question NISE answers:


Can host A reach host B on HTTPS?

---

# Forwarding Intelligence Layer

Location:

app/analysis/
- route_lookup.py
- zone_resolver.py

Purpose:

Simulate firewall forwarding decisions before policy evaluation.

Capabilities include:

- route lookup engine
- longest-prefix route matching
- interface resolution
- zone binding resolution
- automatic IP → zone mapping

Forwarding resolution pipeline:

IP address
↓
Longest-prefix route lookup
↓
Egress interface
↓
Zone binding
↓
Resolved zone

Example:

172.16.90.10
↓
Route match: 172.16.80.0/20
↓
Interface: ethernet1/3
↓
Zone: Internal
---

# Exposure Engine (APE)

Location:


app/analysis/exposure_engine.py


APE = **Attack Path Engine**

Purpose:

Model network reachability and determine potential attack paths.

### APE v1

Original capabilities:

- build zone connectivity graph
- compute reachable zones
- blast radius analysis

### APE v1.1 Enhancements

New capabilities implemented:

- start zone validation
- display available zones when invalid input is provided
- rule-aware connectivity edges
- rule-aware attack path output

Example use case:


If an attacker enters through the Public zone,
what internal zones are reachable?


Output now includes:

- reachable zones
- rule-aware path hops
- rules responsible for connectivity

---

# Network Behavior Engine (Future)

Future versions of NISE will introduce a **Network Behavior Engine (NBE)**.

The NBE will simulate full network decision paths across multiple infrastructure layers.

Example reasoning chain:

Client
↓
Routing decision
↓
Firewall policy evaluation
↓
NAT transformation
↓
Load balancer decision
↓
Application server

This engine will allow NISE to analyze and simulate complex network flows across multiple devices and security controls.

Capabilities will include:

- routing path simulation
- NAT transformation modeling
- load balancer decision logic
- multi-hop path analysis
- cloud security control reasoning

This transforms NISE from a firewall analyzer into a **full network behavior simulation platform**.

---

# Critical Asset Exposure Engine

Location:


app/analysis/critical_asset_engine.py


Purpose:

Determine whether defined **critical assets are reachable from a given entry zone**.

Builds directly on top of the Attack Path Engine.

Capabilities:

- user-defined critical asset list
- zone exposure detection
- hop count analysis
- risk scoring
- asset criticality weighting

Example output:


Domain Controller (Internal-VRF1)
EXPOSED
Risk: CRITICAL
Hops: 1


This allows engineers to quickly determine which assets are reachable from attacker entry points.

---

# Connectivity Troubleshooting Engine

Location:


app/analysis/troubleshooting_engine.py


Purpose:

Explain **why specific traffic is allowed or blocked** by firewall policy.

Capabilities:

- address object resolution
- address group resolution
- application group resolution
- service object resolution
- service group resolution
- forwarding-aware zone resolution
- rule evaluation simulation

The engine evaluates:


source zone
destination zone
source address
destination address
application
service


If traffic is denied, the engine returns:

- closest candidate rules
- failed match conditions
- expected values for rule match

Example:


Best candidate rule: Allow SSH
Failed check: source address mismatch
Expected source address: CTQ-Datacenters


---

# Traffic Identity System

Location:


app/analysis/traffic_identity.py


Purpose:

Normalize troubleshooting inputs into a structured traffic identity model.

Supported traffic inputs:


application only
protocol + port
application + protocol + port


Traffic identity structure:


{
source_ip
destination_ip
application
protocol
port
}


Capabilities include:

- application inference from protocol/port
- candidate service generation
- candidate application inference
- inference confidence scoring

Example inference:


tcp/22 → ssh


Confidence levels:

- explicit
- high
- medium
- none

This allows NISE to troubleshoot traffic even when incomplete information is provided.

---

# Reporting Engine

Location:


app/reports/report_exporter.py


Produces two report types.

### Engineering Reports

- detailed CSV findings
- remediation estimates
- rule-level issues

### Executive Reports

- PDF summary
- severity breakdown
- finding counts
- quick wins
- impacted scopes

---

# Collector Framework

Location:


app/collectors/


Components:

- base.py
- registry.py
- palo_alto_api_collector.py

Purpose:

Allow NISE to collect configurations directly from live devices via API.

Current status:

Collector framework implemented.

Future collectors planned for:

- Palo Alto API
- SSH collectors
- cloud firewall collectors

---

# Application Entry Point

Main program entry:


main.py


Supported CLI modes:


file
collect
simulate
blast-radius
critical-assets
troubleshoot


Example commands:


python main.py file <config.xml>

python main.py collect <host> <api_key>

python main.py simulate <config> <scope> <source> <destination> <application> <service>

python main.py blast-radius <config> <scope> <zone>

python main.py critical-assets <config> <scope> <zone> <assets.json>

python main.py troubleshoot <config> <scope> <src_zone> <dst_zone> <src_ip> <dst_ip> ssh

python main.py troubleshoot <config> <scope> <src_zone> <dst_zone> <src_ip> <dst_ip> tcp 22

python main.py troubleshoot <config> <scope> <src_zone> <dst_zone> <src_ip> <dst_ip> ssh tcp 22


---

# Current System Status

Working features:

Parser & Model
- Palo Alto standalone parser
- Panorama parser
- normalized firewall model

Security Analysis
- security analyzer
- duplicate object detection
- shadow rule detection
- configuration hygiene checks

Reporting
- CSV engineering reports
- executive PDF reports

Policy Simulation
- rule evaluation engine
- application matching
- service matching
- address group resolution
- implicit deny detection

Exposure Analysis
- Attack Path Engine (APE v1)
- blast radius analysis
- rule-aware attack paths (APE v1.1)
- zone validation and discovery

Asset Risk Analysis
- Critical Asset Exposure Engine
- asset criticality weighting
- hop count analysis
- exposure risk scoring

Connectivity Troubleshooting
- full rule evaluation
- candidate rule ranking
- closest-match policy identification
- mismatch explanation

Traffic Identity
- application inference from port/protocol
- protocol/port inference from application
- traffic identity normalization

Infrastructure
- collector framework
- CLI command interface

---

# Planned Architecture Extensions

Near-term:

- automatic IP-to-zone resolution
- service object resolution
- NAT-aware troubleshooting

Mid-term:

- routing-aware path analysis
- multi-vendor firewall parsing
- policy dependency graphing

Long-term:

- cloud firewall analysis
- attack path visualization
- SaaS deployment model

---

## Multi-Vendor Design Guardrails

NISE is already being built for future multi-vendor support through its normalized firewall model.  
This means the long-term strategy is not to rewrite the analysis engines for each firewall vendor, but to convert each vendor's configuration into a common internal representation.

### Core design rule
All vendor-specific syntax and quirks must be handled in the parser layer or vendor-specific helper modules.  
The normalized model and analysis engines must remain vendor-neutral.

### Required separation
- **Vendor parser layer**
  - Palo Alto parser
  - future Cisco ASA parser
  - future Fortinet parser
  - future Check Point parser
  - future cloud security policy parsers

- **Normalized model layer**
  - common representation of interfaces, zones, routes, address objects, services, security rules, NAT rules, and related constructs

- **Analysis engine layer**
  - Policy Analysis Engine
  - Attack Path Engine
  - Critical Asset Exposure Engine
  - Troubleshooting Engine
  - future NAT and routing-aware engines

### Architectural guardrails
To preserve multi-vendor support as NISE grows:

- analysis engines must never depend on raw vendor config structure
- analysis engines must operate only on normalized objects
- vendor-specific behaviors should be translated into normalized equivalents before analysis
- parser-specific helpers should remain isolated from shared engine logic
- future parser selection should be handled through a parser factory or equivalent dispatcher

### Practical meaning
For example:
- Palo Alto XML, Cisco ASA CLI, and Fortinet CLI may all express policy differently
- each parser must normalize those differences into the same internal `SecurityRule`, `RouteEntry`, `Interface`, `ZoneBinding`, and future `NatRule` objects
- once normalized, the engines should analyze them the same way

This keeps NISE scalable, maintainable, and ready for future multi-vendor expansion without requiring a redesign of the analysis engines.

### Future Architectural Direction

Future Direction: Network Behavior Simulation

NISE is evolving beyond firewall configuration analysis toward a network behavior simulation platform.

Rather than modeling only firewall policy decisions, future versions of NISE will simulate the complete network decision chain that determines whether traffic succeeds or fails.

This includes reasoning across multiple infrastructure layers.

Example packet evaluation flow:

Source IP
↓
Routing decision
↓
Egress interface
↓
Zone resolution
↓
NAT translation
↓
Firewall policy evaluation
↓
Load balancer decision
↓
Cloud security policy
↓
Destination reachability

Each stage will be represented as a normalized decision step in the NISE reasoning engine.

This approach allows NISE to model and explain network behavior across multiple enforcement points while preserving the core architectural rule:

Vendor-specific behavior is handled in parsers, while reasoning engines operate only on normalized objects.

This enables NISE to support additional technologies such as:

NAT flow simulation

routing path analysis

load balancer decision modeling

cloud security group analysis

identity-based access controls

without redesigning the core reasoning engine.

---

# Intelligence Layer (Future)

NISE will eventually include an intelligence layer designed to learn from large-scale network environments while preserving customer privacy.

This layer will use anonymized metrics derived from network analysis.

Examples of collected intelligence signals:

- rule structure patterns
- exposure characteristics
- troubleshooting failure patterns
- blast radius distributions
- remediation success rates

These insights will allow NISE to provide:

- better troubleshooting recommendations
- risk benchmarking
- improved remediation suggestions

All telemetry will be optional and privacy-preserving.
