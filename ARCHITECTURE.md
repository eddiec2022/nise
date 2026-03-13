# NISE Architecture

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

- full rule evaluation simulation
- address object resolution
- address group resolution
- application and service evaluation
- candidate rule ranking
- mismatch explanation
- best-match policy identification

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