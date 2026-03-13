# NISE — Network Intelligence & Security Engine

## Project Overview

NISE (Network Intelligence & Security Engine) is a next-generation **network security intelligence platform** designed to analyze firewall configurations, simulate network behavior, detect security exposure, and ultimately provide real-time troubleshooting and attack path analysis across enterprise networks.

The long-term vision of NISE is to become the **intelligence layer for network security infrastructure**, integrating with firewalls, routers, cloud security controls, and other network enforcement points.

NISE focuses on helping engineers and organizations answer critical questions such as:

- What security risks exist in this firewall configuration?
- Why is traffic being blocked?
- What rule is allowing or denying traffic?
- What systems are reachable during a breach?
- What is the blast radius of a ransomware attack?
- What firewall change will fix an issue safely?

---

# Product Vision

NISE aims to provide capabilities beyond traditional firewall management tools like:

- Tufin
- AlgoSec
- FireMon

While those platforms focus on **compliance and change automation**, NISE focuses on **security intelligence and troubleshooting**.

Primary design goals:

- Exposure detection
- Connectivity reasoning
- Attack path intelligence
- Security troubleshooting
- Cross-vendor visibility

---

# Current Architecture

The NISE engine processes firewall configurations using the following pipeline:

```
Configuration File / API Snapshot
↓
Vendor Parser
↓
Normalized Firewall Model
↓
Analysis Engines
• Security Analyzer
• Policy Simulator
• Exposure Engine (APE)
↓
Reports & Intelligence
```

This architecture allows NISE to support **multiple firewall vendors** using a shared internal model.

---

# Current Supported Vendor

Currently implemented:

**Palo Alto Networks**
- Standalone firewall configurations
- Panorama configurations
- Device Groups
- Templates
- Shared objects

Future vendors planned:

- Cisco FTD
- Fortinet
- Juniper SRX
- Cloud firewalls

---

# Core Engine Modules

## 1 Parser Framework

Responsible for detecting vendor configuration types and converting them into the normalized model.

Components:


app/parsers/


Key files:

- parser_dispatcher.py
- parser_registry.py
- palo_alto_parser.py

Capabilities:

- Vendor detection
- Panorama vs Standalone detection
- Object extraction
- Policy extraction

---

# 2 Normalized Firewall Model

The internal representation used by all NISE engines.

Key objects include:

- FirewallConfig
- Scope
- SecurityRule
- AddressObject
- AddressGroup
- Finding

Location:


app/models/normalized_firewall_model.py


This model enables:

- vendor-agnostic analysis
- policy simulation
- attack path modeling

---

# 3 Security Analyzer

The analyzer detects configuration weaknesses and security risks.

Current detections include:

| Code | Description |
|-----|-------------|
OPR | Overly permissive rule |
MSEL | Missing session end logging |
MSP | Missing security profiles |
MLF | Missing log forwarding |
MDR | Missing rule description |
DR | Disabled rule |
DUP_OBJ | Duplicate address objects |
SHADOW_RULE | Shadowed rules |

Output includes:

- CSV engineering reports
- Executive PDF summaries
- Estimated remediation effort

Location:


app/analysis/security_analyzer.py


---

# 4 Policy Simulation Engine

The simulator determines how traffic would be processed by the firewall.

Capabilities include:

- Rule matching simulation
- Address resolution
- Address group resolution
- Subnet matching
- Basic application handling
- Implicit deny detection

Example question NISE answers:

```
Can 10.1.1.10 reach 10.2.2.20 on HTTPS?
```

Location:


app/simulation/policy_simulator.py


---

# 5 Exposure Engine (APE)

APE = **Attack Path Engine**

This engine analyzes network reachability and potential attack paths.

Current capabilities:

- Build zone connectivity graph
- Determine reachable zones from an entry point
- Basic blast radius analysis

Example use case:

```
If an attacker enters through the Public zone,
what internal zones are reachable?
```

Location:


app/analysis/exposure_engine.py


Future versions will include:

- rule-level path analysis
- asset exposure analysis
- ransomware spread modeling

---

# 6 Reporting Engine

Produces:

### Engineering Reports

CSV file containing detailed findings.

### Executive Reports

PDF summary including:

- severity breakdown
- finding counts
- estimated remediation effort
- quick wins
- impacted scopes

Location:


app/reports/report_exporter.py


---

# 7 Collector Framework

Allows NISE to collect configurations directly from devices via API.

Current status:

Framework implemented.

Future support planned for:

- Palo Alto API
- SSH collectors
- cloud firewall collectors

Location:


app/collectors/


---

# Current CLI Commands

NISE currently supports the following command modes.

### Analyze a configuration file

```
python main.py file <config.xml>
```

---

### Simulate firewall traffic

```
python main.py simulate <config> <scope> <source> <destination> <application> <service>
```

Example:

```
simulate sample_panorama.xml "Apex WH" 10.1.1.10 10.2.2.20 web-browsing tcp/80
```

---

### Blast radius analysis

```
python main.py blast-radius <config> <scope> <zone>
```

Example:

```
blast-radius sample_panorama.xml "Apex WH" Public
```

---

### Device collection

```
python main.py collect <host> <api_key>
```

---

# Current Development Status

Working features:

- Panorama parser
- Standalone firewall parser
- Security analyzer
- Duplicate object detection
- Shadow rule detection
- CSV reporting
- Executive PDF reporting
- Policy simulation
- Blast radius analysis
- Collector framework

---

# Next Development Milestones

## APE v1.1

Enhancements:

- Validate zone input
- Display available zones when invalid
- Track which rule created connectivity edges
- Return rule chain paths

---

## Critical Asset Exposure Analysis

Capabilities:

- define critical assets
- detect reachable critical systems
- identify breach exposure

---

## Connectivity Troubleshooting Engine

Goal:

Allow engineers to ask questions like:

```
Why can't server A reach server B?
```

NISE will identify:

- rule blocks
- routing issues
- missing policies

---

# Long Term Vision

NISE will evolve into a comprehensive **Network Security Intelligence Platform** capable of analyzing:

- firewalls
- routers
- load balancers
- cloud security groups
- Azure firewall policies
- AWS security groups

Future features include:

- ransomware attack simulation
- AI troubleshooting assistant
- threat intelligence integration
- cloud security visibility
- policy optimization recommendations


