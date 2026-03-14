# NISE Project Summary

## Project Overview

NISE (Network Intelligence & Security Engine) is a network security analysis platform designed to analyze firewall configurations and provide deep visibility into network security posture, exposure paths, and traffic behavior.

The platform parses firewall configurations, builds a normalized model of the network, and performs advanced analysis to help engineers understand risk, troubleshoot connectivity, and identify security exposures.

The long-term goal of NISE is to become a multi-vendor network security intelligence platform capable of analyzing complex environments across on-prem and cloud infrastructure.

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
- Co-pilot for Network / Security engineers

## Core Capabilities

### Configuration Parsing

NISE parses firewall configuration files and converts them into a normalized internal model. This allows the analysis engines to work consistently across different firewall vendors.

Currently supported:

- Palo Alto Panorama / firewall configuration XML

Future support will include:

- Cisco ASA
- Fortinet FortiGate
- Check Point
- Cloud security groups

---

## Normalized Firewall Model

Parsed configurations are converted into a normalized model representing:

- scopes (device groups / vsys)
- zones
- security rules
- address objects
- address groups
- applications
- services

This normalized model enables the analysis engines to operate independently of vendor-specific syntax.

---

## Analysis Engines

### Security Analyzer

Performs rule-based analysis on firewall policies to identify security findings such as overly permissive rules, shadowed policies, and other potential risks.

---

### Attack Path Engine (APE)

The Attack Path Engine models zone-to-zone connectivity and determines which zones can reach other zones based on firewall rules.

Features include:

- zone connectivity graph
- blast radius analysis
- rule-aware attack paths
- identification of reachable zones

---

### Critical Asset Exposure Engine

Builds on the Attack Path Engine to determine whether defined critical assets are reachable from a given starting zone.

Capabilities:

- user-defined critical assets
- exposure detection
- hop count analysis
- business-aware risk scoring
- criticality classification

---

### Connectivity Troubleshooting Engine

Simulates traffic through the firewall policy to determine why traffic is allowed or blocked.

Capabilities:

- rule-by-rule evaluation
- ranked candidate rules
- explanation of failed rule matches
- identification of closest matching policies

The engine supports flexible traffic identity inputs:

- application only
- protocol and port only
- both application and protocol/port

---

## Traffic Identity Normalization

The system normalizes troubleshooting inputs into a structured traffic identity:


source_ip
destination_ip
application
protocol
port


When incomplete information is provided, NISE automatically infers additional context.

Examples:

- inferring application from port/protocol
- inferring candidate services from application defaults

This allows NISE to simulate traffic even when only partial information is known.

---

## CLI Interface

NISE currently operates through a command-line interface supporting the following commands:


file
collect
simulate
blast-radius
critical-assets
troubleshoot


The troubleshooting command supports multiple input styles:


application only
protocol/port only
application + protocol/port


---

## Future Vision

NISE aims to evolve into a full network security intelligence platform capable of:

- multi-vendor policy analysis
- connectivity troubleshooting
- attack path visualization
- exposure risk analysis
- automated security posture assessment
- cloud network security visibility