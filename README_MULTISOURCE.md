# Attack Thinking Engine (ATE) - Multi-Source Expansion

## Overview

**Attack Thinking Engine** is a graph-based vulnerability analysis tool that synthesizes security data from multiple sources into comprehensive attack paths. It moves beyond traditional vulnerability scanning to automated attack path analysis across web applications (Burp Suite), network infrastructure (Wireshark), and Active Directory domains (BloodHound).

### Key Innovation

ATE bridges three data silos:

```
BloodHound (Domain Intelligence)
    ↓ pivot discovery ↓
Burp Suite (Web Vulnerabilities)  ← IP/Hostname matching
    ↓ credential mapping ↓
Wireshark (Network Traffic & Credentials)
    ↓
= Cross-Layer Attack Paths to Domain Admin
```

## What's New: Multi-Source Expansion

This expansion adds three critical capabilities:

### 1. **Multi-Tool Ingestors** (`ate/ingestors/`)
Specialized data parsers that normalize heterogeneous formats into a common graph model:

- **`bloodhound_p.py`** - Parses BloodHound JSON exports
  - Extracts Users, Computers, Groups, Domains as graph nodes
  - Maps relationships (MemberOf, HasSession, AdminTo) as weighted edges
  - Severity scoring: AdminTo=CRITICAL (privilege escalation), HasSession=HIGH

- **`burp_p.py`** - Parses Burp Suite XML/JSON exports
  - Creates endpoint nodes for each discovered web server
  - Maps vulnerabilities as edges (IDOR, SQLi, Auth Bypass, XXE, SSRF, etc.)
  - Confidence-based weighting (certain=0.95, high=0.8, etc.)

- **`traffic_p.py`** - Parses Wireshark/tshark JSON traffic
  - Extracts IP conversation pairs as communication edges
  - Pattern-matches cleartext credentials (passwords, JWT, API keys)
  - Maps protocols and identifies credential exposure risks

### 2. **Enhanced Reasoning Engine** (`ate/core/reasoning_engine_v2.py`)
Synthesizes multi-source data to discover attack paths:

- **`pivot_discovery()`** - Connects data layers via IP/hostname matching
  - Automatically creates edges between Burp endpoints and BloodHound computers
  - Example: Web server IP 10.0.1.50 matches computer "WEB-SERVER" in AD

- **`credential_mapping()`** - Tracks credentials across layers
  - Links credentials from Wireshark to BloodHound users
  - Maps users to web endpoints they can authenticate to
  - Example: FTP password found in traffic → domain\user1 → Burp endpoint

- **`cross_layer_pathfinding()`** - Finds optimal attack paths
  - Uses NetworkX shortest path algorithms with custom weights
  - Returns "Path of Least Resistance" from external to domain admin
  - Layers: web vulnerabilities → network access → domain escalation

### 3. **Tactical Orchestration** (`ate/modules/scanner_sync.py`)
Generates actionable exploitation steps:

- **`ActiveNextSteps`** class analyzes paths for execution blockers
- Suggests immediate actions: "Use Responder.py on 10.0.0.5 to capture NTLM"
- Generates automated playbooks in multiple formats (bash, JSON, story)
- Estimates time-to-compromise based on path complexity

### 4. **Unified CLI** (`ate/cli/main_v2.py`)
Single command for multi-source analysis:

```bash
ate analyze-multi --burp results.xml \
                  --bloodhound export.json \
                  --pcap traffic.json \
                  --output-format playbook
```

## Architecture

### Data Flow

```
┌──────────────────────────────────────────────────────────────┐
│                   DATA INGESTION LAYER                       │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐         │
│  │  BloodHound │  │ Burp Suite   │  │ Wireshark   │         │
│  │ JSON Export │  │ XML/JSON     │  │ JSON Export │         │
│  └──────┬──────┘  └──────┬───────┘  └──────┬──────┘         │
│         │                │                 │                │
└─────────┼────────────────┼─────────────────┼────────────────┘
          │                │                 │
┌─────────▼────────────────▼─────────────────▼────────────────┐
│        DATA NORMALIZATION LAYER (INGESTORS)                 │
│  ┌─────────────────┐  ┌──────────────┐  ┌─────────────┐    │
│  │BloodHoundIngest │  │ BurpIngestor │  │TrafficInges │    │
│  │    (async)      │  │    (async)   │  │   (async)   │    │
│  └────────┬────────┘  └──────┬───────┘  └──────┬──────┘    │
│           │                   │                 │            │
│    Returns: (nodes, edges)    │         (incl. credentials) │
└───────────┼───────────────────┼─────────────────┼────────────┘
            │                   │                 │
┌───────────▼───────────────────▼─────────────────▼────────────┐
│           UNIFIED GRAPH (NetworkX DiGraph)                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ All nodes from all sources in common format          │   │
│  │ All edges with consistent weights and metadata       │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────────┬───────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼──────┐  ┌──────────▼────────┐  ┌──────▼────────┐
│ Pivot        │  │ Credential       │  │ Cross-Layer  │
│ Discovery    │  │ Mapping          │  │ Pathfinding  │
└───────┬──────┘  └──────────┬────────┘  └──────┬────────┘
        │                    │                   │
└───────┼────────────────────┼───────────────────┘
        │                    │
        └────────┬───────────┘
                 │
        ┌────────▼───────────┐
        │  Attack Paths      │
        │ (sorted by weight) │
        └────────┬───────────┘
                 │
        ┌────────▼──────────────────┐
        │ Tactical Orchestration    │
        │ (ActiveNextSteps)         │
        └────────┬──────────────────┘
                 │
        ┌────────▼──────────────────┐
        │ Actionable Playbook       │
        │ (Responder, psexec, etc)  │
        └───────────────────────────┘
```

## Components

### Core Files

| File | Purpose | Lines |
|------|---------|-------|
| `ate/ingestors/bloodhound_p.py` | BloodHound AD data parser | ~400 |
| `ate/ingestors/burp_p.py` | Burp Suite vulnerability parser | ~450 |
| `ate/ingestors/traffic_p.py` | Wireshark network traffic parser | ~400 |
| `ate/core/reasoning_engine_v2.py` | Multi-source attack path analyzer | ~500 |
| `ate/modules/scanner_sync.py` | Tactical orchestration engine | ~450 |
| `ate/cli/main_v2.py` | Unified CLI interface | ~400 |

**Total: ~2,600 lines of new production code**

### Data Models

All ingestors normalize to common `GraphNode` and `GraphEdge` formats:

```python
class GraphNode:
    id: str                    # Unique identifier
    node_type: NodeType        # ACCOUNT, DEVICE, RESOURCE, etc.
    label: str                 # Human-readable name
    privilege_level: int       # 0-100 scale
    is_sensitive: bool
    metadata: Dict[str, Any]   # Tool-specific properties

class GraphEdge:
    id: str                    # Unique identifier
    source: str                # Source node ID
    target: str                # Target node ID
    edge_type: str             # Relationship type
    weight: float              # 0.0-1.0 exploitation difficulty
    metadata: Dict[str, Any]   # Additional context
```

## Usage

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Ensure you have the ingestors:
python -m ate.ingestors.bloodhound_p
python -m ate.ingestors.burp_p
python -m ate.ingestors.traffic_p
```

### Export Data from Tools

**BloodHound:**
```
Workspace → Export → JSON Format → save as "export.json"
```

**Burp Suite:**
```
Scan Issues → Report → Generate → XML → save as "burp_issues.xml"
```

**Wireshark:**
```
File → Export Packet Dissections → JSON → save as "traffic.json"
(Or use: tshark -r capture.pcap -T json > traffic.json)
```

### Run Analysis

**Command Line:**
```bash
# All three sources
ate analyze-multi --burp burp_issues.xml \
                  --bloodhound export.json \
                  --pcap traffic.json \
                  --output-format playbook \
                  --export playbook.txt

# Two sources
ate analyze-multi --burp burp_issues.xml \
                  --bloodhound export.json

# Export as JSON for automation
ate analyze-multi --burp burp_issues.xml \
                  --bloodhound export.json \
                  --output-format json \
                  --export results.json
```

**Python API:**
```python
import asyncio
from ate.core.reasoning_engine_v2 import EnhancedReasoningEngine
from ate.ingestors import BloodHoundIngestor, BurpIngestor, TrafficIngestor

async def main():
    # Load data
    bh = BloodHoundIngestor("export.json")
    bh_nodes, bh_edges, _ = await bh.ingest()
    
    # Analyze
    reasoning = EnhancedReasoningEngine(graph_builder)
    paths = await reasoning.analyze_multi_source(...)
    
    # Generate playbook
    orchestrator = ActiveNextSteps()
    playbook = orchestrator.generate_playbook(paths, 'bash')

asyncio.run(main())
```

## Output Examples

### Story Format (Default)

```
📊 Graph Statistics:
   Total Nodes: 127
   Total Edges: 342
   Attack Paths Found: 5
   Overall Risk: CRITICAL

⚔️ Attack Paths:
   • [CRITICAL] external_attacker → web_endpoint → domain_user → domain_admin
   • [HIGH] external_attacker → internal_ip → compromised_server → admin_group

🎯 Top Tactical Actions:
   • Exploit IDOR vulnerability on web application (Priority: 1)
   • Capture NTLM credentials via Responder (Priority: 2)
   • Relay credentials to internal server (Priority: 3)

💡 Recommendations:
   🔐 Implement network segmentation to prevent credential capture
   🌐 Perform comprehensive web application security testing
```

### Playbook Format

```
STEP 1: Exploit IDOR vulnerability on web application
  Priority: 1/10
  Category: web_exploitation
  Risk: MEDIUM
  Command:
    $ # Exploit idor on 10.0.1.50

  Expected Result: Access to endpoint granted

---

STEP 2: Capture NTLM credentials via Responder
  Priority: 2/10
  Category: credential_capture
  Risk: LOW
  Command:
    $ responder -I eth0 -rPv

  Expected Result: NTLM hash captured from 10.0.1.50
```

## Algorithm Details

### Pivot Discovery

Matches nodes across layers using IP/hostname:

```python
for burp_endpoint in burp_nodes:
    for bloodhound_computer in bh_nodes:
        if burp_endpoint.ip == bh_computer.ip:
            # Create edge with weight 0.5 (easy lateral movement)
            create_pivot_edge(burp_endpoint → bh_computer)
```

Weight: 0.5 (low resistance, represents internal pivot opportunity)

### Credential Mapping

Links credentials from traffic to users to endpoints:

```python
for credential in traffic_credentials:
    for user in bh_users:
        if match_username(credential.user, user.name):
            # User can authenticate
            create_edge(credential → user)
            # User can access endpoints they authenticate to
            for endpoint in burp_endpoints:
                if supports_auth(endpoint, credential.protocol):
                    create_edge(user → endpoint)
```

### Cross-Layer Pathfinding

Uses NetworkX shortest path with custom weighting:

```python
paths = networkx.all_simple_paths(
    graph,
    source='external_attacker',
    target='domain_admin',
    cutoff=10  # Prevent explosion of paths
)

# Score each path
for path in paths:
    weight = sum(edge.weight for edge in path.edges)
    paths.sort(by_weight=True)
    
    # Return top 5 most feasible paths
```

## Performance

| Dataset Size | Processing Time |
|---|---|
| 1,000 AD nodes | ~2 sec |
| 100 Burp issues | ~1 sec |
| 10,000 packets | ~5 sec |
| **Total (combined)** | **~8 sec** |

Graph operations (pivot discovery, pathfinding):
- Pivot discovery: O(n×m) where n=AD nodes, m=endpoints
- Pathfinding: O(n³) with cutoff limit

## Requirements

### Hard Requirements
- Python 3.13+ (tested)
- NetworkX 3.2.1+
- Pydantic 2.0+
- Click 8.0+
- Rich 13.0+
- asyncio (built-in)

### Soft Requirements
- Responder.py (for credential capture)
- Impacket (for relay attacks)
- hashcat (for hash cracking)

## Limitations & Roadmap

### Current Limitations
- No real-time updates (batch processing only)
- Limited to NetworkX algorithms (scalable to ~10K nodes comfortably)
- Requires explicit tool exports (no API integrations yet)
- Credential pattern matching is signature-based

### Roadmap
- [ ] Live API integrations (BloodHound API, Burp REST API)
- [ ] Graph database backend (Neo4j) for massive scale
- [ ] Machine learning credential extraction
- [ ] Real-time monitoring mode
- [ ] Encrypted traffic analysis (TLS interception)
- [ ] Active scanning integration

## Security Considerations

⚠️ **Important**: This tool is designed for:
- Authorized penetration testing
- Red team exercises
- Security research in controlled environments
- Continuous security monitoring (internal use only)

**Do not use without explicit authorization from the system owner.**

## Contributing

Areas for contribution:
- Additional ingestors (Nessus, Qualys, Metasploit)
- Enhanced credential detection patterns
- Performance optimizations for large graphs
- Additional reasoning engines (ML-based path prediction)

## References

- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - AD data collection
- [Burp Suite](https://portswigger.net/burp) - Web vulnerability scanning
- [Wireshark](https://www.wireshark.org/) - Network analysis
- [NetworkX](https://networkx.org/) - Graph algorithms
- [Responder](https://github.com/lgandx/Responder) - Credential capture
- [Impacket](https://github.com/fortra/impacket) - Network protocol library

## License

[Your License Here]

## Version

**ATE v0.2.0** - Multi-Source Expansion
- Released: [Date]
- New ingestors: BloodHound, Burp Suite, Wireshark
- Enhanced reasoning engine for cross-layer analysis
- Tactical orchestration with actionable playbooks
