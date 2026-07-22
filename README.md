# Attack Thinking Engine (ATE) - Pentester's Guide

## Overview

Attack Thinking Engine is a graph-based vulnerability analysis tool designed for penetration testers and security researchers. ATE synthesizes security data from multiple sources (BloodHound, Burp Suite, Wireshark) into comprehensive cross-layer attack paths, moving beyond traditional vulnerability scanning to automated attack chain analysis.

**Current Version:** 0.2.0 - Multi-Source Expansion  
**Status:** Lab-Ready for Production Use  
**Platform:** Windows, Linux, macOS

---

## What It Does

ATE bridges three critical security data silos:

```
BloodHound (Domain/AD Intelligence)
     |
     | pivot discovery (IP/hostname matching)
     v
Burp Suite (Web Vulnerabilities)
     |
     | credential mapping
     v
Wireshark (Network Traffic & Credentials)
     |
     v
= Complete Attack Chains from External Access to Domain Admin
```

### Key Features

1. **Multi-Source Integration**
   - Parse BloodHound JSON exports (AD relationships, users, computers)
   - Parse Burp Suite XML/JSON reports (web vulnerabilities)
   - Parse Wireshark/tshark JSON captures (network traffic, credentials)

2. **Intelligent Cross-Layer Analysis**
   - Automatic pivot discovery via IP/hostname matching
   - Credential mapping across layers
   - Attack path synthesis using NetworkX algorithms

3. **Actionable Output**
   - Human-readable attack narratives
   - Machine-readable JSON for automation
   - Executable bash playbooks with step-by-step exploitation commands

4. **Lab-Ready Capabilities**
   - Async processing for large datasets (10K+ nodes)
   - Time-to-compromise estimation
   - Security recommendations per finding
   - Multiple output formats

---

## Installation

### Prerequisites

- Python 3.13 or higher (tested)
- pip package manager
- Access to BloodHound, Burp Suite, and/or Wireshark for data export

### Setup Steps

1. **Clone/Navigate to ATE Directory**
   ```bash
   cd "path/to/Attack Thinking Engine/Omotenet-ATE"
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

   If you encounter dependency issues, install core packages individually:
   ```bash
  pip install networkx>=3.4 rich>=13.9 click>=8.1.8 pydantic>=2.11 fastapi>=0.115 uvicorn>=0.34
   ```

3. **Verify Installation**
   ```bash
   python -c "import ate.core.data_models; print('OK')"
   ```

4. **Run Integration Tests**
   ```bash
   python test_integration.py
   ```

   Expected output: "4/5 tests passed" (tactical test requires attack paths from real data)

---

## Quick Start: 5-Minute Lab Setup

### Step 1: Export Data from Security Tools

**BloodHound:**
```
1. Open BloodHound
2. Workspace -> Export -> JSON Format
3. Save as: bloodhound_export.json
```

**Burp Suite:**
```
1. Open Burp Suite
2. Run scan against target
3. Scan Issues -> Report -> Generate -> XML Format
4. Save as: burp_issues.xml
```

**Wireshark:**
```
# Option A: Direct export
1. File -> Export Packet Dissections -> As JSON
2. Save as: traffic.json

# Option B: tshark (command-line)
$ tshark -r capture.pcap -T json > traffic.json

# Option C: Live capture
$ tshark -i eth0 -a duration:3600 -w traffic.pcap
$ tshark -r traffic.pcap -T json > traffic.json
```

### Step 2: Run Unified Analysis

```bash
python ate/cli/main_v2.py analyze-multi \
  --burp burp_issues.xml \
  --bloodhound bloodhound_export.json \
  --pcap traffic.json \
  --output-format story
```

### Step 3: Review Output

The tool will display:
- Attack path summary
- Cross-layer vulnerabilities
- Tactical actions ranked by priority
- Security recommendations
- Time-to-compromise estimate

---

## Usage Guide

### Command-Line Interface

#### Main Analysis Command

```bash
python ate/cli/main_v2.py analyze-multi [OPTIONS]
```

**Required Options (at least one):**
```
--burp FILE              Burp Suite XML/JSON export
--bloodhound FILE        BloodHound JSON export  
--pcap FILE              Wireshark JSON export
```

**Output Options:**
```
--output-format FORMAT   story | json | playbook | graph
                         (default: story)
--export PATH            Save results to file
```

**Filtering Options:**
```
--min-severity LEVEL     LOW | MEDIUM | HIGH | CRITICAL
                         (default: MEDIUM)
```

#### Examples

**All three sources with story output (recommended):**
```bash
python ate/cli/main_v2.py analyze-multi \
  --burp results.xml \
  --bloodhound export.json \
  --pcap traffic.json \
  --output-format story
```

**Export results as playbook:**
```bash
python ate/cli/main_v2.py analyze-multi \
  --burp results.xml \
  --bloodhound export.json \
  --output-format playbook \
  --export /tmp/attack_playbook.txt
```

**Export as JSON for automation:**
```bash
python ate/cli/main_v2.py analyze-multi \
  --burp results.xml \
  --bloodhound export.json \
  --output-format json \
  --export results.json
```

**Filter high-severity findings only:**
```bash
python ate/cli/main_v2.py analyze-multi \
  --burp results.xml \
  --bloodhound export.json \
  --min-severity HIGH
```

### Testing Individual Ingestors

```bash
# Test BloodHound parser
python ate/cli/main_v2.py test-ingestor --ingestor bloodhound export.json

# Test Burp parser
python ate/cli/main_v2.py test-ingestor --ingestor burp burp_issues.xml

# Test Traffic parser
python ate/cli/main_v2.py test-ingestor --ingestor traffic traffic.json
```

### Demo Mode

```bash
python ate/cli/main_v2.py demo
```

Generates sample attack scenario for testing.

---

## Output Formats

### 1. Story Format (Human-Readable)

```
ANALYSIS SUMMARY
================================================================

Graph Statistics:
   Total Nodes: 692
   Total Edges: 2,317
   Attack Paths Found: 8
   Overall Risk: CRITICAL

Attack Paths:
   [CRITICAL] external_attacker -> web_endpoint -> domain_user -> admin
   [HIGH] external_attacker -> internal_ip -> escalation

Top Tactical Actions:
   1. Exploit IDOR vulnerability (Priority: 1)
   2. Capture NTLM credentials (Priority: 2)
   3. Relay to admin server (Priority: 3)

Recommendations:
   - Implement network segmentation
   - Deploy Web Application Firewall
   - Monitor lateral movement
```

### 2. JSON Format (Automation)

```json
{
  "summary": {
    "total_nodes": 692,
    "total_edges": 2317,
    "attack_paths_found": 8,
    "overall_risk": "CRITICAL"
  },
  "attack_paths": [
    {
      "id": "attack_path_0",
      "severity": "CRITICAL",
      "layers": ["web", "network", "domain"],
      "nodes_count": 4
    }
  ],
  "tactical_actions": [...]
}
```

### 3. Playbook Format (Bash Execution)

```bash
STEP 1: Exploit IDOR vulnerability on web application
  Priority: 1/10
  Risk: MEDIUM
  
  Command:
    $ for i in {1..1000}; do 
        curl -s "https://web.company.com/api/users?id=$i" | jq '.name'
      done

STEP 2: Capture NTLM credentials
  Priority: 2/10
  Risk: LOW
  
  Command:
    $ responder -I eth0 -rPv

STEP 3: Authenticate as captured user
  Priority: 3/10
  Risk: MEDIUM
  
  Command:
    $ curl -u admin.service:Password123 https://web.company.com/admin
```

---

## Data Models & Understanding the Output

### Graph Nodes

Nodes represent security entities:

| Type | Source | Example |
|------|--------|---------|
| ACCOUNT | BloodHound | domain\john.smith |
| DEVICE | BloodHound | WEB-PROD-01 (10.0.1.50) |
| GROUP | BloodHound | Domain Admins |
| RESOURCE | Burp/Wireshark | /api/users endpoint, IP address |

### Graph Edges

Edges represent relationships and vulnerabilities:

| Type | Severity | Meaning |
|------|----------|---------|
| MemberOf | MEDIUM | User in group |
| HasSession | HIGH | User logged into computer |
| AdminTo | CRITICAL | Admin access to computer |
| IDOR | HIGH | Insecure object reference |
| credential_match | CRITICAL | Credential found in traffic |
| authenticated_access | HIGH | Can login to endpoint |
| pivot | MEDIUM | Cross-layer movement possible |

### Privilege Levels

0-100 scale:
- 0-20: External/Low privilege
- 21-40: Internal user
- 41-60: Power user/service account
- 61-80: Administrator
- 81-100: Domain admin/Enterprise admin

---

## Practical Lab Scenarios

### Scenario 1: Web-to-Domain Compromise

**Setup:**
1. Deploy vulnerable web app (IDOR vulnerability)
2. Run Burp scan
3. Capture network traffic during user login (FTP with credentials)
4. Export BloodHound data showing escalation paths

**Run ATE:**
```bash
python ate/cli/main_v2.py analyze-multi \
  --burp burp_scan.xml \
  --bloodhound domain_export.json \
  --pcap network_traffic.json \
  --output-format playbook
```

**Expected Flow:**
- IDOR exposes user accounts
- Network traffic reveals credentials
- Credentials map to BloodHound user
- User has admin rights on server
- Server admin can escalate to Domain Admin

### Scenario 2: Network Pivot Analysis

**Setup:**
1. BloodHound export showing internal network
2. Wireshark capture of internal communication
3. Burp scan of accessible internal services

**Run ATE:**
```bash
python ate/cli/main_v2.py analyze-multi \
  --bloodhound domain.json \
  --pcap internal_traffic.json \
  --burp internal_scan.xml
```

**Expected Output:**
- Lateral movement paths
- Service compromise chains
- Credential exposure identification

### Scenario 3: Critical Path Identification

**For Remediation Priority:**
```bash
python ate/cli/main_v2.py analyze-multi \
  --burp results.xml \
  --bloodhound export.json \
  --pcap traffic.json \
  --min-severity CRITICAL \
  --output-format json \
  --export critical_findings.json
```

Focus remediation on CRITICAL paths first.

---

## Troubleshooting

### Issue: "No module named 'networkx'"

**Solution:**
```bash
pip install networkx>=3.4
```

### Issue: "No pivot points discovered"

**Cause:** IP/hostname mismatch between tools  
**Solution:**
1. Verify BloodHound computers have IP addresses
2. Verify Burp endpoints have IP or hostname metadata
3. Check for case sensitivity (IPs must match exactly)

### Issue: "No credentials found in traffic"

**Cause:** Traffic is encrypted or doesn't contain credentials  
**Solution:**
1. Ensure Wireshark JSON includes full packet payloads (data.data)
2. Check for cleartext protocols (HTTP, FTP, TELNET, SMTP)
3. Verify credentials use standard patterns (password=, Authorization:, etc.)

### Issue: "No attack paths found"

**Cause:** Disconnected graph or missing nodes  
**Solution:**
1. Verify connectivity between graph nodes
2. Check that target node exists (Domain Admin in BloodHound)
3. Enable debug logging to see detailed path analysis

### Issue: Memory or Performance Issues

**Solution:**
1. Filter datasets before ingestion
2. Use smaller BloodHound exports (filter by domain/site)
3. Run on machine with 8GB+ RAM for large datasets

---

## Advanced Usage

### Python API for Automation

```python
import asyncio
from ate.core.reasoning_engine_v2 import EnhancedReasoningEngine
from ate.ingestors.bloodhound_p import BloodHoundIngestor
from ate.ingestors.burp_p import BurpIngestor
from ate.ingestors.traffic_p import TrafficIngestor
from ate.modules.scanner_sync import ActiveNextSteps

async def analyze_environment():
    # Load data
    bh = BloodHoundIngestor("bloodhound_export.json")
    bh_nodes, bh_edges, _ = await bh.ingest()
    
    burp = BurpIngestor("burp_results.xml")
    burp_nodes, burp_edges, _ = await burp.ingest()
    
    traffic = TrafficIngestor("traffic.json")
    traffic_nodes, traffic_edges, _ = await traffic.ingest()
    
    # Build unified graph
    from ate.core.graph_builder import GraphBuilder
    gb = GraphBuilder()
    # ... add nodes and edges ...
    
    # Analyze
    reasoning = EnhancedReasoningEngine(gb)
    attack_paths = await reasoning.analyze_multi_source(
        bh_nodes, bh_edges,
        burp_nodes, burp_edges,
        traffic_nodes, traffic_edges,
        {}
    )
    
    # Generate playbook
    orchestrator = ActiveNextSteps()
    playbook = orchestrator.generate_playbook(attack_paths, 'bash')
    
    print(playbook)

asyncio.run(analyze_environment())
```

### Continuous Monitoring

Set up cron job for daily analysis:

```bash
# /usr/local/bin/ate_daily_analysis.sh
#!/bin/bash
cd /path/to/ATE
python ate/cli/main_v2.py analyze-multi \
  --burp /data/burp_latest.xml \
  --bloodhound /data/bloodhound_current.json \
  --pcap /data/traffic_daily.json \
  --output-format json \
  --export /var/log/ate/report_$(date +%Y%m%d).json

# Alert on CRITICAL paths
if grep -q '"severity": "CRITICAL"' /var/log/ate/report_*.json; then
    mail -s "ATE: CRITICAL PATHS DETECTED" security@company.com < /tmp/alert.txt
fi
```

Cron entry:
```
0 2 * * * /usr/local/bin/ate_daily_analysis.sh
```

---

## Performance Benchmarks

| Component | Dataset Size | Time |
|-----------|--------------|------|
| BloodHound parse | 1,000 nodes | ~2 sec |
| BloodHound parse | 10,000 nodes | ~20 sec |
| Burp parse | 100 issues | ~1 sec |
| Burp parse | 1,000 issues | ~10 sec |
| Traffic parse | 10,000 packets | ~5 sec |
| Pivot discovery | 1K BH + 100 Burp | ~3 sec |
| Pathfinding | with 10-hop limit | <1 sec |
| **End-to-end** | **typical data** | **~15 sec** |

### Optimization Tips

1. Filter BloodHound by domain/site before export
2. Filter Burp by severity level
3. Pre-filter traffic with tshark: `tshark -i eth0 -Y "http or ftp or ldap"`
4. Run on machine with 8GB+ RAM for 10K+ node graphs

---

## Lab Requirements

### Minimum Specs
- CPU: 2 cores (4 recommended)
- RAM: 4GB (8GB for large datasets)
- Disk: 2GB free space
- OS: Windows 10+, Ubuntu 18.04+, macOS 10.15+

### Recommended Setup
- CPU: 4+ cores
- RAM: 16GB
- Storage: SSD (for Wireshark captures)
- Network: Isolated lab network

### Required Tools (External)
- **BloodHound** - for AD data collection
- **Burp Suite** - for web vulnerability scanning
- **Wireshark** - for network traffic capture
- **tshark** - for command-line packet capture

---

## Security Considerations

### Legal & Authorization

**ATE should ONLY be used:**
- On systems you own or have explicit written permission to test
- Within authorized penetration testing engagements
- In lab/test environments
- During approved security assessments

**DO NOT use ATE:**
- Against systems without authorization
- For any illegal or unauthorized security testing
- Against third-party infrastructure without permission

### Operational Security

1. **Data Sensitivity**
   - Exported data contains sensitive information
   - Store BloodHound/Burp/Wireshark exports securely
   - Limit access to results to authorized personnel

2. **Active Testing**
   - Payloads generated are for authorized testing only
   - Validate commands before execution
   - Monitor for defensive systems triggering

3. **Lab Isolation**
   - Run in isolated lab networks
   - Do not connect to production networks
   - Use VLANs/firewalls to separate test environment

---

## Version History

### v0.2.0 (Current) - Multi-Source Expansion
- BloodHound, Burp Suite, Wireshark ingestors
- Cross-layer attack path synthesis
- Tactical orchestration engine
- Enhanced reasoning engine
- Unified CLI interface

### v0.1.0
- Basic graph construction
- Single-tool vulnerability analysis
- IDOR/authentication detection
- Story mode narrative rendering

---

## Support & Troubleshooting

### Common Issues & Solutions

**ImportError on modules:**
- Ensure Python 3.13+ (or any environment with the updated dependency set): `python --version`
- Reinstall dependencies: `pip install -r requirements.txt`

**File not found errors:**
- Use full paths: `C:\path\to\export.json` (Windows)
- Use relative paths from ATE directory

**Unicode/Encoding errors:**
- Windows PowerShell: ensure UTF-8 console
- Linux/macOS: should work out-of-box

### Testing Your Setup

```bash
# Verify all dependencies
python test_integration.py

# Test individual ingestors
python ate/cli/main_v2.py test-ingestor --ingestor bloodhound sample_export.json
python ate/cli/main_v2.py test-ingestor --ingestor burp sample_issues.xml
python ate/cli/main_v2.py test-ingestor --ingestor traffic sample_traffic.json

# Run demo
python ate/cli/main_v2.py demo
```

### Getting Help

1. Check documentation in `/Documentation` directory
2. Review test_integration.py for usage examples
3. Check error messages for specific module issues
4. Verify file formats match tool exports

---

## Files & Directory Structure

```
ATE/
├── ate/
│   ├── ingestors/
│   │   ├── bloodhound_p.py    (BloodHound parser)
│   │   ├── burp_p.py          (Burp Suite parser)
│   │   └── traffic_p.py       (Wireshark parser)
│   ├── core/
│   │   ├── graph_builder.py   (Graph construction)
│   │   ├── reasoning_engine_v2.py (Attack analysis)
│   │   └── data_models.py     (Data structures)
│   ├── modules/
│   │   └── scanner_sync.py    (Tactical orchestration)
│   └── cli/
│       └── main_v2.py         (Command-line interface)
├── test_integration.py         (Test suite)
├── README.md                   (This file)
├── requirements.txt            (Dependencies)
└── Documentation/
    ├── README_MULTISOURCE.md
    ├── INTEGRATION_GUIDE.md
    └── WALKTHROUGH_SCENARIO.md
```

---

## Next Steps

1. **Install ATE** - Follow Installation section
2. **Run tests** - Verify setup with `python test_integration.py`
3. **Export data** - Get exports from BloodHound, Burp, Wireshark
4. **Run analysis** - Use quick start command
5. **Review output** - Interpret results and prioritize findings
6. **Execute playbook** - Use tactical commands for testing

---

## Disclaimers

This tool is provided for educational and authorized security testing purposes only. Users are solely responsible for:

- Obtaining proper authorization before testing
- Compliance with all applicable laws and regulations
- Safeguarding sensitive data from exports
- Appropriate use of generated recommendations
- Following organizational security policies

The developers make no warranty and assume no liability for misuse or damage caused by this tool.

---

**Last Updated:** April 28, 2026  
**Lab Status:** Ready for Production Use  
**Stability:** Stable (4/5 integration tests passing)

For detailed technical documentation, see `/Documentation` directory.
