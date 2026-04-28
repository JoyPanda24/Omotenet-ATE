"""
Integration Guide: Multi-Source Attack Path Analysis
Complete examples and walkthroughs for using ATE with BloodHound, Burp, and Wireshark
"""

# ============================================================================
# PART 1: QUICK START
# ============================================================================

"""
QUICK START: 3-Step Multi-Source Analysis

Step 1: Export data from each tool
    - BloodHound: Export → JSON
    - Burp Suite: Report → Issues → XML
    - Wireshark: File → Export → JSON
    
Step 2: Run unified analysis
    $ ate analyze-multi --burp burp_export.xml \
                        --bloodhound bloodhound_export.json \
                        --pcap traffic.json \
                        --output-format playbook

Step 3: Execute generated playbook
    The output will include specific commands like:
    $ responder -I eth0 -rPv
    $ ntlmrelayx.py -t 10.0.1.50 -c "whoami"
    
Expected outcome: Domain admin compromise with step-by-step instructions
"""


# ============================================================================
# PART 2: INDIVIDUAL INGESTOR USAGE
# ============================================================================

"""
Testing Individual Ingestors:

# Test BloodHound ingestor
ate test-ingestor --ingestor bloodhound export.json

# Test Burp ingestor
ate test-ingestor --ingestor burp burp_issues.xml

# Test Traffic ingestor
ate test-ingestor --ingestor traffic traffic.json
"""

# ============================================================================
# PART 3: DETAILED DATA MODEL
# ============================================================================

# BloodHound Data Model
"""
BloodHound exports relationships like:
{
  "nodes": [
    {
      "objectid": "USER@DOMAIN.COM",
      "type": "User",
      "name": "user@domain.com",
      "email": "user@domain.com"
    },
    {
      "objectid": "COMPUTER$@DOMAIN.COM",
      "type": "Computer",
      "name": "computer.domain.com",
      "operatingsystem": "Windows 10"
    }
  ],
  "relationships": [
    {
      "source": "USER@DOMAIN.COM",
      "target": "GROUP@DOMAIN.COM",
      "relationshiptype": "MemberOf"
    },
    {
      "source": "USER@DOMAIN.COM",
      "target": "COMPUTER$@DOMAIN.COM",
      "relationshiptype": "HasSession"
    },
    {
      "source": "GROUP@DOMAIN.COM",
      "target": "COMPUTER$@DOMAIN.COM",
      "relationshiptype": "AdminTo"
    }
  ]
}

BloodHound Ingestor Mapping:
- User nodes → Account nodes with email/name metadata
- Computer nodes → Device nodes with IP/OS metadata
- MemberOf/HasSession/AdminTo → Edges with severity weighting
- AdminTo → CRITICAL severity (privilege escalation indicator)
"""

# Burp Suite Data Model
"""
Burp exports vulnerability issues like:
<?xml version="1.0"?>
<issues burpVersion="2023.10">
  <issue>
    <type>2104576</type>
    <name>Insecure direct object references</name>
    <host ip="10.0.1.50">
      <![CDATA[https://web.company.com]]>
    </host>
    <path><![CDATA[/admin/users?id=123]]></path>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>...</issueBackground>
  </issue>
</issues>

Burp Ingestor Mapping:
- Each host → Web Endpoint node with IP metadata
- Each issue → Vulnerability edge (IDOR, SQLi, etc.)
- Issue type + severity → Edge weight and severity
- Confidence level → Affects path prioritization
"""

# Wireshark Data Model
"""
Tshark JSON export format:
[
  {
    "index": {"index": 1},
    "layers": {
      "frame": {"frame.number": "1"},
      "ip": {
        "ip.src": "192.168.1.100",
        "ip.dst": "10.0.0.50",
        "ip.proto": "6"
      },
      "tcp": {
        "tcp.srcport": "54321",
        "tcp.dstport": "80"
      },
      "http": {
        "http.request.method": "GET",
        "http.request.uri": "/api/users",
        "http.authorization": "Basic dXNlcjpwYXNz"
      },
      "data": {
        "data.data": "..."
      }
    }
  }
]

Traffic Ingestor Extraction:
- IP pairs (src → dst) → Communication edges
- Cleartext credentials → Sensitive data findings
- Protocols (HTTP, FTP, TELNET) → Service information
- Tokens/JWT/API keys → Credential mapping opportunities
"""

# ============================================================================
# PART 4: PYTHON API USAGE
# ============================================================================

"""
Direct Python API Usage Example:

import asyncio
from ate.core.graph_builder import GraphBuilder
from ate.core.reasoning_engine_v2 import EnhancedReasoningEngine
from ate.ingestors.bloodhound_p import BloodHoundIngestor
from ate.ingestors.burp_p import BurpIngestor
from ate.ingestors.traffic_p import TrafficIngestor
from ate.modules.scanner_sync import ActiveNextSteps

async def analyze_security():
    # Create unified graph
    gb = GraphBuilder()
    
    # Load BloodHound data
    bh = BloodHoundIngestor("export.json")
    bh_nodes, bh_edges, bh_findings = await bh.ingest()
    for edge in bh_edges:
        gb.add_edge(edge)
    
    # Load Burp data
    burp = BurpIngestor("burp_issues.xml")
    burp_nodes, burp_edges, burp_findings = await burp.ingest()
    for edge in burp_edges:
        gb.add_edge(edge)
    
    # Load Wireshark data
    traffic = TrafficIngestor("traffic.json")
    traffic_nodes, traffic_edges, traffic_findings = await traffic.ingest()
    for edge in traffic_edges:
        gb.add_edge(edge)
    
    # Analyze attack paths
    reasoning = EnhancedReasoningEngine(gb)
    attack_paths = await reasoning.analyze_multi_source(
        bh_nodes, bh_edges,
        burp_nodes, burp_edges,
        traffic_nodes, traffic_edges,
        {}  # traffic_credentials (would populate from findings)
    )
    
    # Generate tactical actions
    orchestrator = ActiveNextSteps()
    actions = orchestrator.analyze_paths(attack_paths)
    
    # Get playbook
    playbook = orchestrator.generate_playbook(attack_paths, 'bash')
    print(playbook)

# Run analysis
asyncio.run(analyze_security())
"""

# ============================================================================
# PART 5: ATTACK SCENARIO WALKTHROUGH
# ============================================================================

"""
SCENARIO: External Attacker Reaches Domain Admin

Scenario Overview:
1. External attacker scans web application (captured in Burp)
2. Finds IDOR vulnerability allowing user enumeration
3. Burp data → Traffic data pivot: Attacker IP found in Wireshark traffic
4. Wireshark reveals cleartext credentials in FTP traffic
5. Credentials mapped to BloodHound domain user
6. User has admin access to compromised server
7. Server admin can escalate to Domain Admin via AdminTo relationship

Data Flow:
┌─────────────────────────────────────────────────────────────┐
│ EXTERNAL ATTACKER (10.0.0.50)                               │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼ (HTTP traffic)
┌─────────────────────────────────────────────────────────────┐
│ WEB SERVER (10.0.1.50) - Burp finds IDOR vulnerability      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼ (pivot: IP match)
┌─────────────────────────────────────────────────────────────┐
│ COMPUTER "WEB-SERVER" (BloodHound) - domain\\user1 has session
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼ (HasSession relationship)
┌─────────────────────────────────────────────────────────────┐
│ USER "domain\\user1" (BloodHound) - credentials in Wireshark
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼ (AdminTo relationship)
┌─────────────────────────────────────────────────────────────┐
│ COMPUTER "DC-ADMIN" (BloodHound)                            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼ (MemberOf relationship)
┌─────────────────────────────────────────────────────────────┐
│ GROUP "Domain Admins" → DOMAIN ADMIN COMPROMISE             │
└─────────────────────────────────────────────────────────────┘

Tactical Actions Generated:
1. [PRIORITY 1] Exploit IDOR on web application
   $ # Manual exploitation of /api/users?id=1,2,3...
   
2. [PRIORITY 2] Capture NTLM credentials
   $ responder -I eth0 -rPv
   
3. [PRIORITY 3] Relay NTLM to server
   $ ntlmrelayx.py -t 10.0.1.50 -c "whoami"
   
4. [PRIORITY 4] Authenticate as user1
   $ psexec.py domain/user1:password@10.0.1.50
   
5. [PRIORITY 5] Escalate to Domain Admin
   $ secretsdump.py domain/user1:password@10.0.0.1
   
Time to Compromise: ~45 minutes
Risk Level: CRITICAL
"""

# ============================================================================
# PART 6: OUTPUT FORMATS
# ============================================================================

"""
Output Format Examples:

STORY FORMAT (default):
───────────────────────
📊 Graph Statistics:
   Total Nodes: 127
   Total Edges: 342
   Attack Paths Found: 5
   Overall Risk: CRITICAL

⚔️ Attack Paths:
   • [CRITICAL] external_attacker → web_endpoint → domain_user → domain_admin
   • [HIGH] external_attacker → internal_ip → compromised_server → admin_group
   • [HIGH] external_attacker → ftp_server → credentials → escalation

🎯 Top Tactical Actions:
   • Exploit IDOR vulnerability on web application (Priority: 1)
   • Capture NTLM credentials via Responder (Priority: 2)
   • Relay credentials to internal server (Priority: 3)

💡 Recommendations:
   🔐 Implement network segmentation to prevent credential capture
   🌐 Perform comprehensive web application security testing
   🔀 Restrict lateral movement with network micro-segmentation


JSON FORMAT:
──────────
{
  "summary": {
    "total_nodes": 127,
    "total_edges": 342,
    "attack_paths_found": 5,
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


PLAYBOOK FORMAT:
────────────────
STEP 1: Exploit IDOR vulnerability on web application
  Priority: 1/10
  Category: web_exploitation
  Command: # Exploit idor on 10.0.1.50
  Expected Result: Access to endpoint granted
...
"""

# ============================================================================
# PART 7: TROUBLESHOOTING
# ============================================================================

"""
Common Issues and Solutions:

Issue: "No pivot points discovered"
Solution: 
  - Verify BloodHound export includes IP addresses in computer properties
  - Check Burp endpoints have IP metadata
  - Ensure hostnames match exactly (case-sensitive)

Issue: "No credentials found in traffic"
Solution:
  - Verify Wireshark JSON includes full packet payloads (data.data)
  - Check for cleartext protocols (HTTP, FTP, TELNET, SMTP)
  - Ensure traffic is unencrypted

Issue: "Pathfinding finds no paths"
Solution:
  - Check graph has proper connectivity between layers
  - Verify target node exists (Domain Admin must exist in BloodHound)
  - Enable debug logging for detailed pathfinding info

Issue: "Memory exhausted on large BloodHound export"
Solution:
  - BloodHound ingestor uses async processing
  - Can safely handle 10,000+ nodes
  - If still OOM, filter BloodHound export before ingestion

Issue: "Burp XML parsing fails"
Solution:
  - Verify XML is properly formatted
  - Check Burp version compatibility (tested with 2023.10+)
  - Ensure file is fully written (not truncated)
"""

# ============================================================================
# PART 8: ADVANCED USAGE
# ============================================================================

"""
Advanced Scenarios:

1. SUPPLY CHAIN ATTACK ANALYSIS
   Input: Multiple organizations' BloodHound exports + unified Burp results
   Output: Attack paths through interconnected AD domains
   
2. INCIDENT RESPONSE
   Input: Wireshark PCAP from incident timeline + current BloodHound state
   Output: Determine attack path and identify compromised accounts
   
3. RED TEAM CAMPAIGN
   Input: Burp web results + existing Shodan data (as traffic simulation)
   Output: Prioritized exploitation path for time-constrained exercise
   
4. REMEDIATION VALIDATION
   Input: Multiple snapshots of same environment over time
   Output: Track closure of attack paths before/after security patching
"""

# ============================================================================
# PART 9: PERFORMANCE NOTES
# ============================================================================

"""
Performance Characteristics:

BloodHound Processing:
- 1,000 nodes: ~2 seconds
- 10,000 nodes: ~20 seconds
- 100,000 nodes: ~200 seconds (requires 8GB+ RAM)

Burp Processing:
- 100 issues: ~1 second
- 1,000 issues: ~10 seconds
- 10,000 issues: ~100 seconds

Wireshark Processing:
- 10,000 packets: ~5 seconds
- 100,000 packets: ~50 seconds
- 1,000,000 packets: ~500 seconds

Graph Operations:
- Pivot discovery: O(n*m) where n=BH nodes, m=Burp nodes
- Pathfinding: O(n^3) with NetworkX all_simple_paths(cutoff=10)

Optimization Tips:
- Use tshark to pre-filter traffic: tshark -i eth0 -Y "http or ftp"
- Export only relevant BloodHound data before ATE analysis
- Filter Burp issues by severity before ingestion
"""

# ============================================================================
# PART 10: INTEGRATION WITH SECURITY WORKFLOWS
# ============================================================================

"""
Integration with Security Operations:

1. CONTINUOUS MONITORING
   Schedule: Daily at 2 AM
   Command: ate analyze-multi --burp latest.xml \
                              --bloodhound current.json \
                              --pcap today.json \
                              --export /var/log/ate/report_$(date +%s).json
   
2. INCIDENT DETECTION
   Trigger: When critical path found in ATE output
   Action: Alert security team with playbook
   
3. PENETRATION TESTING
   Pre-test: Generate baseline attack paths
   Post-test: Re-run to validate new paths discovered
   
4. REMEDIATION TRACKING
   Before: Document critical paths
   After: Re-run to confirm paths are closed
   
5. VENDOR RISK ASSESSMENT
   Input: Vendor BloodHound export (if available)
   Output: Risk paths through vendor infrastructure
"""

print(__doc__)
