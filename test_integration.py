"""
Integration Tests and Examples for Multi-Source Attack Path Analysis
Demonstrates end-to-end usage of BloodHound, Burp, and Wireshark ingestors
with the enhanced reasoning engine and tactical orchestration.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, Any

# Simulated test data (since actual exports may not be available)

SAMPLE_BLOODHOUND_DATA = {
    "nodes": [
        {
            "objectid": "ADMIN@COMPANY.COM",
            "type": "User",
            "name": "admin@company.com",
            "email": "admin@company.com",
            "displayname": "Administrator"
        },
        {
            "objectid": "JOHN.SMITH@COMPANY.COM",
            "type": "User",
            "name": "john.smith@company.com",
            "email": "john.smith@company.com"
        },
        {
            "objectid": "WEB-PROD-01$@COMPANY.COM",
            "type": "Computer",
            "name": "web-prod-01.company.com",
            "operatingsystem": "Windows Server 2019",
            "ipaddress": "10.0.1.50"
        },
        {
            "objectid": "DC-01$@COMPANY.COM",
            "type": "Computer",
            "name": "dc-01.company.com",
            "operatingsystem": "Windows Server 2019",
            "ipaddress": "10.0.0.1"
        },
        {
            "objectid": "DOMAIN ADMINS@COMPANY.COM",
            "type": "Group",
            "name": "Domain Admins@company.com"
        },
        {
            "objectid": "DEVELOPERS@COMPANY.COM",
            "type": "Group",
            "name": "Developers@company.com"
        }
    ],
    "relationships": [
        {
            "source": "ADMIN@COMPANY.COM",
            "target": "DOMAIN ADMINS@COMPANY.COM",
            "relationshiptype": "MemberOf"
        },
        {
            "source": "JOHN.SMITH@COMPANY.COM",
            "target": "DEVELOPERS@COMPANY.COM",
            "relationshiptype": "MemberOf"
        },
        {
            "source": "JOHN.SMITH@COMPANY.COM",
            "target": "WEB-PROD-01$@COMPANY.COM",
            "relationshiptype": "HasSession"
        },
        {
            "source": "DOMAIN ADMINS@COMPANY.COM",
            "target": "DC-01$@COMPANY.COM",
            "relationshiptype": "AdminTo"
        },
        {
            "source": "DOMAIN ADMINS@COMPANY.COM",
            "target": "WEB-PROD-01$@COMPANY.COM",
            "relationshiptype": "AdminTo"
        }
    ]
}

SAMPLE_BURP_DATA = """<?xml version="1.0"?>
<issues burpVersion="2023.10">
  <issue>
    <type>2104576</type>
    <name>Insecure direct object references</name>
    <host ip="10.0.1.50">
      <![CDATA[https://web.company.com]]>
    </host>
    <path><![CDATA[/api/users]]></path>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground><![CDATA[Insecure direct object references (IDOR)]]></issueBackground>
  </issue>
  <issue>
    <type>1098656</type>
    <name>SQL injection</name>
    <host ip="10.0.1.50">
      <![CDATA[https://web.company.com]]>
    </host>
    <path><![CDATA[/search]]></path>
    <severity>Critical</severity>
    <confidence>Certain</confidence>
    <issueBackground><![CDATA[SQL injection vulnerability]]></issueBackground>
  </issue>
  <issue>
    <type>2101300</type>
    <name>Missing authentication</name>
    <host ip="10.0.1.50">
      <![CDATA[https://web.company.com]]>
    </host>
    <path><![CDATA[/admin]]></path>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground><![CDATA[Admin endpoints are not authenticated]]></issueBackground>
  </issue>
</issues>
"""

SAMPLE_TRAFFIC_DATA = [
    {
        "index": {"index": 1},
        "layers": {
            "frame": {"frame.number": "1"},
            "ip": {
                "ip.src": "192.168.1.100",
                "ip.dst": "10.0.1.50",
                "ip.proto": "6"
            },
            "tcp": {"tcp.srcport": "54321", "tcp.dstport": "80"},
            "http": {
                "http.request.method": "GET",
                "http.request.uri": "/api/users?id=1",
                "http.host": "web.company.com"
            }
        }
    },
    {
        "index": {"index": 2},
        "layers": {
            "frame": {"frame.number": "2"},
            "ip": {
                "ip.src": "10.0.1.50",
                "ip.dst": "10.0.0.100",
                "ip.proto": "6"
            },
            "tcp": {"tcp.srcport": "12345", "tcp.dstport": "21"},
            "ftp": {"ftp.command": "USER admin"},
            "data": {"data.data": "USER admin"}
        }
    },
    {
        "index": {"index": 3},
        "layers": {
            "frame": {"frame.number": "3"},
            "ip": {
                "ip.src": "10.0.1.50",
                "ip.dst": "10.0.0.100",
                "ip.proto": "6"
            },
            "tcp": {"tcp.srcport": "12345", "tcp.dstport": "21"},
            "ftp": {"ftp.command": "PASS P@ssw0rd123"},
            "data": {"data.data": "PASS P@ssw0rd123"}
        }
    }
]


# ============================================================================
# TEST 1: Individual Ingestors
# ============================================================================

async def test_bloodhound_ingestor():
    """Test BloodHound ingestor with sample data."""
    print("\n" + "="*80)
    print("TEST 1: BloodHound Ingestor")
    print("="*80)
    
    # Save sample data to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(SAMPLE_BLOODHOUND_DATA, f)
        temp_path = f.name
    
    try:
        from ate.ingestors.bloodhound_p import BloodHoundIngestor
        
        ingestor = BloodHoundIngestor(temp_path)
        nodes, edges, findings = await ingestor.ingest()
        
        print(f"\n[PASS] BloodHound Ingestor Test Passed")
        print(f"  Nodes: {len(nodes)}")
        print(f"  Edges: {len(edges)}")
        print(f"  Findings: {len(findings)}")
        
        print(f"\n  Node Types:")
        for node_id, node in nodes.items():
            print(f"    - {node.label} ({node.node_type})")
        
        print(f"\n  Edge Types:")
        for edge in edges:
            print(f"    - {edge.source} --[{edge.edge_type}]--> {edge.target}")
        
        return True, nodes, edges
    
    finally:
        Path(temp_path).unlink()


async def test_burp_ingestor():
    """Test Burp ingestor with sample data."""
    print("\n" + "="*80)
    print("TEST 2: Burp Suite Ingestor")
    print("="*80)
    
    # Save sample data to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(SAMPLE_BURP_DATA)
        temp_path = f.name
    
    try:
        from ate.ingestors.burp_p import BurpIngestor
        
        ingestor = BurpIngestor(temp_path)
        nodes, edges, findings = await ingestor.ingest()
        
        print(f"\n[PASS] Burp Ingestor Test Passed")
        print(f"  Nodes: {len(nodes)}")
        print(f"  Edges: {len(edges)}")
        print(f"  Findings: {len(findings)}")
        
        print(f"\n  Nodes (Web Endpoints):")
        for node_id, node in nodes.items():
            print(f"    - {node.label}")
        
        print(f"\n  Vulnerabilities Found:")
        for edge in edges:
            print(f"    - {edge.edge_type}: {edge.source}  {edge.target}")
        
        return True, nodes, edges
    
    finally:
        Path(temp_path).unlink()


async def test_traffic_ingestor():
    """Test Traffic ingestor with sample data."""
    print("\n" + "="*80)
    print("TEST 3: Wireshark Traffic Ingestor")
    print("="*80)
    
    # Save sample data to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(SAMPLE_TRAFFIC_DATA, f)
        temp_path = f.name
    
    try:
        from ate.ingestors.traffic_p import TrafficIngestor
        
        ingestor = TrafficIngestor(temp_path)
        nodes, edges, findings = await ingestor.ingest()
        
        print(f"\n[PASS] Traffic Ingestor Test Passed")
        print(f"  Nodes: {len(nodes)}")
        print(f"  Edges: {len(edges)}")
        print(f"  Findings: {len(findings)}")
        
        print(f"\n  IP Nodes:")
        for node_id, node in nodes.items():
            is_internal = node.metadata.get('is_internal', False)
            print(f"    - {node.label} (internal={is_internal})")
        
        print(f"\n  Communication Patterns:")
        for edge in edges:
            print(f"    - {edge.source} --[{edge.edge_type}]--> {edge.target}")
        
        print(f"\n  Credentials Found:")
        creds = ingestor.get_exposed_credentials()
        for cred in creds[:5]:
            print(f"    - {cred[:50]}...")
        
        return True, nodes, edges
    
    finally:
        Path(temp_path).unlink()


# ============================================================================
# TEST 2: Unified Graph and Reasoning Engine
# ============================================================================

async def test_unified_analysis(bh_nodes, bh_edges, burp_nodes, burp_edges, traffic_nodes, traffic_edges):
    """Test unified multi-source analysis."""
    print("\n" + "="*80)
    print("TEST 4: Unified Multi-Source Analysis")
    print("="*80)
    
    try:
        from ate.core.graph_builder import GraphBuilder
        from ate.core.reasoning_engine_v2 import EnhancedReasoningEngine
        
        # Build unified graph
        gb = GraphBuilder()
        
        # Add nodes first
        for node_id, node in bh_nodes.items():
            gb.add_node(node_id, node.node_type, node.label, node.privilege_level, node.is_sensitive, node.metadata)
        for node_id, node in burp_nodes.items():
            gb.add_node(node_id, node.node_type, node.label, node.privilege_level, node.is_sensitive, node.metadata)
        for node_id, node in traffic_nodes.items():
            gb.add_node(node_id, node.node_type, node.label, node.privilege_level, node.is_sensitive, node.metadata)
        
        # Add edges
        for edge in bh_edges:
            gb.add_edge(edge.source, edge.target, edge.edge_type, edge.weight, metadata=edge.metadata)
        for edge in burp_edges:
            gb.add_edge(edge.source, edge.target, edge.edge_type, edge.weight, metadata=edge.metadata)
        for edge in traffic_edges:
            gb.add_edge(edge.source, edge.target, edge.edge_type, edge.weight, metadata=edge.metadata)
        
        print(f"\n[PASS] Unified Graph Created")
        print(f"  Total Nodes: {len(gb.graph.nodes())}")
        print(f"  Total Edges: {len(gb.graph.edges())}")
        
        # Run reasoning engine
        reasoning = EnhancedReasoningEngine(gb)
        
        # Test pivot discovery
        pivots = await reasoning.pivot_discovery(bh_nodes, bh_edges, burp_nodes, traffic_nodes)
        print(f"\n[PASS] Pivot Discovery Complete")
        print(f"  Pivots Found: {len(pivots)}")
        for src, tgt in pivots[:3]:
            print(f"    - {src.label}  {tgt.label}")
        
        # Test credential mapping
        traffic_credentials = {
            'ftp_admin': {
                'username': 'admin',
                'password': 'P@ssw0rd123',
                'source_ip': '10.0.1.50',
                'protocol': 'ftp'
            }
        }
        
        cred_mappings = await reasoning.credential_mapping(
            traffic_credentials, bh_nodes, burp_nodes
        )
        print(f"\n[PASS] Credential Mapping Complete")
        print(f"  Credentials Mapped: {len(cred_mappings)}")
        
        # Test pathfinding
        attack_paths = await reasoning.cross_layer_pathfinding(
            bh_nodes, burp_nodes, traffic_nodes
        )
        print(f"\n[PASS] Cross-Layer Pathfinding Complete")
        print(f"  Attack Paths Found: {len(attack_paths)}")
        
        if attack_paths:
            for path in attack_paths[:2]:
                print(f"\n  Path: {path.path_id}")
                print(f"    Severity: {path.severity}")
                print(f"    Layers: {path.layers}")
                print(f"    Nodes: {len(path.nodes)}")
        
        return True, attack_paths
    
    except Exception as e:
        print(f"\n[FAIL] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False, None


# ============================================================================
# TEST 3: Tactical Orchestration
# ============================================================================

async def test_tactical_orchestration(attack_paths):
    """Test tactical orchestration and action generation."""
    print("\n" + "="*80)
    print("TEST 5: Tactical Orchestration")
    print("="*80)
    
    if not attack_paths:
        print("[FAIL] No attack paths to orchestrate")
        return False
    
    try:
        from ate.modules.scanner_sync import ActiveNextSteps
        
        orchestrator = ActiveNextSteps()
        
        # Analyze paths
        tactics = orchestrator.analyze_paths(attack_paths)
        print(f"\n[PASS] Tactical Analysis Complete")
        print(f"  Actions Generated: {len(tactics)}")
        
        print(f"\n  Top Tactical Actions:")
        for action in tactics[:3]:
            print(f"    - {action.description}")
            print(f"      Priority: {action.priority}/10")
            print(f"      Category: {action.category}")
            print(f"      Command: {action.command[:60]}...")
        
        # Get recommendations
        recommendations = orchestrator.get_recommendations()
        print(f"\n[PASS] Recommendations Generated: {len(recommendations)}")
        for rec in recommendations[:3]:
            print(f"    - {rec}")
        
        # Estimate time to compromise
        time_estimate, complexity = orchestrator.estimate_time_to_compromise()
        print(f"\n[PASS] Time Estimate: {time_estimate} minutes ({complexity})")
        
        # Generate playbook
        playbook = orchestrator.generate_playbook(attack_paths, 'text')
        print(f"\n[PASS] Playbook Generated ({len(playbook)} characters)")
        
        return True
    
    except Exception as e:
        print(f"\n[FAIL] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

async def run_all_tests():
    """Run all integration tests."""
    print("\n" + "="*80)
    print("ATTACK THINKING ENGINE - INTEGRATION TESTS")
    print("="*80)
    
    results = {}
    
    # Test 1: BloodHound Ingestor
    try:
        success, bh_nodes, bh_edges = await test_bloodhound_ingestor()
        results['bloodhound'] = success
    except Exception as e:
        print(f"\n[FAIL] BloodHound test failed: {str(e)}")
        results['bloodhound'] = False
        bh_nodes, bh_edges = {}, []
    
    # Test 2: Burp Ingestor
    try:
        success, burp_nodes, burp_edges = await test_burp_ingestor()
        results['burp'] = success
    except Exception as e:
        print(f"\n[FAIL] Burp test failed: {str(e)}")
        results['burp'] = False
        burp_nodes, burp_edges = {}, []
    
    # Test 3: Traffic Ingestor
    try:
        success, traffic_nodes, traffic_edges = await test_traffic_ingestor()
        results['traffic'] = success
    except Exception as e:
        print(f"\n[FAIL] Traffic test failed: {str(e)}")
        results['traffic'] = False
        traffic_nodes, traffic_edges = {}, []
    
    # Test 4: Unified Analysis
    try:
        success, attack_paths = await test_unified_analysis(
            bh_nodes, bh_edges,
            burp_nodes, burp_edges,
            traffic_nodes, traffic_edges
        )
        results['unified_analysis'] = success
    except Exception as e:
        print(f"\n[FAIL] Unified analysis test failed: {str(e)}")
        results['unified_analysis'] = False
        attack_paths = None
    
    # Test 5: Tactical Orchestration
    if attack_paths:
        try:
            success = await test_tactical_orchestration(attack_paths)
            results['tactical'] = success
        except Exception as e:
            print(f"\n[FAIL] Tactical orchestration test failed: {str(e)}")
            results['tactical'] = False
    else:
        results['tactical'] = False
    
    # Print summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    for test_name, passed in results.items():
        status = "[PASS] PASS" if passed else "[FAIL] FAIL"
        print(f"{status}: {test_name}")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n All tests passed! System is ready for production use.")
    else:
        print(f"\n {total - passed} test(s) failed. Check logs above.")
    
    return passed == total


if __name__ == '__main__':
    success = asyncio.run(run_all_tests())
    exit(0 if success else 1)
