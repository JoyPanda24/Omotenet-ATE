"""
Comprehensive example demonstrating Attack Thinking Engine (ATE).
Shows how to build a graph, add findings, and analyze attack paths.
"""
import json
from ate.core import (
    GraphBuilder, ReasoningEngine, NodeType, VulnerabilityType,
    SeverityLevel, AtomicFinding
)
from ate.modules import IDORDetector, AuthFlawsDetector, SensitiveDataExposureDetector
from ate.cli import StoryRenderer, AttackPathVisualizer


def example_basic_idor_chain():
    """
    Example: IDOR vulnerability leading to user impersonation.
    
    Scenario: An attacker discovers that user IDs are sequential and
    can access any user's profile by modifying the ID parameter.
    """
    print("\n" + "="*70)
    print("EXAMPLE 1: IDOR-Based User Impersonation Attack")
    print("="*70 + "\n")
    
    # Create graph
    graph = GraphBuilder("E-Commerce Application")
    
    # Add nodes
    graph.add_node(
        'attacker_user',
        NodeType.USER,
        'Attacker User',
        privilege_level=10,
        metadata={'account_type': 'regular_user'}
    )
    
    graph.add_node(
        'get_profile_endpoint',
        NodeType.ENDPOINT,
        'GET /api/users/{id}',
        privilege_level=30,
        metadata={'method': 'GET', 'auth_required': False}
    )
    
    graph.add_node(
        'victim_user',
        NodeType.USER,
        'Premium User (Victim)',
        privilege_level=50,
        is_sensitive=True,
        metadata={'account_type': 'premium', 'has_payment_info': True}
    )
    
    graph.add_node(
        'payment_data',
        NodeType.DATA_OBJECT,
        'User Payment Information',
        privilege_level=95,
        is_sensitive=True,
        metadata={'pci_scope': True}
    )
    
    # Create IDOR findings
    finding1 = AtomicFinding(
        id='idor_sequential_ids',
        finding_type=VulnerabilityType.IDOR,
        severity=SeverityLevel.HIGH,
        source_node='attacker_user',
        target_node='get_profile_endpoint',
        description='User IDs are sequential and enumerable',
        confidence=0.9,
        metadata={
            'url': 'https://app.local/api/users/1',
            'pattern': 'Sequential IDs (1, 2, 3...)',
            'affected_endpoints': ['/api/users/{id}', '/api/profile/{id}']
        }
    )
    
    finding2 = AtomicFinding(
        id='idor_access_other_profiles',
        finding_type=VulnerabilityType.IDOR,
        severity=SeverityLevel.CRITICAL,
        source_node='get_profile_endpoint',
        target_node='victim_user',
        description='Can access any user profile without authorization check',
        confidence=0.95,
        metadata={
            'url': 'https://app.local/api/users/999',
            'discovered_by': 'ID enumeration',
            'affected_data': ['email', 'phone', 'premium_status']
        }
    )
    
    finding3 = AtomicFinding(
        id='idor_payment_exposure',
        finding_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        severity=SeverityLevel.CRITICAL,
        source_node='victim_user',
        target_node='payment_data',
        description='User profile response includes payment card information',
        confidence=1.0,
        metadata={
            'exposed_fields': ['card_last4', 'card_expiry', 'billing_address'],
            'pci_violation': True
        }
    )
    
    # Add findings to graph
    graph.add_finding_and_create_edge(finding1)
    graph.add_finding_and_create_edge(finding2)
    graph.add_finding_and_create_edge(finding3)
    
    # Analyze
    engine = ReasoningEngine(graph)
    result = engine.analyze()
    
    # Display results
    print(StoryRenderer.render_analysis_result(result))
    
    if result.most_dangerous_path:
        print("\nMost Dangerous Path Visualization:")
        print(AttackPathVisualizer.visualize_path(
            result.most_dangerous_path.path_nodes,
            result.most_dangerous_path.steps
        ))
    
    # Export graph
    graph_export = graph.export_to_dict()
    with open('examples/idor_chain_example.json', 'w') as f:
        json.dump(graph_export, f, indent=2)
    print("[*] Graph exported to examples/idor_chain_example.json")


def example_privilege_escalation_chain():
    """
    Example: Multi-step privilege escalation attack.
    
    Scenario: A regular user exploits multiple vulnerabilities to gain
    administrative access to the system.
    """
    print("\n" + "="*70)
    print("EXAMPLE 2: Privilege Escalation Attack Chain")
    print("="*70 + "\n")
    
    # Create graph
    graph = GraphBuilder("Admin Panel Application")
    
    # Nodes representing privilege levels
    graph.add_node(
        'guest_user',
        NodeType.USER,
        'Guest User',
        privilege_level=5,
        metadata={'role': 'guest'}
    )
    
    graph.add_node(
        'login_endpoint',
        NodeType.ENDPOINT,
        'POST /auth/login',
        privilege_level=20
    )
    
    graph.add_node(
        'authenticated_user',
        NodeType.ROLE,
        'Authenticated User',
        privilege_level=30
    )
    
    graph.add_node(
        'privilege_escalation_vuln',
        NodeType.ENDPOINT,
        'GET /admin/settings?role=admin',
        privilege_level=50,
        metadata={'parameter': 'role', 'client_side_validation': True}
    )
    
    graph.add_node(
        'admin_role',
        NodeType.ROLE,
        'Administrator',
        privilege_level=100,
        is_sensitive=True
    )
    
    graph.add_node(
        'system_config',
        NodeType.DATA_OBJECT,
        'System Configuration',
        privilege_level=100,
        is_sensitive=True
    )
    
    # Create findings
    auth_finding = AtomicFinding(
        id='no_rate_limiting',
        finding_type=VulnerabilityType.AUTHENTICATION_FLAW,
        severity=SeverityLevel.MEDIUM,
        source_node='guest_user',
        target_node='login_endpoint',
        description='No rate limiting on login endpoint',
        confidence=1.0,
        metadata={'attack_type': 'brute_force_possible'}
    )
    
    priv_esc_finding = AtomicFinding(
        id='client_side_role_check',
        finding_type=VulnerabilityType.PRIVILEGE_ESCALATION,
        severity=SeverityLevel.CRITICAL,
        source_node='authenticated_user',
        target_node='admin_role',
        description='Role check performed only on client side',
        confidence=0.95,
        metadata={
            'vulnerable_param': 'role',
            'method': 'Modify HTTP parameter'
        }
    )
    
    data_exposure_finding = AtomicFinding(
        id='admin_config_access',
        finding_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        severity=SeverityLevel.CRITICAL,
        source_node='admin_role',
        target_node='system_config',
        description='Admin role can access sensitive system configuration',
        confidence=1.0
    )
    
    graph.add_finding_and_create_edge(auth_finding)
    graph.add_finding_and_create_edge(priv_esc_finding)
    graph.add_finding_and_create_edge(data_exposure_finding)
    
    # Analyze
    engine = ReasoningEngine(graph)
    result = engine.analyze()
    
    # Display results
    print(StoryRenderer.render_analysis_result(result))
    
    # Show privilege escalation chains
    esc_chains = engine.find_privilege_escalation_chains()
    if esc_chains:
        print(f"\nFound {len(esc_chains)} privilege escalation path(s)")
        for path in esc_chains:
            print(StoryRenderer.render_privilege_escalation_story(path))


def example_complex_multi_vulnerability_chain():
    """
    Example: Complex attack requiring multiple vulnerability exploits.
    
    Scenario: Attacker chains IDOR, authentication bypass, and sensitive
    data exposure to completely compromise the system.
    """
    print("\n" + "="*70)
    print("EXAMPLE 3: Complex Multi-Vulnerability Attack Chain")
    print("="*70 + "\n")
    
    graph = GraphBuilder("E-Banking Platform")
    
    # Create a realistic attack surface
    nodes = {
        'internet_user': (NodeType.USER, 'Anonymous User', 0),
        'web_login': (NodeType.ENDPOINT, 'POST /login', 15),
        'customer_user': (NodeType.ROLE, 'Customer', 30),
        'api_user_endpoint': (NodeType.ENDPOINT, 'GET /api/user/{id}', 40),
        'api_accounts_endpoint': (NodeType.ENDPOINT, 'GET /api/accounts/{id}', 50),
        'customer_data': (NodeType.DATA_OBJECT, 'Customer Personal Data', 70),
        'account_data': (NodeType.DATA_OBJECT, 'Bank Account Data', 85),
        'bank_admin': (NodeType.ROLE, 'Bank Administrator', 100),
        'transaction_system': (NodeType.RESOURCE, 'Transaction Processing', 100),
    }
    
    for node_id, (node_type, label, priv) in nodes.items():
        is_sensitive = priv >= 70
        graph.add_node(node_id, node_type, label, privilege_level=priv, is_sensitive=is_sensitive)
    
    # Create a realistic finding chain
    findings = [
        AtomicFinding(
            id='auth_no_2fa',
            finding_type=VulnerabilityType.AUTHENTICATION_FLAW,
            severity=SeverityLevel.MEDIUM,
            source_node='internet_user',
            target_node='web_login',
            description='No multi-factor authentication required',
            confidence=1.0
        ),
        AtomicFinding(
            id='idor_user_ids',
            finding_type=VulnerabilityType.IDOR,
            severity=SeverityLevel.HIGH,
            source_node='customer_user',
            target_node='api_user_endpoint',
            description='User IDs are enumerable and sequential',
            confidence=0.95
        ),
        AtomicFinding(
            id='idor_account_data',
            finding_type=VulnerabilityType.IDOR,
            severity=SeverityLevel.CRITICAL,
            source_node='api_user_endpoint',
            target_node='api_accounts_endpoint',
            description='Can access other users account data via ID parameter',
            confidence=0.98
        ),
        AtomicFinding(
            id='sensitive_data_exposed',
            finding_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
            severity=SeverityLevel.CRITICAL,
            source_node='account_data',
            target_node='transaction_system',
            description='API response includes sufficient data to initiate fraudulent transactions',
            confidence=1.0
        ),
    ]
    
    # Chain the findings together
    chain = [
        ('internet_user', 'customer_user'),
        ('customer_user', 'api_user_endpoint'),
        ('api_user_endpoint', 'account_data'),
        ('account_data', 'transaction_system'),
    ]
    
    for finding in findings:
        graph.add_finding_and_create_edge(finding)
    
    # Analyze
    engine = ReasoningEngine(graph)
    result = engine.analyze()
    
    print(StoryRenderer.render_analysis_result(result))
    
    # Show statistics
    print("\nAttack Surface Analysis:")
    surface = graph.find_attack_surface()
    print(f"  High-Privilege Nodes: {len(surface['high_privilege_nodes'])}")
    print(f"  Sensitive Data Nodes: {len(surface['sensitive_data_nodes'])}")
    print(f"  Critical Nodes: {len(surface['critical_nodes'])}")
    print(f"  Vulnerability Edges: {surface['num_vulnerability_edges']}")


def example_module_based_scanning():
    """
    Example: Using detection modules to automatically find vulnerabilities.
    """
    print("\n" + "="*70)
    print("EXAMPLE 4: Module-Based Vulnerability Scanning")
    print("="*70 + "\n")
    
    # Simulate URLs from scanning
    urls = [
        'https://app.local/api/users/1',
        'https://app.local/api/users/2',
        'https://app.local/api/users/3',
        'https://app.local/api/users/100',
    ]
    
    # Scan for IDOR
    print("Scanning for IDOR vulnerabilities...")
    idor_findings = IDORDetector.bulk_analyze(urls)
    print(f"Found {len(idor_findings)} potential IDOR findings\n")
    
    # Scan for auth flaws
    print("Scanning for authentication flaws...")
    auth_configs = [
        {
            'endpoint': '/api/admin',
            'requires_auth': False,
            'data_sensitivity': 95,
            'cookies': [
                {'name': 'session_id', 'httponly': False, 'secure': False, 'samesite': 'None'}
            ]
        }
    ]
    auth_findings = AuthFlawsDetector.bulk_analyze(auth_configs)
    print(f"Found {len(auth_findings)} authentication vulnerability findings\n")
    
    # Scan for sensitive data exposure
    print("Scanning for sensitive data exposure...")
    responses = [
        {
            'endpoint': '/api/profile',
            'data': 'email: user@example.com, phone: +1-555-1234, ssn: 123-45-6789',
            'is_public': True
        }
    ]
    sde_findings = SensitiveDataExposureDetector.bulk_analyze(responses, [])
    print(f"Found {len(sde_findings)} sensitive data exposure findings\n")


if __name__ == '__main__':
    print("\n" + "="*70)
    print("ATTACK THINKING ENGINE - COMPREHENSIVE EXAMPLES")
    print("="*70)
    
    example_basic_idor_chain()
    example_privilege_escalation_chain()
    example_complex_multi_vulnerability_chain()
    example_module_based_scanning()
    
    print("\n" + "="*70)
    print("All examples completed! Check examples/ directory for exported data.")
    print("="*70 + "\n")
