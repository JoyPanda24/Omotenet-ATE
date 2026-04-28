"""
Tests for ATE core components.
Run with: pytest tests/
"""
import pytest
from datetime import datetime

from ate.core import (
    GraphBuilder, ReasoningEngine, NodeType, VulnerabilityType,
    SeverityLevel, AtomicFinding, AttackPath
)
from ate.modules import IDORDetector, AuthFlawsDetector


class TestGraphBuilder:
    """Test GraphBuilder functionality."""
    
    def test_create_graph(self):
        """Test graph creation."""
        graph = GraphBuilder("Test Graph")
        assert graph.name == "Test Graph"
        assert graph.graph.number_of_nodes() == 0
        assert graph.graph.number_of_edges() == 0
    
    def test_add_node(self):
        """Test adding nodes."""
        graph = GraphBuilder("Test")
        
        node = graph.add_node(
            'test_user',
            NodeType.USER,
            'Test User',
            privilege_level=10
        )
        
        assert node.id == 'test_user'
        assert node.node_type == NodeType.USER
        assert graph.graph.number_of_nodes() == 1
    
    def test_add_edge(self):
        """Test adding edges."""
        graph = GraphBuilder("Test")
        
        graph.add_node('user1', NodeType.USER, 'User 1')
        graph.add_node('user2', NodeType.USER, 'User 2')
        
        edge = graph.add_edge('user1', 'user2', 'permission')
        
        assert graph.graph.number_of_edges() == 1
        assert graph.graph.has_edge('user1', 'user2')
    
    def test_find_paths(self):
        """Test path finding."""
        graph = GraphBuilder("Test")
        
        # Create simple chain: A -> B -> C
        graph.add_node('A', NodeType.USER, 'A')
        graph.add_node('B', NodeType.USER, 'B')
        graph.add_node('C', NodeType.USER, 'C')
        
        graph.add_edge('A', 'B')
        graph.add_edge('B', 'C')
        
        paths = graph.find_paths('A', 'C')
        
        assert len(paths) == 1
        assert paths[0] == ['A', 'B', 'C']
    
    def test_no_path(self):
        """Test when no path exists."""
        graph = GraphBuilder("Test")
        
        graph.add_node('A', NodeType.USER, 'A')
        graph.add_node('B', NodeType.USER, 'B')
        
        paths = graph.find_paths('A', 'B')
        
        assert len(paths) == 0
    
    def test_add_finding_and_edge(self):
        """Test adding findings."""
        graph = GraphBuilder("Test")
        
        graph.add_node('attacker', NodeType.USER, 'Attacker', privilege_level=10)
        graph.add_node('victim', NodeType.USER, 'Victim', privilege_level=90, is_sensitive=True)
        
        finding = AtomicFinding(
            id='test_finding',
            finding_type=VulnerabilityType.IDOR,
            severity=SeverityLevel.HIGH,
            source_node='attacker',
            target_node='victim',
            description='Test IDOR finding',
            confidence=0.9
        )
        
        edge = graph.add_finding_and_create_edge(finding)
        
        assert len(graph.findings) == 1
        assert graph.graph.has_edge('attacker', 'victim')


class TestReasoningEngine:
    """Test ReasoningEngine functionality."""
    
    def test_analyze(self):
        """Test attack analysis."""
        graph = GraphBuilder("Test")
        
        # Create attack scenario
        graph.add_node('low_priv', NodeType.USER, 'Low Priv', privilege_level=10)
        graph.add_node('endpoint', NodeType.ENDPOINT, 'Endpoint', privilege_level=50)
        graph.add_node('high_priv', NodeType.USER, 'High Priv', privilege_level=90, is_sensitive=True)
        
        finding = AtomicFinding(
            id='test',
            finding_type=VulnerabilityType.IDOR,
            severity=SeverityLevel.CRITICAL,
            source_node='low_priv',
            target_node='high_priv',
            description='Test',
            confidence=1.0
        )
        
        graph.add_finding_and_create_edge(finding)
        
        engine = ReasoningEngine(graph)
        result = engine.analyze()
        
        assert result is not None
        assert len(result.attack_paths) > 0
    
    def test_identify_origins(self):
        """Test attack origin identification."""
        graph = GraphBuilder("Test")
        
        graph.add_node('low_user', NodeType.USER, 'Low', privilege_level=10)
        graph.add_node('high_user', NodeType.USER, 'High', privilege_level=90)
        
        engine = ReasoningEngine(graph)
        origins = engine._identify_attack_origins()
        
        assert 'low_user' in origins
        assert 'high_user' not in origins
    
    def test_identify_targets(self):
        """Test high-value target identification."""
        graph = GraphBuilder("Test")
        
        graph.add_node('low_user', NodeType.USER, 'Low', privilege_level=10)
        graph.add_node('sensitive_data', NodeType.DATA_OBJECT, 'Sensitive', is_sensitive=True)
        
        engine = ReasoningEngine(graph)
        targets = engine._identify_high_value_targets()
        
        assert 'sensitive_data' in targets


class TestIDORDetector:
    """Test IDOR detection."""
    
    def test_detect_url_pattern(self):
        """Test IDOR detection in URLs."""
        url = 'https://app.local/api/users/123'
        finding = IDORDetector.detect_from_url(url, 'attacker')
        
        assert finding is not None
        assert finding.finding_type == VulnerabilityType.IDOR
    
    def test_api_response_idor(self):
        """Test IDOR detection in API responses."""
        response = {'user_id': 999}
        finding = IDORDetector.detect_from_api_response(
            response, '/api/user', 'attacker', 'attacker'
        )
        
        # Should detect mismatch
        assert finding is not None


class TestAuthFlawsDetector:
    """Test authentication flaws detection."""
    
    def test_detect_no_auth(self):
        """Test detection of endpoints without authentication."""
        finding = AuthFlawsDetector.detect_no_auth_required(
            '/admin/panel', True, 95
        )
        
        assert finding is not None
        assert finding.severity == SeverityLevel.CRITICAL
    
    def test_detect_weak_token(self):
        """Test detection of weak token schemes."""
        finding = AuthFlawsDetector.detect_weak_token_scheme('basic')
        
        assert finding is not None
        assert finding.severity == SeverityLevel.MEDIUM


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
