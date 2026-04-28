# Attack Thinking Engine - Developer Documentation

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Module Development](#module-development)
4. [Contributing Guidelines](#contributing-guidelines)
5. [API Reference](#api-reference)

## Architecture Overview

ATE is built on three core layers:

### Layer 1: Core Engine
The graph-based analysis engine that models applications as directed graphs and finds attack paths.

- **GraphBuilder**: Constructs and manages the application graph
- **ReasoningEngine**: Analyzes the graph to find attack chains
- **Data Models**: Type definitions for nodes, edges, and findings

### Layer 2: Detection Modules
Pluggable vulnerability detection modules that generate atomic findings.

- **IDORDetector**: Identifies Insecure Direct Object References
- **AuthFlawsDetector**: Finds authentication vulnerabilities
- **SensitiveDataExposureDetector**: Detects data exposure issues

### Layer 3: CLI Interface
User-facing command-line interface with narrative output.

- **main.py**: CLI commands and entry point
- **visualizer.py**: ASCII/terminal visualization
- **story_renderer.py**: Narrative story generation

## Core Components

### GraphBuilder

The `GraphBuilder` class is the foundation of ATE. It manages nodes and edges.

```python
from ate.core import GraphBuilder, NodeType

graph = GraphBuilder("MyApp")

# Add nodes
graph.add_node(
    node_id='endpoint_1',
    node_type=NodeType.ENDPOINT,
    label='/api/users',
    privilege_level=40,
    is_sensitive=False,
    metadata={'method': 'GET'}
)

# Query the graph
neighbors = graph.get_neighbors('endpoint_1')
stats = graph.get_graph_statistics()
critical_nodes = graph.get_critical_nodes(top_n=5)
```

**Key Methods:**
- `add_node()`: Add a node to the graph
- `add_edge()`: Add a directed edge
- `add_finding_and_create_edge()`: Add a security finding with corresponding edge
- `find_paths()`: Find all paths between two nodes
- `calculate_path_risk_score()`: Score a path based on vulnerability weights
- `find_attack_surface()`: Identify high-value targets
- `export_to_dict()`: Export graph to JSON format

### ReasoningEngine

The `ReasoningEngine` analyzes the graph to find attack chains.

```python
from ate.core import ReasoningEngine

engine = ReasoningEngine(graph)

# Run full analysis
result = engine.analyze()

# Specialized analyses
idor_chains = engine.find_idor_chains()
priv_esc_chains = engine.find_privilege_escalation_chains()
data_exposure_chains = engine.find_data_exposure_chains()

# Correlate findings
finding_chains = engine.correlate_findings(findings_list)
```

**Analysis Pipeline:**
1. Identify attack origins (low-privilege nodes)
2. Identify high-value targets (sensitive data or admin nodes)
3. Find all paths between origins and targets
4. Score each path based on vulnerabilities and weights
5. Sort paths by risk score
6. Return `AnalysisResult` with comprehensive findings

### Data Models

Core data structures used throughout ATE:

```python
from ate.core import (
    NodeType, VulnerabilityType, SeverityLevel,
    AtomicFinding, AttackPath, GraphNode, GraphEdge,
    AnalysisResult
)

# Node types
NodeType.USER
NodeType.ROLE
NodeType.ENDPOINT
NodeType.DATA_OBJECT
NodeType.RESOURCE

# Vulnerability types
VulnerabilityType.IDOR
VulnerabilityType.AUTH_BYPASS
VulnerabilityType.SENSITIVE_DATA_EXPOSURE
VulnerabilityType.PRIVILEGE_ESCALATION

# Severity levels
SeverityLevel.CRITICAL  # value=5
SeverityLevel.HIGH      # value=4
SeverityLevel.MEDIUM    # value=3
SeverityLevel.LOW       # value=2
SeverityLevel.INFO      # value=1
```

## Module Development

### Creating a Custom Detection Module

1. Create a new file in `ate/modules/`:

```python
# ate/modules/custom_detector.py
import logging
from typing import List, Optional, Dict
from ..core.data_models import AtomicFinding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

class CustomDetector:
    """Detects custom vulnerability type."""
    
    @staticmethod
    def detect(data: Dict) -> Optional[AtomicFinding]:
        """
        Detect the vulnerability.
        
        Args:
            data: Input data to analyze
            
        Returns:
            AtomicFinding if vulnerability is found, None otherwise
        """
        # Your detection logic here
        if vulnerable_condition(data):
            finding = AtomicFinding(
                id=f'custom_{data["id"]}',
                finding_type=VulnerabilityType.CUSTOM,
                severity=SeverityLevel.HIGH,
                source_node=data['source'],
                target_node=data['target'],
                description='Custom vulnerability description',
                confidence=0.9,
                metadata={'key': 'value'}
            )
            return finding
        return None
    
    @staticmethod
    def bulk_analyze(items: List[Dict]) -> List[AtomicFinding]:
        """Analyze multiple items."""
        findings = []
        for item in items:
            finding = CustomDetector.detect(item)
            if finding:
                findings.append(finding)
        return findings
```

2. Add to `ate/modules/__init__.py`:

```python
from .custom_detector import CustomDetector

__all__ = [
    'IDORDetector',
    'AuthFlawsDetector',
    'SensitiveDataExposureDetector',
    'CustomDetector'  # Add your detector
]
```

3. Use in analysis:

```python
from ate.modules import CustomDetector
from ate.core import GraphBuilder

graph = GraphBuilder("MyApp")
# ... setup nodes and edges ...

# Detect vulnerabilities
findings = CustomDetector.bulk_analyze(data_list)

# Add to graph
for finding in findings:
    graph.add_finding_and_create_edge(finding)
```

## Contributing Guidelines

### Code Style
- Follow PEP 8
- Use type hints for all functions
- Write docstrings for all classes and public methods
- Use `logging` module for debug output

### Testing
- Write tests for new features in `tests/`
- Aim for >80% code coverage
- Run: `pytest tests/ -v --cov=ate`

### Example Template for Tests

```python
import pytest
from ate.core import GraphBuilder, NodeType

class TestMyComponent:
    """Test suite for MyComponent."""
    
    def test_basic_functionality(self):
        """Test basic functionality."""
        component = MyComponent()
        result = component.do_something()
        assert result is not None
    
    def test_edge_case(self):
        """Test edge cases."""
        component = MyComponent()
        with pytest.raises(ValueError):
            component.do_something_invalid()
```

### Git Workflow

1. Create feature branch: `git checkout -b feature/my-feature`
2. Commit with clear messages: `git commit -m "Add feature description"`
3. Write/update tests
4. Update documentation
5. Push and create PR: `git push origin feature/my-feature`

## API Reference

### GraphBuilder

```python
class GraphBuilder:
    def __init__(self, name: str) -> None
    def add_node(
        node_id: str,
        node_type: NodeType,
        label: str,
        privilege_level: int = 0,
        is_sensitive: bool = False,
        metadata: Dict = None
    ) -> GraphNode
    
    def add_edge(
        source_id: str,
        target_id: str,
        edge_type: str = "permission",
        weight: float = 1.0,
        finding: Optional[AtomicFinding] = None,
        metadata: Dict = None
    ) -> GraphEdge
    
    def add_finding_and_create_edge(
        finding: AtomicFinding,
        vulnerability_weight: float = 3.0
    ) -> GraphEdge
    
    def find_paths(
        source: str,
        target: str,
        max_length: int = 5
    ) -> List[List[str]]
    
    def calculate_path_risk_score(path: List[str]) -> float
    def get_neighbors(node_id: str) -> List[str]
    def get_node_info(node_id: str) -> Optional[GraphNode]
    def get_graph_statistics() -> Dict
    def get_critical_nodes(top_n: int = 5) -> List[Tuple[str, float]]
    def find_attack_surface() -> Dict
    def export_to_dict() -> Dict
```

### ReasoningEngine

```python
class ReasoningEngine:
    def __init__(self, graph: GraphBuilder) -> None
    def analyze() -> AnalysisResult
    def find_idor_chains() -> List[AttackPath]
    def find_privilege_escalation_chains() -> List[AttackPath]
    def find_data_exposure_chains() -> List[AttackPath]
    def calculate_impact_score(attack_path: AttackPath) -> Dict
    def correlate_findings(findings: List[AtomicFinding]) -> List[List[AtomicFinding]]
```

### Detectors

```python
class IDORDetector:
    @staticmethod
    def detect_from_url(url: str, source_user: str = "anonymous") -> Optional[AtomicFinding]
    @staticmethod
    def detect_from_api_response(response_data: Dict, endpoint: str, accessed_by: str) -> Optional[AtomicFinding]
    @staticmethod
    def bulk_analyze(urls: List[str], source_user: str = "anonymous") -> List[AtomicFinding]

class AuthFlawsDetector:
    @staticmethod
    def detect_no_auth_required(endpoint: str, expected_auth: bool = True) -> Optional[AtomicFinding]
    @staticmethod
    def detect_weak_token_scheme(token_scheme: str) -> Optional[AtomicFinding]
    @staticmethod
    def bulk_analyze(auth_configs: List[Dict]) -> List[AtomicFinding]

class SensitiveDataExposureDetector:
    @staticmethod
    def detect_in_response(response_data: str, endpoint: str, accessed_by: str) -> List[AtomicFinding]
    @staticmethod
    def detect_in_logs(log_content: str, log_name: str = "application.log") -> List[AtomicFinding]
    @staticmethod
    def detect_in_metadata(metadata: Dict, source: str = "http_headers") -> List[AtomicFinding]
    @staticmethod
    def bulk_analyze(responses: List[Dict], endpoints: List[str]) -> List[AtomicFinding]
```

## Performance Optimization

### Graph Analysis
- NetworkX is optimized for sparse graphs
- For dense graphs (>30% edge density), consider subgraph analysis
- Use `max_length` parameter to limit path search space

### Caching
- Cache `calculate_path_risk_score()` results for repeated paths
- Cache `get_critical_nodes()` between analyses

### Scaling
- For large graphs (>50k nodes), consider parallel analysis
- Use `asyncio` for concurrent module detection
- Consider GraphQL queries for large-scale data retrieval

---

For more information, see [README.md](README.md)
