"""
Data models and type definitions for ATE.
"""
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime


class NodeType(Enum):
    """Types of nodes in the attack graph."""
    USER = "user"
    ACCOUNT = "user"
    ROLE = "role"
    ENDPOINT = "endpoint"
    DATA_OBJECT = "data_object"
    RESOURCE = "resource"
    DEVICE = "resource"


class VulnerabilityType(Enum):
    """Known vulnerability types."""
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTHENTICATION_FLAW = "authentication_flaw"
    AUTHORIZATION_FLAW = "authorization_flaw"
    INFORMATION_DISCLOSURE = "information_disclosure"
    CUSTOM = "custom"


class SeverityLevel(Enum):
    """Severity levels for findings."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class AtomicFinding:
    """
    Represents a single security finding that can be mapped onto the graph.
    Example: "User A can access Endpoint B which returns Admin ID"
    """
    id: str
    finding_type: VulnerabilityType
    severity: SeverityLevel
    source_node: str  # Node ID
    target_node: str  # Node ID
    description: str
    confidence: float = 1.0  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)

    def __hash__(self):
        return hash(self.id)


@dataclass
class AttackPath:
    """Represents a complete attack path from source to target."""
    id: str
    path_nodes: List[str]  # Ordered list of node IDs
    edges: List[str]  # Edge IDs that form the path
    findings: List[AtomicFinding]  # Contributing findings
    risk_score: float  # Weighted score (0.0 to 100.0)
    description: str
    steps: List[str] = field(default_factory=list)  # Human-readable steps

    @property
    def depth(self) -> int:
        """Return the depth/length of the attack path."""
        return len(self.path_nodes)

    @property
    def impact_multiplier(self) -> float:
        """Calculate impact based on number of findings and severity."""
        if not self.findings:
            return 1.0
        total_severity = sum(f.severity.value for f in self.findings)
        return min(total_severity / len(self.findings), 5.0)


@dataclass
class GraphNode:
    """Represents a node in the attack graph."""
    id: str
    node_type: NodeType
    label: str
    privilege_level: int = 0  # 0 (low) to 100 (high)
    is_sensitive: bool = False  # If data exposure is critical
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, GraphNode):
            return self.id == other.id
        return False


@dataclass
class GraphEdge:
    """Represents an edge in the attack graph."""
    id: str
    source: str  # Node ID
    target: str  # Node ID
    edge_type: str  # "permission", "data_flow", "vulnerability"
    weight: float = 1.0  # Edge weight for scoring
    finding: Optional[AtomicFinding] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)


@dataclass
class AnalysisResult:
    """Complete analysis result from the reasoning engine."""
    timestamp: datetime
    attack_paths: List[AttackPath]
    most_dangerous_path: Optional[AttackPath]
    total_findings: int
    critical_findings: int
    high_findings: int
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.attack_paths:
            self.most_dangerous_path = max(self.attack_paths, key=lambda p: p.risk_score)
