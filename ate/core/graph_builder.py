"""
GraphBuilder - Core component for constructing and managing attack graphs.
Uses NetworkX to represent applications as directed graphs for attack analysis.
"""
import uuid
import logging
from typing import Dict, List, Optional, Tuple, Set
import networkx as nx
from .data_models import (
    GraphNode, GraphEdge, NodeType, AtomicFinding,
    VulnerabilityType, SeverityLevel
)

logger = logging.getLogger(__name__)


class GraphBuilder:
    """
    Constructs and manages a directed graph representing an application's
    attack surface. Nodes include Users, Roles, Endpoints, and Data Objects.
    Edges represent permissions, data flow, and vulnerabilities.
    """

    def __init__(self, name: str = "Application Graph"):
        """
        Initialize the graph builder.
        
        Args:
            name: Name of the graph for reference
        """
        self.name = name
        self.graph = nx.DiGraph()
        self.nodes_map: Dict[str, GraphNode] = {}
        self.edges_map: Dict[str, GraphEdge] = {}
        self.findings: List[AtomicFinding] = []
        logger.info(f"Initialized GraphBuilder: {name}")

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str,
        privilege_level: int = 0,
        is_sensitive: bool = False,
        metadata: Dict = None
    ) -> GraphNode:
        """
        Add a node to the graph.
        
        Args:
            node_id: Unique identifier for the node
            node_type: Type of node (USER, ROLE, ENDPOINT, DATA_OBJECT, RESOURCE)
            label: Human-readable label
            privilege_level: 0 (low) to 100 (high)
            is_sensitive: Whether this node contains sensitive data
            metadata: Additional metadata
            
        Returns:
            The created GraphNode
        """
        node = GraphNode(
            id=node_id,
            node_type=node_type,
            label=label,
            privilege_level=min(100, max(0, privilege_level)),
            is_sensitive=is_sensitive,
            metadata=metadata or {}
        )
        
        self.nodes_map[node_id] = node
        self.graph.add_node(node_id, **{
            'type': node_type.value,
            'label': label,
            'privilege_level': node.privilege_level,
            'is_sensitive': is_sensitive
        })
        
        logger.debug(f"Added node: {node_id} ({node_type.value})")
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str = "permission",
        weight: float = 1.0,
        finding: Optional[AtomicFinding] = None,
        metadata: Dict = None
    ) -> GraphEdge:
        """
        Add a directed edge between nodes.
        
        Args:
            source_id: Source node ID
            target_id: Target node ID
            edge_type: Type of edge (permission, data_flow, vulnerability)
            weight: Edge weight for scoring (higher = more dangerous)
            finding: Associated security finding
            metadata: Additional metadata
            
        Returns:
            The created GraphEdge
            
        Raises:
            ValueError: If nodes don't exist
        """
        if source_id not in self.nodes_map:
            raise ValueError(f"Source node '{source_id}' does not exist")
        if target_id not in self.nodes_map:
            raise ValueError(f"Target node '{target_id}' does not exist")

        edge_id = f"{source_id}→{target_id}:{uuid.uuid4().hex[:8]}"
        edge = GraphEdge(
            id=edge_id,
            source=source_id,
            target=target_id,
            edge_type=edge_type,
            weight=weight,
            finding=finding,
            metadata=metadata or {}
        )
        
        self.edges_map[edge_id] = edge
        self.graph.add_edge(source_id, target_id, **{
            'edge_type': edge_type,
            'weight': weight,
            'edge_id': edge_id,
            'finding_id': finding.id if finding else None
        })
        
        if finding:
            self.findings.append(finding)
        
        logger.debug(f"Added edge: {source_id} → {target_id} ({edge_type})")
        return edge

    def add_finding_and_create_edge(
        self,
        finding: AtomicFinding,
        vulnerability_weight: float = 3.0
    ) -> GraphEdge:
        """
        Add an atomic finding and create a corresponding edge in the graph.
        This is the primary method for incorporating security findings.
        
        Args:
            finding: The atomic finding to add
            vulnerability_weight: Weight multiplier for vulnerability edges
            
        Returns:
            The created GraphEdge
            
        Raises:
            ValueError: If nodes referenced in finding don't exist
        """
        # Adjust weight based on severity
        severity_weight = finding.severity.value / 5.0
        total_weight = vulnerability_weight * severity_weight * finding.confidence
        
        return self.add_edge(
            source_id=finding.source_node,
            target_id=finding.target_node,
            edge_type="vulnerability",
            weight=total_weight,
            finding=finding
        )

    def find_paths(
        self,
        source: str,
        target: str,
        max_length: int = 5
    ) -> List[List[str]]:
        """
        Find all paths between two nodes up to max_length.
        
        Args:
            source: Source node ID
            target: Target node ID
            max_length: Maximum path length
            
        Returns:
            List of paths (each path is a list of node IDs)
        """
        try:
            paths = list(nx.all_simple_paths(
                self.graph,
                source,
                target,
                cutoff=max_length
            ))
            logger.debug(f"Found {len(paths)} paths from {source} to {target}")
            return paths
        except nx.NetworkXNoPath:
            logger.debug(f"No path exists from {source} to {target}")
            return []
        except nx.NodeNotFound as e:
            logger.error(f"Node not found: {e}")
            return []

    def calculate_path_risk_score(self, path: List[str]) -> float:
        """
        Calculate cumulative risk score for a path based on edge weights.
        
        Args:
            path: List of node IDs forming a path
            
        Returns:
            Risk score (0.0 to 100.0)
        """
        if len(path) < 2:
            return 0.0
        
        total_score = 0.0
        for i in range(len(path) - 1):
            source, target = path[i], path[i + 1]
            if self.graph.has_edge(source, target):
                edge_data = self.graph[source][target]
                weight = edge_data.get('weight', 1.0)
                total_score += weight
        
        # Normalize and cap at 100
        return min(total_score * 10, 100.0)

    def get_neighbors(self, node_id: str) -> List[str]:
        """Get successor nodes (outgoing edges)."""
        return list(self.graph.successors(node_id))

    def get_predecessors(self, node_id: str) -> List[str]:
        """Get predecessor nodes (incoming edges)."""
        return list(self.graph.predecessors(node_id))

    def get_node_info(self, node_id: str) -> Optional[GraphNode]:
        """Get node information."""
        return self.nodes_map.get(node_id)

    def get_graph_statistics(self) -> Dict:
        """Get graph statistics."""
        return {
            'num_nodes': self.graph.number_of_nodes(),
            'num_edges': self.graph.number_of_edges(),
            'num_findings': len(self.findings),
            'density': nx.density(self.graph),
            'is_connected': nx.is_strongly_connected(self.graph),
            'num_components': nx.number_strongly_connected_components(self.graph)
        }

    def get_critical_nodes(self, top_n: int = 5) -> List[Tuple[str, float]]:
        """
        Identify most critical nodes using betweenness centrality.
        
        Args:
            top_n: Number of top nodes to return
            
        Returns:
            List of (node_id, centrality_score) tuples
        """
        centrality = nx.betweenness_centrality(self.graph)
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return sorted_nodes[:top_n]

    def get_high_privilege_nodes(self) -> List[GraphNode]:
        """Get all high-privilege nodes."""
        return [
            node for node in self.nodes_map.values()
            if node.privilege_level >= 75
        ]

    def get_sensitive_data_nodes(self) -> List[GraphNode]:
        """Get all nodes containing sensitive data."""
        return [
            node for node in self.nodes_map.values()
            if node.is_sensitive
        ]

    def find_attack_surface(self) -> Dict:
        """
        Analyze and return the attack surface.
        
        Returns:
            Dictionary with attack surface metrics
        """
        return {
            'high_privilege_nodes': self.get_high_privilege_nodes(),
            'sensitive_data_nodes': self.get_sensitive_data_nodes(),
            'critical_nodes': self.get_critical_nodes(),
            'num_vulnerability_edges': sum(
                1 for e in self.edges_map.values()
                if e.edge_type == 'vulnerability'
            )
        }

    def export_to_dict(self) -> Dict:
        """Export graph to dictionary format."""
        return {
            'name': self.name,
            'nodes': [
                {
                    'id': n.id,
                    'type': n.node_type.value,
                    'label': n.label,
                    'privilege_level': n.privilege_level,
                    'is_sensitive': n.is_sensitive,
                    'metadata': n.metadata
                }
                for n in self.nodes_map.values()
            ],
            'edges': [
                {
                    'id': e.id,
                    'source': e.source,
                    'target': e.target,
                    'type': e.edge_type,
                    'weight': e.weight,
                    'finding_id': e.finding.id if e.finding else None
                }
                for e in self.edges_map.values()
            ],
            'statistics': self.get_graph_statistics()
        }
