"""
ReasoningEngine - Core logic for analyzing attack paths and connecting vulnerabilities.
Converts atomic findings into comprehensive attack chains with contextual reasoning.
"""
import logging
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from .data_models import (
    AtomicFinding, AttackPath, AnalysisResult, NodeType,
    VulnerabilityType, SeverityLevel
)
from .graph_builder import GraphBuilder

logger = logging.getLogger(__name__)


class ReasoningEngine:
    """
    The reasoning engine analyzes security findings mapped onto the graph
    to identify complete attack chains and assess their risk.
    """

    def __init__(self, graph: GraphBuilder):
        """
        Initialize the reasoning engine with a graph.
        
        Args:
            graph: GraphBuilder instance to analyze
        """
        self.graph = graph
        self.attack_paths: List[AttackPath] = []
        logger.info("Initialized ReasoningEngine")

    def analyze(self) -> AnalysisResult:
        """
        Perform comprehensive attack path analysis.
        
        Returns:
            AnalysisResult with identified attack paths and scoring
        """
        logger.info("Starting attack path analysis...")
        
        # Step 1: Identify potential attack origins (low-privilege nodes)
        attack_origins = self._identify_attack_origins()
        logger.info(f"Identified {len(attack_origins)} potential attack origins")
        
        # Step 2: Identify high-value targets (high-privilege or sensitive data)
        high_value_targets = self._identify_high_value_targets()
        logger.info(f"Identified {len(high_value_targets)} high-value targets")
        
        # Step 3: Find paths between origins and targets
        self.attack_paths = []
        for origin in attack_origins:
            for target in high_value_targets:
                paths = self.graph.find_paths(origin, target)
                for path in paths:
                    attack_path = self._construct_attack_path(path, origin, target)
                    if attack_path:
                        self.attack_paths.append(attack_path)
        
        logger.info(f"Found {len(self.attack_paths)} potential attack paths")
        
        # Step 4: Sort by risk score
        self.attack_paths.sort(key=lambda p: p.risk_score, reverse=True)
        
        # Step 5: Compile findings statistics
        findings = self.graph.findings
        critical_findings = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        high_findings = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        
        result = AnalysisResult(
            timestamp=datetime.now(),
            attack_paths=self.attack_paths,
            most_dangerous_path=self.attack_paths[0] if self.attack_paths else None,
            total_findings=len(findings),
            critical_findings=critical_findings,
            high_findings=high_findings,
            analysis_metadata={
                'num_origins': len(attack_origins),
                'num_targets': len(high_value_targets),
                'graph_density': self.graph.get_graph_statistics()['density'],
                'total_nodes': self.graph.get_graph_statistics()['num_nodes'],
                'total_edges': self.graph.get_graph_statistics()['num_edges']
            }
        )
        
        logger.info("Attack path analysis complete")
        return result

    def _identify_attack_origins(self) -> List[str]:
        """
        Identify low-privilege nodes that could serve as attack entry points.
        
        Returns:
            List of node IDs representing potential attack origins
        """
        origins = []
        for node_id, node in self.graph.nodes_map.items():
            # Low privilege users/roles
            if node.privilege_level <= 25:
                origins.append(node_id)
            # Unauthenticated users (endpoints accessible without auth)
            if node.node_type == NodeType.ENDPOINT and node.privilege_level == 0:
                origins.append(node_id)
        
        return list(set(origins))

    def _identify_high_value_targets(self) -> List[str]:
        """
        Identify high-privilege or sensitive data nodes as targets.
        
        Returns:
            List of node IDs representing high-value targets
        """
        targets = []
        
        # High-privilege roles/users
        for node in self.graph.get_high_privilege_nodes():
            targets.append(node.id)
        
        # Sensitive data objects
        for node in self.graph.get_sensitive_data_nodes():
            targets.append(node.id)
        
        return list(set(targets))

    def _construct_attack_path(
        self,
        path: List[str],
        origin: str,
        target: str
    ) -> Optional[AttackPath]:
        """
        Construct a detailed attack path from a sequence of nodes.
        
        Args:
            path: List of node IDs forming the path
            origin: Starting node ID
            target: Ending node ID
            
        Returns:
            AttackPath object or None if path is invalid
        """
        if len(path) < 2:
            return None
        
        # Extract edges and findings
        edges = []
        findings = []
        edge_descriptions = []
        
        for i in range(len(path) - 1):
            source, target_node = path[i], path[i + 1]
            if self.graph.graph.has_edge(source, target_node):
                edge_data = self.graph.graph[source][target_node]
                edge_id = edge_data.get('edge_id')
                
                if edge_id and edge_id in self.graph.edges_map:
                    edge_obj = self.graph.edges_map[edge_id]
                    edges.append(edge_id)
                    
                    if edge_obj.finding:
                        findings.append(edge_obj.finding)
                    
                    # Create human-readable description
                    source_label = self.graph.get_node_info(source).label
                    target_label = self.graph.get_node_info(target_node).label
                    edge_descriptions.append(
                        f"[{edge_obj.edge_type.upper()}] {source_label} → {target_label}"
                    )
        
        if not edges:
            return None
        
        # Calculate risk score
        risk_score = self.graph.calculate_path_risk_score(path)
        
        # Boost score based on critical findings
        if findings:
            critical_count = sum(
                1 for f in findings if f.severity == SeverityLevel.CRITICAL
            )
            risk_score = min(risk_score * (1 + critical_count * 0.5), 100.0)
        
        # Create attack path
        attack_path = AttackPath(
            id=f"path_{len(self.attack_paths)}",
            path_nodes=path,
            edges=edges,
            findings=findings,
            risk_score=risk_score,
            description=f"Attack chain from {origin} to {target}",
            steps=edge_descriptions
        )
        
        return attack_path

    def find_idor_chains(self) -> List[AttackPath]:
        """
        Specialized analysis for IDOR-based attack chains.
        
        Returns:
            List of IDOR-based attack paths
        """
        idor_paths = [
            p for p in self.attack_paths
            if any(f.finding_type == VulnerabilityType.IDOR for f in p.findings)
        ]
        return sorted(idor_paths, key=lambda p: p.risk_score, reverse=True)

    def find_privilege_escalation_chains(self) -> List[AttackPath]:
        """
        Specialized analysis for privilege escalation chains.
        
        Returns:
            List of privilege escalation attack paths
        """
        escalation_paths = []
        
        for path in self.attack_paths:
            # Check if path involves privilege increase
            if len(path.path_nodes) >= 2:
                start_node = self.graph.get_node_info(path.path_nodes[0])
                end_node = self.graph.get_node_info(path.path_nodes[-1])
                
                if start_node and end_node:
                    privilege_gain = end_node.privilege_level - start_node.privilege_level
                    if privilege_gain > 25:  # Significant privilege gain
                        escalation_paths.append(path)
        
        return sorted(escalation_paths, key=lambda p: p.risk_score, reverse=True)

    def find_data_exposure_chains(self) -> List[AttackPath]:
        """
        Specialized analysis for sensitive data exposure chains.
        
        Returns:
            List of data exposure attack paths
        """
        exposure_paths = [
            p for p in self.attack_paths
            if any(
                self.graph.get_node_info(node).is_sensitive
                for node in p.path_nodes
                if self.graph.get_node_info(node)
            )
        ]
        return sorted(exposure_paths, key=lambda p: p.risk_score, reverse=True)

    def calculate_impact_score(self, attack_path: AttackPath) -> Dict:
        """
        Calculate detailed impact score for an attack path.
        
        Args:
            attack_path: The attack path to score
            
        Returns:
            Dictionary with impact metrics
        """
        # Base risk score
        base_score = attack_path.risk_score
        
        # Distance penalty (longer paths are less likely)
        distance_penalty = 1.0 / attack_path.depth if attack_path.depth > 0 else 0
        
        # Impact multiplier from findings
        impact_mult = attack_path.impact_multiplier
        
        # Final score
        final_score = base_score * distance_penalty * impact_mult
        
        return {
            'base_risk_score': base_score,
            'path_depth': attack_path.depth,
            'distance_penalty': distance_penalty,
            'impact_multiplier': impact_mult,
            'final_impact_score': min(final_score, 100.0),
            'num_findings': len(attack_path.findings)
        }

    def correlate_findings(self, findings: List[AtomicFinding]) -> List[List[AtomicFinding]]:
        """
        Correlate multiple findings to identify attack chains.
        
        Args:
            findings: List of atomic findings to correlate
            
        Returns:
            List of correlated finding chains
        """
        chains = []
        
        for finding in findings:
            # Check if finding target is another finding's source
            chain = [finding]
            current_target = finding.target_node
            
            for other_finding in findings:
                if other_finding.source_node == current_target:
                    chain.append(other_finding)
                    current_target = other_finding.target_node
            
            if len(chain) > 1:
                chains.append(chain)
        
        return list({tuple(sorted(c, key=lambda f: f.id)): c for c in chains}.values())
