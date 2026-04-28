"""
Enhanced Reasoning Engine for Multi-Source Attack Path Analysis
Synthesizes data from BloodHound, Burp Suite, and Wireshark traffic analysis
to identify cross-layer attack paths and privilege escalation routes.
"""
import logging
import asyncio
from typing import Dict, List, Optional, Set, Tuple, Any
import networkx as nx
from dataclasses import dataclass, field

from .data_models import (
    GraphNode, GraphEdge, NodeType, AtomicFinding,
    VulnerabilityType, SeverityLevel
)
from .graph_builder import GraphBuilder

logger = logging.getLogger(__name__)


@dataclass
class AttackPath:
    """Represents a complete attack path across multiple layers."""
    path_id: str
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    total_weight: float = 0.0
    severity: SeverityLevel = SeverityLevel.MEDIUM
    layers: List[str] = field(default_factory=list)  # ['web', 'network', 'domain']
    actions: List[str] = field(default_factory=list)  # Tactical steps
    blockers: List[str] = field(default_factory=list)  # What's preventing progression


class EnhancedReasoningEngine:
    """
    Analyzes multi-source security data to identify attack paths.
    Bridges data silos between BloodHound (domain), Burp Suite (web), and Wireshark (network).
    """

    def __init__(self, graph_builder: GraphBuilder):
        """
        Initialize enhanced reasoning engine.
        
        Args:
            graph_builder: GraphBuilder instance containing unified graph
        """
        self.graph = graph_builder
        self.logger = logging.getLogger(self.__class__.__name__)
        self.attack_paths: List[AttackPath] = []
        self.pivots: List[Tuple[GraphNode, GraphNode]] = []
        self.credential_mappings: Dict[str, List[GraphNode]] = {}

    async def analyze_multi_source(
        self,
        bloodhound_nodes: Dict[str, GraphNode],
        bloodhound_edges: List[GraphEdge],
        burp_nodes: Dict[str, GraphNode],
        burp_edges: List[GraphEdge],
        traffic_nodes: Dict[str, GraphNode],
        traffic_edges: List[GraphEdge],
        traffic_credentials: Dict[str, Any]
    ) -> List[AttackPath]:
        """
        Comprehensive multi-source attack path analysis.
        
        Args:
            bloodhound_nodes: BloodHound AD/domain nodes
            bloodhound_edges: BloodHound relationships
            burp_nodes: Burp Suite endpoint nodes
            burp_edges: Burp vulnerability edges
            traffic_nodes: Network traffic IP nodes
            traffic_edges: Network communication edges
            traffic_credentials: Credentials extracted from traffic
        
        Returns:
            List of attack paths from external to domain admin
        """
        self.logger.info("Starting multi-source attack path analysis")
        
        # Step 1: Discover pivots between layers
        await self.pivot_discovery(
            bloodhound_nodes, bloodhound_edges,
            burp_nodes, traffic_nodes
        )
        
        # Step 2: Map credentials across layers
        await self.credential_mapping(
            traffic_credentials,
            bloodhound_nodes,
            burp_nodes
        )
        
        # Step 3: Find cross-layer paths
        attack_paths = await self.cross_layer_pathfinding(
            bloodhound_nodes,
            burp_nodes,
            traffic_nodes
        )
        
        self.attack_paths = attack_paths
        self.logger.info(f"Identified {len(attack_paths)} attack paths")
        
        return attack_paths

    async def pivot_discovery(
        self,
        bh_nodes: Dict[str, GraphNode],
        bh_edges: List[GraphEdge],
        burp_nodes: Dict[str, GraphNode],
        traffic_nodes: Dict[str, GraphNode]
    ) -> List[Tuple[GraphNode, GraphNode]]:
        """
        Discover pivot points between data sources.
        Automatically creates edges between Burp endpoints and BloodHound computers
        where IP addresses or hostnames match.
        
        Args:
            bh_nodes: BloodHound nodes (Users, Computers, Groups, Domains)
            bh_edges: BloodHound relationship edges
            burp_nodes: Burp endpoint nodes (web servers)
            traffic_nodes: Network traffic IP nodes
        
        Returns:
            List of (source_node, target_node) pivot pairs
        """
        self.logger.info("Discovering pivot points between layers")
        pivots = []
        
        # Extract IP/hostname data from each layer
        burp_ips = self._extract_ips_from_nodes(burp_nodes)
        bh_computers = {
            node_id: node for node_id, node in bh_nodes.items()
            if node.node_type == NodeType.DEVICE
        }
        traffic_ips = traffic_nodes
        
        # Pivot 1: Burp endpoints → BloodHound computers (via IP matching)
        for burp_node in burp_nodes.values():
            burp_ip = burp_node.metadata.get('ip_address')
            burp_hostname = burp_node.metadata.get('hostname')
            
            if not burp_ip and not burp_hostname:
                continue
            
            for bh_id, bh_node in bh_computers.items():
                bh_ip = bh_node.metadata.get('ip_address')
                bh_hostname = bh_node.metadata.get('hostname', '').lower()
                
                # Check for IP match
                if burp_ip and bh_ip and burp_ip == bh_ip:
                    pivot = self._create_pivot_edge(
                        burp_node, bh_node,
                        "Web endpoint IP matches computer IP"
                    )
                    self.graph.add_edge(pivot.source, pivot.target, pivot.edge_type, pivot.weight, metadata=pivot.metadata)
                    pivots.append((burp_node, bh_node))
                    self.logger.info(
                        f"Pivot discovered: {burp_node.id} → {bh_node.id} (IP match)"
                    )
                
                # Check for hostname match
                if burp_hostname and bh_hostname:
                    if burp_hostname.lower() == bh_hostname or \
                       burp_hostname.lower() in bh_hostname or \
                       bh_hostname in burp_hostname.lower():
                        pivot = self._create_pivot_edge(
                            burp_node, bh_node,
                            "Hostname/FQDN match"
                        )
                        self.graph.add_edge(pivot.source, pivot.target, pivot.edge_type, pivot.weight, metadata=pivot.metadata)
                        pivots.append((burp_node, bh_node))
                        self.logger.info(
                            f"Pivot discovered: {burp_node.id} → {bh_node.id} (hostname match)"
                        )
        
        # Pivot 2: Traffic IPs → BloodHound computers
        for traffic_ip_str, traffic_node in traffic_ips.items():
            for bh_id, bh_node in bh_computers.items():
                bh_ip = bh_node.metadata.get('ip_address')
                
                if bh_ip == traffic_ip_str:
                    pivot = self._create_pivot_edge(
                        traffic_node, bh_node,
                        "Network traffic matches computer IP"
                    )
                    self.graph.add_edge(pivot.source, pivot.target, pivot.edge_type, pivot.weight, metadata=pivot.metadata)
                    pivots.append((traffic_node, bh_node))
                    self.logger.info(
                        f"Pivot discovered: {traffic_node.id} → {bh_node.id} (traffic IP match)"
                    )
        
        self.pivots = pivots
        return pivots

    async def credential_mapping(
        self,
        traffic_credentials: Dict[str, Any],
        bh_nodes: Dict[str, GraphNode],
        burp_nodes: Dict[str, GraphNode]
    ) -> Dict[str, List[GraphNode]]:
        """
        Map credentials across layers.
        Links credentials extracted from Wireshark to BloodHound users
        and associates them with Burp web endpoints they can authenticate to.
        
        Args:
            traffic_credentials: Credentials found in traffic (username → password mapping)
            bh_nodes: BloodHound nodes (especially User nodes)
            burp_nodes: Burp endpoint nodes
        
        Returns:
            Dict mapping credentials to accessible nodes
        """
        self.logger.info("Mapping credentials across layers")
        mappings = {}
        
        # Extract BloodHound user nodes
        bh_users = {
            node_id: node for node_id, node in bh_nodes.items()
            if node.node_type == NodeType.ACCOUNT
        }
        
        for cred_id, cred_data in traffic_credentials.items():
            username = cred_data.get('username', '')
            password = cred_data.get('password', '')
            source_ip = cred_data.get('source_ip', '')
            protocol = cred_data.get('protocol', '')
            
            if not username:
                continue
            
            accessible_nodes = []
            
            # Step 1: Match credentials to BloodHound users
            for user_id, user_node in bh_users.items():
                user_name = user_node.metadata.get('name', '').lower()
                user_email = user_node.metadata.get('email', '').lower()
                
                if username.lower() in user_name or username.lower() in user_email:
                    accessible_nodes.append(user_node)
                    
                    # Create edge: Credential → User
                    cred_edge = GraphEdge(
                        id=f"cred_to_user_{cred_id}_{user_id}",
                        source=source_ip,
                        target=user_id,
                        edge_type="credential_match",
                        weight=0.95,  # High confidence
                        metadata={
                            'credential_type': 'domain_credential',
                            'protocol': protocol,
                            'confidence': 0.95
                        }
                    )
                    self.graph.add_edge(cred_edge.source, cred_edge.target, cred_edge.edge_type, cred_edge.weight, metadata=cred_edge.metadata)
                    self.logger.info(f"Credential {username} mapped to user {user_id}")
            
            # Step 2: Link users to web endpoints they can access
            for user_node in accessible_nodes:
                for burp_endpoint in burp_nodes.values():
                    # Check if endpoint might accept this authentication
                    if self._endpoint_accepts_auth(burp_endpoint, protocol):
                        web_edge = GraphEdge(
                            id=f"user_to_endpoint_{user_node.id}_{burp_endpoint.id}",
                            source=user_node.id,
                            target=burp_endpoint.id,
                            edge_type="authenticated_access",
                            weight=0.8,
                            metadata={
                                'protocol': protocol,
                                'credential_available': True,
                                'can_authenticate': True
                            }
                        )
                        self.graph.add_edge(web_edge.source, web_edge.target, web_edge.edge_type, web_edge.weight, metadata=web_edge.metadata)
                        accessible_nodes.append(burp_endpoint)
            
            mappings[cred_id] = accessible_nodes
        
        self.credential_mappings = mappings
        return mappings

    async def cross_layer_pathfinding(
        self,
        bh_nodes: Dict[str, GraphNode],
        burp_nodes: Dict[str, GraphNode],
        traffic_nodes: Dict[str, GraphNode],
        source_node_id: Optional[str] = None,
        target_node_id: Optional[str] = None
    ) -> List[AttackPath]:
        """
        Find cross-layer attack paths using NetworkX pathfinding.
        Identifies "Path of Least Resistance" from external network access
        through web vulnerabilities to domain privilege escalation.
        
        Args:
            bh_nodes: BloodHound domain nodes
            burp_nodes: Burp web endpoints
            traffic_nodes: Network traffic nodes
            source_node_id: Starting point (default: external IP)
            target_node_id: End goal (default: Domain Admin)
        
        Returns:
            List of attack paths sorted by likelihood/severity
        """
        self.logger.info("Finding cross-layer attack paths")
        
        # Determine source and target
        if not source_node_id:
            # Find external IPs
            external_ips = [
                node_id for node_id, node in traffic_nodes.items()
                if not node.metadata.get('is_internal', False)
            ]
            source_node_id = external_ips[0] if external_ips else None
        
        if not target_node_id:
            # Find Domain Admin
            for node_id, node in bh_nodes.items():
                if node.node_type == NodeType.ACCOUNT and \
                   'admin' in node.label.lower():
                    target_node_id = node_id
                    break
        
        if not source_node_id or not target_node_id:
            self.logger.warning("Could not identify source or target for pathfinding")
            return []
        
        self.logger.info(f"Pathfinding from {source_node_id} to {target_node_id}")
        
        attack_paths = []
        
        try:
            # Get NetworkX graph
            G = self.graph.graph
            
            # Find all simple paths (limit to prevent explosion)
            try:
                all_paths = list(nx.all_simple_paths(
                    G,
                    source_node_id,
                    target_node_id,
                    cutoff=10  # Limit path length
                ))
            except nx.NetworkXNoPath:
                self.logger.warning(f"No path found from {source_node_id} to {target_node_id}")
                all_paths = []
            
            # Rank paths by weight
            ranked_paths = []
            for path_nodes in all_paths:
                total_weight = 0.0
                path_edges = []
                layers = set()
                
                for i in range(len(path_nodes) - 1):
                    src, dst = path_nodes[i], path_nodes[i + 1]
                    edge_data = G.get_edge_data(src, dst)
                    
                    if edge_data:
                        weight = edge_data.get('weight', 1.0)
                        total_weight += weight
                        
                        # Determine layer
                        if src in burp_nodes or dst in burp_nodes:
                            layers.add('web')
                        if src in bh_nodes or dst in bh_nodes:
                            layers.add('domain')
                        if src in traffic_nodes or dst in traffic_nodes:
                            layers.add('network')
                        
                        # Get edge object
                        for edge in self.graph.edges:
                            if edge.source == src and edge.target == dst:
                                path_edges.append(edge)
                                break
                
                ranked_paths.append((total_weight, path_nodes, path_edges, list(layers)))
            
            # Sort by weight (lower weight = more resistant)
            ranked_paths.sort(key=lambda x: x[0])
            
            # Create AttackPath objects
            for idx, (weight, path_nodes, path_edges, layers) in enumerate(ranked_paths[:5]):  # Top 5 paths
                node_objects = [
                    bh_nodes.get(n) or burp_nodes.get(n) or traffic_nodes.get(n)
                    for n in path_nodes
                ]
                node_objects = [n for n in node_objects if n]
                
                # Determine severity based on path composition
                severity = self._score_attack_path_severity(path_edges, layers)
                
                # Generate tactical actions
                actions = self._generate_tactical_actions(
                    path_nodes, path_edges, layers,
                    bh_nodes, burp_nodes
                )
                
                attack_path = AttackPath(
                    path_id=f"attack_path_{idx}",
                    nodes=node_objects,
                    edges=path_edges,
                    total_weight=weight,
                    severity=severity,
                    layers=layers,
                    actions=actions
                )
                
                attack_paths.append(attack_path)
                self.logger.info(
                    f"Found attack path {idx}: {weight:.2f} weight, "
                    f"severity={severity}, layers={layers}"
                )
        
        except Exception as e:
            self.logger.error(f"Error during pathfinding: {str(e)}")
        
        return attack_paths

    def _create_pivot_edge(
        self,
        source_node: GraphNode,
        target_node: GraphNode,
        reason: str
    ) -> GraphEdge:
        """Create a pivot edge between nodes."""
        return GraphEdge(
            id=f"pivot_{source_node.id}_{target_node.id}",
            source=source_node.id,
            target=target_node.id,
            edge_type="pivot",
            weight=0.5,  # Low resistance to cross-layer movement
            metadata={
                'pivot_reason': reason,
                'cross_layer': True
            }
        )

    def _extract_ips_from_nodes(self, nodes: Dict[str, GraphNode]) -> Dict[str, str]:
        """Extract IP addresses from nodes."""
        ips = {}
        for node_id, node in nodes.items():
            ip = node.metadata.get('ip_address')
            hostname = node.metadata.get('hostname')
            if ip:
                ips[node_id] = ip
            if hostname:
                ips[node_id] = hostname
        return ips

    def _endpoint_accepts_auth(self, endpoint: GraphNode, protocol: str) -> bool:
        """Check if endpoint accepts authentication for given protocol."""
        accepted_protocols = ['http', 'https', 'ftp', 'ssh', 'ldap']
        return protocol in accepted_protocols

    def _score_attack_path_severity(self, edges: List[GraphEdge], layers: List[str]) -> SeverityLevel:
        """Score severity of attack path."""
        # Multi-layer paths are higher severity
        severity_score = len(layers) * 2
        
        # Add based on edge severities
        for edge in edges:
            if edge.weight > 0.8:
                severity_score += 2
        
        if severity_score >= 5:
            return SeverityLevel.CRITICAL
        elif severity_score >= 3:
            return SeverityLevel.HIGH
        else:
            return SeverityLevel.MEDIUM

    def _generate_tactical_actions(
        self,
        path_nodes: List[str],
        path_edges: List[GraphEdge],
        layers: List[str],
        bh_nodes: Dict[str, GraphNode],
        burp_nodes: Dict[str, GraphNode]
    ) -> List[str]:
        """Generate tactical actions for exploitation of path."""
        actions = []
        
        # Web layer actions
        if 'web' in layers:
            for edge in path_edges:
                if edge.edge_type in ['idor', 'sqli', 'auth_bypass', 'xxe']:
                    actions.append(f"[WEB] Exploit {edge.edge_type} on endpoint {edge.target}")
        
        # Network layer actions
        if 'network' in layers:
            actions.append("[NETWORK] Establish lateral movement through compromised hosts")
        
        # Domain layer actions
        if 'domain' in layers:
            actions.append("[DOMAIN] Escalate privileges using harvested credentials")
            actions.append("[DOMAIN] Move to Domain Admin for complete compromise")
        
        return actions

    def find_critical_paths(self) -> List[AttackPath]:
        """Find paths with CRITICAL severity."""
        return [p for p in self.attack_paths if p.severity == SeverityLevel.CRITICAL]

    def find_paths_by_layer_count(self, layer_count: int) -> List[AttackPath]:
        """Find paths crossing specified number of layers."""
        return [p for p in self.attack_paths if len(p.layers) == layer_count]

    def get_path_summary(self, path: AttackPath) -> str:
        """Generate human-readable summary of attack path."""
        summary = f"\n🎯 Attack Path: {path.path_id}\n"
        summary += f"  Severity: {path.severity}\n"
        summary += f"  Layers: {' → '.join(path.layers)}\n"
        summary += f"  Length: {len(path.nodes)} nodes\n"
        summary += f"\n📍 Nodes:\n"
        for i, node in enumerate(path.nodes):
            summary += f"    {i+1}. {node.label} ({node.node_type})\n"
        summary += f"\n🔗 Edges:\n"
        for edge in path.edges:
            summary += f"    {edge.source} --[{edge.edge_type}]--> {edge.target}\n"
        summary += f"\n⚔️ Tactical Actions:\n"
        for action in path.actions:
            summary += f"    • {action}\n"
        return summary
