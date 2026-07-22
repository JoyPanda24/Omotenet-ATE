"""
BloodHound Data Ingestor
Parses BloodHound JSON export data to extract domain relationships.
Normalizes BloodHound concepts into ATE graph nodes and edges.
"""
import json
import logging
import asyncio
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path

from ..core.data_models import (
    GraphNode, GraphEdge, NodeType, AtomicFinding,
    VulnerabilityType, SeverityLevel
)

logger = logging.getLogger(__name__)


class BloodHoundIngestor:
    """
    Ingests BloodHound JSON export data and normalizes it to ATE format.
    
    BloodHound Relationships:
    - MemberOf: User is member of a group
    - HasSession: User has active session on computer
    - AdminTo: User is admin on computer
    - CanRDP: User can RDP to computer
    - CanPSRemote: User can PSRemote to computer
    - CanLogon: User can logon to computer
    """

    # BloodHound node types
    BLOODHOUND_TYPES = {
        'User': NodeType.USER,
        'Computer': NodeType.RESOURCE,
        'Group': NodeType.ROLE,
        'Domain': NodeType.RESOURCE,
        'OU': NodeType.RESOURCE,
        'GPO': NodeType.RESOURCE,
    }

    # Dangerous relationships
    SENSITIVE_RELATIONSHIPS = {
        'AdminTo': 5.0,  # Weight: high privilege
        'HasSession': 4.0,  # Active session
        'MemberOf': 2.0,  # Group membership
        'CanRDP': 4.0,  # Remote access
        'CanPSRemote': 4.0,  # Remote access
        'CanLogon': 3.0,  # Local logon
        'CanResetPassword': 4.5,  # Privilege
        'AllExtendedRights': 5.0,  # Full control
    }

    def __init__(self, bloodhound_json_path: str):
        """
        Initialize BloodHound ingestor.
        
        Args:
            bloodhound_json_path: Path to BloodHound JSON export
        """
        self.json_path = Path(bloodhound_json_path)
        self.bh_data = {}
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.findings: List[AtomicFinding] = []

    async def ingest(self) -> Tuple[Dict[str, GraphNode], List[GraphEdge], List[AtomicFinding]]:
        """
        Asynchronously ingest BloodHound data.
        
        Returns:
            Tuple of (nodes_dict, edges_list, findings_list)
        """
        logger.info(f"Ingesting BloodHound data from {self.json_path}")
        
        try:
            # Load JSON asynchronously
            self.bh_data = await self._load_json_async()
            
            # Process nodes and relationships
            await self._process_nodes_async()
            await self._process_relationships_async()
            await self._identify_attack_paths_async()
            
            logger.info(f"Ingestion complete: {len(self.nodes)} nodes, {len(self.edges)} edges")
            return self.nodes, self.edges, self.findings
            
        except Exception as e:
            logger.error(f"Error ingesting BloodHound data: {str(e)}")
            raise

    async def _load_json_async(self) -> Dict:
        """Load JSON file asynchronously."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._load_json_sync)

    def _load_json_sync(self) -> Dict:
        """Load JSON file synchronously."""
        with open(self.json_path, 'r') as f:
            return json.load(f)

    async def _process_nodes_async(self):
        """Process BloodHound nodes asynchronously."""
        tasks = []
        
        # Process each node type
        for node_type in self.BLOODHOUND_TYPES.keys():
            key = f"{node_type}s"  # BloodHound typically pluralizes: "Users", "Computers"
            if key in self.bh_data:
                for node_data in self.bh_data[key]:
                    tasks.append(self._process_node(node_data, node_type))
        
        if tasks:
            await asyncio.gather(*tasks)

    async def _process_node(self, node_data: Dict, node_type: str):
        """Process individual node."""
        try:
            node_id = node_data.get('name', node_data.get('objectid', ''))
            if not node_id:
                return
            
            # Determine if sensitive
            is_sensitive = self._is_sensitive_node(node_data, node_type)
            
            # Calculate privilege level based on node type
            privilege_level = self._calculate_privilege_level(node_data, node_type)
            
            # Extract metadata
            metadata = {
                'bloodhound_type': node_type,
                'objectid': node_data.get('objectid'),
                'domain': node_data.get('domain'),
                'distinguishedname': node_data.get('distinguishedname'),
                'properties': node_data.get('properties', {})
            }
            
            # Create node
            node = GraphNode(
                id=node_id,
                node_type=self.BLOODHOUND_TYPES.get(node_type, NodeType.RESOURCE),
                label=node_id.split('@')[0] if '@' in node_id else node_id,
                privilege_level=privilege_level,
                is_sensitive=is_sensitive,
                metadata=metadata
            )
            
            self.nodes[node_id] = node
            logger.debug(f"Added node: {node_id} (type: {node_type}, priv: {privilege_level})")
            
        except Exception as e:
            logger.warning(f"Error processing node: {str(e)}")

    async def _process_relationships_async(self):
        """Process BloodHound relationships asynchronously."""
        tasks = []
        
        if 'Relationships' in self.bh_data:
            for rel in self.bh_data['Relationships']:
                tasks.append(self._process_relationship(rel))
        
        if tasks:
            await asyncio.gather(*tasks)

    async def _process_relationship(self, rel_data: Dict):
        """Process individual relationship."""
        try:
            source = rel_data.get('source', '').lower()
            target = rel_data.get('target', '').lower()
            rel_type = rel_data.get('reltype', '').lower()
            
            if not source or not target or not rel_type:
                return
            
            # Find matching nodes
            source_node = self._find_node(source)
            target_node = self._find_node(target)
            
            if not source_node or not target_node:
                return
            
            # Create edge with weight based on relationship type
            weight = self.SENSITIVE_RELATIONSHIPS.get(rel_type.title(), 1.0)
            
            edge_id = f"bh_{source}→{target}_{rel_type}"
            edge = GraphEdge(
                id=edge_id,
                source=source_node.id,
                target=target_node.id,
                edge_type=rel_type,
                weight=weight,
                metadata={
                    'source_type': self._get_node_type(source),
                    'target_type': self._get_node_type(target),
                    'bloodhound_relationship': rel_type
                }
            )
            
            self.edges.append(edge)
            logger.debug(f"Added edge: {source} -[{rel_type}]-> {target} (weight: {weight})")
            
            # Create findings for dangerous relationships
            if rel_type in self.SENSITIVE_RELATIONSHIPS and self.SENSITIVE_RELATIONSHIPS[rel_type] >= 4.0:
                finding = self._create_finding_from_relationship(source_node, target_node, rel_type)
                if finding:
                    self.findings.append(finding)
            
        except Exception as e:
            logger.warning(f"Error processing relationship: {str(e)}")

    async def _identify_attack_paths_async(self):
        """Identify common attack paths in BloodHound data."""
        # Find Domain Admins
        domain_admins = [n for n in self.nodes.values() 
                        if n.privilege_level >= 90]
        
        # Find users with HasSession on sensitive computers
        for edge in self.edges:
            if edge.edge_type.lower() == 'hassession':
                source_node = self.nodes.get(edge.source)
                target_node = self.nodes.get(edge.target)
                
                if source_node and target_node and target_node.is_sensitive:
                    finding = AtomicFinding(
                        id=f'bh_active_session_{source_node.id}',
                        finding_type=VulnerabilityType.AUTHENTICATION_FLAW,
                        severity=SeverityLevel.CRITICAL,
                        source_node=source_node.id,
                        target_node=target_node.id,
                        description=f"Active session detected: {source_node.label} on {target_node.label}",
                        confidence=1.0,
                        metadata={
                            'session_type': 'HasSession',
                            'source_user': source_node.label,
                            'target_computer': target_node.label
                        }
                    )
                    self.findings.append(finding)

    def _find_node(self, identifier: str) -> Optional[GraphNode]:
        """Find node by identifier (case-insensitive)."""
        for node in self.nodes.values():
            if node.id.lower() == identifier.lower():
                return node
        return None

    def _get_node_type(self, identifier: str) -> Optional[str]:
        """Get node type from identifier."""
        for node in self.nodes.values():
            if node.id.lower() == identifier.lower():
                return node.metadata.get('bloodhound_type')
        return None

    def _is_sensitive_node(self, node_data: Dict, node_type: str) -> bool:
        """Determine if node is sensitive/high-value."""
        if node_type == 'User':
            # Check for admin, high-priv group memberships
            return node_data.get('admin_count', 0) > 0
        
        elif node_type == 'Computer':
            # Domain controllers are sensitive
            return 'DC' in node_data.get('name', '').upper()
        
        elif node_type == 'Group':
            # Domain Admins, Enterprise Admins, Schema Admins
            name = node_data.get('name', '').upper()
            return any(admin_group in name for admin_group in [
                'DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS',
                'ACCOUNT OPERATORS', 'BACKUP OPERATORS'
            ])
        
        return False

    def _calculate_privilege_level(self, node_data: Dict, node_type: str) -> int:
        """Calculate privilege level based on node properties."""
        base_levels = {
            'User': 25,
            'Computer': 40,
            'Group': 50,
            'Domain': 80,
            'OU': 30,
            'GPO': 55,
        }
        
        privilege = base_levels.get(node_type, 25)
        
        # Boost for sensitive nodes
        if self._is_sensitive_node(node_data, node_type):
            privilege += 50
        
        # Boost for admin users
        if node_type == 'User' and node_data.get('admin_count', 0) > 0:
            privilege += 30
        
        return min(privilege, 100)

    def _create_finding_from_relationship(
        self,
        source_node: GraphNode,
        target_node: GraphNode,
        rel_type: str
    ) -> Optional[AtomicFinding]:
        """Create a finding from a dangerous relationship."""
        if rel_type.lower() not in ['adminto', 'hassession', 'canrdp', 'canpsremote']:
            return None
        
        severity_map = {
            'adminto': SeverityLevel.CRITICAL,
            'hassession': SeverityLevel.CRITICAL,
            'canrdp': SeverityLevel.HIGH,
            'canpsremote': SeverityLevel.HIGH,
            'canresetpassword': SeverityLevel.HIGH,
            'allextendedrights': SeverityLevel.CRITICAL,
        }
        
        finding = AtomicFinding(
            id=f'bh_{rel_type}_{source_node.id}_{target_node.id}',
            finding_type=VulnerabilityType.PRIVILEGE_ESCALATION,
            severity=severity_map.get(rel_type.lower(), SeverityLevel.MEDIUM),
            source_node=source_node.id,
            target_node=target_node.id,
            description=f"BloodHound: {source_node.label} has {rel_type} to {target_node.label}",
            confidence=0.95,
            metadata={
                'bloodhound_relationship': rel_type,
                'source_type': source_node.metadata.get('bloodhound_type'),
                'target_type': target_node.metadata.get('bloodhound_type'),
            }
        )
        
        return finding

    def get_all_nodes(self) -> Dict[str, GraphNode]:
        """Get all ingested nodes."""
        return self.nodes

    def get_all_edges(self) -> List[GraphEdge]:
        """Get all ingested edges."""
        return self.edges

    def get_all_findings(self) -> List[AtomicFinding]:
        """Get all identified findings."""
        return self.findings

    def find_domain_admins(self) -> List[GraphNode]:
        """Find all Domain Admin nodes."""
        return [n for n in self.nodes.values() 
                if 'DOMAIN ADMIN' in n.label.upper()]

    def find_admin_users(self) -> List[GraphNode]:
        """Find all users with admin privileges."""
        return [n for n in self.nodes.values()
                if n.node_type == NodeType.USER and n.privilege_level >= 70]

    def find_sensitive_computers(self) -> List[GraphNode]:
        """Find all sensitive computers (DCs, etc)."""
        return [n for n in self.nodes.values()
                if n.node_type == NodeType.RESOURCE and n.is_sensitive]
