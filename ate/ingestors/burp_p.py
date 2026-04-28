"""
Burp Suite Data Ingestor
Parses Burp Suite XML/JSON export data to extract endpoints and vulnerabilities.
Normalizes Burp findings into ATE graph nodes and edges.
"""
import json
import xml.etree.ElementTree as ET
import logging
import asyncio
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse

from ..core.data_models import (
    GraphNode, GraphEdge, NodeType, AtomicFinding,
    VulnerabilityType, SeverityLevel
)

logger = logging.getLogger(__name__)


class BurpIngestor:
    """
    Ingests Burp Suite XML/JSON export data.
    Extracts:
    - Endpoints and their parameters
    - Vulnerabilities (IDOR, SQLi, XSS, etc.)
    - Authentication findings
    - Data exposure issues
    """

    # Burp issue types to ATE vulnerability types
    ISSUE_TYPE_MAPPING = {
        'Insecure direct object references': VulnerabilityType.IDOR,
        'SQL injection': VulnerabilityType.AUTHORIZATION_FLAW,
        'Cross-site scripting': VulnerabilityType.INFORMATION_DISCLOSURE,
        'Weak authentication': VulnerabilityType.AUTHENTICATION_FLAW,
        'Missing authentication': VulnerabilityType.AUTHENTICATION_FLAW,
        'Cleartext transmission': VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        'Unvalidated redirect': VulnerabilityType.AUTHORIZATION_FLAW,
        'Information disclosure': VulnerabilityType.INFORMATION_DISCLOSURE,
    }

    # Burp severity to ATE severity
    SEVERITY_MAPPING = {
        'Critical': SeverityLevel.CRITICAL,
        'High': SeverityLevel.HIGH,
        'Medium': SeverityLevel.MEDIUM,
        'Low': SeverityLevel.LOW,
        'Information': SeverityLevel.INFO,
    }

    def __init__(self, burp_export_path: str):
        """
        Initialize Burp ingestor.
        
        Args:
            burp_export_path: Path to Burp export (XML or JSON)
        """
        self.export_path = Path(burp_export_path)
        self.burp_data = {}
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.findings: List[AtomicFinding] = []
        self.endpoints: Dict[str, Dict] = {}  # Store endpoint details

    async def ingest(self) -> Tuple[Dict[str, GraphNode], List[GraphEdge], List[AtomicFinding]]:
        """
        Asynchronously ingest Burp data.
        
        Returns:
            Tuple of (nodes_dict, edges_list, findings_list)
        """
        logger.info(f"Ingesting Burp Suite data from {self.export_path}")
        
        try:
            # Detect and load based on file type
            if self.export_path.suffix.lower() == '.xml':
                await self._load_xml_async()
            else:
                await self._load_json_async()
            
            # Process endpoints and issues
            await self._process_endpoints_async()
            await self._process_issues_async()
            await self._identify_endpoint_relationships_async()
            
            logger.info(f"Ingestion complete: {len(self.nodes)} nodes, {len(self.edges)} edges, {len(self.findings)} findings")
            return self.nodes, self.edges, self.findings
            
        except Exception as e:
            logger.error(f"Error ingesting Burp data: {str(e)}")
            raise

    async def _load_xml_async(self):
        """Load XML file asynchronously."""
        loop = asyncio.get_event_loop()
        self.burp_data = await loop.run_in_executor(None, self._load_xml_sync)

    def _load_xml_sync(self) -> Dict:
        """Load and parse XML synchronously."""
        tree = ET.parse(self.export_path)
        root = tree.getroot()
        
        # Convert XML to dict-like structure
        result = {
            'issues': [],
            'sites': []
        }
        
        for issue in root.findall('.//issue'):
            result['issues'].append(self._parse_xml_issue(issue))
        
        return result

    def _parse_xml_issue(self, issue_elem) -> Dict:
        """Parse XML issue element."""
        return {
            'type': issue_elem.findtext('type', ''),
            'name': issue_elem.findtext('name', ''),
            'severity': issue_elem.findtext('severity', 'Low'),
            'confidence': issue_elem.findtext('confidence', 'Certain'),
            'host': issue_elem.findtext('host', ''),
            'port': issue_elem.findtext('port', ''),
            'protocol': issue_elem.findtext('protocol', 'https'),
            'url': issue_elem.findtext('url', ''),
            'path': issue_elem.findtext('path', ''),
            'method': issue_elem.findtext('method', 'GET'),
            'issueDetail': issue_elem.findtext('issueDetail', ''),
            'remediationDetail': issue_elem.findtext('remediationDetail', ''),
        }

    async def _load_json_async(self):
        """Load JSON file asynchronously."""
        loop = asyncio.get_event_loop()
        self.burp_data = await loop.run_in_executor(None, self._load_json_sync)

    def _load_json_sync(self) -> Dict:
        """Load JSON synchronously."""
        with open(self.export_path, 'r') as f:
            return json.load(f)

    async def _process_endpoints_async(self):
        """Process all endpoints found in Burp data."""
        tasks = []
        seen_endpoints = set()
        
        # Extract endpoints from issues
        for issue in self.burp_data.get('issues', []):
            endpoint_key = f"{issue.get('host')}:{issue.get('port')}{issue.get('path', '/')}"
            
            if endpoint_key not in seen_endpoints:
                seen_endpoints.add(endpoint_key)
                tasks.append(self._process_endpoint(issue))
        
        if tasks:
            await asyncio.gather(*tasks)

    async def _process_endpoint(self, issue_data: Dict):
        """Process individual endpoint."""
        try:
            host = issue_data.get('host', 'unknown')
            port = issue_data.get('port', 443)
            protocol = issue_data.get('protocol', 'https')
            path = issue_data.get('path', '/')
            method = issue_data.get('method', 'GET')
            
            # Create endpoint node
            endpoint_id = f"{protocol}://{host}:{port}{path}"
            
            if endpoint_id not in self.nodes:
                node = GraphNode(
                    id=endpoint_id,
                    node_type=NodeType.ENDPOINT,
                    label=f"{method} {path}",
                    privilege_level=30,  # Base privilege for web endpoint
                    is_sensitive=self._is_sensitive_endpoint(path),
                    metadata={
                        'source': 'burp_suite',
                        'host': host,
                        'port': port,
                        'protocol': protocol,
                        'path': path,
                        'method': method,
                        'url': issue_data.get('url', endpoint_id)
                    }
                )
                
                self.nodes[endpoint_id] = node
                self.endpoints[endpoint_id] = {
                    'host': host,
                    'port': port,
                    'protocol': protocol,
                    'path': path,
                    'method': method,
                }
                
                logger.debug(f"Added endpoint: {endpoint_id}")
            
        except Exception as e:
            logger.warning(f"Error processing endpoint: {str(e)}")

    async def _process_issues_async(self):
        """Process all Burp issues asynchronously."""
        tasks = []
        
        for issue in self.burp_data.get('issues', []):
            tasks.append(self._process_issue(issue))
        
        if tasks:
            await asyncio.gather(*tasks)

    async def _process_issue(self, issue_data: Dict):
        """Process individual Burp issue."""
        try:
            issue_type = issue_data.get('name', '').lower()
            severity = issue_data.get('severity', 'Low')
            host = issue_data.get('host', '')
            path = issue_data.get('path', '/')
            protocol = issue_data.get('protocol', 'https')
            port = issue_data.get('port', 443)
            
            # Find endpoint node
            endpoint_id = f"{protocol}://{host}:{port}{path}"
            endpoint_node = self.nodes.get(endpoint_id)
            
            if not endpoint_node:
                # Create endpoint node if not exists
                await self._process_endpoint(issue_data)
                endpoint_node = self.nodes.get(endpoint_id)
            
            if not endpoint_node:
                return
            
            # Determine vulnerability type
            vuln_type = self._map_issue_type(issue_type)
            
            # Create finding
            finding = AtomicFinding(
                id=f'burp_{issue_type.replace(" ", "_")}_{host}_{path}',
                finding_type=vuln_type,
                severity=self.SEVERITY_MAPPING.get(severity, SeverityLevel.MEDIUM),
                source_node='external_attacker',  # Web endpoints are externally accessible
                target_node=endpoint_node.id,
                description=f"Burp: {issue_data.get('name', 'Unknown Issue')} at {path}",
                confidence=0.9,
                metadata={
                    'burp_issue_type': issue_type,
                    'endpoint_url': issue_data.get('url'),
                    'issue_detail': issue_data.get('issueDetail', ''),
                    'remediation': issue_data.get('remediationDetail', ''),
                    'host': host,
                    'path': path,
                }
            )
            
            self.findings.append(finding)
            
            # Update endpoint privilege level if critical issue
            if finding.severity == SeverityLevel.CRITICAL:
                endpoint_node.privilege_level = min(endpoint_node.privilege_level + 20, 100)
                endpoint_node.is_sensitive = True
            
            logger.debug(f"Added finding: {finding.id}")
            
        except Exception as e:
            logger.warning(f"Error processing issue: {str(e)}")

    async def _identify_endpoint_relationships_async(self):
        """Identify relationships between endpoints."""
        # Create edges based on same host/port
        host_endpoints = {}
        
        for endpoint_id, endpoint_info in self.endpoints.items():
            key = f"{endpoint_info['host']}:{endpoint_info['port']}"
            if key not in host_endpoints:
                host_endpoints[key] = []
            host_endpoints[key].append(endpoint_id)
        
        # Create edges between endpoints on same host
        for endpoints in host_endpoints.values():
            if len(endpoints) > 1:
                for i, source in enumerate(endpoints):
                    for target in endpoints[i+1:]:
                        edge = GraphEdge(
                            id=f"burp_same_host_{source}_{target}",
                            source=source,
                            target=target,
                            edge_type="same_host",
                            weight=1.5,
                            metadata={'relationship': 'same_host'}
                        )
                        self.edges.append(edge)

    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Determine if endpoint is sensitive based on path."""
        sensitive_keywords = [
            'admin', 'login', 'auth', 'user', 'profile', 'account',
            'database', 'api', 'config', 'secret', 'password',
            'credential', 'token', 'key', 'backup'
        ]
        
        path_lower = path.lower()
        return any(keyword in path_lower for keyword in sensitive_keywords)

    def _map_issue_type(self, issue_type: str) -> VulnerabilityType:
        """Map Burp issue type to ATE vulnerability type."""
        for burp_type, ate_type in self.ISSUE_TYPE_MAPPING.items():
            if burp_type.lower() in issue_type.lower():
                return ate_type
        
        return VulnerabilityType.CUSTOM

    def get_all_nodes(self) -> Dict[str, GraphNode]:
        """Get all ingested nodes."""
        return self.nodes

    def get_all_edges(self) -> List[GraphEdge]:
        """Get all ingested edges."""
        return self.edges

    def get_all_findings(self) -> List[AtomicFinding]:
        """Get all identified findings."""
        return self.findings

    def get_endpoints(self) -> Dict[str, Dict]:
        """Get all endpoints with details."""
        return self.endpoints

    def find_critical_endpoints(self) -> List[str]:
        """Find all critical/sensitive endpoints."""
        return [endpoint_id for endpoint_id, node in self.nodes.items()
                if node.node_type == NodeType.ENDPOINT and node.is_sensitive]

    def find_vulnerable_endpoints(self) -> List[str]:
        """Find all endpoints with vulnerabilities."""
        return [finding.target_node for finding in self.findings
                if finding.target_node in self.nodes]
