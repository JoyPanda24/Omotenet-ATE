"""
Wireshark/Network Traffic Data Ingestor
Parses Tshark JSON export to extract network relationships, IPs, and credentials.
Normalizes network data into ATE graph nodes and edges.
"""
import json
import logging
import asyncio
import re
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path

from ..core.data_models import (
    GraphNode, GraphEdge, NodeType, AtomicFinding,
    VulnerabilityType, SeverityLevel
)

logger = logging.getLogger(__name__)


class TrafficIngestor:
    """
    Ingests Wireshark/Tshark JSON traffic data.
    Extracts:
    - IP relationships and communication patterns
    - Credentials transmitted in cleartext
    - Authentication tokens (JWTs, API keys)
    - DNS resolutions
    - Service/protocol information
    """

    # Patterns for credential detection
    CREDENTIAL_PATTERNS = {
        'password': r'(?:password|passwd|pwd)[=:\s]+([^\s&\n"]+)',
        'username': r'(?:user|username|login)[=:\s]+([^\s&\n"]+)',
        'api_key': r'(?:api[_-]?key|apikey|x-api-key)[=:\s]+([a-zA-Z0-9\-_]{20,})',
        'jwt': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
        'bearer_token': r'(?:bearer|authorization)[=:\s]+([a-zA-Z0-9\-_.]+)',
        'ntlm': r'(?:NTLM|ntlm)\s+([A-Za-z0-9/+]+={0,2})',
    }

    # Cleartext protocols to monitor
    CLEARTEXT_PROTOCOLS = [
        'http', 'ftp', 'telnet', 'smtp', 'pop3', 'imap',
        'ldap', 'snmp', 'mysql', 'mongodb', 'postgresql'
    ]

    def __init__(self, traffic_json_path: str):
        """
        Initialize Traffic ingestor.
        
        Args:
            traffic_json_path: Path to Tshark JSON export
        """
        self.json_path = Path(traffic_json_path)
        self.traffic_data = []
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.findings: List[AtomicFinding] = []
        self.ip_to_hostname: Dict[str, str] = {}
        self.credentials_found: Set[str] = set()

    async def ingest(self) -> Tuple[Dict[str, GraphNode], List[GraphEdge], List[AtomicFinding]]:
        """
        Asynchronously ingest traffic data.
        
        Returns:
            Tuple of (nodes_dict, edges_list, findings_list)
        """
        logger.info(f"Ingesting traffic data from {self.json_path}")
        
        try:
            # Load JSON
            self.traffic_data = await self._load_json_async()
            
            # Process packets
            await self._process_packets_async()
            await self._extract_credentials_async()
            await self._analyze_communication_patterns_async()
            
            logger.info(f"Ingestion complete: {len(self.nodes)} nodes, {len(self.edges)} edges, {len(self.findings)} findings")
            return self.nodes, self.edges, self.findings
            
        except Exception as e:
            logger.error(f"Error ingesting traffic data: {str(e)}")
            raise

    async def _load_json_async(self) -> List[Dict]:
        """Load JSON file asynchronously."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._load_json_sync)

    def _load_json_sync(self) -> List[Dict]:
        """Load JSON synchronously."""
        with open(self.json_path, 'r') as f:
            data = json.load(f)
            # Handle both list and dict formats
            return data if isinstance(data, list) else data.get('packets', [])

    async def _process_packets_async(self):
        """Process all packets asynchronously."""
        tasks = []
        seen_ips = set()
        
        # First pass: extract IPs and create nodes
        for packet in self.traffic_data:
            ip_src = self._extract_field(packet, 'ip.src')
            ip_dst = self._extract_field(packet, 'ip.dst')
            
            if ip_src and ip_src not in seen_ips:
                tasks.append(self._create_ip_node(ip_src))
                seen_ips.add(ip_src)
            
            if ip_dst and ip_dst not in seen_ips:
                tasks.append(self._create_ip_node(ip_dst))
                seen_ips.add(ip_dst)
        
        if tasks:
            await asyncio.gather(*tasks)
        
        # Second pass: create communication edges
        tasks = []
        for packet in self.traffic_data:
            tasks.append(self._process_packet_communication(packet))
        
        if tasks:
            await asyncio.gather(*tasks)

    async def _create_ip_node(self, ip: str):
        """Create a node for an IP address."""
        if ip in self.nodes:
            return
        
        # Determine if IP is internal or external
        is_internal = self._is_internal_ip(ip)
        
        node = GraphNode(
            id=ip,
            node_type=NodeType.RESOURCE,
            label=self.ip_to_hostname.get(ip, ip),
            privilege_level=20 if is_internal else 0,
            is_sensitive=False,
            metadata={
                'source': 'traffic_analysis',
                'ip_address': ip,
                'is_internal': is_internal,
            }
        )
        
        self.nodes[ip] = node
        logger.debug(f"Added IP node: {ip}")

    async def _process_packet_communication(self, packet: Dict):
        """Process individual packet for communication patterns."""
        try:
            ip_src = self._extract_field(packet, 'ip.src')
            ip_dst = self._extract_field(packet, 'ip.dst')
            protocol = self._extract_field(packet, 'highest.layer', 'ip.proto')
            
            if not ip_src or not ip_dst:
                return
            
            # Get protocol and service
            protocol_name = self._get_protocol_name(packet)
            port = self._extract_field(packet, 'tcp.dstport', 'udp.dstport')
            
            # Check for cleartext protocols
            if protocol_name in self.CLEARTEXT_PROTOCOLS:
                payload = self._extract_field(packet, 'data.data', '')
                if payload:
                    await self._analyze_payload(payload, ip_src, ip_dst, protocol_name)
            
            # Create edge if not exists
            edge_id = f"traffic_{ip_src}→{ip_dst}_{protocol_name}"
            edge_exists = any(e.id == edge_id for e in self.edges)
            
            if not edge_exists and ip_src in self.nodes and ip_dst in self.nodes:
                edge = GraphEdge(
                    id=edge_id,
                    source=ip_src,
                    target=ip_dst,
                    edge_type=protocol_name,
                    weight=1.0,
                    metadata={
                        'protocol': protocol_name,
                        'port': port,
                        'source_type': 'traffic_analysis'
                    }
                )
                self.edges.append(edge)
            
        except Exception as e:
            logger.debug(f"Error processing packet communication: {str(e)}")

    async def _extract_credentials_async(self):
        """Extract credentials from traffic asynchronously."""
        tasks = []
        
        for packet in self.traffic_data:
            tasks.append(self._extract_packet_credentials(packet))
        
        if tasks:
            await asyncio.gather(*tasks)

    async def _extract_packet_credentials(self, packet: Dict):
        """Extract credentials from individual packet."""
        try:
            payload = self._extract_field(packet, 'data.data', '')
            ip_src = self._extract_field(packet, 'ip.src', 'unknown')
            ip_dst = self._extract_field(packet, 'ip.dst', 'unknown')
            protocol = self._get_protocol_name(packet)
            
            if not payload:
                return
            
            # Search for credentials using patterns
            for cred_type, pattern in self.CREDENTIAL_PATTERNS.items():
                matches = re.findall(pattern, str(payload), re.IGNORECASE)
                
                for match in matches:
                    if match and match not in self.credentials_found:
                        self.credentials_found.add(match)
                        
                        # Create finding
                        finding = AtomicFinding(
                            id=f'traffic_cred_{cred_type}_{ip_src}',
                            finding_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                            severity=SeverityLevel.CRITICAL,
                            source_node=ip_src,
                            target_node=ip_dst,
                            description=f"{cred_type.upper()} exposed in cleartext {protocol} traffic from {ip_src}",
                            confidence=0.95,
                            metadata={
                                'credential_type': cred_type,
                                'protocol': protocol,
                                'source_ip': ip_src,
                                'destination_ip': ip_dst,
                                'value_preview': match[:20] + '...' if len(match) > 20 else match
                            }
                        )
                        
                        self.findings.append(finding)
                        logger.warning(f"Found {cred_type} in traffic from {ip_src}")
            
        except Exception as e:
            logger.debug(f"Error extracting credentials: {str(e)}")

    async def _analyze_payload(self, payload: str, src_ip: str, dst_ip: str, protocol: str):
        """Analyze payload for sensitive data."""
        # Already handled by extract_credentials_async
        pass

    async def _analyze_communication_patterns_async(self):
        """Analyze communication patterns for suspicious activity."""
        # Count connections per IP
        ip_connection_count = {}
        
        for edge in self.edges:
            ip_connection_count[edge.source] = ip_connection_count.get(edge.source, 0) + 1
        
        # Flag IPs with many outbound connections (possible C2)
        for ip, count in ip_connection_count.items():
            if count >= 5:  # Arbitrary threshold
                finding = AtomicFinding(
                    id=f'traffic_suspicious_outbound_{ip}',
                    finding_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    severity=SeverityLevel.MEDIUM,
                    source_node=ip,
                    target_node='external_network',
                    description=f"IP {ip} has {count} outbound connections (possible C2 or data exfiltration)",
                    confidence=0.6,
                    metadata={
                        'connection_count': count,
                        'source_ip': ip
                    }
                )
                self.findings.append(finding)

    def _extract_field(self, packet: Dict, *field_paths: str) -> Optional[str]:
        """Extract field from packet, trying multiple paths."""
        for field_path in field_paths:
            try:
                value = packet
                for key in field_path.split('.'):
                    if isinstance(value, dict):
                        value = value.get(key)
                    else:
                        value = None
                        break
                
                if value:
                    return str(value)
            except:
                continue
        
        return None

    def _get_protocol_name(self, packet: Dict) -> str:
        """Extract protocol name from packet."""
        protocols = []
        
        # Try multiple protocol indicators
        if self._extract_field(packet, 'tcp.srcport'):
            protocols.append('tcp')
        if self._extract_field(packet, 'udp.srcport'):
            protocols.append('udp')
        if self._extract_field(packet, 'http.request.method'):
            protocols.append('http')
        if self._extract_field(packet, 'https.record.content_type'):
            protocols.append('https')
        if self._extract_field(packet, 'dns.flags.response'):
            protocols.append('dns')
        
        return protocols[0] if protocols else 'unknown'

    def _is_internal_ip(self, ip: str) -> bool:
        """Determine if IP is internal/private."""
        internal_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.1', '127.255.255.255'),
        ]
        
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            # Fallback to simple string matching
            return any(ip.startswith(r.split('.')[0:3]) for r, _ in internal_ranges for r in [ip])

    def get_all_nodes(self) -> Dict[str, GraphNode]:
        """Get all ingested nodes."""
        return self.nodes

    def get_all_edges(self) -> List[GraphEdge]:
        """Get all ingested edges."""
        return self.edges

    def get_all_findings(self) -> List[AtomicFinding]:
        """Get all identified findings."""
        return self.findings

    def get_exposed_credentials(self) -> List[str]:
        """Get all exposed credentials found."""
        return list(self.credentials_found)

    def find_internal_ips(self) -> List[str]:
        """Find all internal IPs."""
        return [ip for ip, node in self.nodes.items()
                if node.metadata.get('is_internal', False)]

    def find_external_ips(self) -> List[str]:
        """Find all external IPs."""
        return [ip for ip, node in self.nodes.items()
                if not node.metadata.get('is_internal', False)]

    def find_suspicious_ips(self) -> List[str]:
        """Find IPs with suspicious activity."""
        return [finding.source_node for finding in self.findings
                if 'suspicious' in finding.description.lower()]
