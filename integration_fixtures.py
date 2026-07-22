"""Reusable pytest fixtures for integration-style tests."""

from __future__ import annotations

from typing import Dict, List, Tuple

import pytest

from ate.core.data_models import GraphEdge, GraphNode, NodeType, SeverityLevel
from ate.core.reasoning_engine_v2 import MultiSourceAttackPath


def _build_bloodhound_graph() -> Tuple[Dict[str, GraphNode], List[GraphEdge]]:
    admin_user = GraphNode(
        id="admin@company.com",
        node_type=NodeType.USER,
        label="admin@company.com",
        privilege_level=95,
        is_sensitive=True,
        metadata={
            "name": "admin@company.com",
            "email": "admin@company.com",
        },
    )
    john_user = GraphNode(
        id="john.smith@company.com",
        node_type=NodeType.USER,
        label="john.smith@company.com",
        privilege_level=25,
        metadata={
            "name": "john.smith@company.com",
            "email": "john.smith@company.com",
        },
    )
    web_computer = GraphNode(
        id="web-prod-01.company.com",
        node_type=NodeType.RESOURCE,
        label="web-prod-01.company.com",
        privilege_level=70,
        metadata={
            "hostname": "web-prod-01.company.com",
            "ip_address": "10.0.1.50",
        },
    )
    dc_computer = GraphNode(
        id="dc-01.company.com",
        node_type=NodeType.RESOURCE,
        label="dc-01.company.com",
        privilege_level=90,
        is_sensitive=True,
        metadata={
            "hostname": "dc-01.company.com",
            "ip_address": "10.0.0.1",
        },
    )
    domain_admins = GraphNode(
        id="domain admins@company.com",
        node_type=NodeType.ROLE,
        label="Domain Admins",
        privilege_level=100,
        is_sensitive=True,
        metadata={
            "name": "Domain Admins@company.com",
        },
    )
    developers = GraphNode(
        id="developers@company.com",
        node_type=NodeType.ROLE,
        label="Developers",
        privilege_level=50,
        metadata={
            "name": "Developers@company.com",
        },
    )

    nodes = {
        admin_user.id: admin_user,
        john_user.id: john_user,
        web_computer.id: web_computer,
        dc_computer.id: dc_computer,
        domain_admins.id: domain_admins,
        developers.id: developers,
    }

    edges = [
        GraphEdge(
            id="bh_memberof_john",
            source=john_user.id,
            target=developers.id,
            edge_type="memberof",
            weight=2.0,
            metadata={"relationship": "MemberOf"},
        ),
        GraphEdge(
            id="bh_memberof_admin",
            source=admin_user.id,
            target=domain_admins.id,
            edge_type="memberof",
            weight=2.0,
            metadata={"relationship": "MemberOf"},
        ),
        GraphEdge(
            id="bh_hassession_john_web",
            source=john_user.id,
            target=web_computer.id,
            edge_type="hassession",
            weight=4.0,
            metadata={"relationship": "HasSession"},
        ),
        GraphEdge(
            id="bh_adminto_domain_web",
            source=domain_admins.id,
            target=web_computer.id,
            edge_type="adminto",
            weight=5.0,
            metadata={"relationship": "AdminTo"},
        ),
        GraphEdge(
            id="bh_adminto_domain_dc",
            source=domain_admins.id,
            target=dc_computer.id,
            edge_type="adminto",
            weight=5.0,
            metadata={"relationship": "AdminTo"},
        ),
    ]

    return nodes, edges


def _build_burp_graph() -> Tuple[Dict[str, GraphNode], List[GraphEdge]]:
    endpoint_id = "https://web.company.com:443/api/users"

    endpoint = GraphNode(
        id=endpoint_id,
        node_type=NodeType.ENDPOINT,
        label="GET /api/users",
        privilege_level=30,
        metadata={
            "source": "burp_suite",
            "host": "web.company.com",
            "hostname": "web.company.com",
            "ip_address": "10.0.1.50",
            "protocol": "https",
            "path": "/api/users",
            "method": "GET",
            "url": "https://web.company.com/api/users",
        },
    )
    admin_endpoint = GraphNode(
        id="https://web.company.com:443/admin",
        node_type=NodeType.ENDPOINT,
        label="GET /admin",
        privilege_level=40,
        is_sensitive=True,
        metadata={
            "source": "burp_suite",
            "host": "web.company.com",
            "hostname": "web.company.com",
            "ip_address": "10.0.1.50",
            "protocol": "https",
            "path": "/admin",
            "method": "GET",
            "url": "https://web.company.com/admin",
        },
    )

    nodes = {
        endpoint.id: endpoint,
        admin_endpoint.id: admin_endpoint,
    }

    edges = [
        GraphEdge(
            id="burp_auth_users_admin",
            source=endpoint.id,
            target="admin@company.com",
            edge_type="authenticated_access",
            weight=0.8,
            metadata={
                "credential_available": False,
                "protocol": "https",
                "auth_required": False,
            },
        ),
        GraphEdge(
            id="burp_idor_users_admin",
            source=admin_endpoint.id,
            target="admin@company.com",
            edge_type="idor",
            weight=0.9,
            metadata={
                "credential_available": True,
                "protocol": "https",
            },
        ),
    ]

    return nodes, edges


def _build_traffic_graph() -> Tuple[Dict[str, GraphNode], List[GraphEdge]]:
    external_attacker = GraphNode(
        id="203.0.113.10",
        node_type=NodeType.RESOURCE,
        label="203.0.113.10",
        privilege_level=0,
        metadata={
            "ip_address": "203.0.113.10",
            "is_internal": False,
            "hostname": "attacker.example",
        },
    )
    internal_web = GraphNode(
        id="10.0.1.50",
        node_type=NodeType.RESOURCE,
        label="10.0.1.50",
        privilege_level=20,
        metadata={
            "ip_address": "10.0.1.50",
            "is_internal": True,
            "hostname": "web.company.com",
        },
    )
    internal_dc = GraphNode(
        id="10.0.0.1",
        node_type=NodeType.RESOURCE,
        label="10.0.0.1",
        privilege_level=20,
        metadata={
            "ip_address": "10.0.0.1",
            "is_internal": True,
            "hostname": "dc-01.company.com",
        },
    )

    nodes = {
        external_attacker.id: external_attacker,
        internal_web.id: internal_web,
        internal_dc.id: internal_dc,
    }

    edges = [
        GraphEdge(
            id="traffic_http_users",
            source=external_attacker.id,
            target="https://web.company.com:443/api/users",
            edge_type="http",
            weight=1.0,
            metadata={
                "protocol": "https",
                "port": "443",
                "source_type": "traffic_analysis",
            },
        ),
        GraphEdge(
            id="traffic_ftp_internal",
            source=internal_web.id,
            target=internal_dc.id,
            edge_type="ftp",
            weight=1.0,
            metadata={
                "protocol": "ftp",
                "port": "21",
                "source_type": "traffic_analysis",
            },
        ),
    ]

    return nodes, edges


@pytest.fixture(scope="session")
def bh_nodes() -> Dict[str, GraphNode]:
    nodes, _ = _build_bloodhound_graph()
    return nodes


@pytest.fixture(scope="session")
def bh_edges() -> List[GraphEdge]:
    _, edges = _build_bloodhound_graph()
    return edges


@pytest.fixture(scope="session")
def burp_nodes() -> Dict[str, GraphNode]:
    nodes, _ = _build_burp_graph()
    return nodes


@pytest.fixture(scope="session")
def burp_edges() -> List[GraphEdge]:
    _, edges = _build_burp_graph()
    return edges


@pytest.fixture(scope="session")
def traffic_nodes() -> Dict[str, GraphNode]:
    nodes, _ = _build_traffic_graph()
    return nodes


@pytest.fixture(scope="session")
def traffic_edges() -> List[GraphEdge]:
    _, edges = _build_traffic_graph()
    return edges


@pytest.fixture(scope="session")
def attack_paths(
    bh_nodes: Dict[str, GraphNode],
    burp_nodes: Dict[str, GraphNode],
    traffic_nodes: Dict[str, GraphNode],
) -> List[MultiSourceAttackPath]:
    path = MultiSourceAttackPath(
        path_id="integration_path_1",
        nodes=[
            traffic_nodes["203.0.113.10"],
            burp_nodes["https://web.company.com:443/api/users"],
            bh_nodes["admin@company.com"],
        ],
        edges=[
            GraphEdge(
                id="integration_credential_capture",
                source="203.0.113.10",
                target="https://web.company.com:443/api/users",
                edge_type="authenticated_access",
                weight=0.5,
                metadata={"credential_available": False},
            ),
            GraphEdge(
                id="integration_idor",
                source="https://web.company.com:443/api/users",
                target="admin@company.com",
                edge_type="idor",
                weight=0.9,
                metadata={"credential_available": True},
            ),
        ],
        total_weight=1.4,
        severity=SeverityLevel.CRITICAL,
        layers=["network", "web", "domain"],
        actions=[
            "[NETWORK] Establish lateral movement through compromised hosts",
            "[DOMAIN] Escalate privileges using harvested credentials",
        ],
    )

    return [path]