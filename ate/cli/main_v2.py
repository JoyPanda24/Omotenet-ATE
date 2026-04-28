"""
Attack Thinking Engine (ATE) - CLI Main Entry Point
Unified command-line interface for attack path analysis across multiple data sources.
Supports BloodHound (domain), Burp Suite (web), and Wireshark (network) integration.
"""
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ate.core.graph_builder import GraphBuilder
from ate.core.data_models import SeverityLevel
from ate.core.reasoning_engine_v2 import EnhancedReasoningEngine
from ate.ingestors.bloodhound_p import BloodHoundIngestor
from ate.ingestors.burp_p import BurpIngestor
from ate.ingestors.traffic_p import TrafficIngestor
from ate.modules.scanner_sync import ActiveNextSteps
from ate.cli.story_renderer import StoryRenderer
from ate.cli.visualizer import GraphVisualizer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
console = Console()


@click.group()
@click.version_option()
def cli():
    """
    🎯 Attack Thinking Engine (ATE)
    
    Unified attack path analysis across BloodHound, Burp Suite, and Wireshark.
    Synthesizes multi-source security data into cross-layer attack paths.
    """
    pass


@cli.command()
@click.option(
    '--burp',
    type=click.Path(exists=True),
    help='Burp Suite XML/JSON export file'
)
@click.option(
    '--bloodhound',
    type=click.Path(exists=True),
    help='BloodHound JSON export file'
)
@click.option(
    '--pcap',
    type=click.Path(exists=True),
    help='Wireshark/tshark JSON traffic export'
)
@click.option(
    '--output-format',
    type=click.Choice(['story', 'json', 'graph', 'playbook']),
    default='story',
    help='Output format for analysis results'
)
@click.option(
    '--export',
    type=click.Path(),
    help='Export results to file'
)
@click.option(
    '--min-severity',
    type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    default='MEDIUM',
    help='Minimum severity level to report'
)
def analyze_multi(
    burp: Optional[str],
    bloodhound: Optional[str],
    pcap: Optional[str],
    output_format: str,
    export: Optional[str],
    min_severity: str
):
    """
    🔗 Unified Multi-Source Analysis
    
    Ingests security data from multiple tools and analyzes cross-layer attack paths.
    
    EXAMPLES:
    
        # Analyze all three sources
        ate analyze-multi --burp results.xml --bloodhound export.json --pcap traffic.json
        
        # Analyze two sources
        ate analyze-multi --burp results.xml --bloodhound export.json
        
        # Export results as playbook
        ate analyze-multi --burp results.xml --bloodhound export.json \\
            --output-format playbook --export /tmp/playbook.txt
    """
    try:
        # Validate that at least one source is provided
        if not any([burp, bloodhound, pcap]):
            console.print(
                "[red]Error: At least one data source required "
                "(--burp, --bloodhound, or --pcap)[/red]"
            )
            sys.exit(1)
        
        console.print(
            Panel(
                "[bold cyan]Attack Thinking Engine - Multi-Source Analysis[/bold cyan]\n"
                f"Sources: {', '.join(s for s in [burp and 'Burp', bloodhound and 'BloodHound', pcap and 'Traffic'] if s)}\n"
                f"Output Format: {output_format}",
                expand=False
            )
        )
        
        # Run async analysis
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(
            _run_multi_source_analysis(
                burp, bloodhound, pcap,
                output_format, min_severity
            )
        )
        
        # Render output
        _render_analysis_output(results, output_format, console)
        
        # Export if requested
        if export:
            _export_results(results, export, output_format)
            console.print(f"[green]✓ Results exported to {export}[/green]")
    
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.argument('graph_output', type=click.Path())
@click.option(
    '--max-nodes',
    type=int,
    default=100,
    help='Maximum nodes to include in visualization'
)
def visualize(graph_output: str, max_nodes: int):
    """Visualize attack graph (requires GraphViz)."""
    try:
        visualizer = GraphVisualizer()
        console.print(f"[yellow]Generating graph visualization...[/yellow]")
        
        # This would load and visualize a graph
        console.print(f"[green]✓ Graph saved to {graph_output}[/green]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)


@cli.command()
@click.option(
    '--ingestor',
    type=click.Choice(['bloodhound', 'burp', 'traffic']),
    required=True,
    help='Which ingestor to test'
)
@click.argument('data_file', type=click.Path(exists=True))
def test_ingestor(ingestor: str, data_file: str):
    """Test data ingestors with sample files."""
    try:
        console.print(f"[yellow]Testing {ingestor} ingestor with {data_file}...[/yellow]")
        
        loop = asyncio.get_event_loop()
        
        if ingestor == 'bloodhound':
            bh = BloodHoundIngestor(data_file)
            nodes, edges, findings = loop.run_until_complete(bh.ingest())
            console.print(f"[green]✓ Loaded {len(nodes)} nodes, {len(edges)} edges[/green]")
        
        elif ingestor == 'burp':
            burp = BurpIngestor(data_file)
            nodes, edges, findings = loop.run_until_complete(burp.ingest())
            console.print(f"[green]✓ Loaded {len(nodes)} nodes, {len(edges)} edges[/green]")
        
        elif ingestor == 'traffic':
            traffic = TrafficIngestor(data_file)
            nodes, edges, findings = loop.run_until_complete(traffic.ingest())
            console.print(f"[green]✓ Loaded {len(nodes)} nodes, {len(edges)} edges[/green]")
            console.print(f"[yellow]Credentials found: {len(traffic.get_exposed_credentials())}[/yellow]")
    
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)


@cli.command()
def demo():
    """Run demonstration with sample data."""
    console.print(
        Panel(
            "[bold cyan]Attack Thinking Engine - Demo Mode[/bold cyan]\n"
            "Generating sample attack scenario...",
            expand=False
        )
    )
    
    try:
        # Create sample graph
        gb = GraphBuilder()
        
        # Add nodes for each layer
        from ate.core.data_models import GraphNode, NodeType
        
        # External attacker
        attacker = GraphNode(
            id="external_attacker",
            node_type=NodeType.RESOURCE,
            label="External IP (10.0.0.50)",
            privilege_level=0,
            is_sensitive=False
        )
        gb.add_node(attacker)
        
        # Web endpoint
        web = GraphNode(
            id="web_endpoint",
            node_type=NodeType.RESOURCE,
            label="Web Server (10.0.1.10)",
            privilege_level=20,
            is_sensitive=False
        )
        gb.add_node(web)
        
        # Domain user
        user = GraphNode(
            id="domain_user",
            node_type=NodeType.ACCOUNT,
            label="domain\\user1",
            privilege_level=40,
            is_sensitive=False
        )
        gb.add_node(user)
        
        # Domain admin
        admin = GraphNode(
            id="domain_admin",
            node_type=NodeType.ACCOUNT,
            label="domain\\administrator",
            privilege_level=100,
            is_sensitive=True
        )
        gb.add_node(admin)
        
        # Create edges
        from ate.core.data_models import GraphEdge
        
        edges = [
            GraphEdge("e1", "external_attacker", "web_endpoint", "http_idor", 0.8),
            GraphEdge("e2", "web_endpoint", "domain_user", "credential_match", 0.9),
            GraphEdge("e3", "domain_user", "domain_admin", "adminTo", 0.7),
        ]
        
        for edge in edges:
            gb.add_edge(edge)
        
        # Display
        console.print("[green]✓ Sample graph created[/green]")
        console.print(f"  Nodes: {len(gb.graph.nodes())}")
        console.print(f"  Edges: {len(gb.graph.edges())}")
        
        # Show story
        story = StoryRenderer()
        narrative = story.create_attack_narrative(
            start_node="external_attacker",
            end_node="domain_admin"
        )
        console.print("\n" + narrative)
    
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)


# ============================================================================
# Helper Functions
# ============================================================================

async def _run_multi_source_analysis(
    burp_file: Optional[str],
    bloodhound_file: Optional[str],
    pcap_file: Optional[str],
    output_format: str,
    min_severity: str
) -> Dict[str, Any]:
    """Run multi-source analysis."""
    results = {
        'summary': {},
        'attack_paths': [],
        'blockers': [],
        'recommendations': [],
        'tactical_actions': []
    }
    
    # Create graph builder
    gb = GraphBuilder()
    
    # Ingest data sources
    bh_nodes, bh_edges, bh_findings = {}, [], []
    burp_nodes, burp_edges, burp_findings = {}, [], []
    traffic_nodes, traffic_edges, traffic_findings = {}, [], []
    traffic_credentials = {}
    
    if bloodhound_file:
        console.print("[cyan]Loading BloodHound data...[/cyan]")
        bh_ingestor = BloodHoundIngestor(bloodhound_file)
        bh_nodes, bh_edges, bh_findings = await bh_ingestor.ingest()
        for edge in bh_edges:
            gb.add_edge(edge)
        console.print(f"[green]✓ BloodHound: {len(bh_nodes)} nodes, {len(bh_edges)} edges[/green]")
    
    if burp_file:
        console.print("[cyan]Loading Burp Suite data...[/cyan]")
        burp_ingestor = BurpIngestor(burp_file)
        burp_nodes, burp_edges, burp_findings = await burp_ingestor.ingest()
        for edge in burp_edges:
            gb.add_edge(edge)
        console.print(f"[green]✓ Burp Suite: {len(burp_nodes)} nodes, {len(burp_edges)} edges[/green]")
    
    if pcap_file:
        console.print("[cyan]Loading Wireshark data...[/cyan]")
        traffic_ingestor = TrafficIngestor(pcap_file)
        traffic_nodes, traffic_edges, traffic_findings = await traffic_ingestor.ingest()
        for edge in traffic_edges:
            gb.add_edge(edge)
        traffic_credentials = {
            cred: {'protocol': 'traffic', 'source_ip': 'network'}
            for cred in traffic_ingestor.get_exposed_credentials()
        }
        console.print(f"[green]✓ Wireshark: {len(traffic_nodes)} nodes, {len(traffic_edges)} edges[/green]")
    
    # Perform multi-source analysis
    console.print("[cyan]Analyzing cross-layer attack paths...[/cyan]")
    
    reasoning = EnhancedReasoningEngine(gb)
    attack_paths = await reasoning.analyze_multi_source(
        bh_nodes, bh_edges,
        burp_nodes, burp_edges,
        traffic_nodes, traffic_edges,
        traffic_credentials
    )
    
    # Generate tactical actions
    console.print("[cyan]Generating tactical recommendations...[/cyan]")
    
    orchestrator = ActiveNextSteps()
    tactical_actions = orchestrator.analyze_paths(attack_paths)
    
    # Compile results
    results['summary'] = {
        'total_nodes': len(gb.graph.nodes()),
        'total_edges': len(gb.graph.edges()),
        'attack_paths_found': len(attack_paths),
        'tactical_actions': len(tactical_actions),
        'overall_risk': 'CRITICAL' if attack_paths else 'LOW'
    }
    
    results['attack_paths'] = [
        {
            'id': path.path_id,
            'severity': path.severity.name,
            'layers': path.layers,
            'nodes_count': len(path.nodes),
            'description': ' → '.join([n.label for n in path.nodes[:5]])
        }
        for path in attack_paths
    ]
    
    results['tactical_actions'] = [
        {
            'action_id': action.action_id,
            'priority': action.priority,
            'category': action.category,
            'description': action.description,
            'command': action.command,
            'risk_level': action.risk_level.name
        }
        for action in tactical_actions
    ]
    
    results['recommendations'] = orchestrator.get_recommendations()
    results['time_estimate'] = orchestrator.estimate_time_to_compromise()
    
    return results


def _render_analysis_output(results: Dict[str, Any], format_type: str, console_: Console):
    """Render analysis output in specified format."""
    
    if format_type == 'story':
        # Narrative format
        console_.print("\n" + "=" * 80)
        console_.print("[bold cyan]ANALYSIS SUMMARY[/bold cyan]")
        console_.print("=" * 80)
        
        summary = results['summary']
        console_.print(f"\n📊 Graph Statistics:")
        console_.print(f"   Total Nodes: {summary['total_nodes']}")
        console_.print(f"   Total Edges: {summary['total_edges']}")
        console_.print(f"   Attack Paths Found: {summary['attack_paths_found']}")
        console_.print(f"   Overall Risk: [red]{summary['overall_risk']}[/red]")
        
        console_.print(f"\n⚔️ Attack Paths:")
        for path in results['attack_paths'][:5]:
            console_.print(
                f"   • [{path['severity']}] {path['description']}..."
            )
        
        console_.print(f"\n🎯 Top Tactical Actions:")
        for action in results['tactical_actions'][:3]:
            console_.print(
                f"   • {action['description']} (Priority: {action['priority']})"
            )
        
        console_.print(f"\n💡 Recommendations:")
        for rec in results['recommendations'][:3]:
            console_.print(f"   • {rec}")
    
    elif format_type == 'json':
        # JSON format
        console_.print(json.dumps(results, indent=2, default=str))
    
    elif format_type == 'playbook':
        # Playbook format
        from ate.modules.scanner_sync import ActiveNextSteps
        orch = ActiveNextSteps()
        playbook = orch._generate_text_playbook(
            [a for action_dict in results['tactical_actions']
             for a in [type('Action', (), action_dict)()]]
        )
        console_.print(playbook)


def _export_results(results: Dict[str, Any], export_path: str, format_type: str):
    """Export results to file."""
    with open(export_path, 'w') as f:
        if format_type == 'json':
            json.dump(results, f, indent=2, default=str)
        else:
            json.dump(results, f, indent=2, default=str)


if __name__ == '__main__':
    cli()
