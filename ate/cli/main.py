"""
ATE CLI - Main command-line interface for Attack Thinking Engine.
"""
import logging
import json
import click
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

from ..core import (
    GraphBuilder, ReasoningEngine, NodeType, VulnerabilityType,
    SeverityLevel, AtomicFinding, AnalysisResult
)
from ..modules import IDORDetector, AuthFlawsDetector, SensitiveDataExposureDetector
from .visualizer import AttackPathVisualizer
from .story_renderer import StoryRenderer

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rich console for beautiful output
console = Console()


@click.group()
@click.version_option()
def cli():
    """
    Attack Thinking Engine (ATE) - Automated Attack Path Analysis
    
    Move beyond vulnerability scanning toward comprehensive attack chain analysis.
    """
    pass


@cli.command()
@click.option('--name', default='MyApp', help='Application name')
@click.option('--output', '-o', type=click.Path(), help='Output file for graph')
def create_graph(name: str, output: Optional[str]):
    """Create a new attack graph."""
    console.print(f"\n[bold cyan]Creating new attack graph: {name}[/bold cyan]\n")
    
    graph = GraphBuilder(name)
    
    # Save if output specified
    if output:
        with open(output, 'w') as f:
            json.dump(graph.export_to_dict(), f, indent=2)
        console.print(f"[green]✓ Graph saved to {output}[/green]\n")
    
    console.print(f"[green]✓ Graph created successfully[/green]\n")


@cli.command()
@click.option('--graph-file', '-g', required=True, type=click.Path(exists=True),
              help='Graph JSON file')
@click.option('--findings-file', '-f', required=True, type=click.Path(exists=True),
              help='Findings JSON file')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
def analyze(graph_file: str, findings_file: str, output: Optional[str]):
    """Analyze attack paths from a graph and findings."""
    console.print("\n[bold cyan]Starting Attack Path Analysis[/bold cyan]\n")
    
    try:
        # Load graph configuration
        with open(graph_file) as f:
            graph_config = json.load(f)
        
        # Load findings
        with open(findings_file) as f:
            findings_data = json.load(f)
        
        # Reconstruct graph
        graph = GraphBuilder(graph_config.get('name', 'Analysis'))
        
        # Add nodes
        for node_data in graph_config.get('nodes', []):
            graph.add_node(
                node_id=node_data['id'],
                node_type=NodeType[node_data['type'].upper()],
                label=node_data['label'],
                privilege_level=node_data.get('privilege_level', 0),
                is_sensitive=node_data.get('is_sensitive', False),
                metadata=node_data.get('metadata', {})
            )
        
        # Add findings and edges
        for finding_data in findings_data:
            finding = AtomicFinding(
                id=finding_data['id'],
                finding_type=VulnerabilityType[finding_data['type'].upper()],
                severity=SeverityLevel[finding_data['severity'].upper()],
                source_node=finding_data['source_node'],
                target_node=finding_data['target_node'],
                description=finding_data['description'],
                confidence=finding_data.get('confidence', 1.0),
                metadata=finding_data.get('metadata', {})
            )
            graph.add_finding_and_create_edge(finding)
        
        # Run analysis
        engine = ReasoningEngine(graph)
        result = engine.analyze()
        
        # Display results
        console.print(StoryRenderer.render_analysis_result(result))
        
        # Show graph statistics
        stats = graph.get_graph_statistics()
        table = Table(title="Graph Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in stats.items():
            table.add_row(key, str(value))
        
        console.print(table)
        console.print()
        
        # Display attack paths
        if result.attack_paths:
            console.print(f"\n[bold]Found {len(result.attack_paths)} Attack Paths[/bold]\n")
            
            for path in result.attack_paths[:5]:  # Show top 5
                console.print(StoryRenderer.render_attack_path(path))
        
        # Save results if requested
        if output:
            results_dict = {
                'total_paths': len(result.attack_paths),
                'critical_findings': result.critical_findings,
                'high_findings': result.high_findings,
                'total_findings': result.total_findings,
                'paths': [
                    {
                        'id': p.id,
                        'risk_score': p.risk_score,
                        'depth': p.depth,
                        'nodes': p.path_nodes,
                        'description': p.description
                    }
                    for p in result.attack_paths
                ]
            }
            
            with open(output, 'w') as f:
                json.dump(results_dict, f, indent=2)
            
            console.print(f"\n[green]✓ Results saved to {output}[/green]\n")
    
    except Exception as e:
        console.print(f"\n[red]✗ Analysis failed: {str(e)}[/red]\n")
        logger.exception("Analysis error")


@cli.command()
@click.option('--urls-file', '-u', required=True, type=click.Path(exists=True),
              help='File with URLs to analyze')
@click.option('--output', '-o', type=click.Path(), help='Output findings file')
def scan_idor(urls_file: str, output: Optional[str]):
    """Scan for IDOR vulnerabilities."""
    console.print("\n[bold cyan]IDOR Vulnerability Scan[/bold cyan]\n")
    
    try:
        # Read URLs
        with open(urls_file) as f:
            urls = [line.strip() for line in f if line.strip()]
        
        # Scan for IDOR
        console.print(f"Scanning {len(urls)} URLs for IDOR...\n")
        findings = IDORDetector.bulk_analyze(urls)
        
        # Display results
        if findings:
            table = Table(title="IDOR Findings")
            table.add_column("URL", style="cyan")
            table.add_column("Severity", style="red")
            table.add_column("Confidence", style="yellow")
            
            for finding in findings:
                table.add_row(
                    finding.metadata.get('url', 'N/A'),
                    finding.severity.name,
                    f"{finding.confidence * 100:.0f}%"
                )
            
            console.print(table)
            console.print()
            
            # Save if requested
            if output:
                findings_dict = [
                    {
                        'id': f.id,
                        'type': f.finding_type.value,
                        'severity': f.severity.name,
                        'description': f.description,
                        'confidence': f.confidence,
                        'metadata': f.metadata
                    }
                    for f in findings
                ]
                
                with open(output, 'w') as f:
                    json.dump(findings_dict, f, indent=2)
                
                console.print(f"[green]✓ Findings saved to {output}[/green]\n")
        else:
            console.print("[green]No IDOR vulnerabilities detected[/green]\n")
    
    except Exception as e:
        console.print(f"\n[red]✗ Scan failed: {str(e)}[/red]\n")
        logger.exception("Scan error")


@cli.command()
@click.option('--graph-file', '-g', required=True, type=click.Path(exists=True),
              help='Graph JSON file')
@click.option('--source', '-s', required=True, help='Source node ID')
@click.option('--target', '-t', required=True, help='Target node ID')
@click.option('--max-length', '-m', default=5, help='Maximum path length')
def find_paths(graph_file: str, source: str, target: str, max_length: int):
    """Find all paths between two nodes."""
    console.print(f"\n[bold cyan]Finding paths from {source} to {target}[/bold cyan]\n")
    
    try:
        # Load and reconstruct graph
        with open(graph_file) as f:
            graph_config = json.load(f)
        
        graph = GraphBuilder(graph_config.get('name', 'Analysis'))
        
        # Add nodes
        for node_data in graph_config.get('nodes', []):
            graph.add_node(
                node_id=node_data['id'],
                node_type=NodeType[node_data['type'].upper()],
                label=node_data['label'],
                privilege_level=node_data.get('privilege_level', 0)
            )
        
        # Add edges
        for edge_data in graph_config.get('edges', []):
            if graph.graph.has_node(edge_data['source']) and graph.graph.has_node(edge_data['target']):
                graph.add_edge(
                    source_id=edge_data['source'],
                    target_id=edge_data['target'],
                    edge_type=edge_data['type'],
                    weight=edge_data.get('weight', 1.0)
                )
        
        # Find paths
        paths = graph.find_paths(source, target, max_length)
        
        if paths:
            console.print(f"[green]Found {len(paths)} path(s)[/green]\n")
            
            for i, path in enumerate(paths, 1):
                console.print(f"Path {i}: {' → '.join(path)}")
                risk_score = graph.calculate_path_risk_score(path)
                console.print(f"  Risk Score: {risk_score:.1f}/100\n")
        else:
            console.print("[yellow]No paths found[/yellow]\n")
    
    except Exception as e:
        console.print(f"\n[red]✗ Error: {str(e)}[/red]\n")
        logger.exception("Path finding error")


@cli.command()
@click.option('--example', type=click.Choice(['basic', 'complex', 'idor']), default='basic',
              help='Example type')
def demo(example: str):
    """Run demonstration with sample data."""
    console.print(f"\n[bold cyan]ATE Demo - {example.upper()} Example[/bold cyan]\n")
    
    # Create sample graph
    graph = GraphBuilder(f"Demo - {example}")
    
    if example == 'basic':
        # Simple IDOR chain
        graph.add_node('user_1', NodeType.USER, 'Attacker', privilege_level=10)
        graph.add_node('endpoint_users', NodeType.ENDPOINT, '/api/users/{id}', privilege_level=30)
        graph.add_node('admin_user', NodeType.USER, 'Admin User', privilege_level=90, is_sensitive=True)
        
        finding = AtomicFinding(
            id='demo_idor_1',
            finding_type=VulnerabilityType.IDOR,
            severity=SeverityLevel.HIGH,
            source_node='user_1',
            target_node='admin_user',
            description='User enumeration via sequential IDs',
            confidence=0.9
        )
        
        graph.add_finding_and_create_edge(finding)
        
        console.print(StoryRenderer.render_idor_story(
            AttackPath(
                id='demo_1',
                path_nodes=['user_1', 'endpoint_users', 'admin_user'],
                edges=['idor_1'],
                findings=[finding],
                risk_score=75.0,
                description='IDOR leading to admin access',
                steps=['Enumerate user IDs', 'Access admin endpoint', 'Retrieve admin data']
            )
        ))
    
    elif example == 'complex':
        # Multi-step privilege escalation
        graph.add_node('guest', NodeType.USER, 'Guest User', privilege_level=5)
        graph.add_node('endpoint_data', NodeType.ENDPOINT, '/api/data', privilege_level=20)
        graph.add_node('member_role', NodeType.ROLE, 'Member Role', privilege_level=50)
        graph.add_node('admin_role', NodeType.ROLE, 'Admin Role', privilege_level=100)
        graph.add_node('db_admin', NodeType.RESOURCE, 'Database', privilege_level=100, is_sensitive=True)
        
        # Create findings chain
        finding1 = AtomicFinding(
            id='demo_auth_1', finding_type=VulnerabilityType.AUTHENTICATION_FLAW,
            severity=SeverityLevel.HIGH, source_node='guest', target_node='member_role',
            description='Auth bypass to member role', confidence=0.85
        )
        
        finding2 = AtomicFinding(
            id='demo_priv_1', finding_type=VulnerabilityType.PRIVILEGE_ESCALATION,
            severity=SeverityLevel.CRITICAL, source_node='member_role', target_node='admin_role',
            description='Privilege escalation to admin', confidence=0.9
        )
        
        graph.add_finding_and_create_edge(finding1)
        graph.add_finding_and_create_edge(finding2)
        
        # Show analysis
        engine = ReasoningEngine(graph)
        result = engine.analyze()
        
        console.print(StoryRenderer.render_analysis_result(result))
    
    elif example == 'idor':
        graph.add_node('attacker', NodeType.USER, 'Attacker', privilege_level=15)
        graph.add_node('api_endpoint', NodeType.ENDPOINT, '/api/profile/{id}', privilege_level=40)
        graph.add_node('sensitive_data', NodeType.DATA_OBJECT, 'User PII Database', privilege_level=95, is_sensitive=True)
        
        finding = AtomicFinding(
            id='demo_idor_full', finding_type=VulnerabilityType.IDOR,
            severity=SeverityLevel.CRITICAL, source_node='attacker', target_node='sensitive_data',
            description='Direct object reference leads to PII exposure', confidence=0.95,
            metadata={'url': '/api/profile/123', 'object_id': '123'}
        )
        
        graph.add_finding_and_create_edge(finding)
        engine = ReasoningEngine(graph)
        result = engine.analyze()
        console.print(StoryRenderer.render_analysis_result(result))
    
    console.print("\n[green]✓ Demo complete[/green]\n")


if __name__ == '__main__':
    cli()
