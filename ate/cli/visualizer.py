"""
Visualizer - ASCII/Terminal-based attack path visualization.
"""
import logging
from typing import List, Dict, Optional
from io import StringIO
import textwrap

logger = logging.getLogger(__name__)


class AttackPathVisualizer:
    """Creates terminal/ASCII visualizations of attack paths."""

    @staticmethod
    def visualize_path(path_nodes: List[str], steps: List[str] = None) -> str:
        """
        Create ASCII visualization of a linear attack path.
        
        Args:
            path_nodes: List of node IDs in order
            steps: List of descriptive steps
            
        Returns:
            ASCII-formatted string
        """
        if not path_nodes:
            return ""
        
        output = StringIO()
        output.write("\n")
        
        for i, node_id in enumerate(path_nodes):
            # Node box
            node_box = f"[{node_id}]"
            output.write(f"  ┌─ {node_box}\n")
            
            # Step description
            if steps and i < len(steps):
                step_text = steps[i]
                wrapped = textwrap.fill(step_text, width=50, subsequent_indent="  ")
                output.write(f"  │  {wrapped}\n")
            
            # Arrow to next node
            if i < len(path_nodes) - 1:
                output.write("  │\n")
                output.write("  ↓\n")
                output.write("  │\n")
        
        output.write("\n")
        return output.getvalue()

    @staticmethod
    def visualize_tree(
        root_node: str,
        graph_dict: Dict,
        max_depth: int = 4
    ) -> str:
        """
        Create ASCII tree visualization of attack paths from a root node.
        
        Args:
            root_node: Root node ID
            graph_dict: Graph representation as dictionary
            max_depth: Maximum tree depth
            
        Returns:
            ASCII-formatted tree
        """
        output = StringIO()
        output.write(f"\nAttack Tree from: {root_node}\n")
        output.write("=" * 60 + "\n\n")
        
        def build_tree(node: str, prefix: str = "", depth: int = 0):
            if depth >= max_depth:
                return
            
            # Find edges from this node
            edges = [e for e in graph_dict.get('edges', []) if e['source'] == node]
            
            for i, edge in enumerate(edges):
                is_last = i == len(edges) - 1
                current_prefix = "└── " if is_last else "├── "
                next_prefix = "    " if is_last else "│   "
                
                target = edge['target']
                output.write(f"{prefix}{current_prefix}[{target}] ({edge['type']})\n")
                
                # Recursive call
                build_tree(target, prefix + next_prefix, depth + 1)
        
        build_tree(root_node)
        output.write("\n")
        return output.getvalue()

    @staticmethod
    def visualize_graph_summary(graph_stats: Dict) -> str:
        """
        Create a summary visualization of graph statistics.
        
        Args:
            graph_stats: Dictionary with graph statistics
            
        Returns:
            Formatted statistics visualization
        """
        output = StringIO()
        output.write("\n")
        output.write("╔" + "═" * 58 + "╗\n")
        output.write("║" + " " * 15 + "GRAPH STATISTICS" + " " * 28 + "║\n")
        output.write("╠" + "═" * 58 + "╣\n")
        
        stats = [
            ("Nodes", graph_stats.get('num_nodes', 0)),
            ("Edges", graph_stats.get('num_edges', 0)),
            ("Findings", graph_stats.get('num_findings', 0)),
            ("Density", f"{graph_stats.get('density', 0):.3f}"),
            ("Components", graph_stats.get('num_components', 1)),
        ]
        
        for label, value in stats:
            row = f"║ {label:<20} {str(value):<35} ║"
            output.write(row + "\n")
        
        output.write("╚" + "═" * 58 + "╝\n")
        output.write("\n")
        
        return output.getvalue()

    @staticmethod
    def visualize_findings(findings: List[Dict]) -> str:
        """
        Create visualization of security findings.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Formatted findings visualization
        """
        output = StringIO()
        output.write("\n")
        output.write("╔" + "═" * 58 + "╗\n")
        output.write("║" + " " * 16 + "SECURITY FINDINGS" + " " * 26 + "║\n")
        output.write("╠" + "═" * 58 + "╣\n")
        
        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        for severity in severity_order:
            if severity in by_severity:
                count = len(by_severity[severity])
                icon = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢',
                    'INFO': '🔵'
                }.get(severity, '  ')
                
                row = f"║ {icon} {severity:<10} {count:>3} findings" + " " * (35 - len(severity)) + "║"
                output.write(row + "\n")
        
        output.write("╚" + "═" * 58 + "╝\n")
        output.write("\n")
        
        return output.getvalue()

    @staticmethod
    def visualize_risk_gauge(risk_score: float) -> str:
        """
        Create a visual risk gauge.
        
        Args:
            risk_score: Risk score (0-100)
            
        Returns:
            ASCII risk gauge visualization
        """
        output = StringIO()
        
        # Determine color/indicator
        if risk_score >= 80:
            level = "CRITICAL"
            bar_char = "█"
        elif risk_score >= 60:
            level = "HIGH"
            bar_char = "▓"
        elif risk_score >= 40:
            level = "MEDIUM"
            bar_char = "▒"
        else:
            level = "LOW"
            bar_char = "░"
        
        # Create bar
        filled = int(risk_score / 5)
        bar = bar_char * filled + " " * (20 - filled)
        
        output.write(f"\n  Risk Score: [{bar}] {risk_score:.1f}/100\n")
        output.write(f"  Level: {level}\n\n")
        
        return output.getvalue()


class GraphVisualizer(AttackPathVisualizer):
    """Backward-compatible alias for older CLI entry points."""
