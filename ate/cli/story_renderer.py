"""
Story Renderer - Narrative-style output for attack paths.
Converts technical attack paths into human-readable stories.
"""
import logging
from typing import List
from io import StringIO
from ..core.data_models import AttackPath, AnalysisResult

logger = logging.getLogger(__name__)


class StoryRenderer:
    """Renders attack paths as narrative stories."""

    # Templates for different scenarios
    STORY_TEMPLATES = {
        'idor': "An attacker can access user {target_user}'s data by directly modifying the ID parameter.",
        'privilege_escalation': "A low-privilege user can escalate to {target_role} by exploiting {vulnerability}.",
        'data_exposure': "Sensitive data ({data_type}) is exposed through {endpoint}.",
        'chain': "By chaining {count} vulnerabilities, an attacker can compromise {target_system}.",
    }

    @staticmethod
    def render_attack_path(attack_path: AttackPath, graph_info: dict = None) -> str:
        """
        Render a single attack path as a narrative story.
        
        Args:
            attack_path: The attack path to render
            graph_info: Additional graph information for context
            
        Returns:
            Narrative string describing the attack
        """
        output = StringIO()
        
        output.write(f"\n{'═' * 70}\n")
        output.write(f"ATTACK PATH #{attack_path.id}\n")
        output.write(f"{'═' * 70}\n\n")
        
        output.write(f"Risk Score: {attack_path.risk_score:.1f}/100\n")
        output.write(f"Attack Depth: {attack_path.depth} steps\n")
        output.write(f"Vulnerabilities Involved: {len(attack_path.findings)}\n\n")
        
        # Narrative story
        output.write("ATTACK NARRATIVE:\n")
        output.write("-" * 70 + "\n\n")
        
        start_node = attack_path.path_nodes[0]
        end_node = attack_path.path_nodes[-1]
        
        story = f"Starting from '{start_node}', an attacker can reach '{end_node}' "
        story += f"through a chain of {len(attack_path.findings)} vulnerabilit{'ies' if len(attack_path.findings) > 1 else 'y'}:\n\n"
        
        output.write(story)
        
        # Step-by-step breakdown
        for i, step in enumerate(attack_path.steps, 1):
            output.write(f"  {i}. {step}\n")
        
        output.write("\n")
        
        # Findings details
        if attack_path.findings:
            output.write("\nVULNERABILITIES IN THIS PATH:\n")
            output.write("-" * 70 + "\n")
            
            for finding in attack_path.findings:
                output.write(f"\n  [{finding.severity.name}] {finding.finding_type.value.upper()}\n")
                output.write(f"  Description: {finding.description}\n")
                output.write(f"  Confidence: {finding.confidence * 100:.0f}%\n")
        
        output.write(f"\n{'═' * 70}\n\n")
        
        return output.getvalue()

    @staticmethod
    def render_analysis_result(result: AnalysisResult) -> str:
        """
        Render the complete analysis result as a detailed narrative report.
        
        Args:
            result: AnalysisResult object
            
        Returns:
            Full narrative report
        """
        output = StringIO()
        
        # Header
        output.write("\n")
        output.write("╔" + "═" * 68 + "╗\n")
        output.write("║" + " " * 15 + "ATTACK PATH ANALYSIS REPORT" + " " * 25 + "║\n")
        output.write("╚" + "═" * 68 + "╝\n\n")
        
        # Executive Summary
        output.write("EXECUTIVE SUMMARY\n")
        output.write("─" * 70 + "\n\n")
        
        most_dangerous_path = result.most_dangerous_path
        risk_score = f"{most_dangerous_path.risk_score:.1f}/100" if most_dangerous_path else "N/A"

        summary = f"""
    Total Attack Paths Found: {len(result.attack_paths)}
    Critical Findings: {result.critical_findings}
    High-Severity Findings: {result.high_findings}
    Total Findings: {result.total_findings}

    Most Dangerous Path: {most_dangerous_path.id if most_dangerous_path else 'None'}
    Risk Score: {risk_score}
    """
        output.write(summary)
        
        # Detailed narrative for most dangerous path
        if result.most_dangerous_path:
            output.write("\n\nMOST CRITICAL ATTACK PATH NARRATIVE\n")
            output.write("─" * 70 + "\n")
            
            path = result.most_dangerous_path
            output.write(f"\nAn attacker could compromise your system through the following sequence:\n\n")
            
            for i, step in enumerate(path.steps, 1):
                output.write(f"  Step {i}: {step}\n")
            
            output.write(f"\nThis attack path would allow the attacker to access critical resources\n")
            output.write(f"with a success likelihood that depends on their ability to exploit each\n")
            output.write(f"individual vulnerability in sequence.\n")
        
        # Threat landscape
        if result.attack_paths:
            output.write("\n\nTHREAT LANDSCAPE\n")
            output.write("─" * 70 + "\n\n")
            
            high_risk_paths = [p for p in result.attack_paths if p.risk_score >= 70]
            medium_risk_paths = [p for p in result.attack_paths if 40 <= p.risk_score < 70]
            low_risk_paths = [p for p in result.attack_paths if p.risk_score < 40]
            
            output.write(f"🔴 Critical Paths (Risk ≥ 70):  {len(high_risk_paths)}\n")
            output.write(f"🟠 Medium Paths (40-70):         {len(medium_risk_paths)}\n")
            output.write(f"🟡 Low-Risk Paths (< 40):       {len(low_risk_paths)}\n\n")
            
            if high_risk_paths:
                output.write("Critical paths require immediate attention:\n")
                for path in high_risk_paths[:3]:  # Top 3
                    output.write(f"  • {path.description} (Risk: {path.risk_score:.1f})\n")
        
        output.write("\n" + "═" * 70 + "\n\n")
        
        return output.getvalue()

    @staticmethod
    def render_idor_story(attack_path: AttackPath) -> str:
        """Render IDOR-specific attack story."""
        output = StringIO()
        
        output.write("\nIDOR ATTACK SCENARIO\n")
        output.write("─" * 70 + "\n\n")
        
        if attack_path.findings:
            finding = attack_path.findings[0]
            
            story = f"""
An attacker with low privileges discovers that user IDs can be enumerated
sequentially. By modifying the ID parameter in requests to {attack_path.path_nodes[-1]},
the attacker can access unauthorized user data.

Attack Vector: {finding.metadata.get('url', 'API endpoint')}
Target Data: User profiles, personal information, sensitive records
Impact: Complete unauthorized access to all user data

Recommended Remediation:
  1. Implement proper authorization checks for all resources
  2. Use non-sequential, unpredictable identifiers
  3. Validate user access at every step
  4. Log and monitor suspicious ID enumeration patterns
"""
            output.write(story)
        
        output.write("\n")
        return output.getvalue()

    @staticmethod
    def render_privilege_escalation_story(attack_path: AttackPath) -> str:
        """Render privilege escalation attack story."""
        output = StringIO()
        
        output.write("\nPRIVILEGE ESCALATION SCENARIO\n")
        output.write("─" * 70 + "\n\n")
        
        if len(attack_path.path_nodes) >= 2:
            start = attack_path.path_nodes[0]
            end = attack_path.path_nodes[-1]
            
            story = f"""
A low-privilege user ({start}) can escalate privileges to administrative
level ({end}) by chaining {len(attack_path.findings)} vulnerabilities.

Attack Progression:
"""
            output.write(story)
            
            for i, step in enumerate(attack_path.steps, 1):
                output.write(f"  {i}. {step}\n")
            
            story_end = f"""
Once at administrative level, the attacker gains complete control over:
  • User management and access controls
  • System configuration and settings
  • Data repositories and sensitive information
  • Audit logs and detection mechanisms

This represents complete system compromise.

Recommended Remediation:
  1. Apply principle of least privilege
  2. Implement role-based access control
  3. Enable comprehensive audit logging
  4. Use multi-factor authentication for privileged accounts
"""
            output.write(story_end)
        
        output.write("\n")
        return output.getvalue()
