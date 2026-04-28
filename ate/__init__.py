"""
Attack Thinking Engine (ATE) - Automated Attack Path Analysis
Moving beyond vulnerability scanning toward comprehensive attack chain analysis.
"""

__version__ = "0.1.0"
__author__ = "Security Research Team"
__description__ = "Graph-based automated attack path analysis engine"

from .core import (
    GraphBuilder, ReasoningEngine, NodeType, VulnerabilityType,
    SeverityLevel, AtomicFinding, AttackPath, AnalysisResult
)
from .modules import IDORDetector, AuthFlawsDetector, SensitiveDataExposureDetector
from .cli import cli, AttackPathVisualizer, StoryRenderer

__all__ = [
    'GraphBuilder',
    'ReasoningEngine',
    'NodeType',
    'VulnerabilityType',
    'SeverityLevel',
    'AtomicFinding',
    'AttackPath',
    'AnalysisResult',
    'IDORDetector',
    'AuthFlawsDetector',
    'SensitiveDataExposureDetector',
    'cli',
    'AttackPathVisualizer',
    'StoryRenderer'
]
