# Attack Thinking Engine - Architecture Document

## System Overview

Attack Thinking Engine (ATE) is a modular, graph-based security analysis platform that transforms individual security findings into comprehensive attack path analysis through automated reasoning.

### Core Philosophy

```
Traditional Approach:
  Vulnerability Scanner → [IDOR] [Auth Bypass] [XSS] [SSRF]
                           ↓
                    "5 vulnerabilities found"
                    
ATE Approach:
  Security Findings → Graph Construction → Automated Reasoning → Attack Chains
                     ↓ ↓ ↓                                          ↓
                    [Atomic Findings mapped to graph nodes]     "Here's how an attacker
                                                                could exploit all 5 to
                                                                access the database"
```

## Three-Layer Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                          User Interface Layer                          │
├────────────────────────────────────────────────────────────────────────┤
│  CLI Commands (Click) │ Story Renderer │ Visualizer │ JSON/CSV Export │
├────────────────────────────────────────────────────────────────────────┤
│                        Detection Modules Layer                         │
├────────────────────────────────────────────────────────────────────────┤
│  IDOR Detector  │  Auth Flaws  │  Data Exposure  │  Custom Modules   │
├────────────────────────────────────────────────────────────────────────┤
│                          Core Engine Layer                             │
├────────────────────────────────────────────────────────────────────────┤
│  GraphBuilder (NetworkX) │  ReasoningEngine  │  Scoring System        │
├────────────────────────────────────────────────────────────────────────┤
│                           Data Models                                  │
└────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### Layer 1: Core Engine

#### GraphBuilder
**Responsibility**: Construct and manage the application attack surface model

```python
class GraphBuilder:
    - Nodes: Users, Roles, Endpoints, Data Objects, Resources
    - Edges: Permissions, Data Flows, Vulnerabilities
    - Operations: Add/query nodes, paths, centrality analysis
```

**Key Algorithms**:
- NetworkX shortest path finding
- Betweenness centrality for critical node identification
- Density calculation for attack surface complexity

**Data Flow**:
```
User Input (URLs/JSON) → Nodes Created → Findings Added → Edges Created
                                            ↓
                                    Risk Score Calculated
```

#### ReasoningEngine
**Responsibility**: Analyze the graph to identify attack chains

```python
class ReasoningEngine:
    1. Identify attack origins (low-privilege nodes)
    2. Identify high-value targets (sensitive data, admin)
    3. Find all paths between origins and targets
    4. Score and rank paths by risk
    5. Correlate findings into chains
```

**Scoring Algorithm**:
```
Risk_Score(path) = Σ(edge_weights) × distance_penalty × impact_multiplier
                 = (Σ(severity × confidence)) × (1/path_length) × (1 + critical_count × 0.5)
                 Normalized to [0, 100]
```

**Attack Origin Heuristics**:
- Users with `privilege_level ≤ 25`
- Unauthenticated endpoints (`privilege_level = 0`)
- Externally accessible resources

**High-Value Target Heuristics**:
- Nodes with `privilege_level ≥ 75`
- Nodes marked `is_sensitive = True`
- Nodes with high betweenness centrality

### Layer 2: Detection Modules

Each module detects a specific vulnerability category and generates `AtomicFinding` objects.

#### IDORDetector
```
Detection Methods:
  1. URL Pattern Matching: Sequential IDs, predictable parameters
  2. API Response Analysis: Unauthorized data access
  3. Bulk Analysis: Multiple URLs for systematic enumeration

Output: AtomicFinding with IDOR type and confidence score
```

**Pattern Library**:
- Sequential numeric IDs: `/users/1`, `/users/2`, `/users/999`
- Predictable identifiers: UUIDs, guessable hashes
- Lack of authorization checks

#### AuthFlawsDetector
```
Detection Methods:
  1. Missing Authentication: Endpoints without auth
  2. Weak Token Schemes: Basic auth, custom tokens
  3. Session Issues: Fixation, lack of HttpOnly
  4. Brute Force: No rate limiting

Output: AtomicFinding with authentication flaw details
```

#### SensitiveDataExposureDetector
```
Detection Methods:
  1. Response Analysis: Detect PII, credentials, keys
  2. Log Analysis: Secrets in logs
  3. Debug Info: Stack traces, SQL errors
  4. Metadata Analysis: HTTP headers revealing system info

Pattern Library:
  - Email: RFC 5322 pattern
  - Credit Cards: Luhn algorithm
  - SSN: NNN-NN-NNNN format
  - API Keys: >20 character alphanumeric
  - JWT: Valid JWT structure
  - Private Keys: PEM headers
```

### Layer 3: User Interface

#### CLI Architecture
```
Click Framework
    ↓
CLI Commands (create-graph, analyze, scan-idor, etc.)
    ↓
Core Engine Processing
    ↓
Story Renderer & Visualizer
    ↓
Rich Console Output
```

#### Output Formats

**Story Mode (Default)**:
Narrative-driven output explaining attack paths in human terms

**JSON Export**:
Machine-readable format for integration and automation

**ASCII Visualization**:
Terminal-based attack path trees and statistics

## Data Flow Architecture

### End-to-End Analysis Flow

```
┌─────────────────┐
│  Raw Input      │
├─────────────────┤
│ • URLs          │
│ • JSON configs  │
│ • Scan results  │
└────────┬────────┘
         ↓
┌─────────────────────────────────┐
│ Detection Modules               │
├─────────────────────────────────┤
│ IDORDetector.bulk_analyze()     │
│ AuthFlawsDetector.bulk_analyze()│
│ SDEDetector.bulk_analyze()      │
└────────┬────────────────────────┘
         ↓ Generates
┌─────────────────────────────────┐
│ Atomic Findings List            │
├─────────────────────────────────┤
│ [                               │
│   Finding(IDOR, HIGH, ...),    │
│   Finding(AUTH, MEDIUM, ...),   │
│   Finding(DATA_EXP, CRITICAL,...│
│ ]                               │
└────────┬────────────────────────┘
         ↓
┌─────────────────────────────────┐
│ GraphBuilder                    │
├─────────────────────────────────┤
│ • Nodes: User, Endpoint, Admin  │
│ • Edges: Permissions, Findings  │
│ • Result: Directed Graph        │
└────────┬────────────────────────┘
         ↓
┌─────────────────────────────────┐
│ ReasoningEngine                 │
├─────────────────────────────────┤
│ analyze()                       │
│ → AnalysisResult                │
│   • attack_paths[]              │
│   • most_dangerous_path         │
│   • risk_scores                 │
└────────┬────────────────────────┘
         ↓
┌─────────────────────────────────┐
│ Story Renderer                  │
├─────────────────────────────────┤
│ Narrative Attack Description    │
│ ASCII Visualizations            │
│ Risk Gauges                     │
└─────────────────────────────────┘
```

## Security Scoring System

### Risk Calculation Formula

```
Base Risk = Σ(Finding Weights) from i=1 to n
  where Finding Weight = Severity × Confidence × (1 + Chain Bonus)

Path Risk = Base Risk × Distance Penalty × Impact Multiplier
  where Distance Penalty = 1 / path_length
  where Impact Multiplier = min(Σ severity_values / finding_count, 5.0)

Final Score = min(Path Risk × 10, 100) normalized to [0, 100]
```

### Severity Levels
- CRITICAL (5): System compromise, data theft
- HIGH (4): Significant privilege gain, major data exposure
- MEDIUM (3): Moderate impact, limited privilege gain
- LOW (2): Minor issue, information disclosure
- INFO (1): Reconnaissance information

### Confidence Scoring
- 1.0: Fully confirmed vulnerability
- 0.9-0.95: High likelihood based on patterns
- 0.7-0.8: Pattern match with some uncertainty
- 0.5-0.6: Potential issue requiring validation

## Graph Modeling Strategy

### Node Types and Privilege Levels

```
Privilege Scale (0-100):

0-25:    Low-Privilege Users, Unauthenticated Access
         └─ Attack Starting Points

26-50:   Standard Users, Authenticated Endpoints
         └─ Mid-level Access

51-75:   Elevated Roles, Admin Functions
         └─ High-Value Transition Points

76-100:  Sensitive Data, Admin Roles, System Resources
         └─ Attack Targets
```

### Edge Weights

```
Permission Edge: 1.0 (baseline)
Data Flow Edge: 1.0 (baseline)
Vulnerability Edge: Severity × Confidence × Multiplier

IDOR Edge: 3.0 × Confidence
Auth Bypass: 2.5 × Confidence
Privilege Escalation: 4.0 × Confidence
Data Exposure: 2.0 × Confidence
```

## Extensibility Design

### Plugin Architecture

```
Custom Detector Template:

class MyDetector:
    @staticmethod
    def detect(data: Dict) -> Optional[AtomicFinding]:
        # Detection logic
        return AtomicFinding(...)
    
    @staticmethod
    def bulk_analyze(items: List[Dict]) -> List[AtomicFinding]:
        # Batch processing
        return findings_list
```

### Adding Detectors

1. Create module in `ate/modules/`
2. Implement `detect()` and `bulk_analyze()` methods
3. Register in `ate/modules/__init__.py`
4. Use in analysis pipeline

### Custom Vulnerability Types

```python
from ate.core import VulnerabilityType

# Extend for your domain
class CustomFinding(AtomicFinding):
    finding_type = VulnerabilityType.CUSTOM
```

## Performance Characteristics

### Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Add Node | O(1) | Direct graph insertion |
| Add Edge | O(1) | Direct graph insertion |
| Find Paths | O(V+E)* | BFS with cutoff |
| Centrality Analysis | O(V×E) | All-pairs shortest path |
| Full Analysis | O(P×C) | P paths, C correlations |

*V = vertices, E = edges, with path length limit L

### Space Complexity
- Graph: O(V + E)
- Findings: O(F) where F = number of findings
- Paths: O(P) where P = number of attack paths

### Recommended Limits
- Nodes: <50,000
- Edges: <200,000 (depends on density)
- Findings: <10,000
- Max Path Length: 5-10 (exponential explosion)

## Deployment Architecture

### Single-Machine Deployment
```
User → CLI (main.py) → Core Engine → Output (Story/JSON)
```

### REST API Deployment (Future)
```
API Client → FastAPI Server → GraphBuilder → Database
                              ↓
                          ReasoningEngine
                              ↓
                          JSON Response
```

### Distributed Analysis (Future)
```
Task Queue → Worker Pool → Graph Analysis → Result Aggregation
  (Redis)    (Celery)        (Parallel)
```

## Testing Strategy

### Unit Tests
- GraphBuilder: Node/edge operations, path finding
- ReasoningEngine: Analysis, scoring, correlation
- Detectors: Pattern matching, finding generation

### Integration Tests
- End-to-end analysis pipelines
- Multi-detector interactions
- CLI command execution

### Acceptance Tests
- Sample vulnerabilities → attack chains
- Realistic application graphs
- Scoring accuracy

## Future Enhancements

### Planned Features
1. Machine Learning-based risk scoring
2. Graph visualization (interactive web UI)
3. API-based analysis service
4. Parallel multi-graph analysis
5. Custom risk scoring profiles
6. Integration with other scanners (Burp, OWASP ZAP)

### Research Directions
1. Probabilistic attack path weighting
2. Temporal vulnerability analysis
3. Attacker capability modeling
4. Defense simulation and optimization

---

**Architecture Version**: 1.0  
**Last Updated**: 2024
