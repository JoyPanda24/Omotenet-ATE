# Quick Start Guide - Attack Thinking Engine

## 5-Minute Setup

### Prerequisites
- Python 3.13 or higher (tested)
- Git
- Kali, Arch, BlackArch, or Parrot OS (or any Linux distribution)

### Installation

```bash
# 1. Clone the repository
git clone <repository-url>
cd Omotenet-ATE

# 2. Run setup script (handles all dependencies)
bash setup.sh

# 3. Activate virtual environment
source venv/bin/activate

# 4. Verify installation
python -m ate.cli.main --version
```

## Your First Analysis (5 minutes)

### Step 1: Run a Demo

```bash
python -m ate.cli.main demo --example basic
```

This will:
- Create a sample graph
- Add IDOR vulnerability finding
- Perform attack path analysis
- Display narrative output

**Output Preview:**
```
═══════════════════════════════════════════════════════════════════════════
ATTACK PATH ANALYSIS REPORT
═══════════════════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
───────────────────────────────────────────────────────────────────────────
Total Attack Paths Found: 1
Critical Findings: 1
Most Dangerous Path: path_0
Risk Score: 75.0/100
```

### Step 2: Run Advanced Demo

```bash
python -m ate.cli.main demo --example complex
```

This demonstrates:
- Privilege escalation chains
- Multi-step attack paths
- Admin access compromise

### Step 3: Real-World Scanning

#### Scan for IDOR Vulnerabilities:

```bash
# Create a file with URLs to scan
echo "https://myapp.local/api/users/1
https://myapp.local/api/users/2
https://myapp.local/api/users/100" > urls.txt

# Scan for IDOR
python -m ate.cli.main scan-idor --urls-file urls.txt --output idor_findings.json

# View results
cat idor_findings.json
```

#### Analyze Attack Paths:

```bash
# Use sample data
python -m ate.cli.main analyze \
  --graph-file examples/sample_graph.json \
  --findings-file examples/sample_findings.json \
  --output analysis_results.json
```

## Understanding the Output

### Story-Mode Narrative
ATE provides attack paths as human-readable stories:

```
ATTACK NARRATIVE:
Starting from 'attacker', an attacker can reach 'payment_data' 
through a chain of 3 vulnerabilities:

  1. [VULNERABILITY] Attacker → User API (IDOR)
  2. [DATA_FLOW] User API → Payment Data
  3. [RISK CALCULATION] Score: 87.5/100
```

### Key Metrics
- **Risk Score (0-100)**: Overall danger level of the attack path
- **Path Depth**: Number of steps required
- **Finding Count**: How many vulnerabilities are chained

## Building Your Own Analysis

### Example: Simple IDOR Detection

```python
from ate.core import (
    GraphBuilder, ReasoningEngine, NodeType, 
    VulnerabilityType, SeverityLevel, AtomicFinding
)

# Create graph
graph = GraphBuilder("MyApp")

# Add nodes
graph.add_node('attacker', NodeType.USER, 'Attacker', privilege_level=10)
graph.add_node('admin_user', NodeType.USER, 'Admin', privilege_level=100, is_sensitive=True)
graph.add_node('api', NodeType.ENDPOINT, 'GET /api/users/{id}')

# Create finding
finding = AtomicFinding(
    id='idor_1',
    finding_type=VulnerabilityType.IDOR,
    severity=SeverityLevel.CRITICAL,
    source_node='attacker',
    target_node='admin_user',
    description='User IDs are enumerable',
    confidence=0.95
)

# Add to graph
graph.add_finding_and_create_edge(finding)

# Analyze
engine = ReasoningEngine(graph)
result = engine.analyze()

print(f"Risk Score: {result.most_dangerous_path.risk_score}")
```

### Example: Multi-Vulnerability Chain

```python
from ate.cli import StoryRenderer

# After creating graph and analyzing...

# Print narrative
print(StoryRenderer.render_analysis_result(result))

# Or for specific path
for path in result.attack_paths[:3]:
    print(StoryRenderer.render_attack_path(path))
```

## Common Commands Reference

```bash
# Show all commands
python -m ate.cli.main --help

# Create new graph
python -m ate.cli.main create-graph --name "MyApp" --output app.json

# Analyze paths
python -m ate.cli.main analyze \
  --graph-file app.json \
  --findings-file findings.json \
  --output results.json

# Find paths between nodes
python -m ate.cli.main find-paths \
  --graph-file app.json \
  --source user_1 \
  --target admin_panel \
  --max-length 5

# Scan for vulnerabilities
python -m ate.cli.main scan-idor --urls-file urls.txt

# Run demos
python -m ate.cli.main demo --example idor
```

## Input Formats

### Graph JSON Format
```json
{
  "name": "Application Name",
  "nodes": [
    {
      "id": "user_1",
      "type": "user",
      "label": "User 1",
      "privilege_level": 10,
      "is_sensitive": false
    }
  ],
  "edges": [
    {
      "id": "edge_1",
      "source": "user_1",
      "target": "endpoint_1",
      "type": "permission",
      "weight": 1.0
    }
  ]
}
```

### Findings JSON Format
```json
[
  {
    "id": "finding_1",
    "type": "idor",
    "severity": "CRITICAL",
    "source_node": "attacker",
    "target_node": "victim",
    "description": "Description of vulnerability",
    "confidence": 0.95,
    "metadata": {
      "url": "https://app.local/api/users/1"
    }
  }
]
```

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'ate'"
**Solution:**
```bash
# Make sure venv is activated
source venv/bin/activate

# Reinstall packages
pip install -r requirements.txt
```

### Issue: "Command not found: python"
**Solution:**
```bash
# Use python3 explicitly
python3 -m ate.cli.main --version
```

### Issue: "No paths found"
**Solution:**
- Ensure nodes are connected with edges
- Check node IDs match exactly
- Increase `--max-length` parameter
- Verify graph is not disconnected

## Next Steps

1. **Read the Full README**: `cat README.md`
2. **Explore Examples**: `cat examples/comprehensive_example.py`
3. **Review Developer Docs**: `cat DEVELOPER.md`
4. **Run Tests**: `pytest tests/ -v`
5. **Create Custom Modules**: See `DEVELOPER.md` for plugin development

## Getting Help

- **CLI Help**: `python -m ate.cli.main --help`
- **Command Help**: `python -m ate.cli.main <command> --help`
- **Examples Directory**: `examples/`
- **Test Cases**: `tests/test_core.py`

## Key Concepts to Remember

| Concept | Description |
|---------|-------------|
| **Node** | Entity in the system (user, endpoint, data) |
| **Edge** | Connection between nodes (permission, data flow) |
| **Finding** | Security vulnerability discovered |
| **Attack Path** | Chain of nodes connected by findings |
| **Risk Score** | Weighted calculation of attack danger (0-100) |

---

**Ready to analyze attack paths?** Start with:
```bash
python -m ate.cli.main demo --example basic
```
