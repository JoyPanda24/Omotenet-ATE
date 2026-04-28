# Attack Thinking Engine - Complete Project Index

## 📑 Table of Contents & Navigation Guide

### Quick Navigation
- **First Time?** → Start with [QUICKSTART.md](QUICKSTART.md)
- **Need Details?** → Read [README.md](README.md)
- **Developer?** → See [DEVELOPER.md](DEVELOPER.md)
- **Understand Design?** → Check [ARCHITECTURE.md](ARCHITECTURE.md)
- **Project Status?** → View [CHANGELOG.md](CHANGELOG.md)

---

## 📁 Project Structure Guide

### Core Engine (`ate/core/`)
**The heart of ATE - graph construction and attack analysis**

| File | Purpose | Lines | Status |
|------|---------|-------|--------|
| `__init__.py` | Module exports | 25 | ✅ |
| `data_models.py` | Type definitions (NodeType, VulnerabilityType, etc) | 350+ | ✅ |
| `graph_builder.py` | NetworkX graph construction and management | 400+ | ✅ |
| `reasoning_engine.py` | Attack path discovery and analysis | 450+ | ✅ |

**Key Classes**:
- `GraphBuilder`: Add nodes/edges, find paths, calculate scores
- `ReasoningEngine`: Analyze graph, find attack chains
- Data model classes: `GraphNode`, `GraphEdge`, `AtomicFinding`, etc

---

### Detection Modules (`ate/modules/`)
**Pluggable vulnerability detection engines**

| File | Vulnerability Type | Lines | Features |
|------|-------------------|-------|----------|
| `idor_detector.py` | IDOR | 150+ | URL patterns, API responses, bulk analysis |
| `auth_flaws.py` | Auth Issues | 250+ | Missing auth, weak tokens, cookies, brute force |
| `sensitive_data_exposure.py` | Data Exposure | 300+ | Response analysis, logs, debug info, metadata |
| `__init__.py` | Exports | 10 | ✅ |

**Key Methods**: `detect()`, `bulk_analyze()`, pattern matching

---

### CLI Interface (`ate/cli/`)
**User-facing command-line tool**

| File | Purpose | Lines | Commands |
|------|---------|-------|----------|
| `main.py` | CLI commands & entry point | 400+ | create-graph, analyze, scan-idor, find-paths, demo |
| `story_renderer.py` | Narrative output generation | 250+ | Story mode, attack narratives, reports |
| `visualizer.py` | ASCII visualization | 200+ | Path visualization, trees, statistics |
| `__init__.py` | Exports | 10 | ✅ |

**Key Commands**:
```bash
python -m ate.cli.main <command>
  create-graph
  analyze
  scan-idor
  find-paths
  demo
```

---

### Tests (`tests/`)
**Quality assurance and examples**

| File | Coverage | Tests | Status |
|------|----------|-------|--------|
| `test_core.py` | GraphBuilder, ReasoningEngine, Detectors | 15+ | ✅ |

**Run Tests**:
```bash
pytest tests/ -v
pytest tests/ --cov=ate  # With coverage
```

---

### Examples (`examples/`)
**Real-world usage demonstrations**

| File | Purpose | Scenarios |
|------|---------|-----------|
| `comprehensive_example.py` | Usage guide | 4 scenarios |
| `sample_graph.json` | Example data | E-commerce graph |
| `sample_findings.json` | Example data | 5 sample findings |
| `sample_urls.txt` | Example data | 14 test URLs |

**Run Examples**:
```bash
python examples/comprehensive_example.py
```

---

### Configuration & Setup
**Project initialization and deployment**

| File | Purpose | Type |
|------|---------|------|
| `setup.sh` | Cross-distro installation | Bash script (100+ lines) |
| `setup.py` | Python package config | Python setuptools |
| `requirements.txt` | Dependencies | 13 packages |
| `.gitignore` | Git configuration | Standard Python ignore |
| `Makefile` | Build automation | 100+ lines |
| `LICENSE` | MIT License | Open source license |

**Setup Commands**:
```bash
bash setup.sh                       # Auto setup
source venv/bin/activate           # Activate venv
python -m ate.cli.main --help      # Verify
```

---

### Documentation
**Comprehensive guides and references**

| Document | Audience | Pages | Focus |
|----------|----------|-------|-------|
| [README.md](README.md) | Users | 30+ | Overview, examples, CLI reference |
| [QUICKSTART.md](QUICKSTART.md) | Beginners | 15+ | 5-minute setup, first analysis |
| [DEVELOPER.md](DEVELOPER.md) | Developers | 20+ | API reference, module development |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architects | 25+ | System design, data flow, algorithms |
| [CHANGELOG.md](CHANGELOG.md) | Project Mgmt | 20+ | Completion status, features, roadmap |
| [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) | Navigation | 15+ | File structure, deliverables checklist |

---

## 🚀 Getting Started Paths

### Path 1: First-Time Users
1. Read: [QUICKSTART.md](QUICKSTART.md) (5 min)
2. Run: `bash setup.sh` (2 min)
3. Try: `python -m ate.cli.main demo --example basic` (1 min)

### Path 2: Hands-On Developers
1. Read: [README.md](README.md) (10 min)
2. Run: `python examples/comprehensive_example.py` (5 min)
3. Explore: [DEVELOPER.md](DEVELOPER.md) (15 min)
4. Code: Create custom detector module (30 min)

### Path 3: System Architects
1. Read: [ARCHITECTURE.md](ARCHITECTURE.md) (20 min)
2. Study: [core/](ate/core/) implementation (15 min)
3. Review: Data flow diagrams in ARCHITECTURE.md (10 min)

### Path 4: Security Researchers
1. Read: [README.md](README.md) (10 min)
2. Try: `python -m ate.cli.main scan-idor --urls-file urls.txt`
3. Analyze: Results with `analyze` command
4. Study: [modules/](ate/modules/) for detection methods

---

## 📊 Quick Reference

### Supported Vulnerability Types
```python
VulnerabilityType.IDOR
VulnerabilityType.AUTH_BYPASS
VulnerabilityType.SENSITIVE_DATA_EXPOSURE
VulnerabilityType.PRIVILEGE_ESCALATION
VulnerabilityType.AUTHENTICATION_FLAW
VulnerabilityType.AUTHORIZATION_FLAW
VulnerabilityType.INFORMATION_DISCLOSURE
VulnerabilityType.CUSTOM
```

### Severity Levels
```python
SeverityLevel.CRITICAL  # value=5 → 100-80 risk score
SeverityLevel.HIGH      # value=4 → 80-60 risk score
SeverityLevel.MEDIUM    # value=3 → 60-40 risk score
SeverityLevel.LOW       # value=2 → 40-20 risk score
SeverityLevel.INFO      # value=1 → 20-0 risk score
```

### Node Types
```python
NodeType.USER          # User accounts
NodeType.ROLE          # Permission roles/groups
NodeType.ENDPOINT      # API endpoints/pages
NodeType.DATA_OBJECT   # Data stores/objects
NodeType.RESOURCE      # System resources
```

---

## 🔨 Common Tasks

### Run a Vulnerability Scan
```bash
python -m ate.cli.main scan-idor --urls-file urls.txt --output findings.json
```

### Analyze Attack Paths
```bash
python -m ate.cli.main analyze \
  --graph-file app.json \
  --findings-file findings.json \
  --output results.json
```

### Find Specific Paths
```bash
python -m ate.cli.main find-paths \
  --graph-file app.json \
  --source user_1 \
  --target admin_panel \
  --max-length 5
```

### Run Tests
```bash
pytest tests/ -v                    # All tests
pytest tests/test_core.py::TestGraphBuilder -v  # Specific class
pytest --cov=ate tests/            # With coverage
```

### Code Formatting
```bash
make format                         # Black + isort
make lint                          # Code quality check
```

---

## 🎯 Key Concepts

### Graph-Based Analysis
ATE models applications as directed graphs where:
- **Nodes** represent entities (users, endpoints, data)
- **Edges** represent relationships (permissions, vulnerabilities)
- **Weights** represent attack difficulty/severity

### Attack Path
A sequence of nodes connected by vulnerability edges, representing a complete attack from entry point to objective.

### Atomic Finding
A single, isolated security vulnerability that becomes an edge in the graph (e.g., "User IDs are enumerable").

### Reasoning
The process of connecting atomic findings into complete attack chains by analyzing paths through the graph.

---

## 📞 Quick Help

### Installation Issues?
→ See [QUICKSTART.md - Troubleshooting](QUICKSTART.md#troubleshooting)

### How Do I...?
- Create a graph? → See [QUICKSTART.md](QUICKSTART.md) or `analyze` command help
- Add custom detectors? → See [DEVELOPER.md - Module Development](DEVELOPER.md#module-development)
- Understand scoring? → See [ARCHITECTURE.md - Scoring System](ARCHITECTURE.md#security-scoring-system)

### Command Help
```bash
python -m ate.cli.main --help              # All commands
python -m ate.cli.main analyze --help      # Specific command
```

---

## 🏆 Features at a Glance

✅ Graph-based attack surface modeling  
✅ Automated attack path discovery  
✅ Multi-step vulnerability correlation  
✅ Risk scoring algorithm  
✅ IDOR, auth, and data exposure detection  
✅ Story-mode narrative reporting  
✅ ASCII graph visualization  
✅ Cross-distro support (Kali, Arch, BlackArch, Parrot)  
✅ Pluggable detection modules  
✅ Complete CLI interface  
✅ Comprehensive documentation  
✅ Unit tests  

---

## 📋 Checklist: What's Included

### Core Files ✅
- [x] GraphBuilder implementation
- [x] ReasoningEngine implementation
- [x] Data models and types
- [x] IDOR detector
- [x] Auth flaws detector
- [x] Data exposure detector

### CLI & UI ✅
- [x] Click-based CLI framework
- [x] 5 main commands
- [x] Story renderer
- [x] ASCII visualizer
- [x] Multiple output formats

### Documentation ✅
- [x] README (500+ lines)
- [x] QUICKSTART (300+ lines)
- [x] DEVELOPER (400+ lines)
- [x] ARCHITECTURE (500+ lines)
- [x] Code docstrings
- [x] Examples

### Quality & Testing ✅
- [x] Unit test suite
- [x] Setup automation
- [x] Package configuration
- [x] Dependency management
- [x] Build automation
- [x] Repository config

---

## 🚢 Ready for...

✅ Security Research  
✅ Penetration Testing  
✅ Vulnerability Analysis  
✅ Attack Simulation  
✅ Risk Assessment  
✅ Academic Study  
✅ Tool Integration  

---

## 📞 Support Resources

| Need | Resource | Location |
|------|----------|----------|
| Setup Help | QUICKSTART.md | [QUICKSTART.md](QUICKSTART.md) |
| How-To Guide | README.md | [README.md](README.md) |
| API Details | DEVELOPER.md | [DEVELOPER.md](DEVELOPER.md) |
| System Design | ARCHITECTURE.md | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Project Status | CHANGELOG.md | [CHANGELOG.md](CHANGELOG.md) |
| File Structure | PROJECT_STRUCTURE.md | [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) |
| This Guide | INDEX.md | [INDEX.md](INDEX.md) (this file) |

---

**Last Updated**: 2024  
**Project Status**: Complete ✅  
**Version**: 0.1.0  
**License**: MIT  

**Ready to begin? Start with [QUICKSTART.md](QUICKSTART.md)** 🚀
