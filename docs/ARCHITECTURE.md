# Architecture Documentation

For the complete architecture design including:
- Project folder structure
- Module breakdown and responsibilities
- Data flow diagrams
- Execution flow sequence diagrams
- Error handling strategy
- Logging strategy
- Future scalability plan

See the [Implementation Plan](../../implementation_plan.md) that was used to build this project.

## Quick Architecture Overview

```
User Input → CLI (cli.py)
                ↓
         Config (config.py)
                ↓
    Permissions Check (utils/permissions.py)
                ↓
    Interface Discovery (core/interfaces.py)
                ↓
      Filter Builder (core/filters.py)
                ↓
    Capture Engine (core/capture.py)
         ↓              ↓
  Parser Pipeline    Raw Storage
  (parsers/*.py)     (for PCAP)
         ↓
    Display Layer
  (display/*.py)
         ↓
    Export Layer
  (export/*.py)
```

## Design Patterns Used

| Pattern | Where | Purpose |
|---|---|---|
| **Observer** | `capture.py` callbacks | Decouple capture from display/export |
| **Builder** | `filters.py` | Construct complex BPF filters step-by-step |
| **Registry** | `parsers/__init__.py` | Auto-discover and register parsers |
| **Template Method** | `parsers/base.py` | Consistent error handling across parsers |
| **Strategy** | `export/*.py` | Interchangeable export formats |
