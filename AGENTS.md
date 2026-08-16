# AGENTS.md

## Overview
FibexConverter - A tool for converting SOME/IP configuration from FIBEX 4 XML files to various output formats including CSV reports, Wireshark configs, and topology visualizations.

## Project Structure
- `configuration_to_*.py` - Main conversion scripts
- `tests/` - Unit tests
- `.venv/` - Python virtual environment (use this for development)

## Running Tests
Activate the virtual environment and run pytest:
```bash
source .venv/bin/activate
pytest tests/ -v
```

## Validating Examples Files
````bash
source .venv/bin/activate
pytest -v tests/test_fibex_schema_validation.py
```

## Notes
- The project uses Python 3.13 (venv_brew)
- Tests require pytest and pytest-cov
- Use `venv_brew` for all testing and development activities
