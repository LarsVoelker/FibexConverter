# AGENTS.md

## Overview
FibexConverter - A tool for converting SOME/IP configuration from FIBEX 4 XML files to various output formats including CSV reports, Wireshark configs, and topology visualizations.

## Project Structure
- `src/` - Source code: `configuration_to_*.py` conversion scripts, parsers (`fibex_parser.py`, `flync_parser.py`, `parser_dispatcher.py`) and `configuration_base_classes.py`; modules import each other as flat top-level modules
- `plugins/` - Example parser plugins
- `tools/` - Helper scripts (schema validation, dependency update)
- `tests/` - Unit tests (`pythonpath = ["src"]` in `pyproject.toml` makes `src/` importable)
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
- Run the tools from the repo root, e.g. `python3 src/configuration_to_text.py FIBEX <file>`
- The project uses Python 3.13 (venv_brew)
- Tests require pytest and pytest-cov
- Use `venv_brew` for all testing and development activities
