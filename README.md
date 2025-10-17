## Intel Hex Tool

Simple CLI tool for working with [intel](https://en.wikipedia.org/wiki/Intel_HEX#Record_types) or raw hex files. Written specifically for working with firmware for the AD5M 3D printer so only the subset of intel hex required for those files is implemented.

All functionality is within `intel_hex_tool.py`. Requires at least python 3.6, no 3rd party dependencies. If used in a venv, can be called with `iht`.


### Usage

```
iht -h
iht write -h
iht info -h
iht diff -h
iht disasm -h
```

## Development

Example environment setup using [uv](https://docs.astral.sh/uv/):
```bash
git clone git@github.com:a-johnston/intel_hex_tool.git
cd intel_hex_tool
uv sync
source .venv/bin/activate
```

Optionally install or manually run the precommit hooks:
```bash
pre-commit install
pre-commit run --all-files
```
_(the `ty` hook requires python 3.8. If that is not available, disable that hook.)_

Run tests:
```bash
python -m unittest
```
