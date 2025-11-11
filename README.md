## Intel Hex Tool

Simple CLI tool for working with [intel hex](https://en.wikipedia.org/wiki/Intel_HEX#Record_types) or raw binary files. Written specifically for working with [firmware for the AD5M 3D printer](https://github.com/a-johnston/ad5m_temp_limit_mod) so only the subset of intel hex required for those files is implemented.

### Installation

The script can be used standalone with any python 3.6 or higher installation. If installed as a python package, an alias `iht` can be used.

Install via `pip` to an existing venv:
```
pip install git+https://github.com/a-johnston/intel_hex_tool
```

Install with `uv` to `~/.local/bin` for use outside of a venv:
```
uv tool install intel-hex-tool --from git+https://github.com/a-johnston/intel_hex_tool
```

### Usage

```
iht -h
iht write -h
iht info -h
iht diff -h
iht disasm -h
```

### Development

Some dev tools require at least python 3.8. Example environment setup using `uv`:
```
git clone git@github.com:a-johnston/intel_hex_tool.git
cd intel_hex_tool
uv sync
source .venv/bin/activate
```

Optionally install or manually run the precommit hooks:
```bash
prek install
prek run --all-files
```

Run tests:
```bash
python -m unittest
```
