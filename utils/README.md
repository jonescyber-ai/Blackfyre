# Blackfyre Utilities

Utilities for generating and working with Binary Context Container (BCC) files.

## Quick Reference

| Tool | Description and Usage |
|------|----------------------|
| 📦 **generate_bcc.py** | Generate BCC files using Ghidra headless analyzer. Supports single/batch processing, parallel execution, and YAML configuration. **Python API available for programmatic use.**<br><br>`python -m utils.generate_bcc --binary test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd --output-dir ./out` |
| 🔧 **extract_binary_from_bcc.py** | Extract original binary from BCC file<br><br>`python -m utils.extract_binary_from_bcc test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90f_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd.bcc ./extracted_binary` |

---

## Prerequisites

Before using these utilities, ensure you have the following installed:

1. **Blackfyre Python Library**:
   - Required for working with BCC files
   - See the [main README](../README.md#installing-the-blackfyre-python-library) for installation instructions

2. **Ghidra and Blackfyre Plugin** (required for `generate_bcc.py`):
   - Ghidra 11.4.2 or later
   - Blackfyre Ghidra plugin installed
   - See the [main README](../README.md#installation-and-usage-of-the-ghidra-plugin) for complete setup instructions

3. **Utility-Specific Dependencies**:
   ```bash
   pip install -r utils/requirements.txt
   ```

---

## generate_bcc.py

Generate Binary Context Container (BCC) files using Ghidra's headless analyzer in batch mode. BCC files contain binary metadata, function information, and decompiled code for analysis.

This utility automates the process of running Ghidra headless analysis on single binaries or entire directories of binaries, with support for parallel processing and customizable configuration.

### Configuration (Required First Step)

**IMPORTANT**: Before using this utility, you **must** edit `utils/bcc_generator_config.yaml` and update the following required paths:

1. **`ghidra_path`** - Set to your Ghidra 11.4.2 installation directory
2. **`blackfyre_root`** - (Optional) Set to your Blackfyre repository root directory, or leave as `null` to auto-detect

These paths are clearly marked in the YAML file with `# ← CHANGE THIS` comments.

### Programmatic Usage (Python API)

Use the Python API to integrate BCC generation into your scripts:

```python
import os
from utils.generate_bcc import generate_bcc_for_binary, generate_bcc_for_directory
from blackfyre.common import VerbosityLevel

# Set the path to your Blackfyre repository
BLACKFYRE_REPO = "/opt/jc_ai_repos/Blackfyre"

# Generate single BCC (output_dir is the folder, BCC filename is auto-generated)
# Using the test binary included in the repository
test_binary = os.path.join(
    BLACKFYRE_REPO,
    "test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd"
)
success = generate_bcc_for_binary(test_binary, "./output")

# Generate BCCs for directory (parallel) with custom verbosity
results = generate_bcc_for_directory(
    binary_dir="/firmware/bin",
    output_dir="./bccs",
    parallel=4,
    verbosity=VerbosityLevel.NORMAL.value
)
print(f"Generated {results['success']}/{results['total']} BCCs")
```

**Verbosity Levels** (optional parameter):
- `VerbosityLevel.SILENT.value` (0) - No output, no progress bars
- `VerbosityLevel.NORMAL.value` (1) - Standard output with progress bars (default)
- `VerbosityLevel.VERBOSE.value` (2) - Detailed output with debug information


**Available Functions**:

| Function | Returns |
|----------|---------|
| `generate_bcc_for_binary(binary_path, output_dir, config=None)` | `bool` |
| `generate_bcc_for_directory(binary_dir, output_dir, config=None, parallel=None)` | `Dict[str, int]` |
| `generate_bcc_for_list(binary_list, output_dir, config=None, parallel=None)` | `Dict[str, int]` |
| `get_bcc_generator_config(config_path=None)` | `BCCGeneratorConfig` |

**Note**: All functions take `output_dir` as a directory path. The BCC filename is automatically generated based on the binary name and hash.

### Quick Start (Command Line)

```bash
# 1. Install dependencies (from the Blackfyre root directory)
pip install -r utils/requirements.txt

# 2. REQUIRED: Edit utils/bcc_generator_config.yaml and update these paths:
#    - ghidra_path: "/your/path/to/ghidra_11.4.2_PUBLIC"
#    - blackfyre_root: null  # auto-detect (or set to "/your/path/to/Blackfyre/")

# 3. Generate BCC for single binary (using test binary from repository)
# Run from the Blackfyre root directory
python -m utils.generate_bcc \
    --binary test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd \
    --output-dir ./output

# 4. Batch process directory (parallel)
python -m utils.generate_bcc --binary-dir /firmware/bin --output-dir ./bccs --parallel 4
```

### Usage Examples

#### Single Binary
```bash
# Using the test binary included in the repository
# Run from the Blackfyre root directory
python -m utils.generate_bcc \
    --binary test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd \
    --output-dir ./output
```

#### Batch Processing from Directory
```bash
python -m utils.generate_bcc \
    --binary-dir /firmware/bin \
    --output-dir ./bccs \
    --parallel 4 \
    --verbose
```

#### Use All CPU Cores
```bash
# Use all available CPU cores
python -m utils.generate_bcc --binary-dir /firmware/bin --output-dir ./bccs --parallel 0
```

#### Disable Embedding Raw Binary Bytes
```bash
# Generate BCCs without embedding raw binary bytes (overrides YAML)
python -m utils.generate_bcc --binary-dir /firmware/bin --output-dir ./bccs --disable-raw-binary
```

#### Batch Processing from List
```bash
# Create list of binaries
cat > binaries.txt << EOF
/bin/ls
/bin/cat
/bin/grep
EOF

# Generate BCCs
python -m utils.generate_bcc \
    --binary-list binaries.txt \
    --output-dir ./bccs
```

### Command-Line Options

**Input** (choose one):
- `--binary PATH` - Process single binary
- `--binary-dir DIR` - Process all binaries in directory
- `--binary-list FILE` - Process binaries from text file

**Output**:
- `--output-dir DIR` - Output directory (required)

**Configuration**:
- `--config PATH` - Custom config file (default: `utils/bcc_generator_config.yaml`)
- `--ghidra-path PATH` - Override Ghidra path
- `--parallel N` - Number of parallel workers (`0` = all CPU cores)
- `--disable-raw-binary` - Force `include_raw_binary: false` (bypasses config for this setting)

**Other**:
- `-v, --verbose` - Show detailed Ghidra output

### Configuration Priority

Settings are applied in this order (highest priority first):

1. Command-line arguments (`--ghidra-path`, `--parallel`, etc.)
2. Environment variables (`$GHIDRA_PATH`)
3. Config file (`bcc_generator_config.yaml`)
4. Built-in defaults

### Testing

The repository’s binary fixtures live under `test/` (e.g., `test/bison_arm_...`).

Automated Python tests also live under `test/` and are named `test_*.py`.

The `generate_bcc` test is an **integration** test (it requires Ghidra headless). It will
automatically skip if `support/analyzeHeadless` cannot be found via `$GHIDRA_PATH` or the
configured `ghidra_path`.

Run it from the Blackfyre repo root:

```bash
python -m unittest discover -s test -p "test_*.py" -v
```

---

## extract_binary_from_bcc.py

Extract the original binary executable from a BCC file.

**Note**: This only works if the BCC was generated with the raw binary included. When using `generate_bcc.py`, this is the default behavior (controlled by `include_raw_binary: true` in the YAML configuration).

### Usage

```bash
# Using the test BCC file included in the repository
# Run from the Blackfyre root directory
python -m utils.extract_binary_from_bcc \
    test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90f_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd.bcc \
    ./extracted_binary
```

This is useful for recovering binaries from BCC files for further analysis or verification.
