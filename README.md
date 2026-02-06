# **Blackfyre**

**Blackfyre** is an open-source platform designed to standardize and streamline binary analysis. It provides tools and APIs for extracting, analyzing, and storing binary data in a disassembler-agnostic and architecture-agnostic format. This enables consistent workflows for advanced reverse engineering tasks powered by AI/ML, NLP, and LLMs.

---

### **Origin and Purpose**

Blackfyre was originally developed to support the course **"Automating Reverse Engineering Processes with AI/ML, NLP, and LLMs"** at **Blackhat** (since 2019) and **RECON** (since 2023). The platform was created to demonstrate and teach cutting-edge techniques for automating reverse engineering workflows using advanced machine learning and natural language processing tools. Today, Blackfyre continues to empower developers and researchers with a robust framework for integrating AI-driven workflows into reverse engineering.

---


### **What is Blackfyre?**

Blackfyre consists of two core components:

1. **Disassembler Plugins**  
   Extract structured data and metadata from binaries and save them in the **Binary Context Container (BCC)** format. This ensures compatibility and standardization for subsequent analysis across different tools and architectures.

2. **Python Library**  
   Provides APIs for working with BCC files, enabling detailed analysis of binary data, including functions, basic blocks, instructions, and their relationships. These APIs are designed to integrate seamlessly into workflows that leverage AI/ML and NLP techniques for advanced binary analysis.

---

### Integration with PyVEX and Vex IR

A key feature of Blackfyre is its integration with **pyvex**, a library for lifting disassembly code to an intermediate representation (IR) called **Vex IR**. This enables users to perform architecture-agnostic analysis across a wide range of supported architectures. With Vex IR, you can analyze binaries at a higher level of abstraction while maintaining precise control over low-level details.

#### Architectures Supported by Vex IR
By leveraging pyvex, Blackfyre supports analysis for the following architectures:
- **x86 (32-bit and 64-bit)**
- **ARM (32-bit and 64-bit)**
- **MIPS (32-bit and 64-bit)**
- **PowerPC (32-bit and 64-bit)**

This architecture coverage ensures Blackfyre can be applied to a wide range of binaries, making it an essential tool for cross-platform analysis.

---

## Key Features

1. **Disassembler-Agnostic**:
   - Integrates with multiple disassemblers, including **Ghidra**, and allows additional plugins to be developed for **IDA Pro** and **Binary Ninja**.

2. **Architecture-Agnostic**:
   - By using pyvex and Vex IR, Blackfyre enables analysis across all architectures supported by Vex IR, ensuring a consistent workflow for heterogeneous binaries.

3. **Comprehensive Data Extraction**:
   - Strings, imports, exports, constants, functions, basic blocks, and raw binary data can all be extracted and analyzed.

4. **Advanced Analysis APIs**:
   - Explore decompiled functions, instruction details, basic blocks, and function relationships (callers and callees).

5. **Optimized for AI/ML Integration**:
   - Blackfyre’s structured output makes it easy to integrate binary analysis workflows into AI/ML pipelines, enabling advanced research and automation.

---

## Key Data Captured by Blackfyre Plugins

| Data Type       | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| **Strings**      | Text and address references.                                               |
| **Imports**      | Library function references and library names.                             |
| **Exports**      | References of the exported functions.                                      |
| **Constants**    | Data and address constants.                                                |
| **Functions**    | Decompiled code, basic blocks, callers, callees, size, and names.          |
| **Basic Blocks** | Instruction mnemonics and opcodes.                                         |
| **Binary Metadata** | Architecture, file type, endianness, and disassembler details.           |
| **Raw Binary**   | (Optional) The raw binary data for additional analysis.                    |

---
### ⚙️ Compatibility and Version Notes

The **latest `main` branch** of this repository contains code that was **built from the Blackfyre source** and **tested on Ghidra 11.4.2**.

> **Important:**  
> - Ghidra **11.4 introduces breaking API changes** that make this plugin **incompatible with older Ghidra versions**, such as **11.2**.  
> - The plugin’s Java and Ghidra integration code (including the `blackfyre` components) was **generated using Protocol Buffers v3.21.8**, which matches the **protobuf version bundled with Ghidra 11.4.2**.  
> - Attempting to build or load this plugin on earlier Ghidra releases will result in **API resolution errors or runtime incompatibilities**.  
> - For consistent results, use **Ghidra 11.4.2** when building or deploying this plugin.

---

## Installation

### Prerequisites
- Python 3.x
- Ghidra (optional, for Ghidra Plugin)

### Installing the Blackfyre Python Library

Blackfyre relies on pyvex, which has a straightforward installation process via pip on x86_64/AMD64 architectures. 
However, installation on ARM-based architectures (e.g., Mac M1/M2) can be more complex and may require additional troubleshooting.

#### Steps for Installation:
1. Clone the Blackfyre repository:
   ```sh
   git clone https://github.com/jonescyber-ai/Blackfyre.git
   cd Blackfyre
   ```

2. Install the Python library:
   ```sh
   cd src/python
   pip install -e .
   ```
   
3. **Resolve pyvex installation issues (if applicable)**:
   - For x86_64/AMD64 systems:
     - `pyvex` should install without issues using `pip`, as it has prebuilt wheels for these architectures.
   - For ARM-based systems (e.g., Mac M1/M2):
     - Installation can be more challenging. A potential workaround is:
       - Use the [Anaconda distribution](https://www.anaconda.com/) to create a virtual environment.
       - Install `pyvex` and its dependencies manually within this environment.
     - There is no guarantee this workaround will work and additional troubleshooting may still be required.
3. Go back to the root directory:
   ```sh
   cd ../../
   ```   

4. Verify the install by running the example python script:
   ```sh
    python examples/python/example_displaying_binary_metadata.py
    ```
   If the script runs without errors, the installation was successful.

#### Additional Notes:
- On x86_64/AMD64 systems, the installation process for `Blackfyre` is typically smooth due to the availability of prebuilt binaries for `pyvex`.
- On ARM-based systems, some dependencies might need to be built from source, which can require additional configuration.
- If you encounter errors or need further assistance, refer to the `pyvex` GitHub repository or community forums for guidance.

---


## Getting Started
Note: For the following examples, We will assume the blackfyre repo is located in '/opt/Blackfyre'. Change the path to the Blackfyre repository as needed.

### Example 1: Exploring Binary Metadata with Python APIs
Retrieve metadata about a binary using the Blackfyre Python API.
```python
import os.path
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

# Change the path to the Blackfyre repository
PATH_TO_BLACKFYRE_REPO = "/opt/Blackfyre"

# Test bcc file path included in the repository
bcc_file_path = os.path.join(PATH_TO_BLACKFYRE_REPO, "test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90f_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd.bcc")

# Load the appropriate binary context with the determined cache path
binary_context = BinaryContext.load_from_file(bcc_file_path)

# Display basic meta-data about the binary
print(f"Binary Name: {binary_context.name}")
print(f"Binary SHA256: {binary_context.sha256_hash}")
print(f"Binary File Type: {binary_context.file_type}")
print(f"Processor Type: {binary_context.proc_type}")
print(f"Number of Functions: {len(binary_context.function_context_dict)}")
print(f"Number of Strings: {len(binary_context.string_refs)}")
print(f"Number of Import Functions: {len(binary_context.import_symbols)}")
print(f"Number of Export Functions: {len(binary_context.export_symbols)}")
print(f"Number of Defined Data: {len(binary_context.defined_data_map)}")
print(f"Disassembly Type: {binary_context.disassembler_type}")
print(f"Endianness: {binary_context.endness}")
print(f"Disassembler Version: {binary_context.disassembler_version}")
print(f"BCC File Version: {binary_context.bcc_version}")

# Print the function names in the binary context container (bcc) file
num_functions_to_display = 5
max_decompiled_code_length = 100
print(f"\nDisplaying up to {num_functions_to_display} Functions:")
counter = 0
for index, function_context in enumerate(binary_context.function_contexts):

    print("=" * 100)
    print(f"  - Function Name: {function_context.name}")
    print(f"  - Function Start Address: {function_context.address}")
    print(f"  - Function End Address: {function_context.end_address}")
    print(f"  - Function Size: {function_context.size}")
    print(f"  - Function Number of Blocks: {len(function_context.basic_block_context_dict)}")
    print(f"  - Function Number of Callers: {len(function_context.callers)}")
    print(f"  - Function Number of Callees: {len(function_context.callees)}")
    print(f"  - Function Number of Unique Callees: {len(set(function_context.callees))}")
    if hasattr(function_context, "all_callees"):
        print(f"  - Function Unique All Callees: {len(function_context.all_callees)}")
    if hasattr(function_context, "num_all_call_sites"):
        print(f"  - Function Number of All Call Sites: {function_context.num_all_call_sites}")
    print(f"  - Function Decompiled Code: {function_context.decompiled_code[:max_decompiled_code_length]}")
    print("=" * 100 + "\n")

    counter += 1
    if counter >= num_functions_to_display:
        break

```

### Exploring Functions and Basic Blocks with Blackfyre API using Vex IR: 
```python
import os
from blackfyre.datatypes.contexts.vex.vexbinarycontext import VexBinaryContext
from blackfyre.datatypes.contexts.vex.vexfunctioncontext import VexFunctionContext
from blackfyre.common import IRCategory
from blackfyre.datatypes.contexts.vex.vexinstructcontext import VexInstructionContext

# Step 0: Load the binary context
# Change the path to the Blackfyre repository
PATH_TO_BLACKFYRE_REPO = "/opt/Blackfyre"

# Test bcc file path included in the repository
bcc_file_path = os.path.join(PATH_TO_BLACKFYRE_REPO, "test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90f_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd.bcc")

vex_binary_context = VexBinaryContext.load_from_file(bcc_file_path)

# Step 1: Select a function context by address
FUNCTION_ADDRESS = 0x2986c  # Replace with an actual function address from your binary
vex_function_context: VexFunctionContext = vex_binary_context.function_context_dict[FUNCTION_ADDRESS]

# Step 2: Get the entry basic block
entry_bb_context = vex_function_context.entry_basic_block_context

# Step 3: Print the first 10 instructions and their categories
print(f"Function: 0x{vex_function_context.start_address:x} ({vex_function_context.name})")
print(f"Entry Basic Block: 0x{entry_bb_context.start_address:x} -> 0x{entry_bb_context.end_address:x}")

# Iterate through the instructions in the entry basic block
print("\nFirst 10 Instructions in Entry Basic Block:")
vex_instruction_context: VexInstructionContext
for i, vex_instruction_context in enumerate(entry_bb_context.vex_instruction_contexts):
    # Break after the first 10 instructions
    if i >= 10:
        break

    # Extract instruction address and category
    instruction_address = vex_instruction_context.native_address
    category = vex_instruction_context.category.name if vex_instruction_context.category else "Unknown"

    # Print the instruction details
    print(f"  Instruction 0x{instruction_address:x}: Vex Instruction: {vex_instruction_context.instruction}   Vex Mnemonic - {vex_instruction_context.mnemonic} | Category - {category}")

    # Additional: Handle branches (optional)
    if vex_instruction_context.category == IRCategory.branch:
        jump_target_address = vex_instruction_context.jump_target_addr
        if jump_target_address is not None:
            print(f"    Jump target address: 0x{jump_target_address:x}")

```

### Analyzing Function Relationships in Blackfyre: Exploring  Callees and Callers
```python
import os
from blackfyre.datatypes.contexts.vex.vexbinarycontext import VexBinaryContext
from blackfyre.datatypes.contexts.vex.vexfunctioncontext import VexFunctionContext
from typing import List

# Step 0: Load the binary context
# Change the path to the Blackfyre repository
PATH_TO_BLACKFYRE_REPO = "/opt/Blackfyre"

# Test bcc file path included in the repository
bcc_file_path = os.path.join(PATH_TO_BLACKFYRE_REPO, "test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90f_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd.bcc")

vex_binary_context = VexBinaryContext.load_from_file(bcc_file_path)

# Step 1: Pick a function context by address
FUNCTION_ADDRESS = 0x2986c  # Replace with an actual function address from your binary
vex_function_context: VexFunctionContext = vex_binary_context.function_context_dict[FUNCTION_ADDRESS]

# Step 2: Explore the function's basic blocks
print(f"Function 0x{vex_function_context.start_address:x}: {vex_function_context.name}")
print(f"Number of basic blocks: {len(vex_function_context.basic_block_context_dict)}")

# Step 3: Print basic block details
print("\nBasic Blocks:")
for bb in vex_function_context.basic_block_contexts:
    print(f"  Block 0x{bb.start_address:x} -> 0x{bb.end_address:x}")

# Step 4: List direct callees (functions called by this function)
print("\nDirect Callees:")
if vex_function_context.callees:
    for callee_address in vex_function_context.callees:
        callee_function = vex_binary_context.function_context_dict.get(callee_address)
        callee_name = callee_function.name if callee_function else "Unnamed"
        print(f"  0x{callee_address:x} ({callee_name})")
else:
    print("  None")

# Step 5: Find and list direct callers (functions calling this function)
print("\nDirect Callers:")
direct_callers = [
    func_ctx for func_ctx in vex_binary_context.function_context_dict.values()
    if FUNCTION_ADDRESS in func_ctx.callees
]

if direct_callers:
    for caller in direct_callers:
        caller_name = caller.name if caller.name else "Unnamed"
        print(f"  0x{caller.start_address:x} ({caller_name})")
else:
    print("  None")



```

## Ghidra Plugin 

The **Blackfyre Ghidra Plugin** enables streamlined extraction of binary data into the BCC format. This plugin is specifically designed for users of the Ghidra reverse engineering tool and serves as a central component of Blackfyre's data extraction pipeline.

### Features
- **Seamless Integration**: Adds Blackfyre’s capabilities directly to Ghidra.
- **Consistent Output**: Ensures data is captured in the standardized BCC format.
- **Extensibility**: Additional plugins can be written for other disassemblers like **IDA Pro** and **Binary Ninja**.

### **Installation and Usage of the Ghidra Plugin **

1. **Download the Plugin**:
   - Locate the latest `ghidra_*.zip` plugin file in the [Releases section](https://github.com/jonescyber-ai/Blackfyre/releases) of the Blackfyre repository.
   - Ensure you select the plugin version that matches your Ghidra version, as the plugin is tied to the specific Ghidra version it was built for.

2. **Install the Plugin in Ghidra**:
   - Open Ghidra and navigate to **File > Install Extensions**.
   - In the **Install Extensions** dialog:
     - Click on the "Plus" icon to add a new extension.
     - Browse to the location of the downloaded `ghidra_*.zip` file.
     - Select the file and click **OK**.
   - After installation, restart Ghidra for the plugin to be fully loaded.

3. **Run the Ghidra Script to Generate the BCC**:
   - Open the binary you want to analyze in Ghidra.
   - Navigate to **Script Manager** from the **Window** menu or toolbar.
   - Locate and run the script `GenerateBinaryContext.java`.
   - During execution, the script will prompt you for the following inputs:
     - **Output Directory**: Specify where the `.bcc` file should be saved.
     - **Include Raw Binary**: Indicate whether to include the raw binary in the `.bcc` file. Including it will increase the file size.
     - **Include Decompiled Code**: Specify if decompiled code should be included. Note that decompilation will add processing time, and in the worst case, the time will scale as `timeout × number of functions`.
     - **Decompilation Timeout**: Enter the timeout value for decompiling each function, if applicable. If decompiled code is not needed, set this option to "No" to avoid delays.

4. **Verify Installation and Output**:
   - After running the script, verify that the `.bcc` file has been generated in the specified output directory.
   - Check the content of the `.bcc` file to ensure it includes the selected components (e.g., raw binary or decompiled code).
   - If any errors occur during script execution, refer to the error messages for troubleshooting.

5. **Notes**:
   - Always use a plugin version compatible with your Ghidra version to avoid compatibility issues.
   - Excluding decompiled code can significantly reduce processing time, especially for binaries with a large number of functions.
   - If you encounter issues during installation or script execution, refer to the plugin documentation _(if available)_ or open an issue in the Blackfyre repository.


### **Using Ghidra in Headless Mode**

Ghidra supports running scripts and performing automated tasks in headless mode. This is particularly useful for batch processing or when a graphical user interface (GUI) is not required.

#### **Automated BCC Generation Utility (Recommended)**

For streamlined BCC generation with batch processing support, use the **`generate_bcc.py` utility** in the `utils/` directory:

- **Python API** for programmatic integration into your scripts
- **Batch processing** for single binaries, directories, or lists of binaries
- **Parallel processing** support for faster batch operations
- **Configuration** via YAML file for easy customization

See the [utils README](utils/README.md) for complete documentation and examples.

**Quick Examples:**
```python
from utils.generate_bcc import generate_bcc_for_binary, generate_bcc_for_directory

# Generate BCC for a single binary
success = generate_bcc_for_binary("/bin/ls", "./output")

# Generate BCCs for all binaries in a directory (batch processing)
results = generate_bcc_for_directory(
    binary_dir="/firmware/bin",
    output_dir="./bccs",
    parallel=4
)
```

#### **Manual Headless Mode (Low-Level)**

For manual control or understanding the underlying process, example scripts are provided:

- **Linux**: `example_generate_bcc_headless.sh`
- **Windows**: `example_generate_bcc_headless.bat`

These scripts demonstrate how to directly configure and execute Ghidra's `analyzeHeadless` command for generating BCCs using the `GenerateBinaryContext.java` script.

### Building the Ghidra Plugin

The Ghidra plugin for **Blackfyre** uses the `protobuf-java` library bundled with **Ghidra 11.4.2**. This guide explains how to build the plugin using either Gradle or Eclipse GhidraDev.


#### Prerequisites

1. **Ghidra Installation**
   Ensure that Ghidra is installed on your system. For this guide, we use **Ghidra 11.4.2** as an example.

2. **Gradle Version**
   - **Ghidra 11.4.2** requires **Gradle 8.5** to build plugins.
   - If using a different version of Ghidra, refer to the [release notes](https://github.com/NationalSecurityAgency/ghidra/releases) for the correct Gradle version.

3. **Set `GHIDRA_INSTALL_DIR`**  
   The `GHIDRA_INSTALL_DIR` environment variable must point to your Ghidra installation directory. You can set it inline or as a persistent environment variable.

---

#### Building with Gradle (Recommended)

1. **Run the Gradle Build Command**  
   Navigate to the plugin's source directory and use the following command to build the plugin, where the build.gradle should be there. Replace `/path/to/ghidra/install/path` with the actual path to your Ghidra installation:

   ```bash
   GHIDRA_INSTALL_DIR=/path/to/ghidra/install/path gradle
   ```

2. **Verify the Build Output**  
   After the build completes successfully, the compiled plugin will be available in the `dist` directory.

3. **Deploy the Plugin**
   - Launch Ghidra.
   - Navigate to **File → Install Extensions** and enable the plugin.

#### Building with Eclipse GhidraDev (Optional for Debugging)

If you require debugging capabilities or a development environment, use Eclipse with the GhidraDev plugin.

1. **Install GhidraDev Plugin**  
   Follow the setup instructions in the [GhidraDev Plugin README](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/README.md).

2. **Import the Project**  
   Use the GhidraDev wizard to import the plugin project. The `build.gradle` file will manage all dependencies, including `protobuf-java`.

3. **Build the Plugin**  
   Use Eclipse’s build tools to compile the plugin. Eclipse will rely on the `build.gradle` file for dependency resolution.

4. **Test and Debug**  
   Deploy the plugin to Ghidra and use Eclipse’s debugging tools for development and troubleshooting.

#### Notes

- **Protobuf Dependency**:
  The plugin uses the `protobuf-java` library bundled with Ghidra 11.4.2. The dependency is automatically managed through the `build.gradle` file.

- **Gradle Version Compatibility**:
  - Use **Gradle 8.5** for **Ghidra 11.4.2**.
  - If using a different version of Ghidra, confirm the required Gradle version in the [Ghidra release notes](https://github.com/NationalSecurityAgency/ghidra/releases).

- **Debugging with GhidraDev**:
  Eclipse GhidraDev is recommended if you require enhanced debugging or development tools.

## Contributing

We welcome contributions to improve Blackfyre! Here's how you can contribute:
1. Fork the repository and create a new branch.
2. Submit a pull request with a clear description of your changes.
3. Ensure your contributions adhere to the repository's coding standards.

---

## License

Blackfyre is licensed under the [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)

