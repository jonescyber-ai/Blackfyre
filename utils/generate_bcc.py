#!/usr/bin/env python3
"""
BCC (Binary Context Container) Generation Utility

This utility wraps Ghidra's headless analyzer to generate BCC files from binary executables.
BCC files contain lifted VEX IR, decompiled code, and other metadata used by binql-lite for
binary analysis.

Configuration is managed via bcc_generator_config.yaml using OmegaConf (following the
lab_common.llm design pattern).

Usage:
    # Activate virtual environment first
    source venv/bin/activate

    # Run with -m flag
    python -m utils.generate_bcc --binary /path/to/binary --output-dir /path/to/output
    python -m utils.generate_bcc --binary-dir /path/to/binaries --output-dir /path/to/output
    python -m utils.generate_bcc --binary-list binaries.txt --output-dir /path/to/output

Requirements:
    - Ghidra installed (configure in bcc_generator_config.yaml or use --ghidra-path)
    - GenerateBinaryContext.java script (should be in Blackfyre/examples/ghidra/)
    - Virtual environment activated with required dependencies

Examples:
    # Activate venv first
    source venv/bin/activate

    # Generate BCC for a single binary (uses config defaults)
    python -m utils.generate_bcc --binary /bin/ls --output-dir ./output

    # Generate BCCs for all binaries in a directory (parallel)
    python -m utils.generate_bcc --binary-dir /firmware/bin --output-dir ./bccs --parallel 4

    # Generate BCCs from a list of binaries with verbose output
    python -m utils.generate_bcc --binary-list binaries.txt --output-dir ./bccs -v

Public API Usage (programmatic):
    from utils.generate_bcc import generate_bcc_for_binary, generate_bcc_for_directory, generate_bcc_for_list
    from blackfyre.common import VerbosityLevel

    # Single binary - pass output directory (Blackfyre generates ls.bcc)
    success = generate_bcc_for_binary("/bin/ls", "./output", verbosity=VerbosityLevel.SILENT.value)

    # Directory - generates *.bcc files in ./bccs/ directory
    results = generate_bcc_for_directory("/firmware/bin", "./bccs", parallel=4, verbosity=VerbosityLevel.NORMAL.value)

    # List - generates *.bcc files in ./bccs/ directory
    binaries = ["/bin/ls", "/bin/cat"]
    results = generate_bcc_for_list(binaries, "./bccs", verbosity=VerbosityLevel.VERBOSE.value)

Verbosity Levels:
    - VerbosityLevel.SILENT (0): No output, no progress bars
    - VerbosityLevel.NORMAL (1): Standard logging with progress bars (default)
    - VerbosityLevel.VERBOSE (2): Detailed logging with progress bars
"""

import os
import sys
import argparse
import subprocess
import logging
import re
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass
from concurrent.futures import ProcessPoolExecutor, as_completed
from omegaconf import OmegaConf
from tqdm import tqdm

# Module-level logger (will be overridden in __main__ for proper naming)
logger = logging.getLogger(__name__)

# Public API
__all__ = [
    "BCCGeneratorConfig",
    "BCCGenerator",
    "get_bcc_generator_config",
    "generate_bcc_for_binary",
    "generate_bcc_for_directory",
    "generate_bcc_for_list",
]


@dataclass
class BCCGeneratorConfig:
    """
    Configuration for BCC Generator.

    This dataclass is populated from bcc_generator_config.yaml using OmegaConf.
    Follows the same design pattern as lab_common.llm.LLMClientConfig.

    Attributes:
        ghidra_path: Path to Ghidra installation directory
        blackfyre_root: Path to Blackfyre root directory (auto-detected if None)
        script_path: Path to GenerateBinaryContext.java (auto-constructed if None)
        project_dir: Temporary directory for Ghidra projects
        project_name: Base name for Ghidra projects
        include_raw_binary: Whether to include raw binary bytes in BCC
        include_decompiled_code: Whether to include decompiled code in BCC
        decompile_timeout: Timeout for decompilation in seconds
        parallel: Default number of parallel workers for batch processing
        timeout: Timeout for entire Ghidra analysis process in seconds
        output_dir: Default output directory for generated BCC files
    """
    ghidra_path: str = "/opt/ghidra_11.2.1_PUBLIC"
    blackfyre_root: Optional[str] = None
    script_path: Optional[str] = None
    project_dir: str = "/tmp"
    project_name: str = "bcc_generation"
    include_raw_binary: bool = True
    include_decompiled_code: bool = True
    decompile_timeout: int = 30
    parallel: int = 1
    timeout: int = 300
    output_dir: str = "./bccs"


def get_bcc_generator_config(config_path: Optional[Path] = None) -> BCCGeneratorConfig:
    """
    Load the BCC generator configuration from a YAML file.

    Follows the same pattern as lab_common.llm.get_llm_client_config().

    Args:
        config_path: Path to config file (defaults to utils/bcc_generator_config.yaml)

    Returns:
        BCCGeneratorConfig instance with values loaded from YAML

    Raises:
        FileNotFoundError: If config file doesn't exist (falls back to defaults with warning)
    """
    if config_path is None:
        # Default to config file in same directory as this script
        config_path = Path(__file__).parent / "bcc_generator_config.yaml"

    if not config_path.exists():
        logger.warning(f"Config file not found: {config_path}, using defaults")
        return BCCGeneratorConfig()

    # Set PROJECT_ROOT environment variable if not already set
    # This must be done BEFORE OmegaConf.load() to allow interpolation
    if "PROJECT_ROOT" not in os.environ:
        # Assume this script is in utils/ subdirectory of project root
        project_root = Path(__file__).parent.parent.absolute()
        os.environ["PROJECT_ROOT"] = str(project_root)

    # Register custom resolver for OmegaConf to access environment variables
    # Use oc.env: prefix in YAML, e.g., ${oc.env:PROJECT_ROOT}
    if not OmegaConf.has_resolver("env"):
        OmegaConf.register_new_resolver("env", lambda var, default=None: os.environ.get(var, default))

    # Load config with OmegaConf (will resolve ${oc.env:PROJECT_ROOT} from environment)
    cfg = OmegaConf.load(config_path)
    cfg = OmegaConf.to_container(cfg, resolve=True)
    config = BCCGeneratorConfig(**cfg[BCCGeneratorConfig.__name__])

    # Resolve environment variables in paths
    if config.ghidra_path and "${" in config.ghidra_path:
        config.ghidra_path = os.path.expandvars(config.ghidra_path)

    if config.blackfyre_root and "${" in config.blackfyre_root:
        config.blackfyre_root = os.path.expandvars(config.blackfyre_root)

    # Auto-construct script_path from blackfyre_root if not explicitly set
    if config.script_path is None and config.blackfyre_root:
        config.script_path = str(Path(config.blackfyre_root) / "src" / "ghidra" / "Blackfyre" / "ghidra_scripts" / "GenerateBinaryContext.java")

    return config


class BCCGenerator:
    """
    BCC (Binary Context Container) generator using Ghidra headless analyzer.

    This class wraps Ghidra's analyzeHeadless command to generate BCC files from
    binary executables. BCC files contain VEX IR, decompiled code, and metadata
    used by binql-lite for binary analysis.

    Attributes:
        config: BCCGeneratorConfig instance with generation settings
        ghidra_path: Path to Ghidra installation
        project_dir: Path to temporary project directory
        analyze_headless: Path to Ghidra's analyzeHeadless script
        script_path: Path to GenerateBinaryContext.java script
    """

    def __init__(self, config: BCCGeneratorConfig) -> None:
        """
        Initialize BCC generator with configuration.

        Args:
            config: BCCGeneratorConfig instance

        Raises:
            FileNotFoundError: If Ghidra analyzeHeadless or script not found
        """
        self.config = config
        self.ghidra_path = Path(config.ghidra_path)
        self.project_dir = Path(config.project_dir)

        # Validate Ghidra installation
        self.analyze_headless = self.ghidra_path / "support" / "analyzeHeadless"
        if not self.analyze_headless.exists() or not self.analyze_headless.is_file():
            raise FileNotFoundError(
                f"Ghidra analyzeHeadless not found at: {self.analyze_headless}"
            )

        # Auto-detect or validate script path
        if config.script_path is None:
            self.script_path = self._find_script()
        else:
            self.script_path = Path(config.script_path)
            if not self.script_path.exists():
                raise FileNotFoundError(f"Script not found: {self.script_path}")

        logger.info(f"Initialized BCC generator with Ghidra: {self.ghidra_path}")
        logger.info(f"Using script: {self.script_path}")
        logger.info(f"Configuration:")
        logger.info(f"  Include raw binary: {self.config.include_raw_binary}")
        logger.info(f"  Include decompiled code: {self.config.include_decompiled_code}")
        logger.info(f"  Decompile timeout: {self.config.decompile_timeout}s")
        logger.info(f"  Process timeout: {self.config.timeout}s")

    def _find_script(self) -> Path:
        """
        Auto-detect GenerateBinaryContext.java script location.

        Searches common locations relative to this file and current directory.

        Returns:
            Path to GenerateBinaryContext.java script

        Raises:
            FileNotFoundError: If script cannot be found in any search location
        """
        # Check if blackfyre_root is set in config
        if self.config.blackfyre_root:
            blackfyre_path = Path(self.config.blackfyre_root) / "src" / "ghidra" / "Blackfyre" / "ghidra_scripts" / "GenerateBinaryContext.java"
            if blackfyre_path.exists():
                logger.debug(f"Found script at: {blackfyre_path}")
                return blackfyre_path

        # Check common locations relative to this file
        search_paths = [
            Path(__file__).parent.parent / "Blackfyre" / "src" / "ghidra" / "Blackfyre" / "ghidra_scripts" / "GenerateBinaryContext.java",
            Path(__file__).parent.parent / "Blackfyre" / "examples" / "ghidra" / "GenerateBinaryContext.java",
            Path(__file__).parent.parent / "Blackfyre" / "ghidra_scripts" / "GenerateBinaryContext.java",
            Path.cwd() / "Blackfyre" / "src" / "ghidra" / "Blackfyre" / "ghidra_scripts" / "GenerateBinaryContext.java",
        ]

        for path in search_paths:
            if path.exists():
                logger.debug(f"Found script at: {path}")
                return path

        raise FileNotFoundError(
            "Could not find GenerateBinaryContext.java script. "
            "Please specify blackfyre_root or script_path in config or ensure Blackfyre is in the correct location."
        )

    def generate_bcc(
        self,
        binary_path: Path,
        output_path: Path,
        project_name: Optional[str] = None,
        show_progress: bool = True,
    ) -> bool:
        """
        Generate BCC file for a single binary.

        Args:
            binary_path: Path to input binary executable
            output_path: Path to output directory (e.g., "./output")
                        Blackfyre generates binary_name.bcc in this directory
            project_name: Ghidra project name (uses config default + PID if None)
            show_progress: Whether to show detailed progress bars (default: True)

        Returns:
            True if BCC generation succeeded, False otherwise
        """
        binary_path = Path(binary_path).absolute()
        output_dir = Path(output_path).absolute()

        if not binary_path.exists():
            logger.error(f"Binary not found: {binary_path}")
            return False

        # Create output directory if needed (must exist before Ghidra runs)
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Ensured output directory exists: {output_dir}")

        # Generate unique project name to avoid conflicts
        if project_name is None:
            project_name = f"{self.config.project_name}_{binary_path.stem}_{os.getpid()}"

        logger.info(f"Generating BCC for: {binary_path}")
        logger.info(f"  Output will be saved to: {output_dir}")
        logger.debug(f"  Output directory for Ghidra: {output_dir}")
        logger.debug(f"  Project: {self.project_dir / project_name}")

        # Build Ghidra analyzeHeadless command
        # Note: Script expects absolute path to output directory (not filename)
        cmd = [
            str(self.analyze_headless),
            str(self.project_dir),
            project_name,
            "-import", str(binary_path),
            "-deleteProject",
            "-scriptPath", str(self.script_path.parent),
            "-postScript", self.script_path.name,
            str(output_dir.absolute()),  # Must be absolute path
            str(self.config.include_raw_binary).lower(),
            str(self.config.include_decompiled_code).lower(),
            str(self.config.decompile_timeout),
        ]

        logger.debug(f"Executing: {' '.join(cmd)}")

        try:
            # Check if we're in verbose mode
            verbose_mode = logging.getLogger().level <= logging.DEBUG

            # Always stream output to capture progress bars
            if verbose_mode:
                logger.info("=" * 80)
                logger.info("Ghidra Analysis Output:")
                logger.info("=" * 80)

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            # Show initial progress indicator only if show_progress is True
            if show_progress:
                print(f"⏳ Starting Ghidra analysis for {binary_path.name}...", flush=True)

            # Regex patterns to parse progress
            progress_pattern = re.compile(r'\[(\d+)/(\d+)\]\s+Processed (Function|Export Symbol|Import Symbol|String Reference|Caller to Callees):\s*(.+)')

            # Track progress bars for different stages
            progress_bars = {}
            first_progress_seen = False

            # Stream output line by line
            for line in process.stdout:
                # Check if this is a progress line
                match = progress_pattern.search(line)
                if match:
                    # Only show detailed progress if requested
                    if show_progress:
                        # Clear the initial progress indicator on first progress line
                        if not first_progress_seen:
                            print("\r" + " " * 80 + "\r", end='', flush=True)  # Clear the waiting message
                            first_progress_seen = True

                        current = int(match.group(1))
                        total = int(match.group(2))
                        stage = match.group(3)
                        item = match.group(4)

                        # Create or update progress bar for this stage
                        if stage not in progress_bars:
                            progress_bars[stage] = tqdm(
                                total=total,
                                desc=f"  {stage}s",
                                unit=stage.lower(),
                                leave=False,
                                position=0
                            )

                        # Update progress bar
                        progress_bars[stage].n = current
                        progress_bars[stage].set_postfix_str(item[:40])  # Show item name (truncated)
                        progress_bars[stage].refresh()
                else:
                    # Only print non-progress lines in verbose mode
                    if verbose_mode:
                        print(line, end='')

            # Close all progress bars
            for pbar in progress_bars.values():
                pbar.close()

            process.wait(timeout=self.config.timeout)
            returncode = process.returncode

            if verbose_mode:
                logger.info("=" * 80)
                logger.info("End Ghidra Output")
                logger.info("=" * 80)

            if returncode == 0:
                # Check if BCC file was created
                # Ghidra script creates files with pattern: {binary_name}_{sha256}.bcc
                # Look for any .bcc file in the output directory matching the binary name
                matching_bccs = list(output_dir.glob(f"{binary_path.name}*.bcc"))

                if matching_bccs:
                    # Found at least one BCC file - keep it with its generated name
                    generated_bcc = matching_bccs[0].absolute()
                    logger.info(f"✓ Successfully generated: {generated_bcc}")
                    return True
                else:
                    logger.error("=" * 80)
                    logger.error(f"✗✗✗ FAILED: BCC file was not created for '{binary_path.name}'")
                    logger.error(f"    Output directory: {output_dir}")
                    logger.error(f"    Expected pattern: {binary_path.name}*.bcc")
                    logger.error(f"    Ghidra may have failed to analyze this file (not a valid binary?)")
                    logger.error("=" * 80)
                    return False
            else:
                logger.error("=" * 80)
                logger.error(f"✗✗✗ FAILED: Ghidra analysis failed for '{binary_path.name}'")
                logger.error(f"    Exit code: {returncode}")
                logger.error(f"    Binary: {binary_path}")
                logger.error("=" * 80)
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"✗ Timeout generating BCC for: {binary_path} (limit: {self.config.timeout}s)")
            return False
        except Exception as e:
            logger.error(f"✗ Error generating BCC: {e}")
            return False

    def generate_batch(
        self,
        binary_paths: List[Path],
        output_dir: Path,
        parallel: Optional[int] = None,
        verbosity: Optional[int] = None,
    ) -> Dict[str, int]:
        """
        Generate BCC files for multiple binaries.

        Args:
            binary_paths: List of binary file paths to process
            output_dir: Output directory for BCC files
            parallel: Number of parallel workers (uses config default if None)
            verbosity: VerbosityLevel (0=SILENT, 1=NORMAL, 2=VERBOSE). None uses logger level.

        Returns:
            Dict with 'success', 'failed', and 'total' counts
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if parallel is None:
            parallel = self.config.parallel

        # Only log if not SILENT
        if verbosity is None or verbosity > 0:
            logger.info(f"Generating BCCs for {len(binary_paths)} binaries")
            logger.info(f"Output directory: {output_dir}")
            logger.info(f"Parallel workers: {parallel}")

        results = {"success": 0, "failed": 0, "total": len(binary_paths)}

        # Suppress progress bars if SILENT
        show_progress = verbosity is None or verbosity > 0

        if parallel == 1:
            # Sequential processing - show detailed progress for each binary
            if show_progress:
                with tqdm(total=len(binary_paths), desc="Overall Progress", unit="binary") as pbar:
                    for binary_path in binary_paths:
                        pbar.set_postfix_str(f"Processing {binary_path.name[:30]}")
                        if self.generate_bcc(binary_path, output_dir, show_progress=True):
                            results["success"] += 1
                        else:
                            results["failed"] += 1
                        pbar.update(1)
            else:
                for binary_path in binary_paths:
                    if self.generate_bcc(binary_path, output_dir, show_progress=False):
                        results["success"] += 1
                    else:
                        results["failed"] += 1
        else:
            # Parallel processing with process pool - use high-level progress bar only
            with ProcessPoolExecutor(max_workers=parallel) as executor:
                futures = {}
                for binary_path in binary_paths:
                    # Disable detailed progress for parallel execution to avoid conflicts
                    future = executor.submit(self.generate_bcc, binary_path, output_dir, show_progress=False)
                    futures[future] = binary_path

                if show_progress:
                    with tqdm(total=len(binary_paths), desc="Overall Progress", unit="binary", position=0) as pbar:
                        for future in as_completed(futures):
                            binary_path = futures[future]
                            try:
                                if future.result():
                                    results["success"] += 1
                                    pbar.set_postfix_str(f"✓ {binary_path.name[:30]}")
                                else:
                                    results["failed"] += 1
                                    pbar.set_postfix_str(f"✗ {binary_path.name[:30]}")
                            except Exception as e:
                                if verbosity != 0:  # Not SILENT
                                    logger.error(f"Exception processing {binary_path}: {e}")
                                results["failed"] += 1
                            pbar.update(1)
                else:
                    for future in as_completed(futures):
                        binary_path = futures[future]
                        try:
                            if future.result():
                                results["success"] += 1
                            else:
                                results["failed"] += 1
                        except Exception as e:
                            results["failed"] += 1

        # Only show summary if not SILENT
        if verbosity is None or verbosity > 0:
            logger.info(f"\n{'='*80}")
            logger.info(f"BCC Generation Summary:")
            logger.info(f"  Total Processed: {results['total']}")
            logger.info(f"  ✓ Success:       {results['success']}")
            logger.info(f"  ✗ Failed:        {results['failed']}")
            logger.info(f"{'='*80}")

        return results


def generate_bcc_for_binary(
    binary_path: str | Path,
    output_path: str | Path,
    config: Optional[BCCGeneratorConfig] = None,
    verbosity: Optional[int] = None,
) -> bool:
    """
    Public API: Generate BCC file for a single binary.

    This is the recommended public API for programmatic BCC generation from Python code.

    Args:
        binary_path: Path to input binary executable
        output_path: Path to output directory (e.g., "./output")
                    Blackfyre generates binary_name.bcc in this directory
        config: BCCGeneratorConfig instance (uses defaults if None)
        verbosity: VerbosityLevel (0=SILENT, 1=NORMAL, 2=VERBOSE). None uses logger level.

    Returns:
        True if BCC generation succeeded, False otherwise

    Raises:
        FileNotFoundError: If binary doesn't exist or Ghidra/script not found
        Exception: For other configuration or generation errors

    Example:
        >>> from utils.generate_bcc import generate_bcc_for_binary
        >>> from blackfyre.common import VerbosityLevel
        >>> # Pass output directory - Blackfyre generates ls.bcc automatically
        >>> success = generate_bcc_for_binary("/bin/ls", "./output")
        >>> # Silent mode
        >>> success = generate_bcc_for_binary("/bin/ls", "./output", verbosity=VerbosityLevel.SILENT.value)
        >>> if success:
        ...     print("BCC generated: ./output/ls.bcc")
    """
    if config is None:
        config = get_bcc_generator_config()

    # Suppress logger output if SILENT
    if verbosity == 0:  # SILENT
        original_level = logger.level
        logger.setLevel(logging.CRITICAL + 1)  # Suppress all output

    try:
        generator = BCCGenerator(config)
        show_progress = verbosity is None or verbosity > 0
        return generator.generate_bcc(Path(binary_path), Path(output_path), show_progress=show_progress)
    finally:
        if verbosity == 0:  # Restore logger level
            logger.setLevel(original_level)


def generate_bcc_for_directory(
    binary_dir: str | Path,
    output_dir: str | Path,
    config: Optional[BCCGeneratorConfig] = None,
    parallel: Optional[int] = None,
    verbosity: Optional[int] = None,
) -> Dict[str, int]:
    """
    Public API: Generate BCC files for all binaries in a directory.

    This is the recommended public API for batch BCC generation from Python code.

    Args:
        binary_dir: Directory containing binary files
        output_dir: Output directory for BCC files
        config: BCCGeneratorConfig instance (uses defaults if None)
        parallel: Number of parallel workers (uses config default if None)
        verbosity: VerbosityLevel (0=SILENT, 1=NORMAL, 2=VERBOSE). None uses logger level.

    Returns:
        Dict with 'success', 'failed', 'total', and 'skipped' counts

    Raises:
        FileNotFoundError: If binary_dir doesn't exist or Ghidra/script not found
        NotADirectoryError: If binary_dir is not a directory
        Exception: For other configuration or generation errors

    Example:
        >>> from utils.generate_bcc import generate_bcc_for_directory
        >>> from blackfyre.common import VerbosityLevel
        >>> # Normal output with progress bars
        >>> results = generate_bcc_for_directory("/firmware/bin", "./bccs", parallel=4)
        >>> # Silent mode (no output)
        >>> results = generate_bcc_for_directory("/firmware/bin", "./bccs", parallel=4, verbosity=VerbosityLevel.SILENT.value)
        >>> print(f"Generated {results['success']}/{results['total']} BCCs")
    """
    binary_dir = Path(binary_dir)
    output_dir = Path(output_dir)

    if not binary_dir.exists():
        raise FileNotFoundError(f"Binary directory not found: {binary_dir}")
    if not binary_dir.is_dir():
        raise NotADirectoryError(f"Not a directory: {binary_dir}")

    if config is None:
        config = get_bcc_generator_config()

    # Extensions to skip (non-binary files)
    skip_extensions = {'.bcc', '.json', '.txt', '.xml', '.yaml', '.yml', '.md', '.log', '.conf', '.cfg'}

    # Get all files from directory, filtering out non-binary files
    all_files = [f for f in binary_dir.iterdir() if f.is_file()]
    binary_paths = []
    skipped_count = 0

    for file_path in all_files:
        # Skip files with known non-binary extensions
        if file_path.suffix.lower() in skip_extensions:
            if verbosity is None or verbosity > 0:  # Not SILENT
                logger.info(f"⊘ Skipping non-binary file: {file_path.name}")
            skipped_count += 1
            continue
        binary_paths.append(file_path)

    if skipped_count > 0 and (verbosity is None or verbosity > 0):  # Not SILENT
        logger.info(f"Skipped {skipped_count} non-binary file(s)")

    if not binary_paths:
        if verbosity is None or verbosity > 0:  # Not SILENT
            logger.warning(f"No binary files found in: {binary_dir}")
        return {"success": 0, "failed": 0, "total": 0, "skipped": skipped_count}

    # Suppress logger output if SILENT
    if verbosity == 0:  # SILENT
        original_level = logger.level
        logger.setLevel(logging.CRITICAL + 1)  # Suppress all output

    try:
        generator = BCCGenerator(config)
        results = generator.generate_batch(binary_paths, output_dir, parallel=parallel, verbosity=verbosity)
        results["skipped"] = skipped_count
        return results
    finally:
        if verbosity == 0:  # Restore logger level
            logger.setLevel(original_level)


def generate_bcc_for_list(
    binary_list: List[str | Path],
    output_dir: str | Path,
    config: Optional[BCCGeneratorConfig] = None,
    parallel: Optional[int] = None,
    verbosity: Optional[int] = None,
) -> Dict[str, int]:
    """
    Public API: Generate BCC files for a list of binaries.

    This is the recommended public API for batch BCC generation from a list of paths.

    Args:
        binary_list: List of binary file paths
        output_dir: Output directory for BCC files
        config: BCCGeneratorConfig instance (uses defaults if None)
        parallel: Number of parallel workers (uses config default if None)
        verbosity: VerbosityLevel (0=SILENT, 1=NORMAL, 2=VERBOSE). None uses logger level.

    Returns:
        Dict with 'success', 'failed', and 'total' counts

    Raises:
        FileNotFoundError: If Ghidra/script not found
        Exception: For other configuration or generation errors

    Example:
        >>> from utils.generate_bcc import generate_bcc_for_list
        >>> from blackfyre.common import VerbosityLevel
        >>> binaries = ["/bin/ls", "/bin/cat", "/bin/grep"]
        >>> results = generate_bcc_for_list(binaries, "./bccs", parallel=2, verbosity=VerbosityLevel.SILENT.value)
        >>> print(f"Success: {results['success']}, Failed: {results['failed']}")
    """
    output_dir = Path(output_dir)

    if config is None:
        config = get_bcc_generator_config()

    # Convert to Path objects
    binary_paths = [Path(p) for p in binary_list]

    if not binary_paths:
        if verbosity is None or verbosity > 0:  # Not SILENT
            logger.warning("Empty binary list provided")
        return {"success": 0, "failed": 0, "total": 0}

    # Suppress logger output if SILENT
    if verbosity == 0:  # SILENT
        original_level = logger.level
        logger.setLevel(logging.CRITICAL + 1)  # Suppress all output

    try:
        generator = BCCGenerator(config)
        return generator.generate_batch(binary_paths, output_dir, parallel=parallel, verbosity=verbosity)
    finally:
        if verbosity == 0:  # Restore logger level
            logger.setLevel(original_level)


def main() -> None:
    """
    Main entry point for BCC generation utility.

    Parses command-line arguments, loads configuration, initializes generator,
    and processes binaries according to specified input mode (single, directory, or list).
    """
    parser = argparse.ArgumentParser(
        description="Generate BCC (Binary Context Container) files using Ghidra",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--binary",
        type=Path,
        help="Path to single binary file"
    )
    input_group.add_argument(
        "--binary-dir",
        type=Path,
        help="Directory containing binaries (non-recursive)"
    )
    input_group.add_argument(
        "--binary-list",
        type=Path,
        help="Text file with binary paths (one per line)"
    )

    # Output options
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory for BCC files (works for all modes)"
    )

    # Configuration options
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration YAML file (default: utils/bcc_generator_config.yaml)"
    )
    parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Override Ghidra path from config"
    )
    parser.add_argument(
        "--parallel",
        type=int,
        help="Override parallel workers from config"
    )

    # Logging options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load configuration from YAML
    try:
        config = get_bcc_generator_config(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    # Apply CLI overrides to config
    if args.ghidra_path:
        config.ghidra_path = str(args.ghidra_path)
    if args.output_dir:
        config.output_dir = str(args.output_dir)
    if args.parallel is not None:
        config.parallel = args.parallel

    # Check if Ghidra path is set, try environment variable as fallback
    if not config.ghidra_path or config.ghidra_path == "/opt/ghidra_11.2.1_PUBLIC":
        if "GHIDRA_PATH" in os.environ:
            config.ghidra_path = os.environ["GHIDRA_PATH"]
            logger.info(f"Using GHIDRA_PATH from environment: {config.ghidra_path}")

    # Initialize generator
    try:
        generator = BCCGenerator(config)
    except Exception as e:
        logger.error(f"Failed to initialize BCC generator: {e}")
        sys.exit(1)

    # Process binaries based on input mode
    try:
        if args.binary:
            # Single binary mode
            output_dir = Path(args.output_dir) if args.output_dir else Path(config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / f"{args.binary.name}.bcc"
            success = generator.generate_bcc(args.binary, output_path)
            sys.exit(0 if success else 1)

        elif args.binary_dir:
            # Directory mode - use the public API function which handles filtering
            output_dir = Path(args.output_dir) if args.output_dir else Path(config.output_dir)
            results = generate_bcc_for_directory(
                binary_dir=args.binary_dir,
                output_dir=output_dir,
                config=config,
                parallel=args.parallel
            )

            # Display final summary with skipped files
            if results.get("skipped", 0) > 0:
                logger.info(f"⊘ Skipped: {results['skipped']} non-binary file(s)")

            sys.exit(0 if results["failed"] == 0 else 1)

        elif args.binary_list:
            # List mode - read paths from file
            with open(args.binary_list, 'r') as file:
                binary_paths = [
                    Path(line.strip()) for line in file
                    if line.strip() and not line.strip().startswith('#')
                ]

            if not binary_paths:
                logger.error(f"No binaries found in list: {args.binary_list}")
                sys.exit(1)

            output_dir = Path(args.output_dir) if args.output_dir else Path(config.output_dir)
            results = generator.generate_batch(binary_paths, output_dir)
            sys.exit(0 if results["failed"] == 0 else 1)

    except KeyboardInterrupt:
        logger.warning("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    # Override logger to use actual module name instead of __main__
    # This ensures log messages show "generate_bcc" instead of "__main__"
    module_name = Path(__file__).stem

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    logger = logging.getLogger(module_name)

    main()
