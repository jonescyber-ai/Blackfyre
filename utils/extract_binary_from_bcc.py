#!/usr/bin/env python3
"""
Extract raw binary from a Blackfyre Binary Context Container (.bcc) file.

Usage:
    python -m labs.lab3.extract_binary_from_bcc <bcc_file> [output_directory]
"""

import argparse
import sys
import os

from blackfyre.datatypes.contexts.binarycontext import BinaryContext


def extract_binary(bcc_file_path: str, output_dir: str = "."):
    """
    Extract the raw binary from a .bcc file.

    Args:
        bcc_file_path: Path to the .bcc file
        output_dir: Directory where to save the extracted binary

    Returns:
        Path to the extracted binary file
    """
    if not os.path.exists(bcc_file_path):
        print(f"Error: BCC file not found: {bcc_file_path}", file=sys.stderr)
        return None

    print(f"Loading Binary Context Container: {bcc_file_path}")

    try:
        # Load with raw binary
        bc = BinaryContext.load_from_file(
            bcc_file_path,
            verify_sha_256_digest=True,
            load_raw_binary=True
        )

        print(f"✓ Loaded: {bc.name}")
        print(f"  SHA256: {bc.sha256_hash}")
        print(f"  Architecture: {bc.proc_type}")
        print(f"  File Type: {bc.file_type}")
        print(f"  Functions: {bc.total_functions}")

        # Check if raw binary is included
        if bc._raw_binary_file_bytes is None:
            print("✗ Error: Raw binary not included in BCC file", file=sys.stderr)
            print("  The BCC was created without --include-raw-binary flag", file=sys.stderr)
            return None

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Generate output filename
        output_file = os.path.join(output_dir, f"{bc.name}")

        # Write binary
        with open(output_file, 'wb') as f:
            f.write(bc._raw_binary_file_bytes)

        print(f"\n✓ Binary extracted to: {output_file}")
        print(f"  Size: {len(bc._raw_binary_file_bytes)} bytes")

        return output_file

    except Exception as e:
        print(f"✗ Error extracting binary: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Extract raw binary from Blackfyre Binary Context Container (.bcc)"
    )
    parser.add_argument(
        "bcc_file",
        help="Path to the .bcc file"
    )
    parser.add_argument(
        "output_dir",
        nargs='?',
        default=".",
        help="Output directory (default: current directory)"
    )

    args = parser.parse_args()

    result = extract_binary(args.bcc_file, args.output_dir)

    if result:
        print("\n" + "="*80)
        print("Extraction completed successfully!")
        print("="*80)
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
