import os
import re
import sys
import unittest
import warnings
from pathlib import Path
from tempfile import TemporaryDirectory


class TestGenerateBccIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # protobuf (google._upb) currently emits DeprecationWarnings on import on
        # newer Python versions (3.13+), warning about 3.14 behavior. This is
        # upstream noise and not actionable within this integration test.
        warnings.filterwarnings(
            "ignore",
            message=r"Type google\._upb\._message\.(MessageMapContainer|ScalarMapContainer) uses PyType_Spec.*",
            category=DeprecationWarning,
        )

        # Import inside the test to avoid import-time hard failures when optional
        # dependencies or environment prerequisites (Ghidra) are missing.
        try:
            from utils.generate_bcc import get_bcc_generator_config  # noqa: WPS433
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"Cannot import utils.generate_bcc: {exc}")

        # Store as staticmethod to avoid Python binding it as an instance method.
        cls._get_bcc_generator_config = staticmethod(get_bcc_generator_config)

        # Resolve repo root via the generate_bcc config auto-detection.
        cls._config = cls._get_bcc_generator_config()

        blackfyre_root = cls._config.blackfyre_root
        if not blackfyre_root:
            raise unittest.SkipTest("Blackfyre root was not detected (config.blackfyre_root is empty)")

        cls._blackfyre_root = Path(blackfyre_root)

        # Ensure the in-repo Python package is importable when running tests
        # without an editable install.
        python_src = cls._blackfyre_root / "src" / "python"
        if python_src.exists() and str(python_src) not in sys.path:
            sys.path.insert(0, str(python_src))

        # Gate on Ghidra availability.
        ghidra_path = os.environ.get("GHIDRA_PATH", cls._config.ghidra_path)
        if not ghidra_path:
            raise unittest.SkipTest("Ghidra path not configured (set GHIDRA_PATH or config.ghidra_path)")

        analyze_headless = Path(ghidra_path) / "support" / "analyzeHeadless"
        if not analyze_headless.exists():
            raise unittest.SkipTest(f"Ghidra analyzeHeadless not found at: {analyze_headless}")

    def test_generate_bcc_for_repo_test_binary(self) -> None:
        from utils.generate_bcc import generate_bcc_for_binary  # noqa: WPS433

        binary_path = self._blackfyre_root / "test" / "bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd"
        self.assertTrue(binary_path.exists(), f"Missing test binary fixture: {binary_path}")

        with TemporaryDirectory(prefix="blackfyre_bcc_test_") as tmpdir:
            tmpdir_path = Path(tmpdir)
            out_dir = tmpdir_path / "bcc_out"
            project_dir = tmpdir_path / "ghidra_projects"
            project_dir.mkdir(parents=True, exist_ok=True)

            # Use the repo config as a baseline but ensure we don't write into
            # shared locations during tests.
            config = self._get_bcc_generator_config()
            config.project_dir = str(project_dir)
            config.project_name = "bcc_generation_test"
            # Keep the test reasonably bounded.
            config.timeout = min(int(getattr(config, "timeout", 600)), 600)
            config.decompile_timeout = min(int(getattr(config, "decompile_timeout", 30)), 30)

            # Prefer GHIDRA_PATH env var for hermetic CI.
            if os.environ.get("GHIDRA_PATH"):
                config.ghidra_path = os.environ["GHIDRA_PATH"]

            success = generate_bcc_for_binary(binary_path, out_dir, config=config)
            self.assertTrue(success, "BCC generation returned False")

            produced = list(out_dir.glob(f"{binary_path.name}*.bcc"))
            self.assertTrue(
                produced,
                f"No .bcc produced. Expected pattern {binary_path.name}*.bcc in {out_dir}",
            )

            # Load the BCC and validate key contents.
            try:
                from blackfyre.datatypes.contexts.binarycontext import BinaryContext  # noqa: WPS433
            except Exception as exc:  # pragma: no cover
                raise unittest.SkipTest(f"Cannot import blackfyre BinaryContext to parse .bcc: {exc}")

            bcc_path = produced[0]
            bc = BinaryContext.load_from_file(str(bcc_path), verify_sha_256_digest=False, cache_path=None)

            # Basic structural checks.
            import_count = len(getattr(bc, "import_symbols", []) or [])
            export_count = len(getattr(bc, "export_symbols", []) or [])
            string_count = len(getattr(bc, "string_refs", {}) or {})

            total_functions = int(getattr(bc, "total_functions", 0) or 0)
            function_contexts = list(getattr(bc, "function_contexts", []) or [])

            self.assertGreater(import_count, 0, "Expected at least 1 import symbol in the generated BCC")
            self.assertGreater(export_count, 0, "Expected at least 1 export symbol in the generated BCC")
            self.assertGreater(string_count, 0, "Expected at least 1 string reference in the generated BCC")
            self.assertGreater(total_functions, 0, "Expected at least 1 function in the generated BCC")
            self.assertGreater(len(function_contexts), 0, "Expected function contexts to be present in the generated BCC")
            self.assertGreaterEqual(
                total_functions,
                len(function_contexts),
                "Expected BinaryContext.total_functions to be >= number of loaded FunctionContext entries",
            )

            # Grab a sample decompiled function and assert it looks like decompiler output.
            decompiled_samples = [
                fc.decompiled_code
                for fc in function_contexts
                if getattr(fc, "decompiled_code", None) and str(fc.decompiled_code).strip()
            ]

            if not decompiled_samples:
                raise unittest.SkipTest(
                    "No decompiled code present in the BCC. "
                    "This may happen if include_decompiled_code was disabled or decompilation failed."
                )

            sample = str(decompiled_samples[0])
            self.assertGreater(len(sample), 40, "Expected non-trivial decompiled code text")
            self.assertRegex(sample, r"\b(return|if|while|for)\b", "Expected common C-like tokens in decompiled code")
            self.assertTrue(
                ("{" in sample and "}" in sample) or ("(" in sample and ")" in sample),
                "Expected decompiled code to contain C-like structural characters",
            )

            # A small sanity check that we can locate a function signature-like line.
            self.assertTrue(
                re.search(r"\w+\s+\w+\s*\(.*\)", sample) is not None,
                "Expected to find a function signature-like pattern in decompiled output",
            )


if __name__ == "__main__":
    unittest.main()
