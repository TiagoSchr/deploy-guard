"""Tests for CLI interface."""

import pytest
from deploy_guard.cli import main


class TestCLI:
    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_scan_clean_file(self):
        """Clean backend should exit 0."""
        import os
        tests_dir = os.path.dirname(__file__)
        clean = os.path.join(tests_dir, "scenario-6-clean-backend.js")
        if os.path.exists(clean):
            exit_code = main([clean, "--target", "backend", "--no-banner"])
            assert exit_code == 0

    def test_scan_insecure_file(self):
        """Insecure file should exit 1 (block)."""
        import os
        tests_dir = os.path.dirname(__file__)
        insecure = os.path.join(tests_dir, "scenario-1-github-actions.yml")
        if os.path.exists(insecure):
            exit_code = main([insecure, "--no-banner"])
            assert exit_code == 1

    def test_json_output(self, capsys):
        """JSON output should be valid JSON."""
        import os, json
        tests_dir = os.path.dirname(__file__)
        clean = os.path.join(tests_dir, "scenario-6-clean-backend.js")
        if os.path.exists(clean):
            main([clean, "--format", "json", "--no-banner"])
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "summary" in data

    def test_nonexistent_path(self):
        exit_code = main(["/nonexistent/path", "--no-banner"])
        assert exit_code == 2

    def test_exit_zero_flag(self):
        """--exit-zero should always return 0."""
        import os
        tests_dir = os.path.dirname(__file__)
        insecure = os.path.join(tests_dir, "scenario-1-github-actions.yml")
        if os.path.exists(insecure):
            exit_code = main([insecure, "--exit-zero", "--no-banner"])
            assert exit_code == 0
