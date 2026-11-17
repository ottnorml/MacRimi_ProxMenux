"""Inert regression tests for Lynis detection and installation ownership (#675)."""
import ast
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
BASH = ROOT / "scripts/security/lynis_installer.sh"
PYTHON = ROOT / "AppImage/scripts/security_manager.py"
UI = ROOT / "AppImage/components/security.tsx"


def extracted_python(name, namespace):
    tree = ast.parse(PYTHON.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                 str(PYTHON), "exec"), namespace)
    return namespace[name]


class LynisDetection(unittest.TestCase):
    def test_bash_checks_debian_package_and_ownership(self):
        source = BASH.read_text()
        self.assertIn("/usr/sbin/lynis", source)
        self.assertIn('LYNIS_SOURCE="external"', source)
        self.assertIn("lynis_install_target_safe", source)
        self.assertIn('! -L /usr/local/bin/lynis', source)

    def detect_python(self, paths, git=False, wrapper=False):
        fake_path = SimpleNamespace(
            islink=lambda path: False,
            isdir=lambda path: git and path == "/opt/lynis/.git",
            isfile=lambda path: path in paths,
            isabs=os.path.isabs)
        fake_os = SimpleNamespace(path=fake_path,
                                  access=lambda path, mode: path in paths, X_OK=os.X_OK)
        ns = {"os": fake_os, "shutil": SimpleNamespace(which=lambda name: None),
              "_lynis_is_managed_wrapper": lambda: wrapper}
        return extracted_python("_find_lynis_installation", ns)()

    def test_python_finds_apt_with_restricted_path(self):
        self.assertEqual(self.detect_python({"/usr/sbin/lynis"}),
                         ("/usr/sbin/lynis", "external"))

    def test_python_keeps_legacy_path(self):
        self.assertEqual(self.detect_python({"/usr/bin/lynis"}),
                         ("/usr/bin/lynis", "external"))

    def test_verified_git_checkout_precedes_apt(self):
        paths = {"/usr/sbin/lynis", "/opt/lynis/lynis"}
        self.assertEqual(self.detect_python(paths, git=True, wrapper=True),
                         ("/usr/local/bin/lynis", "git"))
        self.assertEqual(self.detect_python(paths, git=True, wrapper=False),
                         ("/opt/lynis/lynis", "git"))

    def test_foreign_wrapper_is_not_git_managed(self):
        self.assertEqual(self.detect_python({"/usr/local/bin/lynis"}),
                         ("/usr/local/bin/lynis", "external"))

    def test_no_executable_is_not_installed(self):
        self.assertEqual(self.detect_python(set()), (None, "none"))

    def test_package_uninstall_refused_before_any_side_effect(self):
        fake_os = SimpleNamespace(path=SimpleNamespace(islink=lambda path: False),
                                  remove=lambda path: self.fail("unexpected removal"))
        ns = {"os": fake_os, "_find_lynis_installation":
              lambda: ("/usr/sbin/lynis", "external")}
        result = extracted_python("uninstall_lynis", ns)()
        self.assertFalse(result[0])
        self.assertEqual(result[3], "external_installation")

    def test_monitor_does_not_offer_git_uninstall_for_apt(self):
        source = UI.read_text()
        self.assertIn('lynisInfo?.installed && lynisInfo.source === "git"', source)

    def test_bash_detects_package_in_inert_filesystem(self):
        source = BASH.read_text()
        names = ("lynis_git_checkout", "lynis_is_managed_wrapper", "lynis_run", "detect_lynis")
        parts = []
        for name in names:
            match = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", source,
                              re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, name)
            parts.append(match.group())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "usr/sbin/lynis"
            package.parent.mkdir(parents=True)
            package.write_text("#!/bin/sh\necho 3.1.7\n")
            package.chmod(0o755)
            script = "\n".join(parts)
            for path in ("/usr/sbin/lynis", "/usr/bin/lynis",
                         "/usr/local/bin/lynis", "/opt/lynis"):
                script = script.replace(path, str(root / path.lstrip("/")))
            script += '\ndetect_lynis; printf "%s|%s|%s\\n" "$LYNIS_INSTALLED" "$LYNIS_SOURCE" "$LYNIS_VERSION"\n'
            result = subprocess.run(["bash", "-c", script], capture_output=True,
                                    text=True, env={**os.environ, "PATH": "/usr/bin:/bin"},
                                    timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "true|external|3.1.7")


    def test_package_symlink_is_not_a_safe_install_target(self):
        source = BASH.read_text()
        parts = []
        for name in ("lynis_is_managed_wrapper", "lynis_install_target_safe"):
            match = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", source,
                              re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, name)
            parts.append(match.group())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "opt/lynis/.git").mkdir(parents=True)
            package = root / "usr/sbin/lynis"
            package.parent.mkdir(parents=True)
            package.write_text("#!/bin/sh\necho package\n")
            package.chmod(0o755)
            wrapper = root / "usr/local/bin/lynis"
            wrapper.parent.mkdir(parents=True)
            wrapper.symlink_to(package)
            script = "\n".join(parts)
            for path in ("/usr/local/bin/lynis", "/opt/lynis"):
                script = script.replace(path, str(root / path.lstrip("/")))
            run = subprocess.run(["bash", "-c", script + "\nlynis_install_target_safe\n"],
                                 capture_output=True, text=True, timeout=10)
            self.assertNotEqual(run.returncode, 0, "A package symlink must never be replaced")
            wrapper.unlink()
            wrapper.write_text("#!/bin/bash\nexec /usr/sbin/lynis \"$@\"\n")
            wrapper.chmod(0o755)
            run = subprocess.run(["bash", "-c", script + "\nlynis_install_target_safe\n"],
                                 capture_output=True, text=True, timeout=10)
            self.assertNotEqual(run.returncode, 0, "A foreign wrapper must not be replaced")

    def test_git_detection_runs_without_wrapper(self):
        source = BASH.read_text()
        parts = []
        for name in ("lynis_git_checkout", "lynis_is_managed_wrapper", "lynis_run", "detect_lynis"):
            match = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", source,
                              re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, name)
            parts.append(match.group())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            git = root / "opt/lynis"
            (git / ".git").mkdir(parents=True)
            binary = git / "lynis"
            binary.write_text("#!/bin/sh\necho git-version\n")
            binary.chmod(0o755)
            pkg = root / "usr/sbin/lynis"
            pkg.parent.mkdir(parents=True)
            pkg.write_text("#!/bin/sh\necho package-version\n")
            pkg.chmod(0o755)
            script = "\n".join(parts)
            for path in ("/usr/sbin/lynis", "/usr/bin/lynis",
                         "/usr/local/bin/lynis", "/opt/lynis"):
                script = script.replace(path, str(root / path.lstrip("/")))
            script += '\ndetect_lynis; printf "%s|%s|%s\\n" "$LYNIS_INSTALLED" "$LYNIS_SOURCE" "$LYNIS_VERSION"\n'
            result = subprocess.run(["bash", "-c", script], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "true|git|git-version")




if __name__ == "__main__":
    unittest.main()
