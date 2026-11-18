"""Inert regression tests for Lynis detection and installation ownership (#675)."""
import ast
import io
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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
              "_lynis_is_managed_wrapper": lambda: wrapper,
              "_lynis_git_checkout_owned": lambda: git}
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
        names = ("lynis_is_managed_wrapper", "lynis_managed_marker", "lynis_git_checkout", "lynis_run", "detect_lynis")
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
        for name in ("lynis_is_managed_wrapper", "lynis_managed_marker", "lynis_git_checkout", "lynis_install_target_safe"):
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
        for name in ("lynis_is_managed_wrapper", "lynis_managed_marker", "lynis_git_checkout", "lynis_run", "detect_lynis"):
            match = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", source,
                              re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, name)
            parts.append(match.group())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            git = root / "opt/lynis"
            git.mkdir(parents=True)
            subprocess.run(["git", "-C", str(git), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(git), "remote", "add", "origin",
                            "https://github.com/CISOfy/lynis.git"], check=True)
            (git / ".proxmenux-managed").write_text("proxmenux-lynis-git-v1\n")
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




    def test_bash_foreign_wrapper_with_extra_commands_is_not_managed(self):
        source = BASH.read_text()
        match = re.search(r"^lynis_is_managed_wrapper\(\) \{\n.*?^\}\n",
                          source, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "lynis"
            path.write_text('#!/bin/bash\ncd /opt/lynis && ./lynis "$@"\necho foreign\n')
            path.chmod(0o755)
            func = match.group().replace("/usr/local/bin/lynis", str(path))
            actual = subprocess.run(["bash", "-c", func + "\nlynis_is_managed_wrapper\n"],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(actual.returncode, 0)
            path.write_text('#!/bin/bash\ncd /opt/lynis && ./lynis "$@"\n')
            actual = subprocess.run(["bash", "-c", func + "\nlynis_is_managed_wrapper\n"],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(actual.returncode, 0, actual.stderr)

    def test_python_foreign_wrapper_with_extra_commands_is_not_managed(self):
        path = "/usr/local/bin/lynis"
        fake_os = SimpleNamespace(path=SimpleNamespace(
            islink=lambda p: False, isfile=lambda p: p == path),
            access=lambda p, mode: True, X_OK=os.X_OK)
        run = extracted_python("_lynis_is_managed_wrapper", {"os": fake_os})
        exact = b'#!/bin/bash\ncd /opt/lynis && ./lynis "$@"\n'
        for contents, expected in ((exact, True), (exact + b"echo foreign\n", False)):
            with self.subTest(extra_bytes=len(contents)-len(exact)):
                with patch("builtins.open", side_effect=lambda *a, **k: io.BytesIO(contents)):
                    self.assertEqual(run(), expected)

    def test_bash_foreign_git_remote_is_never_proxmenux_owned(self):
        source = BASH.read_text()
        functions = []
        for name in ("lynis_is_managed_wrapper", "lynis_managed_marker", "lynis_git_checkout"):
            match = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", source,
                              re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, name)
            functions.append(match.group())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            git = root / "opt/lynis"
            git.mkdir(parents=True)
            subprocess.run(["git", "-C", str(git), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(git), "remote", "add", "origin",
                            "https://github.com/foreign/unrelated.git"], check=True)
            (git / "lynis").write_text("#!/bin/sh\necho foreign\n")
            (git / "lynis").chmod(0o755)
            (git / ".proxmenux-managed").write_text("proxmenux-lynis-git-v1\n")
            script = "\n".join(functions).replace("/opt/lynis", str(git))
            script = script.replace("/usr/local/bin/lynis", str(root / "usr/local/bin/lynis"))
            result = subprocess.run(["bash", "-c", script + "\nlynis_git_checkout\n"],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)

    def test_python_checkout_remote_and_marker(self):
        def check(remote, marker, wrapper):
            fake_path = SimpleNamespace(islink=lambda path: False,
                isdir=lambda path: path == "/opt/lynis/.git",
                isfile=lambda path: path == "/opt/lynis/lynis")
            fake_os = SimpleNamespace(path=fake_path,
                access=lambda p, mode: p == "/opt/lynis/lynis", X_OK=os.X_OK)
            process = SimpleNamespace(returncode=0, stdout=remote)
            runner = SimpleNamespace(run=lambda *args, **kwargs: process,
                                     TimeoutExpired=subprocess.TimeoutExpired)
            ns = {"os": fake_os, "subprocess": runner,
                  "_lynis_has_managed_marker": lambda: marker,
                  "_lynis_is_managed_wrapper": lambda: wrapper}
            return extracted_python("_lynis_git_checkout_owned", ns)()
        official = "https://github.com/CISOfy/lynis.git\n"
        foreign = "https://github.com/elsewhere/lynis.git\n"
        self.assertTrue(check(official, True, False))
        self.assertTrue(check(official, False, True))   # legacy
        self.assertFalse(check(official, False, False)) # unknown checkout
        self.assertFalse(check(foreign, True, True))    # spoofed marker

    def test_python_marker_requires_complete_contents(self):
        path = "/opt/lynis/.proxmenux-managed"
        fake_os = SimpleNamespace(path=SimpleNamespace(
            islink=lambda p: False, isfile=lambda p: p == path))
        check = extracted_python("_lynis_has_managed_marker", {"os": fake_os})
        good = b"proxmenux-lynis-git-v1\n"
        for contents, expected in ((good, True), (good + b"extra\n", False)):
            with patch("builtins.open", side_effect=lambda *a, **k: io.BytesIO(contents)):
                self.assertEqual(check(), expected)

    def test_python_git_checkout_requires_provenance(self):
        self.assertIn("def _lynis_git_checkout_owned():", PYTHON.read_text())
        self.assertIn("git -C", BASH.read_text())
        self.assertIn(".proxmenux-managed", BASH.read_text())
        self.assertIn(".proxmenux-managed", PYTHON.read_text())


    def test_monitor_git_version_runs_in_checkout_directory(self):
        # Inert AST execution: never invoke the actual Lynis executable.
        calls = []
        def run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return 0, "3.1.7", ""
        ns = {"os": SimpleNamespace(path=SimpleNamespace(isfile=lambda path: False)),
              "parse_lynis_report": lambda: None, "_run_cmd": run,
              "_find_lynis_installation": lambda: ("/opt/lynis/lynis", "git")}
        info = extracted_python("_detect_lynis", ns)()
        self.assertTrue(info["installed"])
        self.assertEqual(info["version"], "3.1.7")
        self.assertEqual(calls[0][1].get("cwd"), "/opt/lynis")
        calls.clear()
        ns["_find_lynis_installation"] = lambda: ("/usr/sbin/lynis", "external")
        extracted_python("_detect_lynis", ns)()
        self.assertIsNone(calls[0][1].get("cwd"))

    def test_monitor_git_audit_uses_checkout_cwd_for_pty_and_fallback(self):
        import threading
        for binary, expected_cwd in (("/opt/lynis/lynis", "/opt/lynis"),
                                     ("/usr/sbin/lynis", None)):
            with self.subTest(binary=binary):
                script_calls, fallback_calls = [], []
                def run_script(cmd, **kwargs):
                    script_calls.append((cmd, kwargs))
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                def run_fallback(cmd, **kwargs):
                    fallback_calls.append((cmd, kwargs))
                    return 0, "", ""
                fake_os = SimpleNamespace(
                    path=SimpleNamespace(isfile=lambda path: False),
                    environ={},
                    remove=lambda path: self.fail("unexpected file deletion"))
                ns = {"os": fake_os, "subprocess": SimpleNamespace(run=run_script),
                      "_run_cmd": run_fallback, "_find_lynis_cmd": lambda: binary,
                      "_state_lock": threading.Lock(),
                      "_lynis_audit_running": False, "_lynis_audit_progress": ""}
                audit = extracted_python("run_lynis_audit", ns)
                with patch("threading.Thread", side_effect=lambda target, daemon:
                           SimpleNamespace(start=target)):
                    accepted, _ = audit()
                self.assertTrue(accepted)
                self.assertEqual(ns["_lynis_audit_progress"], "completed")
                self.assertEqual(script_calls[0][1].get("cwd"), expected_cwd)
                self.assertEqual(fallback_calls[0][1].get("cwd"), expected_cwd)



    def test_lynis_terminal_catalog_filters(self):
        """Locale-only PRs must trigger the targeted Lynis workflow."""
        workflow = (ROOT / ".github/workflows/test-lynis.yml").read_text()
        for event, next_event in (
            ("push", "pull_request"),
            ("pull_request", "workflow_dispatch"),
        ):
            with self.subTest(event=event):
                start = f"  {event}:\\n"
                end = f"\\n  {next_event}:"
                self.assertIn(start, workflow)
                event_block = workflow.split(start, 1)[1].split(end, 1)[0]
                self.assertIn("'lang/*.json'", event_block)

    def test_terminal_safety_messages_have_all_supported_translations(self):
        """Prevent untranslated Lynis safety warnings on future locale edits."""
        import json
        keys = (
            "Existing Lynis files are not managed by ProxMenux. Refusing to overwrite them.",
            "Could not record Lynis installation ownership.",
            "Unsafe Lynis wrapper target. Refusing to overwrite it.",
            "This installation is externally managed. Use its package manager to update Lynis.",
            "This installation is externally managed. Use its package manager to remove Lynis.",
            "Use your package manager to update or remove this Lynis installation.",
        )
        for locale in ("de", "es", "fr", "it", "pt", "sk", "sv"):
            catalog = json.loads((ROOT / "lang" / f"{locale}.json").read_text())
            for key in keys:
                with self.subTest(locale=locale, key=key):
                    self.assertIn(key, catalog)
                    self.assertTrue(catalog[key].strip())


if __name__ == "__main__":
    unittest.main()
