import shutil
import subprocess
import unittest

from asustor_nas_cli.platform import (
    DRIVER_MODULES,
    build_module_change_command,
    build_module_preflight_command,
)
from asustor_nas_cli.security import build_scan_command
from asustor_nas_cli.smart_health import build_smart_health_command


class RemoteCommandSyntaxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shell = shutil.which("sh")
        if cls.shell is None:
            raise unittest.SkipTest("a POSIX shell is not available for syntax checks")

    def assert_shell_syntax(self, command):
        result = subprocess.run(
            [self.shell, "-n"],
            input=command,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_scanner_and_smart_commands_parse_as_posix_shell(self):
        self.assert_shell_syntax(build_scan_command(10, 5))
        self.assert_shell_syntax(build_smart_health_command())

    def test_module_operation_commands_parse_as_posix_shell(self):
        target = {module: True for module in DRIVER_MODULES}
        current = {module: False for module in DRIVER_MODULES}
        self.assert_shell_syntax(build_module_change_command(target))
        self.assert_shell_syntax(build_module_preflight_command(target, current))


if __name__ == "__main__":
    unittest.main()
