import subprocess
import unittest
from unittest.mock import MagicMock, patch

from asustor_nas_cli import __version__
from asustor_nas_cli.client import inspect_adm_portal, run_ssh


class ClientTests(unittest.TestCase):
    def test_https_user_agent_uses_package_version(self):
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"<html>ASUSTOR</html>"
        context = MagicMock()
        context.__enter__.return_value = response
        with patch("asustor_nas_cli.client.urlopen", return_value=context) as urlopen:
            inspect_adm_portal("nas.example", 8001, 3, insecure=True)

        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("User-agent"), f"asustor-nas-cli/{__version__}")

    def test_ssh_connect_timeout_uses_cli_timeout(self):
        completed = subprocess.CompletedProcess([], 0, "ready", "")
        with (
            patch("asustor_nas_cli.client.shutil.which", return_value="ssh"),
            patch("asustor_nas_cli.client.subprocess.run", return_value=completed) as subprocess_run,
            patch("asustor_nas_cli.client.sys.stdin", MagicMock(isatty=lambda: False)),
            patch("asustor_nas_cli.client.sys.stderr", MagicMock(isatty=lambda: False)),
        ):
            self.assertEqual(run_ssh("nas.example", "nas-user", 22, "true", 17), "ready")

        self.assertIn("ConnectTimeout=17", subprocess_run.call_args.args[0])
        self.assertEqual(subprocess_run.call_args.kwargs["timeout"], 45)


if __name__ == "__main__":
    unittest.main()
