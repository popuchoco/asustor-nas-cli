# Installation

This guide installs the `adm` command on Windows, macOS, and Ubuntu. The project requires Python 3.11 or newer, Git for the tagged-source install, and the operating system's OpenSSH client for NAS connections. It has no runtime Python dependencies.

The package is not currently published to PyPI. Install the reviewed GitHub tag with `pipx`; a tag build does not publish the package to PyPI.

```text
git+https://github.com/popuchoco/asustor-nas-cli.git@v1.9.0
```

## Windows 10 / 11

1. Install Python 3.14 from [python.org](https://www.python.org/downloads/windows/). Keep the Python launcher (`py`) enabled. The project minimum is Python 3.11, and CI tests Python 3.11–3.14.
2. Install [Git for Windows](https://git-scm.com/download/win) if `git --version` is not available.
3. Ensure the OpenSSH Client optional feature is installed. In Settings, open **System → Optional features → View features**, search for **OpenSSH Client**, and install it if needed. See [Microsoft's OpenSSH installation guide](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse).
4. In PowerShell, install `pipx` using a supported Python version:

   ```powershell
   py -3.14 -m pip install --user pipx
   py -3.14 -m pipx ensurepath
   ```

   Close and reopen PowerShell after `ensurepath` so the updated `PATH` is loaded.

5. Install the tagged release and check the command:

   ```powershell
   pipx install --python 3.14 "git+https://github.com/popuchoco/asustor-nas-cli.git@v1.9.0"
   adm --version
   adm --help
   ssh -V
   ```

## macOS

1. Install [Homebrew](https://docs.brew.sh/Installation) if it is not already installed.
2. Install Python, `pipx`, and Git:

   ```console
   brew install python@3.14 pipx git
   pipx ensurepath
   ```

   Open a new terminal after `ensurepath`.

3. Install the tagged release and check the commands:

   ```console
   pipx install --python 3.14 "git+https://github.com/popuchoco/asustor-nas-cli.git@v1.9.0"
   adm --version
   adm --help
   ssh -V
   ```

## Ubuntu 24.04 LTS or newer

1. Install the system Python tools, `pipx`, Git, and OpenSSH Client:

   ```console
   sudo apt update
   sudo apt install python3 python3-venv pipx git openssh-client
   ```

2. Confirm that `python3 --version` is 3.11 or newer, then make the `pipx` command available:

   ```console
   python3 --version
   pipx ensurepath
   ```

   Open a new terminal after `ensurepath`.

3. Install the tagged release and check the commands:

   ```console
   pipx install --python python3 "git+https://github.com/popuchoco/asustor-nas-cli.git@v1.9.0"
   adm --version
   adm --help
   ssh -V
   ```

Ubuntu releases whose system Python is older than 3.11 need a separate supported Python interpreter. Keep Ubuntu's system Python in place, install Python 3.11 or newer through an approved Python distribution method, and pass that interpreter to `pipx install --python`.

## First connection

Set the NAS address and account for the current shell, then run a read-only status query. Replace the placeholders with your own values; do not put passwords in shell commands or scripts.

```console
adm status --host nas.example --user nas-user
```

The CLI uses the operating system's `ssh` client. Password authentication, when enabled by the NAS, is requested interactively. The MCP server uses SSH batch mode and requires a working key or agent. See [troubleshooting](docs/TROUBLESHOOTING.md) for SSH and certificate issues.

For a local editable checkout, offline wheel installs, or optional PyPI publication setup, see [publishing and package builds](docs/PUBLISHING.md).
