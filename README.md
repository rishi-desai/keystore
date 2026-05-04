# keys — API Key & Token Manager

A simple CLI tool to securely store and copy API keys, PATs, and access tokens to your clipboard.  
Works in **WSL**, **MobaXterm**, **PowerShell** (via Git Bash / Python), and native Linux.

Keys are encrypted at rest. Your master password is asked **once per terminal session** — cached until you close that terminal.

---

## Features

- Encrypted vault (AES-128-CBC + PBKDF2-SHA256, 480k iterations)
- Clipboard support — `clip.exe` on WSL/Windows, `xclip`/`xsel` on Linux
- Session password cache — one prompt per terminal, then silent
- Organise keys into **folders/projects** (optional)
- Interactive picker (`keys` with no args) — stays open, Ctrl+C to exit
- Live fuzzy search with `fzf` if installed, numbered list fallback otherwise
- Direct copy shortcut: `keys github` fuzzy-matches name or folder and copies instantly
- Works fully offline, no external services

---

## Requirements

| Dependency        | Required | Notes                                    |
| ----------------- | -------- | ---------------------------------------- |
| Python 3.8+       | **Yes**  | Pre-installed on most systems            |
| `cryptography`    | **Yes**  | `pip install cryptography`               |
| `fzf`             | No       | Live fuzzy search in the picker          |
| `clip.exe`        | No       | Pre-installed in WSL — Windows clipboard |
| `xclip` or `xsel` | No       | Native Linux clipboard                   |

---

## Installation

> Choose the section for your environment. Run `keys setup` at the end — it checks dependencies and creates the `keys` command automatically.

### WSL (Ubuntu / Debian)

```bash
# Install Python dependencies
pip install cryptography

# Optional: live fuzzy search
sudo apt install fzf

# Clone the repo
git clone https://github.com/rishi-desai/keystore.git

# Run setup (creates ~/bin/keys and checks everything)
cd ~/.../keystore/
python3 keystore.py setup
```

If `~/bin` is not on your PATH yet, setup will tell you. Add this to `~/.bashrc` or `~/.zshrc` and restart your terminal:

```bash
export PATH="$HOME/bin:$PATH"
```

---

### MobaXterm

MobaXterm has a built-in Linux environment with Python. Open a MobaXterm local terminal and follow the same steps as WSL above.

If `pip` is not found, use:

```bash
python3 -m pip install cryptography
```

Clipboard is handled via `xclip` if you have an X server active (MobaXterm runs one by default):

```bash
apt install xclip
```

Or just skip it — if neither `xclip` nor `clip.exe` is found, the tool will print the key value instead so you can copy it manually.

---

### PowerShell / Git Bash (Windows, no WSL)

Python must be installed and on your PATH. Download from [python.org](https://www.python.org/downloads/) if needed.

**Git Bash:**

```bash
pip install cryptography

# Clone the repo
git clone https://github.com/rishi-desai/keystore.git

# Run setup
cd ~/.../keystore/
python3 keystore.py setup
```

**PowerShell:**

```powershell
pip install cryptography

# Clone the repo
git clone https://github.com/rishi-desai/keystore.git

# Run setup
cd keystore/
python "~/.../keystore.py" setup
```

> In PowerShell the `keys` shortcut won't be available (no `~/bin` on PATH by default). Use the full command `python "~/.../keystore.py" <args>`, or add a PowerShell alias to your profile:
>
> ```powershell
> # Add to $PROFILE (run: notepad $PROFILE)
> function keys { python "keystore.py" @args }
> ```

`clip.exe` is already available in PowerShell and Git Bash — clipboard copy works out of the box.

---

## Keeping it up to date

To pull the latest version of the tool (your vault is never touched by git):

```bash
cd keystore/
git pull
```

That's it. Your `.keys.enc` vault is listed in `.gitignore` and will never be modified or overwritten by a pull.

---

## Usage

| Command              | What it does                                          |
| -------------------- | ----------------------------------------------------- |
| `keys`               | Interactive picker — stays open until Ctrl+C          |
| `keys add`           | Add a new key (prompts: name, folder, value)          |
| `keys edit <name>`   | Edit a key's name, folder, or value                   |
| `keys list`          | List all keys grouped by folder                       |
| `keys <name>`        | Copy key to clipboard (fuzzy match on name or folder) |
| `keys copy <name>`   | Same as above                                         |
| `keys delete <name>` | Delete a key (or multiple), or delete a whole folder  |
| `keys setup`         | Check dependencies and create `~/bin/keys` symlink    |
| `keys help`          | Show help                                             |

### Examples

```bash
# Add a key with an optional folder
keys add
#   Key name: GitHub PAT - work
#   Folder/project (optional): github
#   Key value: <hidden>
#   ✓ GitHub PAT - work saved.

# Copy it — fuzzy matches name or folder
keys github
#   ✓ GitHub PAT - work copied to clipboard.

# Open the interactive picker (stays open until Ctrl+C)
keys
#   Select a key  (number · text to filter · Ctrl+C to exit)
#
#   github
#      1.  GitHub PAT - work
#   AWS
#      2.  prod access key
#   > _

# List everything grouped by folder
keys list
#   3 key(s):
#
#   AWS
#      1.  prod access key
#      2.  staging access key
#   github
#      3.  GitHub PAT - work

# Edit a key (rename, move folder, or update value)
keys edit "prod access"
#   Editing AWS  /  prod access key
#   Key name [prod access key]:
#   Folder/project [AWS]: aws-prod
#   Change value? [y/N]: n
#   ✓ prod access key updated.

# Delete one key
keys delete staging
#   Delete AWS  /  staging access key? [y/N]: y
#   ✓ Deleted 1 key(s).

# Delete multiple keys — type space-separated numbers, or "all"
keys delete aws
#   Multiple matches for 'aws':
#     1. prod access key   AWS
#     2. staging access key  AWS
#   Enter numbers to delete (e.g. 1 3) or "all":
#   Choose: 1 2
#   Delete prod access key, staging access key? [y/N]: y
#   ✓ Deleted 2 key(s).

# Delete a whole folder — match the folder name exactly
keys delete AWS
#   Folder AWS contains 2 key(s):
#     prod access key
#     staging access key
#   Delete entire folder? [y/N]: y
#   ✓ Deleted 2 key(s).
```

---

## Security

| Property       | Detail                                                          |
| -------------- | --------------------------------------------------------------- |
| Encryption     | Fernet (AES-128-CBC + HMAC-SHA256)                              |
| Key derivation | PBKDF2-SHA256, 480,000 iterations                               |
| Vault file     | `~/.../keystore/.keys.enc` — mode `600` (owner read/write only) |
| Session cache  | `/tmp/.keys_sess_<ppid>` — mode `600`, tied to your shell PID   |

The vault file is safe to back up — it cannot be decrypted without your master password.  
**Never commit `.keys.enc` to version control.** It is listed in `.gitignore` to prevent this.

---

## Moving your vault to a new machine

```bash
# Copy your vault to the new machine
scp ~/.../keystore/.keys.enc <new-machine>:~/keystore/.keys.enc

# Then run keys normally — you'll be prompted for your master password once
keys
```

