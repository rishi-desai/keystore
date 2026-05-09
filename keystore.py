#!/usr/bin/env python3
"""
keys — API Key & Token Manager

Usage:
  keys                   interactive picker (fzf or numbered list, stays open)
  keys add               add a new key / token
  keys edit <name>       edit an existing key's name, folder, or value
  keys list              list all saved key names grouped by folder
  keys copy <name>       copy key to clipboard by name (fuzzy match)
  keys <name>            shortcut for copy
  keys delete <name>     delete a key by name (fuzzy match)
  keys setup             check dependencies and create ~/bin/keys symlink
  keys help              show this help

Keys are organised into optional folders/projects.
Master password is cached for the life of your terminal session.
Clipboard: uses pbcopy (macOS), clip.exe (WSL/Windows), xclip, or xsel.
Requires: pip install cryptography
Optional: sudo apt install fzf   (for live fuzzy search in the picker)
"""

import base64
import getpass as _getpass
import json
import os
import shutil
import subprocess
import sys

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

TOOL_DIR     = os.path.dirname(os.path.realpath(__file__))
VAULT_FILE   = os.path.join(TOOL_DIR, ".keys.enc")
APP_NAME     = "KEYS"
VERSION      = "1.0"
PBKDF2_ITERS = 480_000

class C:
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    CYAN   = "\033[96m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    RESET  = "\033[0m"

def col(color, text):
    return f"{color}{text}{C.RESET}"

# ---------------------------------------------------------------------------
# Session password cache  (keyed to parent shell PID)
# ---------------------------------------------------------------------------
def _cache_path():
    return f"/tmp/.keys_sess_{os.getppid()}"

def _parent_alive():
    ppid = os.getppid()
    if ppid <= 1:
        return False
    try:
        os.kill(ppid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True

def _save_cached_pw(pw):
    path = _cache_path()
    fd   = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(pw)

def _load_cached_pw():
    if not _parent_alive():
        return None
    path = _cache_path()
    if not os.path.exists(path):
        return None
    try:
        st = os.stat(path)
        if st.st_mode & 0o077:   # group/other readable — reject
            os.unlink(path)
            return None
        with open(path) as f:
            return f.read().strip() or None
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------
def _clipboard_backends():
    if sys.platform == "darwin":
        return [
            ("pbcopy (macOS)", ["pbcopy"], None),
            ("clip.exe (WSL/Windows)", ["clip.exe"], "utf-16-le"),
            ("xclip", ["xclip", "-selection", "clipboard"], None),
            ("xsel", ["xsel", "--clipboard", "--input"], None),
        ]
    return [
        ("clip.exe (WSL/Windows)", ["clip.exe"], "utf-16-le"),
        ("xclip", ["xclip", "-selection", "clipboard"], None),
        ("xsel", ["xsel", "--clipboard", "--input"], None),
    ]

def _available_clipboard_backend():
    for name, cmd, _encoding in _clipboard_backends():
        if shutil.which(cmd[0]):
            return name
    return None

def copy_to_clipboard(text):
    for _name, cmd, encoding in _clipboard_backends():
        try:
            subprocess.run(cmd, input=text.encode(encoding or "utf-8"),
                           check=True, stderr=subprocess.DEVNULL)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
    return False

# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------
def _derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=PBKDF2_ITERS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_vault(master_pw):
    if not CRYPTO_OK:
        die("cryptography not installed. Run: pip install cryptography")
    if not os.path.exists(VAULT_FILE):
        return []
    try:
        with open(VAULT_FILE) as f:
            raw  = json.load(f)
        salt = bytes.fromhex(raw["salt"])
        key  = _derive_key(master_pw, salt)
        data = Fernet(key).decrypt(raw["data"].encode()).decode()
        return json.loads(data)
    except (InvalidToken, KeyError, ValueError):
        return None

def save_vault(master_pw, keys):
    if not CRYPTO_OK:
        die("cryptography not installed. Run: pip install cryptography")
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE) as f:
            raw  = json.load(f)
        salt = bytes.fromhex(raw["salt"])
    else:
        salt = os.urandom(16)
    key  = _derive_key(master_pw, salt)
    data = Fernet(key).encrypt(json.dumps(keys).encode()).decode()
    fd   = os.open(VAULT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"salt": salt.hex(), "data": data}, f)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def die(msg):
    print(col(C.RED, f"  Error: {msg}"), file=sys.stderr)
    sys.exit(1)

def get_master_pw(confirm=False):
    """Return master password, using session cache when available."""
    cached = _load_cached_pw()
    if cached:
        if os.path.exists(VAULT_FILE):
            if load_vault(cached) is not None:
                return cached
        else:
            return cached   # new vault — any password is valid

    try:
        pw = _getpass.getpass("  Master password: ")
        if confirm:
            pw2 = _getpass.getpass("  Confirm password: ")
            if pw != pw2:
                die("Passwords do not match.")
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)

    _save_cached_pw(pw)
    return pw

def fuzzy_match(query, keys):
    q = query.lower()
    return [k for k in keys if q in k["name"].lower()
            or q in k.get("folder", "").lower()]

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_add():
    first_time = not os.path.exists(VAULT_FILE)
    if first_time:
        print(f"\n  {col(C.YELLOW, 'No vault found — creating a new encrypted vault.')}")
        print(f"  {col(C.DIM, 'Choose a strong master password to protect all your keys.')}\n")

    master_pw = get_master_pw(confirm=first_time)
    keys      = [] if first_time else load_vault(master_pw)
    if keys is None:
        die("Wrong master password.")

    print()
    try:
        name = input(f"  {col(C.CYAN, 'Key name')}: ").strip()
        if not name:
            print("  Cancelled.\n")
            return
        folder = input(f"  {col(C.CYAN, 'Folder/project')} {col(C.DIM, '(optional, Enter to skip)')}: ").strip()
        value = _getpass.getpass(f"  {col(C.CYAN, 'Key value')}: ")
        if not value:
            print("  Cancelled — no value entered.\n")
            return
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.\n")
        return

    keys.append({"name": name, "folder": folder, "value": value})
    save_vault(master_pw, keys)
    print(f"\n  {col(C.GREEN, '✓')} {col(C.BOLD, name)} saved.\n")


def cmd_edit(query):
    if not os.path.exists(VAULT_FILE):
        die("No vault found.")
    master_pw = get_master_pw()
    keys = load_vault(master_pw)
    if keys is None:
        die("Wrong master password.")

    matches = fuzzy_match(query, keys)
    if not matches:
        die(f"No key matching '{query}'.")
    if len(matches) == 1:
        target = matches[0]
    else:
        print(f"\n  Multiple matches for '{query}':\n")
        for i, k in enumerate(matches, 1):
            print(f"    {col(C.BOLD, str(i))}. {_make_display(k)}")
        try:
            raw = input(f"\n  Choose [1-{len(matches)}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)
        if not raw.isdigit() or not (1 <= int(raw) <= len(matches)):
            die("Invalid selection.")
        target = matches[int(raw) - 1]

    print(f"\n  Editing {col(C.BOLD, _make_display(target))}"
          f"  {col(C.DIM, '(Enter to keep current value)')}\n")
    try:
        new_name = input(
            f"  {col(C.CYAN, 'Key name')} [{target['name']}]: ").strip()
        cur_folder = target.get("folder", "")
        folder_prompt = f"  {col(C.CYAN, 'Folder/project')}"
        folder_hint   = f" [{cur_folder}]" if cur_folder else f" {col(C.DIM, '(blank to clear)')}"
        new_folder = input(f"{folder_prompt}{folder_hint}: ").strip()
        change_val = input(f"  {col(C.DIM, 'Change value? [y/N]')}: ").strip().lower()
        if change_val in ("y", "yes"):
            new_value = _getpass.getpass(f"  {col(C.CYAN, 'New key value')}: ")
            if not new_value:
                print("  Value unchanged.\n")
                new_value = target["value"]
        else:
            new_value = target["value"]
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.\n")
        return

    target["name"]   = new_name   if new_name   else target["name"]
    target["folder"] = new_folder if new_folder else ("" if not cur_folder else cur_folder)
    target["value"]  = new_value
    save_vault(master_pw, keys)
    print(f"\n  {col(C.GREEN, '✓')} {col(C.BOLD, target['name'])} updated.\n")


def _make_display(k):
    """Single-line display string for a key, including folder prefix if set."""
    folder = k.get("folder", "").strip()
    if folder:
        return f"{folder}  /  {k['name']}"
    return k["name"]


def _grouped(keys):
    """Return list of (folder_label, [keys]) sorted: named folders first, then ungrouped."""
    groups = {}
    for k in keys:
        f = k.get("folder", "").strip() or ""
        groups.setdefault(f, []).append(k)
    named   = sorted((f, ks) for f, ks in groups.items() if f)
    unnamed = groups.get("", [])
    return named + ([("ungrouped", unnamed)] if unnamed else [])


def cmd_list():
    if not os.path.exists(VAULT_FILE):
        print("\n  No vault found. Use 'keys add' to create one.\n")
        return
    master_pw = get_master_pw()
    keys = load_vault(master_pw)
    if keys is None:
        die("Wrong master password.")
    if not keys:
        print("\n  No keys stored yet. Use 'keys add'.\n")
        return
    print(f"\n  {col(C.BOLD, str(len(keys)) + ' key(s):')}\n")
    n = 1
    for folder_label, items in _grouped(keys):
        label = folder_label if folder_label != "ungrouped" else col(C.DIM, "ungrouped")
        print(f"  {col(C.YELLOW, label)}")
        for k in items:
            print(f"  {col(C.DIM, str(n).rjust(3))}.  {col(C.CYAN, k['name'])}")
            n += 1
        print()


def _pick_key(keys):
    """Returns a key dict chosen interactively, or None if cancelled.

    Uses fzf when available. Falls back to a numbered filter picker that
    works in any shell / terminal.
    """
    import shutil

    # Sort by folder then name so grouped entries appear together
    ordered = sorted(keys, key=lambda k: (k.get("folder", "").lower(), k["name"].lower()))
    display  = [_make_display(k) for k in ordered]

    # --- fzf path ---
    if shutil.which("fzf"):
        lines = "\n".join(display)
        try:
            result = subprocess.run(
                ["fzf", "--prompt", "  key> ", "--height", "50%",
                 "--layout", "reverse", "--border", "--info", "inline"],
                input=lines.encode(),
                stdout=subprocess.PIPE,  # capture selection only; fzf draws its TUI via the tty
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None
            chosen = result.stdout.decode().strip()
            # Match back by display string
            for k, d in zip(ordered, display):
                if d == chosen:
                    return k
            return None
        except Exception:
            pass  # fall through to numbered picker

    # --- numbered picker fallback ---
    print(f"  {col(C.BOLD, 'Select a key')}  "
          f"{col(C.DIM, '(number · text to filter · Ctrl+C to exit)')}\n")
    visible  = ordered
    vis_disp = display

    while True:
        # Print grouped
        seen_folder = None
        for i, (k, d) in enumerate(zip(visible, vis_disp), 1):
            folder = k.get("folder", "").strip()
            if folder != seen_folder:
                seen_folder = folder
                label = col(C.YELLOW, folder) if folder else col(C.DIM, "ungrouped")
                print(f"  {label}")
            print(f"  {col(C.DIM, str(i).rjust(3))}.  {col(C.CYAN, k['name'])}")
        print()
        try:
            raw = input("  > ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return None
        if not raw:
            # Reset filter and redisplay instead of quitting
            visible  = ordered
            vis_disp = display
            print()
            continue
        # Number selection
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(visible):
                return visible[idx]
            print(f"  {col(C.RED, 'Invalid number.')}\n")
            continue
        # Filter by substring across name and folder
        q = raw.lower()
        pairs = [(k, d) for k, d in zip(visible, vis_disp)
                 if q in k["name"].lower() or q in k.get("folder", "").lower()]
        if not pairs:
            print(f"  {col(C.YELLOW, 'No match — showing all.')}\n")
            visible  = ordered
            vis_disp = display
            continue
        if len(pairs) == 1:
            return pairs[0][0]
        visible, vis_disp = zip(*pairs)
        visible  = list(visible)
        vis_disp = list(vis_disp)
        print(f"  {col(C.DIM, str(len(visible)) + ' matches:')}\n")


def cmd_pick():
    """Interactive search & copy — stays open until Ctrl+C."""
    if not os.path.exists(VAULT_FILE):
        print("\n  No vault found. Use 'keys add' to create one.\n")
        return
    master_pw = get_master_pw()
    keys = load_vault(master_pw)
    if keys is None:
        die("Wrong master password.")
    if not keys:
        print("\n  No keys stored yet. Use 'keys add'.\n")
        return

    print(f"  {col(C.DIM, 'Ctrl+C to exit')}\n")
    try:
        while True:
            target = _pick_key(keys)
            if target is None:
                # fzf was cancelled (ESC/Ctrl+C propagates as returncode != 0)
                break
            ok = copy_to_clipboard(target["value"])
            if ok:
                print(f"  {col(C.GREEN, '✓')} {col(C.BOLD, target['name'])} copied — pick another or Ctrl+C to exit\n")
            else:
                print(col(C.RED, "  ✗ Clipboard unavailable."))
    except KeyboardInterrupt:
        print()


def cmd_copy(query):
    if not os.path.exists(VAULT_FILE):
        die("No vault found. Use 'keys add' first.")
    master_pw = get_master_pw()
    keys = load_vault(master_pw)
    if keys is None:
        die("Wrong master password.")

    matches = fuzzy_match(query, keys)
    if not matches:
        die(f"No key matching '{query}'.")
    if len(matches) == 1:
        target = matches[0]
    else:
        print(f"\n  Multiple matches for '{query}':\n")
        for i, k in enumerate(matches, 1):
            print(f"    {col(C.BOLD, str(i))}. {k['name']}")
        try:
            raw = input(f"\n  Choose [1-{len(matches)}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)
        if not raw.isdigit() or not (1 <= int(raw) <= len(matches)):
            die("Invalid selection.")
        target = matches[int(raw) - 1]

    ok = copy_to_clipboard(target["value"])
    if ok:
        print(f"  {col(C.GREEN, '✓')} {col(C.BOLD, target['name'])} copied to clipboard.")
    else:
        print(col(C.RED, "  ✗ Clipboard unavailable."))
        sys.exit(1)


def cmd_delete(query):
    if not os.path.exists(VAULT_FILE):
        die("No vault found.")
    master_pw = get_master_pw()
    keys = load_vault(master_pw)
    if keys is None:
        die("Wrong master password.")

    # Check for exact folder match first (case-insensitive)
    q_lower = query.lower()
    folder_keys = [k for k in keys if k.get("folder", "").lower() == q_lower]
    if folder_keys:
        folder_name = folder_keys[0].get("folder", "")
        print(f"\n  Folder {col(C.YELLOW, folder_name)} contains {len(folder_keys)} key(s):\n")
        for k in folder_keys:
            print(f"    {col(C.CYAN, k['name'])}")
        try:
            confirm = input(f"\n  Delete entire folder? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)
        if confirm not in ("y", "yes"):
            print("  Cancelled.\n")
            return
        to_delete = set(id(k) for k in folder_keys)
        keys = [k for k in keys if id(k) not in to_delete]
        save_vault(master_pw, keys)
        print(f"  {col(C.GREEN, '✓')} Deleted {len(folder_keys)} key(s).\n")
        return

    matches = fuzzy_match(query, keys)
    if not matches:
        die(f"No key matching '{query}'.")
    if len(matches) == 1:
        targets = matches
    else:
        print(f"\n  Multiple matches for '{query}':\n")
        for i, k in enumerate(matches, 1):
            folder = k.get("folder", "")
            suffix = f"  {col(C.DIM, folder)}" if folder else ""
            print(f"    {col(C.BOLD, str(i))}. {col(C.CYAN, k['name'])}{suffix}")
        print(f"\n  {col(C.DIM, 'Enter numbers to delete (e.g. 1 3) or \"all\":')}")
        try:
            raw = input(f"  Choose: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)
        if raw in ("all", "a"):
            targets = matches
        else:
            selected = []
            for part in raw.split():
                if part.isdigit() and 1 <= int(part) <= len(matches):
                    selected.append(matches[int(part) - 1])
            if not selected:
                die("Invalid selection.")
            targets = selected

    names = ", ".join(col(C.RED, k["name"]) for k in targets)
    try:
        confirm = input(f"  Delete {names}? [y/N]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print(); sys.exit(0)
    if confirm not in ("y", "yes"):
        print("  Cancelled.\n")
        return
    to_delete = set(id(k) for k in targets)
    keys = [k for k in keys if id(k) not in to_delete]
    save_vault(master_pw, keys)
    print(f"  {col(C.GREEN, '✓')} Deleted {len(targets)} key(s).\n")


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
def cmd_setup():
    """Walk a new user through installation and first-run checks."""
    script  = os.path.realpath(__file__)
    bin_dir = os.path.join(os.path.expanduser("~"), "bin")
    link    = os.path.join(bin_dir, "keys")

    print(f"\n  {col(C.BOLD + C.CYAN, f'{APP_NAME} v{VERSION} — Setup')}\n")

    # 1. Python version
    major, minor = sys.version_info[:2]
    ok   = major == 3 and minor >= 8
    mark = col(C.GREEN, "✓") if ok else col(C.RED, "✗")
    print(f"  {mark}  Python {major}.{minor}" + ("" if ok else "  (need 3.8+)"))

    # 2. cryptography
    if CRYPTO_OK:
        print(f"  {col(C.GREEN, '✓')}  cryptography package installed")
    else:
        print(f"  {col(C.RED, '✗')}  cryptography missing — run: {col(C.BOLD, 'pip install cryptography')}")

    # 3. fzf (optional but recommended for interactive search)
    if shutil.which("fzf"):
        print(f"  {col(C.GREEN, '✓')}  fzf installed (interactive search enabled)")
    else:
        print(f"  {col(C.DIM, '-')}  fzf not found (optional) — install for live fuzzy search:")
        print(f"        {col(C.BOLD, 'sudo apt install fzf')}  or  {col(C.BOLD, 'brew install fzf')}")

    # 4. Clipboard backend
    clip_backend = _available_clipboard_backend()
    if clip_backend:
        print(f"  {col(C.GREEN, '✓')}  Clipboard: {clip_backend}")
    else:
        if sys.platform == "darwin":
            print(f"  {col(C.RED, '✗')}  No clipboard backend — expected macOS pbcopy")
        else:
            print(f"  {col(C.RED, '✗')}  No clipboard backend — install xclip: {col(C.BOLD, 'sudo apt install xclip')}")

    # 5. ~/bin symlink
    os.makedirs(bin_dir, exist_ok=True)
    if os.path.islink(link) and os.readlink(link) == script:
        print(f"  {col(C.GREEN, '✓')}  ~/bin/keys symlink OK")
    else:
        try:
            if os.path.lexists(link):
                os.unlink(link)
            os.symlink(script, link)
            print(f"  {col(C.GREEN, '✓')}  Created ~/bin/keys → {script}")
        except OSError as e:
            print(f"  {col(C.RED, '✗')}  Could not create symlink: {e}")

    # 6. PATH check
    path_dirs = os.environ.get("PATH", "").split(":")
    if bin_dir in path_dirs:
        print(f"  {col(C.GREEN, '✓')}  ~/bin is on PATH")
    else:
        shell_rc = "~/.zshrc" if os.environ.get("SHELL", "").endswith("zsh") else "~/.bashrc"
        print(f"  {col(C.YELLOW, '!')}  ~/bin not on PATH — add to {shell_rc}:")
        print(f"        {col(C.BOLD, 'export PATH=\"$HOME/bin:$PATH\"')}")
        print(f"      then: {col(C.BOLD, f'source {shell_rc}')}")

    # 7. Vault status
    if os.path.exists(VAULT_FILE):
        print(f"  {col(C.GREEN, '✓')}  Vault found: {VAULT_FILE}")
    else:
        print(f"  {col(C.DIM, '-')}  No vault yet — run {col(C.BOLD, 'keys add')} to create one")

    print()


HELP = f"""
  {col(C.BOLD + C.CYAN, f'{APP_NAME} v{VERSION}')} — API Key & Token Manager

  {col(C.YELLOW, 'Usage:')}
    keys               interactive picker — stays open, Ctrl+C to exit
    keys add           add a new key  (prompts: name, folder, value)
    keys edit <name>   edit a key's name, folder, or value
    keys list          list all keys grouped by folder
    keys copy <name>   copy key to clipboard (fuzzy match on name/folder)
    keys <name>        shortcut for copy
    keys delete <name> delete a key (fuzzy match)
    keys setup         check dependencies and create ~/bin/keys symlink
    keys help          show this help

  {col(C.YELLOW, 'Folders:')}
    Keys can be grouped into folders/projects (optional).
    Leave folder blank when adding to keep a key ungrouped.
    Use 'keys edit <name>' to move a key to a different folder later.

  {col(C.YELLOW, 'Interactive picker (bare keys):')}
    fzf installed  → live fuzzy search, arrow keys, Enter to copy
    no fzf         → numbered list; type a number, or text to filter

  {col(C.YELLOW, 'Session password:')}
    Prompted once per terminal session — cached until you close the terminal.

  {col(C.YELLOW, 'Clipboard:')}
    pbcopy (macOS) → clip.exe (WSL/Windows) → xclip → xsel

  {col(C.YELLOW, 'Vault:')}
    {VAULT_FILE}  (AES-128-CBC · PBKDF2-SHA256 · {PBKDF2_ITERS:,} iters · mode 600)
"""

def main():
    args = sys.argv[1:]
    if not args:
        cmd_pick()
    elif args[0] in ("pick", "search", "find"):
        cmd_pick()
    elif args[0] in ("edit", "update", "rename"):
        if len(args) < 2:
            die("Usage: keys edit <name>")
        cmd_edit(" ".join(args[1:]))
    elif args[0] == "list":
        cmd_list()
    elif args[0] == "add":
        cmd_add()
    elif args[0] in ("copy", "cp"):
        if len(args) < 2:
            die("Usage: keys copy <name>")
        cmd_copy(" ".join(args[1:]))
    elif args[0] in ("delete", "del", "rm", "remove"):
        if len(args) < 2:
            die("Usage: keys delete <name>")
        cmd_delete(" ".join(args[1:]))
    elif args[0] in ("setup", "install"):
        cmd_setup()
    elif args[0] in ("help", "--help", "-h"):
        print(HELP)
    else:
        cmd_copy(" ".join(args))

if __name__ == "__main__":
    main()
