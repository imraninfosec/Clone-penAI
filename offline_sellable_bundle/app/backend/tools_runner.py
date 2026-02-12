import subprocess
import json
import shlex
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = BASE_DIR / "tools"

def run_tool(tool, target):
    if tool == "nuclei":
        cmd = f"nuclei -u {target} -json"
    elif tool == "nikto":
        cmd = f"nikto -h {target} -Format json"
    elif tool == "katana":
        cmd = f"katana -u {target} -json"
    elif tool == "sqlmap":
        cmd = f"python3 {TOOLS_DIR / 'sqlmap' / 'sqlmap.py'} -u {target} --batch --output-dir=/tmp/sqlmap"
    else:
        raise ValueError("Unsupported tool")

    proc = subprocess.run(
        shlex.split(cmd),
        capture_output=True,
        text=True,
        timeout=1800
    )

    if proc.returncode != 0:
        raise RuntimeError(proc.stderr)

    return proc.stdout
