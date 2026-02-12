"""
AI Helper - Real integration with scan results
"""
import json
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "pentest.db"
LLAMA_PATH = BASE_DIR / "llama.cpp" / "build" / "bin" / "llama-cli"


def resolve_model() -> Path:
    preferred = [
        BASE_DIR / "models" / "qwen2.5-3b-instruct-q4_k_m.gguf",
        BASE_DIR / "models" / "mistral-7b-instruct-v0.2.Q4_K_M.gguf",
        BASE_DIR / "models" / "tinyllama.gguf",
    ]
    for p in preferred:
        if p.exists():
            return p
    matches = sorted((BASE_DIR / "models").glob("*.gguf"))
    return matches[0] if matches else preferred[-1]


MODEL_PATH = resolve_model()


def generate_ai_report(scan_id: int) -> str:
    print(f"🤖 Generating AI report for scan {scan_id}")

    if not LLAMA_PATH.exists():
        return "AI not available: llama.cpp not installed"

    if not MODEL_PATH.exists():
        return f"AI not available: no compatible GGUF model found in {BASE_DIR / 'models'}"

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        "SELECT target, tool, results FROM scans WHERE id=?",
        (scan_id,)
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return "AI report error: scan not found"

    target = row["target"]
    tool = row["tool"]
    results_json = row["results"]

    findings = "No significant findings."
    raw_output = ""

    if results_json:
        try:
            results = json.loads(results_json)
            raw_output = results.get("output", "")[:2000]
        except Exception:
            raw_output = "Unable to parse scan output."

    prompt = f"""
You are a cybersecurity expert.

Analyze the following scan results and generate:
1. Executive summary
2. Risk level
3. Key vulnerabilities
4. Actionable recommendations

Target: {target}
Tool: {tool}

Scan Output:
{raw_output}
"""

    try:
        proc = subprocess.run(
            [
                str(LLAMA_PATH),
                "-m", str(MODEL_PATH),
                "-p", prompt,
                "--temp", "0.2",
                "--ctx-size", "2048",
                "--n-predict", "400"
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        ai_output = proc.stdout.strip()
        if not ai_output:
            ai_output = "AI analysis produced no output."

    except Exception as e:
        ai_output = f"AI execution failed: {e}"

    return f"""
🤖 AI SECURITY ANALYSIS
======================
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target: {target}
Tool: {tool}

{ai_output}
"""
