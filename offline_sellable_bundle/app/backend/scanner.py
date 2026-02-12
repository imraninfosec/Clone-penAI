"""
Simple scanner module - runs security tools
"""
import json
import asyncio
import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "pentest.db"
TOOLS_DIR = BASE_DIR / "tools"
LOG_DIR = BASE_DIR / "logs"

def update_scan_in_db(scan_id, status, results=None):
    """Update scan status in database"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    if results:
        cur.execute(
            "UPDATE scans SET status=?, results=? WHERE id=?",
            (status, results, scan_id)
        )
    else:
        cur.execute(
            "UPDATE scans SET status=? WHERE id=?",
            (status, scan_id)
        )
    
    conn.commit()
    conn.close()
    print(f"✅ Scan {scan_id} updated to: {status}")

async def run_scan(scan_id: int, target: str, tool: str):
    """Run a security scan"""
    print(f"🚀 Starting scan {scan_id} with {tool} on {target}")
    update_scan_in_db(scan_id, "running")
    
    # Fix target if needed
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"
    
    log_file = LOG_DIR / f"scan_{scan_id}.log"
    
    try:
        # Build command based on tool
        if tool == "nuclei":
            cmd = [str(TOOLS_DIR / "nuclei"), "-u", target, "-json", "-silent", "-timeout", "30"]
        elif tool == "katana":
            cmd = [str(TOOLS_DIR / "katana"), "-u", target, "-jc"]
        elif tool == "nikto":
            cmd = ["perl", str(TOOLS_DIR / "nikto/program/nikto.pl"), "-h", target, "-Tuning", "123"]
        elif tool == "sqlmap":
            cmd = ["python3", str(TOOLS_DIR / "sqlmap/sqlmap.py"), "-u", target, "--batch", "--level=1", "--risk=1"]
        else:
            error_msg = f"Unsupported tool: {tool}"
            update_scan_in_db(scan_id, "failed", json.dumps({"error": error_msg}))
            return
        
        print(f"📝 Running command: {' '.join(cmd)}")
        
        # Run the command with timeout
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Wait for completion (5 minutes max)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            error_msg = "Scan timed out after 5 minutes"
            update_scan_in_db(scan_id, "failed", json.dumps({"error": error_msg}))
            return
        
        # Prepare results
        result = {
            "tool": tool,
            "target": target,
            "return_code": proc.returncode,
            "stdout": stdout.decode('utf-8', errors='ignore')[:5000] if stdout else "",
            "stderr": stderr.decode('utf-8', errors='ignore') if stderr else "",
            "timestamp": datetime.utcnow().isoformat(),
            "success": proc.returncode == 0
        }
        
        # Save log
        log_file.write_text(json.dumps(result, indent=2))
        
        # Update database
        if proc.returncode == 0:
            update_scan_in_db(scan_id, "completed", json.dumps(result))
            print(f"✅ Scan {scan_id} completed successfully")
        else:
            update_scan_in_db(scan_id, "failed", json.dumps(result))
            print(f"❌ Scan {scan_id} failed with code {proc.returncode}")
            
    except Exception as e:
        error_msg = f"Scan error: {str(e)}"
        print(f"❌ Error in scan {scan_id}: {error_msg}")
        
        error_result = {
            "tool": tool,
            "target": target,
            "error": error_msg,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        log_file.write_text(json.dumps(error_result, indent=2))
        update_scan_in_db(scan_id, "failed", json.dumps(error_result))
