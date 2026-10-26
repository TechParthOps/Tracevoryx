import glob
import os
import shutil

# clean the real runtime store of demo-era data and issue a fresh token
# without printing it (operator reads it from the file)
from tracevoryx.config import get_settings

data_dir = get_settings().data_dir
print("data dir:", data_dir)

# is a server still running?
import socket

s = socket.socket()
s.settimeout(1)
running = s.connect_ex(("127.0.0.1", 8640)) == 0
s.close()
if running:
    print("ERROR: TrustWeave is still running on port 8640 - stop it first (scripts\\stop.ps1)")
    raise SystemExit(1)

from tracevoryx.state import reset_state

reset_state()
removed = 0
for pattern in ("trustweave.db*", "api_tokens.json", "audit_key",
                "tw_instance.json", "audit_export_*.jsonl",
                "current_admin_token.txt"):
    for f in glob.glob(str(data_dir / pattern)):
        os.remove(f)
        removed += 1
for d in ("exchange_tmp", "exchange_inbox", "uploads", "keys", "logs"):
    p = data_dir / d
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)

from tracevoryx.state import bootstrap_tokens

token = bootstrap_tokens(data_dir)
token_file = data_dir / "current_admin_token.txt"
token_file.write_text(token, encoding="utf-8")
print(f"removed {removed} item(s); production store is now clean")
print(f"fresh admin token written to: {token_file} (not displayed here)")
