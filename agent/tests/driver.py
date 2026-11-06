"""Run the agent once in its own process, optionally crashing hard at a named failpoint.

Used by the crash-recovery tests: ``os._exit`` skips every ``finally`` and ``atexit``, so the
on-disk state afterwards is what a power cut or ``kill -9`` would leave.
"""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rootsentinel_agent.client import GatewayClient  # noqa: E402
from rootsentinel_agent.fsutil import read_credentials  # noqa: E402
from rootsentinel_agent.journal import Journal  # noqa: E402
from rootsentinel_agent.pipeline import Agent, AgentConfig, Failpoints  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--base-url", required=True)
parser.add_argument("--origin", required=True)
parser.add_argument("--credentials-file", type=Path, required=True)
parser.add_argument("--crash")
parser.add_argument("--max-wait", type=float, default=30.0)
args = parser.parse_args()

creds, _ = read_credentials(args.credentials_file)
root = args.root
config = AgentConfig(root / "staging", root / "outbound", root / "quarantine", root / "state", creds,
                     poll_interval=0.02, settle_seconds=0.05, wait_scale=0.01, unavailable_wait=0.05,
                     min_relogin=0.0, retry_base=0.01, retry_cap=0.05, rate_per_minute=100000)
journal = Journal(root / "state" / "journal.jsonl")
journal.open()
agent = Agent(config, GatewayClient(args.base_url, args.origin), journal, Failpoints(args.crash, mode="exit"))
code = agent.run(once=True, max_wait=args.max_wait)
journal.close()
agent.close()
sys.exit(code)
