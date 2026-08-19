import logging
import re
import json
from datetime import datetime, timezone
from pathlib import Path


AUDIT_LOG_FILE = Path(__file__).parent / "logs" / "scam_detection_audit.jsonl"

def get_logger(name: str) -> logging.Logger:
    """Get a simple logger for the given name."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s'
    )
    return logging.getLogger(name)


def log_audit_event(event: str, **details) -> None:
    """Append a structured, machine-readable event to the detection audit log.

    The JSON Lines format stores one complete event per line, which makes it easy
    to inspect manually or load later into pandas, a database, or a log platform.
    """
    AUDIT_LOG_FILE.parent.mkdir(exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **details,
    }
    try:
        with AUDIT_LOG_FILE.open("a", encoding="utf-8") as audit_log:
            audit_log.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError as error:
        # Audit-log failures should not prevent a user from receiving a scan result.
        logging.getLogger(__name__).error("Could not write audit log: %s", error)

def extract_json_from_text(text: str) -> dict:
    """Extract JSON from text string. Returns empty dict if not found."""
    try:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
        return {}
    except json.JSONDecodeError:
        return {}

def load_file(file_path: str) -> str:
    """Load and return file contents as string."""
    return Path(file_path).read_text().strip()
