from datetime import datetime
from pathlib import Path


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

LOG_FILE = OUTPUT_DIR / "recon.log"


def log(message):

    timestamp = datetime.now().strftime('%H:%M:%S')

    log_msg = f"[{timestamp}] {message}"

    print(log_msg)

    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_msg + '\n')