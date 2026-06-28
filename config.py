import os

# Try to load environment variables from a local .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _get_env_str(key: str, default: str) -> str:
    val = os.environ.get(key)
    return val if val else default


def _get_env_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    if not val:
        return default
    try:
        return int(val)
    except ValueError:
        return default


# Read configuration from environment variables with fallbacks
IMAP_HOST     = _get_env_str('IMAP_HOST', '')
IMAP_PORT     = _get_env_int('IMAP_PORT', 993)
IMAP_USER     = _get_env_str('IMAP_USER', '')
IMAP_PASS     = _get_env_str('IMAP_PASS', '')
POLL_INTERVAL = _get_env_int('POLL_INTERVAL', 30)
DB_PATH       = _get_env_str('DB_PATH', './phish_siem.db')

# ML model — loaded directly via transformers (no Ollama needed)
ML_MODEL_NAME = _get_env_str(
    'ML_MODEL_NAME',
    'cybersectony/phishing-email-detection-distilbert_v2.4.1'
)