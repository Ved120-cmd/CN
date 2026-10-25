from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = f"sqlite:///{(BASE_DIR / 'netdoctor.db').as_posix()}"
APP_TITLE = "NetDoctor API"
API_PREFIX = "/api/v1"
