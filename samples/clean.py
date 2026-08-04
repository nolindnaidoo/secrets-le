import os

# No literals here — everything comes from the environment.
DATABASE_URL = os.environ["DATABASE_URL"]
API_TOKEN = os.environ.get("API_TOKEN")
TIMEOUT = int(os.environ.get("TIMEOUT", "30"))
