import sys
from pathlib import Path

# Add project root and src/ to path so serverless functions can resolve imports
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(ROOT_DIR / "src") not in sys.path:
    sys.path.insert(0, str(ROOT_DIR / "src"))

from arena.app import app
from proxy.app import app as proxy_app

# Include proxy routes on the same ASGI app
for route in proxy_app.routes:
    if getattr(route, "path", "").startswith("/v1"):
        app.routes.append(route)
