"""Export the OpenAPI spec and a static Redoc page to docs/api/ (CI checks the
spec is up to date; the same docs are live at /docs and /redoc when the API runs).

    python scripts/export_openapi.py
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost:1/x")  # not used

from backend.app.main import create_app  # noqa: E402

OUT = ROOT / "docs" / "api"

PAGE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ConsentLedger API</title>
    <style>body { margin: 0; }</style>
  </head>
  <body>
    <redoc spec-url="openapi.json" hide-hostname></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@2.1.5/bundles/redoc.standalone.js"></script>
  </body>
</html>
"""


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    spec = create_app().openapi()
    (OUT / "openapi.json").write_text(json.dumps(spec, indent=2) + "\n")
    (OUT / "index.html").write_text(PAGE)
    print(f"Wrote {len(spec['paths'])} paths to {OUT}")


if __name__ == "__main__":
    main()
