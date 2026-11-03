"""Export API schema without creating users or using operator runtime data."""
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.api import create_app
from app.config import StoragePaths
from app.settings import Settings


def main():
    with tempfile.TemporaryDirectory(prefix="rootsentinel-openapi-") as external:
        paths = StoragePaths(Path(external) / "runtime", Path(external) / "artifacts")
        settings = Settings(paths, f"sqlite:///{paths.database.as_posix()}")
        app = create_app(settings)
        schema = app.openapi()
        app.state.db.engine.dispose()
    (ROOT / "docs/openapi.json").write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Exported {len(schema['paths'])} API paths; no credentials or runtime data included.")


if __name__ == "__main__":
    main()
