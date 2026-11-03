from pathlib import Path
import unittest

from app.config import StoragePaths, validate_external_path


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd().anchor
        self.source = Path(self.root) / "example-source" / "project"
        self.runtime = Path(self.root) / "example-runtime"
        self.artifacts = Path(self.root) / "example-artifacts"

    def test_external_paths_without_filesystem_mutation(self):
        paths = StoragePaths.from_environment(self.source, {
            "ROOTSENTINEL_RUNTIME_ROOT": str(self.runtime),
            "ROOTSENTINEL_ARTIFACT_ROOT": str(self.artifacts),
        })
        self.assertEqual(paths.snapshots, self.runtime / "snapshots")
        self.assertEqual(paths.database, self.runtime / "database" / "rootsentinel.sqlite3")

    def test_repository_and_relative_paths_rejected(self):
        for path in [Path("relative"), self.source, self.source / "data", self.source.parent]:
            with self.subTest(path=path):
                with self.assertRaises(ValueError): validate_external_path(path, self.source)

    def test_onedrive_and_named_sync_root_rejected(self):
        with self.assertRaises(ValueError): validate_external_path(Path(self.root) / "OneDrive - Example" / "data", self.source)
        sync = Path(self.root) / "synced"
        with self.assertRaises(ValueError): validate_external_path(sync / "runtime", self.source, (sync,))

    def test_runtime_and_artifacts_do_not_overlap(self):
        with self.assertRaises(ValueError):
            StoragePaths.from_environment(self.source, {
                "ROOTSENTINEL_RUNTIME_ROOT": str(self.runtime),
                "ROOTSENTINEL_ARTIFACT_ROOT": str(self.runtime / "artifacts"),
            })
