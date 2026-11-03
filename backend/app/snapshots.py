"""Retained, generated-name snapshots. Nothing is exposed as static content."""
import re
from uuid import UUID

from .crypto import MAX_FILE_SIZE
from .errors import DomainError
from .private_files import private_directory, read_private, sync_directory, write_exclusive


class SnapshotStore:
    def __init__(self, root):
        self.root = root
        private_directory(root)

    def path(self, identifier):
        if str(UUID(identifier)) != identifier:
            raise DomainError("INVALID_SNAPSHOT_ID", 503)
        return self.root / (identifier + ".blob")

    def save(self, snapshot):
        if type(snapshot.data) is not bytes or len(snapshot.data) > MAX_FILE_SIZE:
            raise DomainError("INPUT_TOO_LARGE", 413)
        private_directory(self.root)
        target = self.path(snapshot.id)
        created = False
        try:
            # Never overwrite a previously retained snapshot.
            write_exclusive(target, snapshot.data)
            created = True
            sync_directory(self.root)
        except BaseException:
            if created:
                target.unlink(missing_ok=True)
            raise

    def capture(self, identifier):
        private_directory(self.root)
        return read_private(self.path(identifier), MAX_FILE_SIZE)

    def remove(self, identifier):
        private_directory(self.root)
        # unlink never follows a leaf symlink; only generated UUID names accepted.
        self.path(identifier).unlink(missing_ok=True)

    def candidates(self, limit=100):
        import os
        result = []
        with os.scandir(self.root) as entries:
            for inspected, entry in enumerate(entries):
                if inspected >= 1000:
                    break
                if re.fullmatch(r"[0-9a-f-]{36}\.blob", entry.name):
                    try:
                        identifier = str(UUID(entry.name[:-5]))
                    except ValueError:
                        continue
                    result.append((identifier, entry.stat(follow_symlinks=False).st_mtime))
                if len(result) >= limit:
                    break
        return result
