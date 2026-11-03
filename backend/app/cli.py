"""Operator-only local bootstrap and session revocation; no credentials in argv."""
import argparse
import getpass

from pydantic import TypeAdapter
from sqlalchemy import select, update

from .auth import HASHER
from .db import Database, now
from .models import User, SessionRecord
from .schemas import Username
from .settings import Settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["create-user", "revoke-sessions", "reset-password"])
    parser.add_argument("username")
    parser.add_argument("--role", choices=["ADMIN", "ANALYST", "EMPLOYEE"], default="EMPLOYEE")
    args = parser.parse_args()
    username = TypeAdapter(Username).validate_python(args.username)
    settings = Settings.from_environment()
    if settings.mode != "local":
        parser.error("Bootstrap is restricted to local mode")
    settings.prepare_storage()
    password = None
    if args.action != "revoke-sessions":
        password = getpass.getpass("Password (12-128 characters): ")
        if not 12 <= len(password) <= 128 or password != getpass.getpass("Confirm password: "):
            parser.error("Invalid password length or confirmation")
    db = Database(settings.database_url)
    try:
        with db.transaction() as s:
            user = s.scalar(select(User).where(User.username == username))
            if args.action == "create-user":
                if user:
                    parser.error("User already exists")
                s.add(User(username=username, password_hash=HASHER.hash(password), role=args.role))
            else:
                if user is None:
                    parser.error("User not found")
                if args.action == "reset-password":
                    user.password_hash = HASHER.hash(password)
                s.execute(update(SessionRecord).where(SessionRecord.user_id == user.id).values(revoked_at=now()))
        print("Local account operation completed. No credentials were printed.")
    finally:
        db.engine.dispose()


if __name__ == "__main__":
    main()
