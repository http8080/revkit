"""Verify revkit migration — standalone script."""

from .migrate import verify_migration

if __name__ == "__main__":
    for line in verify_migration():
        print(line)
