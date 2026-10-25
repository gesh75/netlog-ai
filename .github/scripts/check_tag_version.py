"""Fail unless the pushed tag equals ``v<pyproject version>``.

Usage: python check_tag_version.py <tag> [path/to/pyproject.toml]
Prevents publishing e.g. tag v2.2.0 from a tree whose pyproject still says 2.1.0
(PyPI would receive 2.1.0 and the GitHub release would be mislabelled).
"""
import re
import sys

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_tag_version.py <tag> [pyproject.toml]", file=sys.stderr)
        return 2
    tag = argv[1]
    path = argv[2] if len(argv) > 2 else "pyproject.toml"
    with open(path, "rb") as fh:
        version = tomllib.load(fh)["project"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+([.\-+]?[0-9A-Za-z.]+)?", version):
        print(f"::error::unexpected pyproject version format: {version!r}")
        return 1
    expected = f"v{version}"
    if tag != expected:
        print(f"::error::tag {tag!r} does not match pyproject version {version!r} (expected {expected!r})")
        return 1
    print(f"tag {tag} matches pyproject version {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
