"""Install one explicitly selected official Linux release, verifying its checksum."""

import hashlib
import io
from pathlib import Path
import platform
import re
import sys
import tarfile
import urllib.request


def release_asset(version, architecture):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("release must be a stable version such as 0.3.5")
    target = {"aarch64": "aarch64", "x86_64": "x86_64"}[architecture]
    name = f"attached-{target}-unknown-linux-gnu.tar.xz"
    return f"https://github.com/pvalletbo/attached/releases/download/v{version}/{name}"


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def executable(archive, checksum, member):
    if hashlib.sha256(archive).hexdigest() != checksum.split()[0]:
        raise ValueError("release archive checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:xz") as tar:
        info = tar.getmember(member)
        if not info.isfile():
            raise ValueError("release executable is not a regular file")
        # Never extract arbitrary archive paths, links, or permissions.
        return tar.extractfile(info).read()


def main():
    url = release_asset(sys.argv[1], platform.machine())
    member = url.rsplit("/", 1)[1].removesuffix(".tar.xz") + "/attached"
    binary = executable(download(url), download(url + ".sha256").decode(), member)
    destination = Path("/usr/local/bin/attached")
    destination.write_bytes(binary)
    destination.chmod(0o755)


if __name__ == "__main__":
    main()
