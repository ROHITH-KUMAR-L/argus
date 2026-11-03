"""Workspace staging into, and artifact export out of, disposable workers.

* **Staging** builds a tar stream of *approved* regular files and directories
  only, re-owned to the worker UID (10001). Symlinks, devices, FIFOs and
  sockets in the source are refused rather than copied (POL-020: whatever the
  source ownership, the worker gets a fresh copy it owns).
* **Export** validates an untrusted tar stream from the worker before writing
  anything: absolute paths, ``..``, links, devices, FIFOs and unexpected
  entries reject the whole export (AUD-016). Accepted files are written with
  ``O_EXCL | O_NOFOLLOW`` into a fresh directory and hashed (AUD-015).
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

WORKER_UID = 10001
WORKER_GID = 10001
MAX_STAGE_BYTES = 256 * 1024 * 1024
MAX_STAGE_ENTRIES = 20_000
MAX_EXPORT_BYTES = 256 * 1024 * 1024
MAX_EXPORT_ENTRIES = 20_000


class StagingError(ValueError):
    pass


class ExportRejected(ValueError):
    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons[:10]))
        self.reasons = reasons


@dataclass(frozen=True)
class Artifact:
    path: str
    size: int
    sha256: str


def _safe_rel(name: str) -> str | None:
    """Normalize an archive member name; None if it is unsafe."""
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        return None
    parts = [p for p in PurePosixPath(name).parts if p not in (".", "")]
    if any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def build_stage_archive(src: Path, include: list[str] | None = None) -> bytes:
    """Tar the approved contents of ``src`` for staging into ``/workspace/task``."""
    src = src.resolve(strict=True)
    if not src.is_dir():
        raise StagingError(f"{src} is not a directory")
    wanted: set[str] | None = None
    if include is not None:
        wanted = set()
        for rel in include:
            safe = _safe_rel(rel)
            if safe is None or not safe:
                raise StagingError(f"unsafe include path {rel!r}")
            wanted.add(safe)

    buf = io.BytesIO()
    total = 0
    count = 0
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for root, dirs, files in os.walk(src, followlinks=False):
            dirs.sort()
            for name in sorted(dirs) + sorted(files):
                full = Path(root) / name
                rel = full.relative_to(src).as_posix()
                st = full.lstat()
                is_dir = stat.S_ISDIR(st.st_mode)
                if wanted is not None and not is_dir and rel not in wanted:
                    continue
                if (
                    wanted is not None
                    and is_dir
                    and not any(w == rel or w.startswith(rel + "/") for w in wanted)
                ):
                    continue
                if stat.S_ISLNK(st.st_mode):
                    raise StagingError(f"refusing to stage symlink {rel}")
                if not (is_dir or stat.S_ISREG(st.st_mode)):
                    raise StagingError(f"refusing to stage special file {rel}")
                count += 1
                if count > MAX_STAGE_ENTRIES:
                    raise StagingError("too many entries to stage")
                info = tarfile.TarInfo(rel)
                info.uid, info.gid = WORKER_UID, WORKER_GID
                info.uname = info.gname = ""
                info.mtime = 0
                if is_dir:
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    tar.addfile(info)
                else:
                    total += st.st_size
                    if total > MAX_STAGE_BYTES:
                        raise StagingError("workspace exceeds staging size limit")
                    info.size = st.st_size
                    info.mode = 0o644
                    with open(full, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as fh:
                        tar.addfile(info, fh)
    if wanted is not None:
        staged = {m for m in _names(buf.getvalue())}
        missing = wanted - staged
        if missing:
            raise StagingError(f"approved files not found: {sorted(missing)[:5]}")
    return buf.getvalue()


def _names(data: bytes) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as t:
        return [m.name for m in t.getmembers()]


def safe_extract(
    data: bytes,
    dest: Path,
    *,
    strip_prefix: str | None = None,
    expected: set[str] | None = None,
) -> list[Artifact]:
    """Validate and extract an untrusted worker tar stream into an empty ``dest``.

    Every member is checked before anything is written. Any unsafe member
    rejects the whole export.
    """
    try:
        return _safe_extract(data, dest, strip_prefix=strip_prefix, expected=expected)
    except tarfile.TarError as exc:
        # Truncated or corrupt streams are rejected, never partially accepted.
        raise ExportRejected([f"corrupt tar stream: {exc}"]) from exc


def _safe_extract(
    data: bytes,
    dest: Path,
    *,
    strip_prefix: str | None,
    expected: set[str] | None,
) -> list[Artifact]:
    reasons: list[str] = []
    plan: list[tuple[str, tarfile.TarInfo]] = []
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:")  # noqa: SIM115 - closed by "with tar" below
    except tarfile.TarError as exc:
        raise ExportRejected([f"not a tar stream: {exc}"]) from exc
    with tar:
        members = tar.getmembers()
        if len(members) > MAX_EXPORT_ENTRIES:
            raise ExportRejected(["too many entries"])
        total = 0
        for m in members:
            name = m.name
            if strip_prefix is not None:
                if name == strip_prefix or name == strip_prefix + "/":
                    continue
                if not name.startswith(strip_prefix + "/"):
                    reasons.append(f"{name!r}: outside export root")
                    continue
                name = name[len(strip_prefix) + 1 :]
            rel = _safe_rel(name)
            if rel is None:
                reasons.append(f"{m.name!r}: absolute or traversal path")
                continue
            if not rel:
                continue
            if m.issym() or m.islnk():
                reasons.append(f"{rel}: link entries are not allowed")
            elif m.ischr() or m.isblk() or m.isfifo() or m.isdev():
                reasons.append(f"{rel}: special file")
            elif not (m.isfile() or m.isdir()):
                reasons.append(f"{rel}: unsupported entry type")
            elif m.isfile() and expected is not None and rel not in expected:
                reasons.append(f"{rel}: unexpected file")
            else:
                if m.isfile():
                    total += m.size
                plan.append((rel, m))
        if total > MAX_EXPORT_BYTES:
            reasons.append("export exceeds size limit")
        if reasons:
            raise ExportRejected(reasons)

        dest.mkdir(mode=0o700, parents=True, exist_ok=True)
        if any(dest.iterdir()):
            raise ExportRejected(["destination is not empty"])
        artifacts: list[Artifact] = []
        for rel, m in plan:
            target = dest / rel
            if m.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            src = tar.extractfile(m)
            assert src is not None
            h = hashlib.sha256()
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out:
                while chunk := src.read(1 << 20):
                    h.update(chunk)
                    out.write(chunk)
            artifacts.append(Artifact(rel, m.size, "sha256:" + h.hexdigest()))
    return sorted(artifacts, key=lambda a: a.path)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return "sha256:" + h.hexdigest()
