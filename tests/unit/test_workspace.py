"""Workspace staging and export validation (POL-020, AUD-015, AUD-016, SC-F13)."""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

import pytest

from controller.workspace import (
    ExportRejected,
    StagingError,
    build_stage_archive,
    safe_extract,
    sha256_file,
)


def _tar(entries: list[tarfile.TarInfo], payload: bytes = b"data") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for info in entries:
            if info.isfile():
                info.size = len(payload)
                t.addfile(info, io.BytesIO(payload))
            else:
                t.addfile(info)
    return buf.getvalue()


def _member(name: str, kind: bytes = tarfile.REGTYPE, linkname: str = "") -> tarfile.TarInfo:
    i = tarfile.TarInfo(name)
    i.type = kind
    i.linkname = linkname
    return i


def test_staging_reowns_and_filters(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.py").write_text("x = 1\n")
    (tmp_path / "secret.env").write_text("TOKEN=abc\n")
    data = build_stage_archive(tmp_path, include=["src/app.py"])
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        members = {m.name: m for m in t.getmembers()}
    assert set(members) == {"src", "src/app.py"}
    assert all(m.uid == 10001 and m.gid == 10001 for m in members.values())
    assert members["src/app.py"].mode == 0o644


def test_staging_refuses_symlinks_and_specials(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("")
    os.symlink("/etc/passwd", tmp_path / "evil")
    with pytest.raises(StagingError, match="symlink"):
        build_stage_archive(tmp_path)
    os.unlink(tmp_path / "evil")
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(StagingError, match="special"):
        build_stage_archive(tmp_path)


def test_staging_rejects_unsafe_includes(tmp_path: Path) -> None:
    for bad in ["../etc/passwd", "/etc/passwd", ""]:
        with pytest.raises(StagingError):
            build_stage_archive(tmp_path, include=[bad])
    with pytest.raises(StagingError, match="not found"):
        build_stage_archive(tmp_path, include=["missing.py"])


def test_aud_015_artifact_hash_verifiable(tmp_path: Path) -> None:
    data = _tar([_member("task/out/result.txt")], payload=b"hello\n")
    arts = safe_extract(data, tmp_path / "x", strip_prefix="task")
    assert [a.path for a in arts] == ["out/result.txt"]
    assert arts[0].sha256 == sha256_file(tmp_path / "x/out/result.txt")
    assert (tmp_path / "x/out/result.txt").read_bytes() == b"hello\n"


@pytest.mark.parametrize(
    ("member", "why"),
    [
        (_member("/etc/passwd"), "absolute"),
        (_member("../../home/user/.bashrc"), "traversal"),
        (_member("a/../../b"), "traversal"),
        (_member("link", tarfile.SYMTYPE, "/etc/shadow"), "link"),
        (_member("hard", tarfile.LNKTYPE, "/etc/shadow"), "link"),
        (_member("dev", tarfile.CHRTYPE), "special"),
        (_member("blk", tarfile.BLKTYPE), "special"),
        (_member("fifo", tarfile.FIFOTYPE), "special"),
    ],
)
def test_aud_016_unsafe_entries_reject_whole_export(
    tmp_path: Path, member: tarfile.TarInfo, why: str
) -> None:
    data = _tar([_member("good.txt"), member])
    dest = tmp_path / "out"
    with pytest.raises(ExportRejected) as e:
        safe_extract(data, dest)
    assert why in str(e.value)
    assert not dest.exists() or not any(dest.iterdir()), "nothing may be written on rejection"


def test_unexpected_and_outside_root_entries(tmp_path: Path) -> None:
    data = _tar([_member("task/report.json"), _member("task/stolen.txt")])
    with pytest.raises(ExportRejected, match="unexpected"):
        safe_extract(data, tmp_path / "a", strip_prefix="task", expected={"report.json"})
    data = _tar([_member("other/x")])
    with pytest.raises(ExportRejected, match="outside"):
        safe_extract(data, tmp_path / "b", strip_prefix="task")
    with pytest.raises(ExportRejected, match="not a tar"):
        safe_extract(b"garbage", tmp_path / "c")


def test_export_refuses_non_empty_destination(tmp_path: Path) -> None:
    dest = tmp_path / "d"
    dest.mkdir()
    (dest / "existing").write_text("")
    with pytest.raises(ExportRejected, match="not empty"):
        safe_extract(_tar([_member("x")]), dest)
