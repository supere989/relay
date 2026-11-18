"""Actual HTTP export and independent real-age recovery acceptance."""

import io
import json
import os
import subprocess
import sys
import zipfile

from chatmaild.backup import recovery_tool as tool
from chatmaild.tests.recovery_fixture import Scenario


def isolated_restore(tmp_path, kit, archives, output):
    parts = tool.zip_components(kit)
    script = tmp_path / "restore.py"
    script.write_bytes(parts["restore.py"])
    paths = []
    for run, payload in archives:
        path = tmp_path / (run + ".age")
        path.write_bytes(payload)
        paths.append(str(path))
    fd = os.memfd_create("private-recovery-kit", os.MFD_CLOEXEC)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(kit)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        os.lseek(fd, 0, os.SEEK_SET)
        bootstrap = """import os,runpy,sys
script,forbidden=sys.argv[1:3]
def deny(event,args):
    if event=='import' and str(args[0]).split('.')[0] in ('chatmaild','pyinfra'):
        raise RuntimeError('server_import_forbidden')
    if event=='open' and isinstance(args[0],str):
        path=os.path.abspath(args[0])
        if any(path==root or path.startswith(root+'/') for root in (forbidden,'/project','/source','/var/lib/chatmail','/home/vmail','/opt/chatmaild')):
            raise RuntimeError('server_file_forbidden')
    if event=='subprocess.Popen' and any('AGE-SECRET-KEY-' in str(arg) for arg in args[1]):
        raise RuntimeError('identity_in_argv_forbidden')
sys.addaudithook(deny)
sys.argv=[script]+sys.argv[3:]
runpy.run_path(script,run_name='__main__')
"""
        args = [
            sys.executable,
            "-I",
            "-c",
            bootstrap,
            str(script),
            str(tmp_path.parent / "server"),
            "--kit-fd",
            str(fd),
            "--output",
            str(output),
            *paths,
        ]
        result = subprocess.run(
            args,
            pass_fds=(fd,),
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        return result
    finally:
        os.close(fd)


def test_actual_http_export_then_later_uploads_and_renewal_original_kit_restores_all(
    tmp_path,
):
    scenario = Scenario(tmp_path / "server")
    first = scenario.capture()
    scenario.historical_key_transition_fixture()
    second = scenario.capture()
    status, headers, kit = scenario.http_download(fields={"mode": "keys"})
    assert status == 200 and headers["Content-Type"] == "application/zip"
    assert (
        "no-store" in headers["Cache-Control"]
        and headers["X-Content-Type-Options"] == "nosniff"
    )
    assert headers["X-Accel-Buffering"] == "no"
    assert headers["Content-Disposition"].startswith('attachment; filename="recovery-')
    parts = tool.zip_components(kit)
    from importlib.resources import files

    exact_tool = (
        parts["restore.py"]
        == files("chatmaild.backup").joinpath("recovery_tool.py").read_bytes()
    )
    assert exact_tool
    metadata = tool.json_object(parts["recovery.json"], tool.MAX_KIT)
    key_count = len(metadata["keys"])
    receipt_count = len(metadata["receipts"])
    assert key_count == 2 and receipt_count == 0
    assert metadata["receipt_coverage"] == {"kind": "none"}
    refs_exposed = any(
        text in parts["recovery.json"]
        for text in (
            b"archive-key-a",
            b"archive-key-b",
            b"archive-credential",
            b"incarnation",
            b"password",
        )
    )
    assert not refs_exposed
    old_reference = scenario.binding.credential_ref
    scenario.change_after_export()
    third = scenario.capture()
    scenario.renew()
    fourth = scenario.capture()
    assert scenario.binding.credential_ref != old_reference
    assert third["key_ref"] == fourth["key_ref"] == second["key_ref"]
    assert first["key_ref"] != second["key_ref"]
    client = tmp_path / "client"
    client.mkdir(mode=0o700)
    output = client / "quarantine"
    result = isolated_restore(
        client, kit, [*scenario.archives, scenario.archives[-1]], output
    )
    assert result.returncode == 0
    summary = json.loads(result.stdout)
    assert summary == {
        "duplicate_inputs": 1,
        "messages": len(scenario.expected),
        "runs": 4,
        "state": "complete",
    }
    for relative, expected in scenario.expected.items():
        same_bytes = (output / relative).read_bytes() == expected
        assert same_bytes
    assert (
        not (output / ".incomplete").exists() and (output / "completion.json").is_file()
    )
    persisted_key = any(
        row["identity"].encode() in scenario.store.path.read_bytes()
        for row in scenario.broker.values.values()
    )
    assert not persisted_key


def test_plaintext_kit_never_written_by_export(tmp_path, caplog):
    scenario = Scenario(tmp_path / "server")
    scenario.capture()
    status, _headers, kit = scenario.http_download()
    assert status == 200
    with zipfile.ZipFile(io.BytesIO(kit)) as archive:
        names = sorted(archive.namelist())
    assert names == sorted(tool.COMPONENTS)
    leaked_log = any(
        row["identity"] in caplog.text for row in scenario.broker.values.values()
    )
    assert not leaked_log
    unexpected_zip = list((tmp_path / "server").rglob("*.zip"))
    assert not unexpected_zip
