"""Luna-only source-free acceptance runner; packet/key bytes never touch disk.

Run this public harness on the rootless Podman host. The producer has source RO;
the client has NO mounts and a read-only image plus private ephemeral /tmp.
Only a captured process pipe carries the kit and encrypted synthetic fixtures.
"""

import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

PRODUCER = """
import logging,sys,tempfile
from pathlib import Path
from chatmaild.tests.recovery_fixture import Scenario
logging.disable(logging.CRITICAL)
try:
    with tempfile.TemporaryDirectory(dir='/tmp') as root:
        packet=Scenario(Path(root)/'server').acceptance_packet()
        sys.stdout.buffer.write(packet)
except BaseException:
    sys.stderr.write('synthetic_producer_failed\\n')
    sys.exit(1)
"""

CLIENT = """
import base64,hashlib,importlib.util,io,json,os,re,subprocess,sys,zipfile
from pathlib import Path
try:
    assert importlib.util.find_spec('chatmaild') is None
    for name in ('/source','/var/lib/chatmail','/home/vmail','/opt/chatmaild','/usr/local/lib/chatmaild','/home/raymondj/.local/bin/kwsecret'):
        assert not Path(name).exists()
    assert not Path('/project').exists() or not any(Path('/project').iterdir())
    packet=sys.stdin.buffer.read(16*1024*1024+1)
    assert len(packet)<=16*1024*1024
    data=json.loads(packet)
    kit=base64.b64decode(data['kit'],validate=True)
    work=Path('/tmp/client')
    work.mkdir(mode=0o700)
    with zipfile.ZipFile(io.BytesIO(kit)) as archive:
        script=archive.read('restore.py')
    assert len(script)<256*1024
    (work/'restore.py').write_bytes(script)
    inputs=[]
    for record in data['archives']:
        assert re.fullmatch('[a-f0-9]{32}\\.age',record['name'])
        path=work/record['name']
        path.write_bytes(base64.b64decode(record['data'],validate=True))
        inputs.append(str(path))
    fd=os.memfd_create('private-owner-kit',os.MFD_CLOEXEC)
    os.fchmod(fd,0o600)
    view=memoryview(kit)
    while view:
        written=os.write(fd,view)
        assert written>0
        view=view[written:]
    os.lseek(fd,0,os.SEEK_SET)
    result=subprocess.run([sys.executable,'-I',str(work/'restore.py'),'--kit-fd',str(fd),'--output',str(work/'quarantine'),*inputs],pass_fds=(fd,),cwd=work,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,check=False)
    os.close(fd)
    assert result.returncode==0
    outcome=json.loads(result.stdout)
    assert outcome['state']=='complete' and outcome['runs']==4
    root=work/'quarantine'
    assert (root/'completion.json').is_file() and not (root/'.incomplete').exists()
    actual={str(path.relative_to(root)):hashlib.sha256(path.read_bytes()).hexdigest() for path in root.rglob('*') if path.is_file() and path!=root/'completion.json'}
    assert actual==data['expected']
    print(json.dumps({'source_free':True,'runs':outcome['runs'],'messages':outcome['messages'],'checked_files':len(actual)},sort_keys=True))
except BaseException:
    sys.stderr.write('source_free_recovery_failed\\n')
    sys.exit(1)
"""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image",
        required=True,
        help="Reviewed local test image with Python3, age and age-keygen, no installed relay",
    )
    parser.add_argument("--repo", required=True)
    parser.add_argument("--podman-module", required=True)
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()
    podman = ["podman", "--module", args.podman_module]
    names = [
        "recovery-producer-" + uuid.uuid4().hex[:12],
        "recovery-client-" + uuid.uuid4().hex[:12],
    ]

    def command(name):
        return [
            *podman,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "none",
            "--read-only",
            "--cpus",
            "4",
            "--memory",
            "4g",
            "--pids-limit",
            "256",
            "--tmpfs",
            "/tmp:rw,size=2g,nosuid,nodev,mode=1777",
            "--entrypoint",
            "python3",
        ]

    try:
        producer = subprocess.run(
            [
                *command(names[0]),
                "-v",
                str(repo) + ":/project:ro",
                "-e",
                "PYTHONPATH=/project/chatmaild/src:/opt/testdeps",
                args.image,
                "-c",
                PRODUCER,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=240,
            check=False,
        )
        if producer.returncode or len(producer.stdout) > 16 * 1024 * 1024:
            raise RuntimeError("producer_failed")
        client = subprocess.run(
            [*command(names[1]), "-i", args.image, "-I", "-c", CLIENT],
            input=producer.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=240,
            check=False,
        )
        if client.returncode:
            raise RuntimeError("client_failed")
        result = json.loads(client.stdout)
        if (
            set(result) != {"source_free", "runs", "messages", "checked_files"}
            or result["source_free"] is not True
            or result["runs"] != 4
            or any(
                type(result[field]) is not int
                for field in ("runs", "messages", "checked_files")
            )
        ):
            raise RuntimeError("invalid_acceptance_result")
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        # Never print subprocess output, packet, kit, identities or exception repr.
        print("source_free_acceptance_failed", file=sys.stderr)
        return 1
    finally:
        for name in names:
            subprocess.run(
                [*podman, "stop", "--time", "1", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )


if __name__ == "__main__":
    sys.exit(main())
