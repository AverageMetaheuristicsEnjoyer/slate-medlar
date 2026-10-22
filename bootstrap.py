import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time

os.umask(0o077)
key = os.environ.pop('BUNDLE_KEY')
root = Path(__file__).resolve().parent
payload = (root / 'payload.fernet').read_bytes()
public_manifest = json.loads((root / 'manifest.json').read_text())
if hashlib.sha256(payload).hexdigest() != public_manifest['payload_sha256']:
    raise RuntimeError('Encrypted payload checksum mismatch')
with tempfile.TemporaryDirectory(prefix='encrypted-job-', dir='/tmp') as directory:
    destination = Path(directory)
    deps = destination / 'dependencies'
    # every MPI rank installs it, and one failed PyPI request on any rank aborts the whole job: retried
    for attempt in range(6):
        if subprocess.run([sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check',
                           '--no-cache-dir', '--only-binary=:all:', '--target', str(deps),
                           'cryptography==46.0.5']).returncode == 0:
            break
        if attempt == 5:
            raise RuntimeError('pip install cryptography failed 6 times')
        time.sleep(30)
    sys.path.insert(0, str(deps))
    from cryptography.fernet import Fernet
    plaintext = Fernet(key.encode()).decrypt(payload)
    del key
    source = destination / 'source'
    source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode='r:gz') as archive:
        archive.extractall(source, filter='data')
    del plaintext
    manifest = json.loads((source / 'bundle_manifest.json').read_text())
    if manifest['bundle_id'] != public_manifest['bundle_id']:
        raise RuntimeError('Bundle id mismatch')
    print('BUNDLE_AUTHENTICATED=' + manifest['bundle_id'], flush=True)
    if sys.argv[1:] != ['--verify-only']:
        os.environ['BUNDLE_ID'] = manifest['bundle_id']
        raise SystemExit(subprocess.call(manifest['entry'] + sys.argv[1:], cwd=source))
