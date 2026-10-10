"""Verify an approved website archive before extracting or staging any files."""
import argparse
import hashlib
import importlib.util
import json
import stat
import tempfile
import zipfile
from pathlib import Path

ARCHIVE_SHA256 = 'c4c34721413d8b12cfbfae0795b4598939f9aa3177b4285197db633d94d8815c'
MANIFEST_SHA256 = 'f0320a1a08c982f4f45f50fd95a667d310d93890c38a88255237741cab8a325c'
ARCHIVE_BYTES = 168070721

def release(archive, manifest, output, expected_manifest):
    if expected_manifest != MANIFEST_SHA256:
        raise ValueError('UNREVIEWED_MANIFEST')
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError('MANIFEST_DIGEST_MISMATCH')
    if archive.stat().st_size != ARCHIVE_BYTES:
        raise ValueError('ARCHIVE_SIZE_MISMATCH')
    with archive.open('rb') as f:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            hasher.update(chunk)
        digest = hasher.hexdigest()
    if digest != ARCHIVE_SHA256:
        raise ValueError('ARCHIVE_DIGEST_MISMATCH')
    spec = importlib.util.spec_from_file_location('release_gate', Path(__file__).with_name('verify-and-stage.py'))
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    entries = json.loads(raw)['files']
    names = [e['path'] for e in entries]
    if len(names) != len(set(names)) or any(not gate.permitted(n) for n in names):
        raise ValueError('INVALID_MANIFEST_PATH')
    approved = {e['path']: e for e in entries}
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        zipped = [i.filename for i in infos]
        if len(zipped) != len(set(zipped)) or set(zipped) != set(names):
            raise ValueError('ZIP_INVENTORY_MISMATCH')
        for info in infos:
            mode = info.external_attr >> 16
            if info.is_dir() or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                raise ValueError('ZIP_NON_REGULAR_FILE')
            if info.file_size != approved[info.filename]['bytes'] or info.flag_bits & 1:
                raise ValueError('ZIP_SIZE_OR_ENCRYPTION_MISMATCH')
        # Read and hash all entries before writing. Never call extractall or execute ZIP contents.
        checked = []
        for info in infos:
            body = z.read(info)
            if hashlib.sha256(body).hexdigest() != approved[info.filename]['sha256']:
                raise ValueError('ZIP_FILE_DIGEST_MISMATCH')
            checked.append((info.filename, body))
    with tempfile.TemporaryDirectory(prefix='reviewed-site-') as temp:
        source = Path(temp)
        for name, body in checked:
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        return gate.stage(source, manifest, output, expected_manifest)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(release(args.archive, args.manifest, args.output, args.expected_manifest_sha256)))
    except (ValueError, KeyError, OSError, zipfile.BadZipFile) as error:
        print(json.dumps({'release_gate': 'blocked', 'reason': str(error)}))
        raise SystemExit(1)
