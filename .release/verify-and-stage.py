"""Proposed local/CI release gate. Copies exact reviewed paths into an empty output.
This script has no GitHub client, credential access, upload, or deploy operation.
"""
import argparse, hashlib, json, re, shutil
from pathlib import Path, PurePosixPath

DENY_COMPONENTS={'.git','.github','.agents','.codex','.claude','_team','_experts','orchestrator','supabase','docs','_research','_specs','_archive','_build','_assets','_mapping_review','_qa_audit','_qa_screenshots','_qa_pdf','sample','samples','fixtures','fixture','tests','test'}
DENY_NAMES={'dashboard-state.json','dashboard-messages.json','work-status.json','team-live.html','data.sample.js'}
DENY_EXTENSIONS={'.md','.map','.log','.csv','.gpx','.py','.pyc','.sql','.yml','.yaml','.bak','.bak2','.command','.plist','.example'}
SECRET=re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{25,}|sb_secret_[A-Za-z0-9_-]{20,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}|xox[baprs]-[A-Za-z0-9-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|sourceMappingURL=data:')
TEXT={'.html','.js','.css','.json','.svg','.xml','.txt','.webmanifest'}

def permitted(name):
    p=PurePosixPath(name)
    return not(p.is_absolute() or '..' in p.parts or '\\' in name or any(x in DENY_COMPONENTS or x.startswith(('_','.')) for x in p.parts[:-1]) or p.name in DENY_NAMES or p.name.startswith(('_','.','selftest-')) or p.suffix.lower() in DENY_EXTENSIONS or (name.startswith('admin/dashboard/') and name not in {'admin/dashboard/index.html','admin/dashboard/sw.js'}))

def stage(source,manifest_path,output,expected_manifest=None):
    source=source.resolve(); output=output.resolve()
    raw=manifest_path.read_bytes()
    if expected_manifest is not None and hashlib.sha256(raw).hexdigest()!=expected_manifest: raise ValueError('MANIFEST_DIGEST_MISMATCH')
    manifest=json.loads(raw); entries=manifest['files']
    names=[x['path'] for x in entries]
    if len(names)!=len(set(names)): raise ValueError('DUPLICATE_PATH')
    if any(not permitted(p) for p in names): raise ValueError('FORBIDDEN_PATH')
    # No deletion: output must be new, empty and disjoint from source and manifest.
    if output==source or source in output.parents or output in source.parents or output==manifest_path.resolve().parent: raise ValueError('UNSAFE_OUTPUT')
    if output.exists() and any(output.iterdir()): raise ValueError('OUTPUT_NOT_EMPTY')
    actual=[]
    for p in source.rglob('*'):
        if p.is_symlink(): raise ValueError('SYMLINK_REJECTED')
        if p.is_file(): actual.append(p.relative_to(source).as_posix())
    if set(actual)!=set(names): raise ValueError('EXTRA_OR_MISSING_SOURCE_FILE')
    checked=[]
    for entry in entries:
        p=entry['path']; f=source/p
        if not f.is_file() or f.is_symlink() or source not in f.resolve().parents: raise ValueError('INVALID_SOURCE_FILE')
        body=f.read_bytes()
        if len(body)!=entry['bytes'] or hashlib.sha256(body).hexdigest()!=entry['sha256']: raise ValueError('FILE_DIGEST_MISMATCH')
        if (f.suffix.lower() in TEXT or p=='CNAME') and SECRET.search(body): raise ValueError('SECRET_OR_INLINE_SOURCE_MAP')
        if f.suffix.lower()=='.json':
            obj=json.loads(body)
            def check(v):
                if isinstance(v,dict):
                    if any(k.lower() in {'email','phone','address','customer_email','customer_phone','access_token','refresh_token','password'} and isinstance(x,str) and x.strip() for k,x in v.items()): raise ValueError('STRUCTURED_CONTACT_OR_AUTH_VALUE')
                    for x in v.values(): check(x)
                elif isinstance(v,list):
                    for x in v: check(x)
            check(obj)
        checked.append((p,body))
    output.mkdir(parents=True,exist_ok=True)
    for p,body in checked:
        target=output/p; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(body)
    return {'files':len(checked),'bytes':sum(len(b) for _,b in checked),'manifest_sha256':hashlib.sha256(raw).hexdigest(),'output':str(output)}

if __name__=='__main__':
    cli=argparse.ArgumentParser(); cli.add_argument('--source',type=Path,required=True); cli.add_argument('--manifest',type=Path,required=True); cli.add_argument('--output',type=Path,required=True); cli.add_argument('--expected-manifest-sha256')
    a=cli.parse_args()
    try: print(json.dumps(stage(a.source,a.manifest,a.output,a.expected_manifest_sha256)))
    except (ValueError,KeyError,OSError) as e: print(json.dumps({'release_gate':'blocked','category':type(e).__name__,'reason':str(e)})); raise SystemExit(1)
