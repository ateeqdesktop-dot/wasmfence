from __future__ import annotations
import argparse,hashlib,json,re,sys
from pathlib import Path

def parse(path:Path):
 if path.stat().st_size>=10*1024*1024: raise ValueError('module exceeds 10 MiB')
 text=path.read_text(encoding='utf-8')
 imports=[]; exports=[]
 for m in re.finditer(r'\(import\s+"([^"]+)"\s+"([^"]+)"',text): imports.append({'module':m.group(1),'name':m.group(2)})
 for m in re.finditer(r'\(export\s+"([^"]+)"',text): exports.append(m.group(1))
 return {'imports':imports,'exports':sorted(set(exports))}

def audit(mod,policy):
 findings=[]; allowed=set(policy.get('allowed_imports',[])); required=set(policy.get('required_exports',[]))
 def add(c,s,l,m): findings.append({'code':c,'severity':s,'location':l,'message':m,'fingerprint':hashlib.sha256(f'{c}|{l}|{m}'.encode()).hexdigest()[:16]})
 for i,item in enumerate(mod['imports']):
  ref=f"{item['module']}.{item['name']}"
  if ref not in allowed:add('WF001','high',f'imports[{i}]',f'capability import is not allowed: {ref}')
 for name in sorted(required-set(mod['exports'])): add('WF002','high','exports',f'required export is missing: {name}')
 if len(mod['imports'])>int(policy.get('max_imports',32)): add('WF003','medium','imports',f'import surface exceeds {policy["max_imports"]}')
 findings.sort(key=lambda x:(x['code'],x['location'],x['fingerprint']))
 return {'schema_version':1,'imports':mod['imports'],'exports':mod['exports'],'findings':findings}

def main():
 p=argparse.ArgumentParser();p.add_argument('module',type=Path);p.add_argument('--policy',type=Path,required=True);p.add_argument('--format',choices=['json','markdown'],default='markdown');a=p.parse_args()
 try:r=audit(parse(a.module),json.loads(a.policy.read_text()))
 except (OSError,ValueError,json.JSONDecodeError) as e: print(f'WasmFence error: {e}',file=sys.stderr);return 2
 if a.format=='json':print(json.dumps(r,indent=2,sort_keys=True))
 else:
  print(f"# WasmFence\n\nImports: **{len(r['imports'])}** | Exports: **{len(r['exports'])}** | Findings: **{len(r['findings'])}**\n\n| Code | Severity | Message |\n|---|---|---|")
  for f in r['findings']:print(f"| `{f['code']}` | {f['severity']} | {f['message']} |")
 return 1 if r['findings'] else 0
if __name__=='__main__':raise SystemExit(main())
