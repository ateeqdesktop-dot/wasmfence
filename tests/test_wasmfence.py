from pathlib import Path
from wasmfence import parse,audit
R=Path(__file__).parents[1]
def test_policy():
 r=audit(parse(R/'fixtures/module.wat'),__import__('json').loads((R/'fixtures/policy.json').read_text())); assert [x['code'] for x in r['findings']]==['WF001']
def test_size(tmp_path):
 p=tmp_path/'x.wat';p.write_text('x'*(10*1024*1024));
 try:parse(p);assert False
 except ValueError:pass
