const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
const {parse,entries,MAX_BYTES}=require('../web/report-core.js');
const slug=path.basename(path.resolve(__dirname,'..'));
const fixture=(extra='')=>`{"schema_version":1,"project":"${slug}","mode":"fixture","summary":{},"findings":[]${extra}}`;
test('accepts a valid Thai report',()=>assert.equal(parse(fixture(',"message":"ภาษาไทย"'),slug).message,'ภาษาไทย'));
test('rejects duplicate and escaped duplicate keys',()=>{assert.throws(()=>parse(fixture(',"mode":"live"'),slug));assert.throws(()=>parse('{"a":1,"\\u0061":2}',slug));});
test('rejects wrong project and unsupported schema',()=>{assert.throws(()=>parse(fixture(),'other'));assert.throws(()=>parse(fixture().replace('"schema_version":1','"schema_version":3'),slug));});
test('rejects misleading mode, unknown summary shape and scalar root',()=>{assert.throws(()=>parse(fixture().replace('"fixture"','"success"'),slug));assert.throws(()=>parse(fixture().replace('"summary":{}','"summary":[]'),slug));assert.throws(()=>parse('null',slug));});
test('rejects trailing payload, invalid escapes, missing delimiters and unsafe numbers',()=>{for(const s of [fixture()+'{}','{"x":"\\x"}',fixture().slice(0,-1),fixture(',"n":9007199254740993'),fixture(',"n":1e999')])assert.throws(()=>parse(s,slug));});
test('enforces UTF-8 byte, depth, node and findings limits',()=>{assert.throws(()=>parse('ก'.repeat(MAX_BYTES/3+1),slug));assert.throws(()=>parse('['.repeat(42)+'0'+']'.repeat(42),slug));assert.throws(()=>parse(fixture(',"many":['+'0,'.repeat(30000)+'0]'),slug));assert.throws(()=>entries({findings:Array(10001).fill({})}));});
test('prototype keys remain inert own properties',()=>{const r=parse(fixture(',"__proto__":{"polluted":true}'),slug);assert.equal(Object.getPrototypeOf(r),null);assert.equal({}.polluted,undefined);});
test('sample belongs to this project and declares synthetic mode',()=>{const data=fs.readFileSync(path.join(__dirname,'../web/demo.json'),'utf8');const report=parse(data,slug);assert.equal(report.mode,'fixture');entries(report);});
test('viewer uses text-only rendering and restrictive local assets',()=>{const app=fs.readFileSync(path.join(__dirname,'../web/app.js'),'utf8'),html=fs.readFileSync(path.join(__dirname,'../web/index.html'),'utf8');assert.ok(!app.includes('innerHTML'));assert.match(html,/default-src 'none'/);assert.match(html,/connect-src 'self'/);assert.ok(!/https?:\/\/[^" ]+\.(?:js|css)/.test(html));assert.match(app,/TextDecoder\('utf-8',\{fatal:true,ignoreBOM:true\}\)/);});

const current=()=>JSON.parse(fs.readFileSync(path.join(__dirname,'../examples/multiversion/report-v2.json'),'utf8'));
test('schema2 viewer preserves repeated versions and all occurrence cards',()=>{
 const r=parse(JSON.stringify(current()),slug),cards=entries(r);
 assert.equal(r.packages.length,3);assert.equal(new Set(r.packages.map(p=>p.id)).size,3);
 assert.equal(cards.filter(p=>p.entry_type==='package_occurrence').length,3);
 assert.equal(cards.filter(p=>p.entry_type==='vulnerability_evidence').length,1);
 assert.deepEqual(cards.filter(p=>p.entry_type==='package_occurrence').map(p=>p.version).sort(),['1.0.0','1.0.0','2.0.0']);
});
test('schema2 occurrence identity metadata and finding links are structurally checked',()=>{
 for(const mutate of [
  r=>r.packages[0].family_id='invalid',r=>r.packages[0].id=[r.packages[0].id],
  r=>r.packages[0].source.ref_sha256='invalid',r=>r.packages[0].source.raw_path='PRIVATE',
  r=>r.packages[1].id=r.packages[0].id,r=>r.packages[1].source.ref_sha256=r.packages[0].source.ref_sha256,
  r=>r.findings[0].package_id='0'.repeat(64),r=>r.summary.packages++,
  r=>r.summary.vulnerability_scan='not-run'
 ]){const r=current();mutate(r);assert.throws(()=>parse(JSON.stringify(r),slug));}
});
test('schema2 added removed diff cards render with incomplete scan semantics',()=>{
 const r=current(),removed=r.packages.filter(p=>p.version==='2.0.0');
 const diff={schema_version:2,project:slug,mode:'import',summary:{added:0,removed:1},findings:[],
  comparison:{packages:{added:[],removed},vulnerabilities:{new:[],resolved:[],status:'incomplete; one or both reports were not scanned'},meaning:'No upgrade pairing or remediation inference.'}};
 const parsed=parse(JSON.stringify(diff),slug);
 assert.equal(entries(parsed)[0].entry_type,'package_removed');assert.equal(entries(parsed)[0].version,'2.0.0');
 diff.comparison.vulnerabilities.resolved=[r.findings[0]];assert.throws(()=>parse(JSON.stringify(diff),slug));
});
test('legacy schema1 remains viewable and is not relabeled schema2',()=>{
 const legacy=fs.readFileSync(path.join(__dirname,'../examples/report.json'),'utf8');
 const r=parse(legacy,slug);assert.equal(r.schema_version,1);assert.equal(entries(r).length,1);
});
