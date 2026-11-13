'use strict';
(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.SandwormReport=api;})(typeof globalThis==='object'?globalThis:this,function(){
  const MAX_BYTES=2*1024*1024;
  function parse(text,project){
    if(typeof text!=='string'||new TextEncoder().encode(text).length>MAX_BYTES)throw Error('รายงานต้องเป็น UTF-8 JSON ขนาดไม่เกิน 2 MiB');
    let i=0,nodes=0;
    const fail=()=>{throw Error('รูปแบบ JSON ไม่ถูกต้อง หรือมี key ซ้ำ');};
    function space(){while(/[\t\n\r ]/.test(text[i]||'!'))i++;}
    function string(){const start=i++;while(i<text.length){if(text[i]==='\\'){i+=2;continue;}if(text[i++]==='"'){try{return JSON.parse(text.slice(start,i));}catch{fail();}}}fail();}
    function value(depth){
      if(depth>40||++nodes>30000)throw Error('รายงานมีโครงสร้างซับซ้อนเกินขอบเขต');
      space();const c=text[i];
      if(c==='"')return string();
      if(c==='{'){i++;space();const obj=Object.create(null),seen=new Set();if(text[i]==='}'){i++;return obj;}while(i<text.length){space();if(text[i]!=='"')fail();const k=string();if(seen.has(k))fail();seen.add(k);space();if(text[i++]!==':')fail();obj[k]=value(depth+1);space();const end=text[i++];if(end==='}')return obj;if(end!==',')fail();}fail();}
      if(c==='['){i++;space();const arr=[];if(text[i]===']'){i++;return arr;}while(i<text.length){arr.push(value(depth+1));space();const end=text[i++];if(end===']')return arr;if(end!==',')fail();}fail();}
      for(const [word,result] of [['true',true],['false',false],['null',null]])if(text.slice(i,i+word.length)===word){i+=word.length;return result;}
      const m=/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i));if(!m)fail();i+=m[0].length;const num=Number(m[0]);if(!Number.isFinite(num)||(Number.isInteger(num)&&!Number.isSafeInteger(num)))throw Error('ตัวเลขในรายงานเกินขอบเขตที่อ่านได้อย่างแม่นยำ');return num;
    }
    const result=value(0);space();if(i!==text.length)fail();
    if(!result||typeof result!=='object'||Array.isArray(result))throw Error('รายงานต้องเป็น JSON object');
    if(result.project!==project)throw Error('รายงานนี้เป็นของโปรเจกต์อื่น');
    if(![1,2].includes(result.schema_version))throw Error('ยังไม่รองรับ schema version นี้');
    if(!['live','fixture','import'].includes(result.mode))throw Error('รายงานต้องระบุโหมด live, fixture หรือ import');
    if(!result.summary||typeof result.summary!=='object'||Array.isArray(result.summary))throw Error('ไม่พบ summary ของรายงาน');
    if(result.schema_version===2)validateV2(result);
    return result;
  }
  const FORMATS=['syft-json','cyclonedx','spdx'],HASH=/^[a-f0-9]{64}$/;
  const hash=value=>typeof value==='string'&&HASH.test(value);
  const own=(value,key)=>Object.prototype.hasOwnProperty.call(value,key);
  function invalid(){throw Error('รูปแบบ occurrence หรือ comparison ไม่ถูกต้อง');}
  function exact(value,keys){
    if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==keys.length||keys.some(k=>!own(value,k)))invalid();
  }
  function label(value,limit=500){if(typeof value!=='string'||value.length>limit||/[\u0000-\u001f]/.test(value))invalid();}
  function rows(value){if(!Array.isArray(value)||value.length>10000)invalid();return value;}
  function packageRows(list,format){
    const known=new Map(),references=new Set();
    for(const p of rows(list)){
      exact(p,['id','family_id','name','version','type','purl','source']);
      if(!hash(p.id)||!hash(p.family_id)||known.has(p.id))invalid();
      label(p.name);label(p.version);label(p.type,200);
      if(!p.name)invalid();if(p.purl!==null)label(p.purl,2000);
      exact(p.source,['format','ref_sha256']);
      if(!FORMATS.includes(p.source.format)||(format&&p.source.format!==format))invalid();
      const ref=p.source.ref_sha256;
      if(ref!==null&&(!hash(ref)||references.has(p.source.format+':'+ref)))invalid();
      if(ref!==null)references.add(p.source.format+':'+ref);
      known.set(p.id,p);
    }
    return known;
  }
  function findingRows(list,known){
    const seen=new Set();
    for(const f of rows(list)){
      exact(f,['id','package_id','package','version','advisory_id','severity','fixed_versions','fix_status']);
      if(!hash(f.id)||!hash(f.package_id)||seen.has(f.id))invalid();seen.add(f.id);
      for(const k of ['package','version','advisory_id','severity','fix_status'])label(f[k],500);
      if(!f.advisory_id||!f.package)invalid();
      if(!Array.isArray(f.fixed_versions)||f.fixed_versions.length>200)invalid();
      for(const version of f.fixed_versions)label(version);
      if(known){
        const p=known.get(f.package_id);
        if(!p||p.name!==f.package||p.version!==f.version)invalid();
      }
    }
  }
  function comparisonRows(value){
    exact(value,['packages','vulnerabilities','meaning']);
    exact(value.packages,['added','removed']);
    packageRows(value.packages.added);packageRows(value.packages.removed);
    exact(value.vulnerabilities,['new','resolved','status']);
    const v=value.vulnerabilities;
    if(!['compared','incomplete; one or both reports were not scanned'].includes(v.status))invalid();
    findingRows(v.new);findingRows(v.resolved);label(value.meaning,2000);
    if(v.status!=='compared'&&(v.new.length||v.resolved.length))invalid();
  }
  function validateV2(report){
    if(report.project!=='sandworm-supply-chain-lens')invalid();
    if(own(report,'packages')){
      if(!FORMATS.includes(report.sbom_format))invalid();
      const known=packageRows(report.packages,report.sbom_format);
      findingRows(report.findings,known);
      if(!Number.isSafeInteger(report.summary.packages)||report.summary.packages!==known.size||
         !Number.isSafeInteger(report.summary.findings)||report.summary.findings!==report.findings.length||
         !['completed-report','not-run'].includes(report.summary.vulnerability_scan))invalid();
      if(report.summary.vulnerability_scan==='not-run'&&report.findings.length)invalid();
    }else{
      if(!own(report,'comparison')||!Array.isArray(report.findings)||report.findings.length)invalid();
      for(const k of ['added','removed']){
        if(!Number.isSafeInteger(report.summary[k])||report.summary[k]!==report.comparison.packages[k].length)invalid();
      }
    }
    if(own(report,'comparison'))comparisonRows(report.comparison);
  }
  function entries(report){
    let result=Array.isArray(report.findings)?report.findings:[];
    if(report.schema_version===2){
      result=(report.packages||[]).map(p=>({...p,entry_type:'package_occurrence',title:p.name+' '+p.version})).concat(
        result.map(f=>({...f,entry_type:'vulnerability_evidence',title:f.package+' '+f.version+' · '+f.advisory_id})));
      if(report.comparison){
        for(const status of ['added','removed'])for(const p of report.comparison.packages[status]){
          result.push({...p,entry_type:'package_'+status,title:status+' · '+p.name+' '+p.version});
        }
        for(const status of ['new','resolved'])for(const f of report.comparison.vulnerabilities[status]){
          result.push({...f,entry_type:'finding_'+status,title:status+' evidence · '+f.package+' '+f.version});
        }
      }
    }
    if(result.length>10000)throw Error('รายการผลตรวจเกิน 10,000 รายการ');
    return result;
  }
  return Object.freeze({parse,entries,MAX_BYTES});
});
