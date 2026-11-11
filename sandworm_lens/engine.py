"""SBOM normalization, ambiguity rejection, and vulnerability comparison."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib, json, re
from urllib.parse import unquote
from .safety import RadarError, array, obj, text
PROJECT='sandworm-supply-chain-lens'

def _identity(name, kind, purl):
    # Keep purl qualifiers and subpath as identity; remove only its version.
    if purl:
        if not purl.startswith('pkg:'): raise RadarError('invalid package URL')
        main, _, fragment = purl.partition('#')
        base, mark, rest = main.partition('?')
        if base.rfind('@') > base.rfind('/'): base=base.rsplit('@',1)[0]
        qualifiers={}
        if mark:
            for pair in rest.split('&'):
                key, equals, raw = pair.partition('=')
                if not equals or not re.fullmatch(r'[a-z][a-z0-9._-]*',key) or key in qualifiers:
                    raise RadarError('invalid or duplicate purl qualifier')
                if re.search(r'%(?![0-9a-fA-F]{2})',raw): raise RadarError('invalid purl percent encoding')
                try: qualifiers[key]=unquote(raw,encoding='utf-8',errors='strict')
                except UnicodeError: raise RadarError('invalid purl qualifier UTF-8') from None
        value=[base,sorted(qualifiers.items()),fragment]
    else: value=[kind,name]
    return hashlib.sha256(json.dumps(value,ensure_ascii=False).encode()).hexdigest()

def packages_from_sbom(data):
    data=obj(data); rows=[]
    if 'artifacts' in data:
        format_='syft-json'
        for item in array(data['artifacts']):
            item=obj(item); rows.append((item.get('name'),item.get('version'),item.get('type','unknown'),item.get('purl','')))
    elif data.get('bomFormat')=='CycloneDX':
        format_='cyclonedx'
        def components(items,depth=0):
            if depth>20: raise RadarError('component nesting limit')
            for item in array(items):
                item=obj(item); rows.append((item.get('name'),item.get('version',''),item.get('type','unknown'),item.get('purl','')))
                if 'components' in item: components(item['components'],depth+1)
                if len(rows)>20000: raise RadarError('package limit exceeded')
        components(data.get('components',[]))
    elif str(data.get('spdxVersion','')).startswith('SPDX-'):
        format_='spdx'
        for item in array(data.get('packages',[])):
            item=obj(item); purls=[]
            for ref in array(item.get('externalRefs',[]),100):
                ref=obj(ref)
                if ref.get('referenceType') in ('purl','http://spdx.org/rdf/references/purl'): purls.append(text(ref.get('referenceLocator'),limit=2000))
            if len(set(purls))>1: raise RadarError('ambiguous SPDX package URLs')
            rows.append((item.get('name'),item.get('versionInfo',''),'unknown',purls[0] if purls else ''))
    else: raise RadarError('unsupported SBOM format')
    packages={}
    for name,version,kind,purl in rows:
        name=text(name,limit=500); version=text(version,limit=500); kind=text(kind,limit=200); purl=text(purl,limit=2000)
        if not name: raise RadarError('package name missing')
        identity=_identity(name,kind,purl)
        row={'id':identity,'name':name,'version':version,'type':kind,'purl':purl or None}
        # Multiple records may represent multiple locations. Collapse only identical records.
        if identity in packages and packages[identity]!=row: raise RadarError('ambiguous package identity; multiple versions or conflicting metadata')
        packages[identity]=row
    return format_, sorted(packages.values(),key=lambda r:r['id'])

def vulnerabilities_from_grype(data):
    data=obj(data)
    if 'matches' not in data: raise RadarError('not a Grype JSON report')
    findings={}
    for match in array(data['matches']):
        match=obj(match); v=obj(match.get('vulnerability')); a=obj(match.get('artifact'))
        vid=text(v.get('id'),limit=200); name=text(a.get('name'),limit=500); version=text(a.get('version'),limit=500);kind=text(a.get('type','unknown'),limit=200);purl=text(a.get('purl',''),limit=2000)
        if not vid or not name: raise RadarError('vulnerability identity missing')
        pkgid=_identity(name,kind,purl)
        fix=obj(v.get('fix',{})); versions=sorted({text(f,limit=500) for f in array(fix.get('versions',[]),200)})
        row={'id':hashlib.sha256(json.dumps([pkgid,version,vid]).encode()).hexdigest(), 'package_id':pkgid,'package':name,'version':version,
             'advisory_id':vid,'severity':text(v.get('severity'),default='Unknown',limit=100),
             'fixed_versions':versions,'fix_status':text(fix.get('state'),default='unknown',limit=100)}
        if row['id'] in findings and findings[row['id']]!=row: raise RadarError('conflicting duplicate vulnerability')
        findings[row['id']]=row
    db=obj(obj(data.get('descriptor',{})).get('db',{}))
    db=obj(db.get('status',db))
    if db.get('valid') is False: raise RadarError('Grype database reported invalid')
    return sorted(findings.values(),key=lambda r:r['id']), {'built':text(db.get('built'),default='',limit=100) or None,
            'schema_version':db.get('schemaVersion') if isinstance(db.get('schemaVersion'),(int,str)) else None,
            'status':'reported-by-grype' if db else 'not-provided'}

def report(sbom, sbom_sha256, grype=None, grype_sha256=None, mode='import'):
    format_,packages=packages_from_sbom(sbom)
    findings,db=vulnerabilities_from_grype(grype) if grype is not None else ([],{'built':None,'schema_version':None,'status':'not-scanned'})
    package_keys={(p['id'],p['version']) for p in packages}
    if any((v['package_id'],v['version']) not in package_keys for v in findings): raise RadarError('Grype findings do not match this SBOM')
    return {'schema_version':1,'project':PROJECT,'mode':mode,'generated_at':datetime.now(timezone.utc).isoformat(),
            'inputs_sha256':{'sbom':sbom_sha256,'grype':grype_sha256},'sbom_format':format_,'packages':packages,
            'summary':{'packages':len(packages),'findings':len(findings),'vulnerability_scan':'completed-report' if grype is not None else 'not-run'},
            'findings':findings,'database':db,
            'methodology':{'identity':'purl without version; qualifier order/percent-decoding normalized, base/subpath exact; otherwise type+name',
            'ambiguity':'conflicting package identities rejected, not guessed',
            'zero_findings':'No reported matches, not a security certification.'}}

def _index(rows,key='id'):
    output={}
    for row in array(rows):
        row=obj(row); identity=text(row.get(key),limit=2000)
        if not identity or identity in output: raise RadarError('duplicate or missing identity')
        output[identity]=row
    return output

def compare(before,after):
    for value in [before,after]:
        value=obj(value)
        if value.get('schema_version')!=1 or value.get('project')!=PROJECT: raise RadarError('incompatible report')
        for p in array(value.get('packages')):
            p=obj(p)
            if set(p)!={'id','name','version','type','purl'}: raise RadarError('incompatible package fields')
            if p.get('id')!=_identity(text(p.get('name'),limit=500),text(p.get('type'),limit=200),text(p.get('purl'),limit=2000)):
                raise RadarError('invalid package identity')
            text(p.get('version'),limit=500)
        known={p['id']:p for p in value['packages']}
        for v in array(value.get('findings')):
            v=obj(v)
            if set(v)!={'id','package_id','package','version','advisory_id','severity','fixed_versions','fix_status'}: raise RadarError('incompatible finding fields')
            for field in ('id','package_id','package','version','advisory_id','severity','fix_status'): text(v.get(field),limit=2000)
            for fixed in array(v.get('fixed_versions'),200): text(fixed,limit=500)
            if v['package_id'] not in known or v['package']!=known[v['package_id']]['name'] or v['version']!=known[v['package_id']]['version']: raise RadarError('baseline vulnerability package mismatch')
            if v['id']!=hashlib.sha256(json.dumps([v['package_id'],v['version'],v['advisory_id']]).encode()).hexdigest(): raise RadarError('invalid vulnerability identity')
        obj(value.get('summary'))
    old,new=_index(before['packages']),_index(after['packages'])
    shared=old.keys() & new.keys()
    package_diff={'added':[new[k] for k in sorted(new.keys()-old.keys())],
                  'removed':[old[k] for k in sorted(old.keys()-new.keys())],
                  'version_changed':[{'package_id':k,'name':new[k]['name'],'before':old[k]['version'],'after':new[k]['version']} for k in sorted(shared) if old[k]['version']!=new[k]['version']]}
    ov,nv=_index(before.get('findings',[])),_index(after.get('findings',[]))
    scanned = before.get('summary',{}).get('vulnerability_scan')=='completed-report' and after.get('summary',{}).get('vulnerability_scan')=='completed-report'
    return {'packages':package_diff,'vulnerabilities':{'new':[nv[k] for k in sorted(nv.keys()-ov.keys())] if scanned else [],
            'resolved':[ov[k] for k in sorted(ov.keys()-nv.keys())] if scanned else [],
            'status':'compared' if scanned else 'incomplete; one or both reports were not scanned'},
            'meaning':'Absent findings are not proof of remediation; database/scope changes affect comparisons.'}
