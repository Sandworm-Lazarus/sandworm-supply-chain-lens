"""Versioned SBOM occurrences and unambiguous Grype evidence mapping."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib, json, re
from urllib.parse import unquote
from .safety import RadarError, array, obj, text
PROJECT='sandworm-supply-chain-lens'
SCHEMA_VERSION=2
FORMATS=('syft-json','cyclonedx','spdx')

def _digest(value):
    return hashlib.sha256(json.dumps(value,ensure_ascii=False).encode()).hexdigest()

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


def _version(version,purl):
    version=text(version,limit=500)
    if purl:
        base=purl.partition('#')[0].partition('?')[0]
        if base.rfind('@') > base.rfind('/'):
            raw=base.rsplit('@',1)[1]
            if not raw or re.search(r'%(?![0-9a-fA-F]{2})',raw): raise RadarError('invalid purl version')
            try: declared=unquote(raw,encoding='utf-8',errors='strict')
            except UnicodeError: raise RadarError('invalid purl version') from None
            declared=text(declared,limit=500)
            if version and version!=declared: raise RadarError('package version conflicts with purl')
            version=version or declared
    return version

def _occurrence_id(family,version,format_,reference):
    return _digest(['occurrence-v2',family,version,format_,reference])

def _finding_id(package_id,advisory_id):
    return _digest(['finding-v2',package_id,advisory_id])

def packages_from_sbom(data):
    data=obj(data); rows=[]
    def append(item,format_,version_key='version',reference_key=None,kind_default='unknown',purl=None):
        item=obj(item)
        name=text(item.get('name'),limit=500)
        kind=text(item.get('type',kind_default),limit=200)
        purl=text(item.get('purl','') if purl is None else purl,limit=2000)
        version=_version(item.get(version_key,''),purl)
        reference=text(item.get(reference_key,''),limit=2000) if reference_key else ''
        if not name: raise RadarError('package name missing')
        # A native reference identifies an upstream package record, potentially
        # aggregating several locations. Never discard location evidence into
        # the reference-free version-only fallback.
        location_evidence=bool(item.get('locations')) if format_=='syft-json' else False
        if format_=='cyclonedx':
            evidence=obj(item.get('evidence',{}))
            location_evidence=bool(evidence.get('occurrences')) or bool(item.get('properties'))
        if format_=='spdx':
            location_evidence=bool(item.get('packageFileName')) or bool(item.get('hasFiles'))
        if not reference and location_evidence: raise RadarError('native reference required for occurrence location evidence')
        family=_identity(name,kind,purl)
        ref_hash=_digest(['source-reference-v2',reference]) if reference else None
        rows.append({'id':_occurrence_id(family,version,format_,ref_hash),'family_id':family,
                     'name':name,'version':version,'type':kind,'purl':purl or None,
                     'source':{'format':format_,'ref_sha256':ref_hash}})
        if len(rows)>20000: raise RadarError('package limit exceeded')
    if 'artifacts' in data:
        format_='syft-json'
        for item in array(data['artifacts']): append(item,format_,reference_key='id')
    elif data.get('bomFormat')=='CycloneDX':
        format_='cyclonedx'
        def components(items,depth=0):
            if depth>20: raise RadarError('component nesting limit')
            for item in array(items):
                append(item,format_,reference_key='bom-ref')
                if 'components' in item: components(item['components'],depth+1)
        components(data.get('components',[]))
    elif str(data.get('spdxVersion','')).startswith('SPDX-'):
        format_='spdx'
        for item in array(data.get('packages',[])):
            item=obj(item); purls=[]
            for ref in array(item.get('externalRefs',[]),100):
                ref=obj(ref)
                if ref.get('referenceType') in ('purl','http://spdx.org/rdf/references/purl'):
                    purls.append(text(ref.get('referenceLocator'),limit=2000))
            if len(set(purls))>1: raise RadarError('ambiguous SPDX package URLs')
            append(item,format_,version_key='versionInfo',reference_key='SPDXID',purl=purls[0] if purls else '')
    else: raise RadarError('unsupported SBOM format')
    packages={}; references={}
    for row in rows:
        reference=row['source']['ref_sha256']
        if reference:
            if reference in references and references[reference]!=row: raise RadarError('conflicting source package reference')
            references[reference]=row
        if row['id'] in packages and packages[row['id']]!=row: raise RadarError('conflicting occurrence metadata')
        # With no source reference, this is a version-level record, not an
        # assertion about how many installed copies exist.
        packages[row['id']]=row
    return format_,sorted(packages.values(),key=lambda row:row['id'])

def vulnerabilities_from_grype(data,packages):
    data=obj(data)
    if 'matches' not in data: raise RadarError('not a Grype JSON report')
    by_version={}
    for package in array(packages):
        by_version.setdefault((package['family_id'],package['version']),[]).append(package)
    findings={}
    for match in array(data['matches']):
        match=obj(match); v=obj(match.get('vulnerability')); a=obj(match.get('artifact'))
        vid=text(v.get('id'),limit=200); name=text(a.get('name'),limit=500)
        kind=text(a.get('type','unknown'),limit=200); purl=text(a.get('purl',''),limit=2000)
        version=_version(a.get('version',''),purl); artifact_id=text(a.get('id',''),limit=2000)
        if not vid or not name: raise RadarError('vulnerability identity missing')
        candidates=by_version.get((_identity(name,kind,purl),version),[])
        native=[p for p in candidates if p['source']['format']=='syft-json' and p['source']['ref_sha256'] is not None]
        if artifact_id and native:
            reference=_digest(['source-reference-v2',artifact_id])
            candidates=[p for p in native if p['source']['ref_sha256']==reference]
        # CDX bom-ref/SPDXID are not assumed to equal Grype's generated ID.
        # No fanout or first-match fallback is allowed for repeated versions.
        if len(candidates)!=1 or candidates[0]['name']!=name:
            raise RadarError('Grype artifact occurrence is missing or ambiguous')
        package=candidates[0]; package_id=package['id']
        fix=obj(v.get('fix',{}))
        versions=sorted({text(f,limit=500) for f in array(fix.get('versions',[]),200)})
        row={'id':_finding_id(package_id,vid),'package_id':package_id,'package':name,'version':version,
             'advisory_id':vid,'severity':text(v.get('severity'),default='Unknown',limit=100),
             'fixed_versions':versions,'fix_status':text(fix.get('state'),default='unknown',limit=100)}
        if row['id'] in findings and findings[row['id']]!=row: raise RadarError('conflicting duplicate vulnerability')
        findings[row['id']]=row
    db=obj(obj(data.get('descriptor',{})).get('db',{})); db=obj(db.get('status',db))
    if db.get('valid') is False: raise RadarError('Grype database reported invalid')
    return sorted(findings.values(),key=lambda row:row['id']),{
        'built':text(db.get('built'),default='',limit=100) or None,
        'schema_version':db.get('schemaVersion') if type(db.get('schemaVersion')) in (int,str) else None,
        'status':'reported-by-grype' if db else 'not-provided'}

def report(sbom,sbom_sha256,grype=None,grype_sha256=None,mode='import'):
    if mode not in ('live','fixture','import'): raise RadarError('invalid report mode')
    format_,packages=packages_from_sbom(sbom)
    findings,db=vulnerabilities_from_grype(grype,packages) if grype is not None else ([],{'built':None,'schema_version':None,'status':'not-scanned'})
    return {'schema_version':SCHEMA_VERSION,'project':PROJECT,'mode':mode,
            'generated_at':datetime.now(timezone.utc).isoformat(),
            'inputs_sha256':{'sbom':sbom_sha256,'grype':grype_sha256},'sbom_format':format_,'packages':packages,
            'summary':{'packages':len(packages),'findings':len(findings),
                       'vulnerability_scan':'completed-report' if grype is not None else 'not-run'},
            'findings':findings,'database':db,
            'methodology':{'identity':'versionless family + exact version + source format + hashed native reference; absent reference is version-level only',
                           'ambiguity':'native Syft ID or unique family/version; ambiguous Grype artifacts rejected',
                           'comparison':'exact occurrence added/removed; no inferred upgrade pairing',
                           'zero_findings':'No reported matches, not a security certification.'}}

def _index(rows,key='id'):
    output={}
    for row in array(rows):
        row=obj(row); identity=text(row.get(key),limit=2000)
        if not identity or identity in output: raise RadarError('duplicate or missing identity')
        output[identity]=row
    return output

def _validated_report(value):
    value=obj(value)
    if type(value.get('schema_version')) is not int or value.get('schema_version')!=SCHEMA_VERSION or value.get('project')!=PROJECT:
        raise RadarError('schema 2 required; re-import original SBOM and Grype inputs')
    format_=value.get('sbom_format')
    if format_ not in FORMATS: raise RadarError('incompatible SBOM format')
    known=_index(value.get('packages')); references=set()
    for p in known.values():
        if set(p)!={'id','family_id','name','version','type','purl','source'}: raise RadarError('incompatible package fields')
        name=text(p.get('name'),limit=500); kind=text(p.get('type'),limit=200)
        purl=text(p.get('purl'),limit=2000); version=text(p.get('version'),limit=500)
        if not name or _version(version,purl)!=version or p.get('family_id')!=_identity(name,kind,purl):
            raise RadarError('invalid package family or version')
        source=obj(p.get('source'))
        if set(source)!={'format','ref_sha256'} or source['format']!=format_: raise RadarError('invalid occurrence source')
        reference=source['ref_sha256']
        if reference is not None:
            if not isinstance(reference,str) or not re.fullmatch(r'[a-f0-9]{64}',reference) or reference in references:
                raise RadarError('duplicate or invalid occurrence reference')
            references.add(reference)
        if p['id']!=_occurrence_id(p['family_id'],version,format_,reference): raise RadarError('invalid occurrence identity')
    findings=_index(value.get('findings'))
    for v in findings.values():
        if set(v)!={'id','package_id','package','version','advisory_id','severity','fixed_versions','fix_status'}:
            raise RadarError('incompatible finding fields')
        for field in ('id','package_id','package','version','advisory_id','severity','fix_status'): text(v.get(field),limit=2000)
        for fixed in array(v.get('fixed_versions'),200): text(fixed,limit=500)
        package=known.get(v['package_id'])
        if not package or v['package']!=package['name'] or v['version']!=package['version']:
            raise RadarError('baseline vulnerability package mismatch')
        if not v['advisory_id'] or v['id']!=_finding_id(v['package_id'],v['advisory_id']):
            raise RadarError('invalid vulnerability identity')
    summary=obj(value.get('summary'))
    if summary.get('vulnerability_scan') not in ('completed-report','not-run'): raise RadarError('invalid scan status')
    if type(summary.get('packages')) is not int or summary['packages']!=len(known) or type(summary.get('findings')) is not int or summary['findings']!=len(findings):
        raise RadarError('inconsistent summary counts')
    if summary['vulnerability_scan']=='not-run' and findings: raise RadarError('unscanned report has findings')
    return value,known,findings

def compare(before,after):
    before,old,ov=_validated_report(before); after,new,nv=_validated_report(after)
    scanned=before['summary']['vulnerability_scan']=='completed-report' and after['summary']['vulnerability_scan']=='completed-report'
    return {'packages':{'added':[new[k] for k in sorted(new.keys()-old.keys())],
                        'removed':[old[k] for k in sorted(old.keys()-new.keys())]},
            'vulnerabilities':{'new':[nv[k] for k in sorted(nv.keys()-ov.keys())] if scanned else [],
                               'resolved':[ov[k] for k in sorted(ov.keys()-nv.keys())] if scanned else [],
                               'status':'compared' if scanned else 'incomplete; one or both reports were not scanned'},
            'meaning':'Exact occurrence evidence only; no upgrade pairing. Missing findings do not prove remediation; database/scope/source-reference changes affect comparisons.'}
