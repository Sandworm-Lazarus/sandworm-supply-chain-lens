from __future__ import annotations
import argparse, json, os, re, sys, tempfile
from pathlib import Path
from .engine import report, compare
from .safety import RadarError, read_json, parse_json, local_target, run_bounded, sha256, write_report
PINS={'syft':'1.57.1','grype':'0.121.3'}

def _check(binary,name,env):
    raw,code=run_bounded([binary,'version'],timeout=10,limit=65536,env=env)
    if code or not re.search(r'(?m)^Version:\s+v?'+re.escape(PINS[name])+r'\s*$',raw.decode('utf-8',errors='replace')):
        raise RadarError('engine version differs from upstream-lock.json')

def scan(target,syft='syft',grype='grype',db_cache=None,timeout=120):
    target=local_target(target)
    with tempfile.TemporaryDirectory(prefix='sandworm-sbom-') as tmp:
        env={'PATH':os.environ.get('PATH',''),'HOME':tmp,'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
             'SYFT_CHECK_FOR_APP_UPDATE':'false','GRYPE_CHECK_FOR_APP_UPDATE':'false','GRYPE_DB_AUTO_UPDATE':'false'}
        config=Path(tmp)/'config.yaml';config.write_text('{}\n')
        _check(syft,'syft',env)
        raw,code=run_bounded([syft,'scan','dir:'+str(target),'--output','syft-json','--config',str(config),'--quiet'],timeout=timeout,env=env)
        if code: raise RadarError('Syft scan failed')
        sbom=parse_json(raw);sbom_path=Path(tmp)/'sbom.json';sbom_path.write_bytes(raw)
        vulnerabilities=None;vhash=None
        if db_cache:
            try:cache=Path(db_cache).resolve(strict=True)
            except OSError:raise RadarError('Grype database cache unavailable') from None
            if not cache.is_dir() or Path(db_cache).is_symlink(): raise RadarError('invalid Grype database cache')
            env['GRYPE_DB_CACHE_DIR']=str(cache)
            _check(grype,'grype',env)
            vraw,code=run_bounded([grype,'sbom:'+str(sbom_path),'--output','json','--config',str(config),'--quiet'],timeout=timeout,env=env)
            if code: raise RadarError('Grype scan failed; offline database must be available and valid')
            vulnerabilities=parse_json(vraw);vhash=sha256(vraw)
        result=report(sbom,sha256(raw),vulnerabilities,vhash,mode='live')
        result['engines']={'syft':PINS['syft'],'grype':PINS['grype'] if db_cache else None,'network':'updates disabled; directory source only'}
        return result

def main(argv=None):
    parser=argparse.ArgumentParser(description='Sandworm Supply Chain Lens: local SBOM and vulnerability review')
    sub=parser.add_subparsers(dest='command',required=True)
    imp=sub.add_parser('import-report');imp.add_argument('sbom');imp.add_argument('--grype-report');imp.add_argument('--baseline');imp.add_argument('--out',required=True)
    live=sub.add_parser('scan');live.add_argument('target');live.add_argument('--syft',default='syft');live.add_argument('--grype',default='grype');live.add_argument('--db-cache');live.add_argument('--timeout',type=int,default=120);live.add_argument('--baseline');live.add_argument('--out',required=True)
    diff=sub.add_parser('diff');diff.add_argument('before');diff.add_argument('after');diff.add_argument('--out',required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='diff':
            old,oh=read_json(args.before);new,nh=read_json(args.after);delta=compare(old,new)
            result={'schema_version':1,'project':'sandworm-supply-chain-lens','mode':'import','summary':{k:len(v) for k,v in delta['packages'].items()},'findings':[],'comparison':delta,'inputs_sha256':{'before':oh,'after':nh}};inputs=[args.before,args.after]
        else:
            if args.command=='scan':result=scan(args.target,args.syft,args.grype,args.db_cache,args.timeout);inputs=[]
            else:
                sbom,sh=read_json(args.sbom);inputs=[args.sbom];vulns=None;vh=None
                if args.grype_report:vulns,vh=read_json(args.grype_report);inputs.append(args.grype_report)
                result=report(sbom,sh,vulns,vh)
            if args.baseline:
                old,digest=read_json(args.baseline);result['comparison']=compare(old,result);result['baseline_sha256']=digest;inputs.append(args.baseline)
        write_report(args.out,result,inputs)
        print(json.dumps({'status':'written','summary':result['summary']},ensure_ascii=False));return 0
    except (RadarError,OSError,TypeError,KeyError):
        print('Sandworm: operation failed; check SBOM/report schema, ambiguity, limits, pinned engines, and offline database.',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
