"""Real Syft directory scan, optional Grype offline DB scan; no target registry."""
import argparse,hashlib,json,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from sandworm_lens.cli import scan
from sandworm_lens.safety import RadarError
p=argparse.ArgumentParser();p.add_argument('--syft',default=str(ROOT/'.tools/syft'));p.add_argument('--grype',default=str(ROOT/'.tools/grype'));p.add_argument('--db-cache');args=p.parse_args()
try:
    result=scan(ROOT/'examples/live-project',args.syft,args.grype,args.db_cache,120)
    assert any(p['name']=='example-widget' and p['version']=='1.0.0' for p in result['packages'])
    if args.db_cache:assert result['summary']['vulnerability_scan']=='completed-report'
    record={'schema_version':1,'status':'passed' if args.db_cache else 'partial','mode':'live-engines-synthetic-project','generated_at':datetime.now(timezone.utc).isoformat(),'engines':result['engines'],'binary_sha256':{'syft':hashlib.sha256(Path(args.syft).read_bytes()).hexdigest(),'grype':hashlib.sha256(Path(args.grype).read_bytes()).hexdigest() if args.db_cache else None},'database':result['database'],'input_sha256':hashlib.sha256((ROOT/'examples/live-project/package-lock.json').read_bytes()).hexdigest(),'summary':result['summary'],'assertions':['real pinned Syft engine executed','invented fixture package catalogued','Grype offline scan completed' if args.db_cache else 'Grype scan not run; no clean status inferred','no registry source or project upload enabled']}
    (ROOT/'reports/live-smoke.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'status':record['status'],'summary':result['summary']}))
except (RadarError,AssertionError,OSError):
    print('Live supply chain smoke failed or engine/database unavailable; no passing record written.',file=sys.stderr);raise SystemExit(2)
