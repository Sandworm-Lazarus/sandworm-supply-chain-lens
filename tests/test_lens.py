import copy, io, json, os, tempfile, unittest
from pathlib import Path
from contextlib import redirect_stderr,redirect_stdout
from unittest.mock import patch
from sandworm_lens.engine import packages_from_sbom,vulnerabilities_from_grype,report,compare
from sandworm_lens.cli import main,scan
from sandworm_lens.safety import RadarError,parse_json,run_bounded
ROOT=Path(__file__).resolve().parents[1]
def sbom():return json.loads((ROOT/'examples/sbom.cdx.json').read_text())
def grype():return json.loads((ROOT/'examples/grype-report.json').read_text())
class LensTests(unittest.TestCase):
 def test_cyclonedx(self):
  fmt,rows=packages_from_sbom(sbom());self.assertEqual(fmt,'cyclonedx');self.assertEqual(rows[0]['name'],'example-widget')
 def test_syft(self):
  fmt,rows=packages_from_sbom({'artifacts':[{'name':'example-widget','version':'1.0.0','type':'npm','purl':'pkg:npm/example-widget@1.0.0'}]});self.assertEqual(fmt,'syft-json');self.assertEqual(len(rows),1)
 def test_spdx(self):
  fmt,rows=packages_from_sbom({'spdxVersion':'SPDX-2.3','packages':[{'name':'example-widget','versionInfo':'1.0.0','externalRefs':[{'referenceType':'purl','referenceLocator':'pkg:npm/example-widget@1.0.0'}]}]});self.assertEqual(fmt,'spdx');self.assertEqual(len(rows),1)
 def test_no_scan_is_not_clean(self):
  r=report(sbom(),'a');self.assertEqual(r['summary']['vulnerability_scan'],'not-run');self.assertEqual(r['database']['status'],'not-scanned')
 def test_grype_report_fix(self):
  r=report(sbom(),'a',grype(),'b');self.assertEqual(r['summary']['findings'],1);self.assertEqual(r['findings'][0]['fixed_versions'],['1.0.1'])
 def test_grype_other_sbom_rejected(self):
  d=grype();d['matches'][0]['artifact']['name']='other';d['matches'][0]['artifact']['purl']='pkg:npm/other@1.0.0'
  with self.assertRaises(RadarError):report(sbom(),'a',d,'b')
 def test_multiversion_ambiguity(self):
  d=sbom();r=copy.deepcopy(d['components'][0]);r['version']='2.0.0';r['purl']='pkg:npm/example-widget@2.0.0';d['components'].append(r)
  with self.assertRaises(RadarError):packages_from_sbom(d)
 def test_identical_duplicate_collapsed(self):
  d=sbom();d['components']*=2;self.assertEqual(len(packages_from_sbom(d)[1]),1)
 def test_spdx_conflicting_purls(self):
  d={'spdxVersion':'SPDX-2.3','packages':[{'name':'x','externalRefs':[{'referenceType':'purl','referenceLocator':'pkg:npm/a@1'},{'referenceType':'purl','referenceLocator':'pkg:npm/b@1'}]}]}
  with self.assertRaises(RadarError):packages_from_sbom(d)
 def test_bad_purl(self):
  d=sbom();d['components'][0]['purl']='https://invalid.test'
  with self.assertRaises(RadarError):packages_from_sbom(d)
 def test_unsupported_format(self):
  with self.assertRaises(RadarError):packages_from_sbom({})
 def test_missing_grype_schema(self):
  with self.assertRaises(RadarError):vulnerabilities_from_grype({})
 def test_conflicting_vuln_duplicate(self):
  d=grype();r=copy.deepcopy(d['matches'][0]);r['vulnerability']['severity']='Critical';d['matches'].append(r)
  with self.assertRaises(RadarError):vulnerabilities_from_grype(d)
 def test_identical_vuln_duplicate(self):
  d=grype();d['matches']*=2;self.assertEqual(len(vulnerabilities_from_grype(d)[0]),1)
 def test_version_change_diff(self):
  before=report(sbom(),'a',grype(),'b');s=sbom();s['components'][0]['version']='1.0.1';s['components'][0]['purl']='pkg:npm/example-widget@1.0.1';after=report(s,'c',{'matches':[]},'d')
  d=compare(before,after);self.assertEqual(len(d['packages']['version_changed']),1);self.assertEqual(len(d['vulnerabilities']['resolved']),1)
 def test_added_removed(self):
  before=report(sbom(),'a');s=sbom();s['components'][0]['name']='another';s['components'][0]['purl']='pkg:npm/another@1.0.0';after=report(s,'b')
  d=compare(before,after);self.assertEqual(len(d['packages']['added']),1);self.assertEqual(len(d['packages']['removed']),1)
 def test_unscanned_comparison_incomplete(self):
  r=report(sbom(),'a');self.assertTrue(compare(r,r)['vulnerabilities']['status'].startswith('incomplete'))
 def test_unscanned_after_has_no_resolved_claim(self):
  before=report(sbom(),'a',grype(),'b');after=report(sbom(),'c')
  self.assertEqual(compare(before,after)['vulnerabilities']['resolved'],[])
 def test_duplicate_baseline(self):
  r=report(sbom(),'a');r['packages']*=2
  with self.assertRaises(RadarError):compare(r,r)
 def test_tampered_identity(self):
  r=report(sbom(),'a');r['packages'][0]['id']='wrong'
  with self.assertRaises(RadarError):compare(r,r)
 def test_baseline_unknown_package_field_rejected(self):
  r=report(sbom(),'a');r['packages'][0]['private_original']='must-not-export'
  with self.assertRaises(RadarError):compare(r,r)
 def test_baseline_unknown_finding_field_rejected(self):
  r=report(sbom(),'a',grype(),'b');r['findings'][0]['private_original']='must-not-export'
  with self.assertRaises(RadarError):compare(r,r)
 def test_baseline_malformed_summary_rejected(self):
  r=report(sbom(),'a');r['summary']='bad'
  with self.assertRaises(RadarError):compare(r,r)
 def test_baseline_tampered_vulnerability_identity(self):
  r=report(sbom(),'a',grype(),'b');r['findings'][0]['id']='wrong'
  with self.assertRaises(RadarError):compare(r,r)
 def test_control_text(self):
  d=sbom();d['components'][0]['name']='bad\x00value'
  with self.assertRaises(RadarError):packages_from_sbom(d)
 def test_deep_components(self):
  d=sbom();r=d['components'][0]
  for _ in range(22):r['components']=[{'name':'a','version':'1'}];r=r['components'][0]
  with self.assertRaises(RadarError):packages_from_sbom(d)
 def test_purl_qualifier_kept(self):
  d=sbom();a=copy.deepcopy(d['components'][0]);d['components'][0]['purl']+='?arch=arm64';a['purl']+='?arch=amd64';d['components'].append(a);self.assertEqual(len(packages_from_sbom(d)[1]),2)
 def test_purl_qualifier_order_equivalent(self):
  a=sbom();b=sbom();a['components'][0]['purl']+='?arch=arm64&distro=ubuntu';b['components'][0]['purl']+='?distro=ubuntu&arch=arm64'
  d=compare(report(a,'a'),report(b,'b'));self.assertEqual(d['packages']['added'],[]);self.assertEqual(d['packages']['removed'],[])
 def test_purl_duplicate_qualifier_rejected(self):
  d=sbom();d['components'][0]['purl']+='?arch=arm64&arch=amd64'
  with self.assertRaises(RadarError):packages_from_sbom(d)
 def test_purl_percent_encoded_qualifier_equivalent(self):
  a=sbom();b=sbom();a['components'][0]['purl']+='?vendor=example%20org';b['components'][0]['purl']+='?vendor=example org'
  self.assertEqual(packages_from_sbom(a)[1][0]['id'],packages_from_sbom(b)[1][0]['id'])
 def test_purl_invalid_percent_rejected(self):
  d=sbom();d['components'][0]['purl']+='?arch=%GG'
  with self.assertRaises(RadarError):packages_from_sbom(d)
 def test_cli_import(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'r.json'
   with redirect_stdout(io.StringIO()):c=main(['import-report',str(ROOT/'examples/sbom.cdx.json'),'--grype-report',str(ROOT/'examples/grype-report.json'),'--out',str(p)])
   self.assertEqual(c,0);self.assertEqual(json.loads(p.read_text())['summary']['findings'],1)
 def test_cli_error_no_original_data(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'bad.json';p.write_text('SECRET-SENTINEL');e=io.StringIO()
   with redirect_stderr(e):c=main(['import-report',str(p),'--out',str(Path(tmp)/'out.json')])
   self.assertEqual(c,2);self.assertNotIn('SECRET-SENTINEL',e.getvalue())
 def test_scan_output_cannot_replace_source(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'package-lock.json';p.write_text('source-keep')
   with patch('sandworm_lens.cli.scan',return_value=report(sbom(),'x')),redirect_stderr(io.StringIO()):
    c=main(['scan',tmp,'--out',str(p)])
   self.assertEqual(c,2);self.assertEqual(p.read_text(),'source-keep')
 def test_current_grype_nested_db_status(self):
  d=grype();d['descriptor']['db']={'status':{'built':'2026-11-11T00:00:00Z','schemaVersion':'v6.1.10','valid':True}}
  self.assertEqual(vulnerabilities_from_grype(d)[1]['schema_version'],'v6.1.10')
 def test_invalid_grype_database(self):
  d=grype();d['descriptor']['db']={'status':{'valid':False}}
  with self.assertRaises(RadarError):vulnerabilities_from_grype(d)
 def test_live_adapter_no_registry_or_credential_env(self):
  calls=[];raw=json.dumps({'artifacts':[{'name':'example-widget','version':'1.0.0','type':'npm','purl':'pkg:npm/example-widget@1.0.0'}]}).encode()
  def fake(args,**kw):calls.append((args,kw));return (b'Version: 1.57.1\n',0) if args[1]=='version' else (raw,0)
  with patch('sandworm_lens.cli.run_bounded',side_effect=fake),patch.dict(os.environ,{'AWS_SECRET_ACCESS_KEY':'must-not-pass'}):r=scan(ROOT/'examples/live-project')
  self.assertEqual(r['summary']['vulnerability_scan'],'not-run');self.assertTrue(calls[1][0][2].startswith('dir:'));self.assertNotIn('AWS_SECRET_ACCESS_KEY',calls[1][1]['env'])
 def test_live_syft_failure(self):
  def fake(args,**kw):return (b'Version: 1.57.1\n',0) if args[1]=='version' else (b'private-content',1)
  with patch('sandworm_lens.cli.run_bounded',side_effect=fake):
   with self.assertRaises(RadarError):scan(ROOT/'examples/live-project')
 def test_duplicate_json(self):
  with self.assertRaises(RadarError):parse_json('{"a":1,"a":2}')
 def test_nonfinite(self):
  with self.assertRaises(RadarError):parse_json('{"x":Infinity}')
if __name__=='__main__':unittest.main()
