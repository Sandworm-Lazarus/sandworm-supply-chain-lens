"""Synthetic multi-version occurrence and conservative mapping regression cases."""
import copy,json,unittest
from pathlib import Path
from sandworm_lens.engine import packages_from_sbom,report,compare
from sandworm_lens.safety import RadarError
ROOT=Path(__file__).resolve().parents[1]
def fixture(name): return json.loads((ROOT/'examples/multiversion'/name).read_text())

class OccurrenceTests(unittest.TestCase):
 def test_authored_viewer_fixture_has_actual_engine_identities(self):
  expected=fixture('report-v2.json')
  actual=report(fixture('sbom.cdx.json'),'a',fixture('grype-unique-version.json'),'b')
  self.assertEqual(actual['packages'],expected['packages'])
  self.assertEqual(actual['findings'],expected['findings'])
 def test_three_occurrences_two_versions_all_formats(self):
  for name in ['sbom.syft.json','sbom.cdx.json','sbom.spdx.json']:
   rows=report(fixture(name),'synthetic')['packages']
   self.assertEqual(len(rows),3)
   self.assertEqual(len({p['id'] for p in rows}),3)
   self.assertEqual(len({p['family_id'] for p in rows}),1)
   self.assertEqual(sorted(p['version'] for p in rows),['1.0.0','1.0.0','2.0.0'])
 def test_native_syft_grype_ref_maps_repeated_version_separately(self):
  r=report(fixture('sbom.syft.json'),'a',fixture('grype-native.json'),'b')
  self.assertEqual(len(r['findings']),2)
  self.assertEqual(len({f['package_id'] for f in r['findings']}),2)
  serialized=json.dumps(r)
  self.assertNotIn('SYNTHETIC-install-',serialized)
 def test_grype_missing_id_repeated_version_rejected(self):
  g=fixture('grype-native.json')
  for row in g['matches']:row['artifact'].pop('id')
  with self.assertRaisesRegex(RadarError,'missing or ambiguous'):report(fixture('sbom.syft.json'),'a',g,'b')
 def test_unknown_native_ref_not_replaced_by_unique_key(self):
  g=fixture('grype-unique-version.json');g['matches'][0]['artifact']['id']='WRONG-PRIVATE-REFERENCE'
  with self.assertRaisesRegex(RadarError,'missing or ambiguous'):report(fixture('sbom.syft.json'),'a',g,'b')
 def test_native_ref_wrong_version_or_family_rejected(self):
  for field,value in [('version','3.0.0'),('purl','pkg:npm/another@1.0.0')]:
   g=fixture('grype-native.json');g['matches']=g['matches'][:1];g['matches'][0]['artifact'][field]=value
   with self.assertRaises(RadarError):report(fixture('sbom.syft.json'),'a',g,'b')
 def test_all_formats_unique_version_without_native_id(self):
  for name in ['sbom.syft.json','sbom.cdx.json','sbom.spdx.json']:
   r=report(fixture(name),'a',fixture('grype-unique-version.json'),'b')
   self.assertEqual(len(r['findings']),1);self.assertEqual(r['findings'][0]['version'],'2.0.0')
 def test_cdx_spdx_ids_not_assumed_to_equal_grype_ids(self):
  for name in ['sbom.cdx.json','sbom.spdx.json']:
   with self.assertRaisesRegex(RadarError,'missing or ambiguous'):
    report(fixture(name),'a',fixture('grype-native.json'),'b')
 def test_reused_native_ref_conflicts_even_across_versions(self):
  specs=[('sbom.syft.json','artifacts','id'),('sbom.cdx.json','components','bom-ref'),('sbom.spdx.json','packages','SPDXID')]
  for name,key,ref in specs:
   d=fixture(name);d[key][1][ref]=d[key][0][ref]
   with self.assertRaisesRegex(RadarError,'conflicting source'):packages_from_sbom(d)
 def test_missing_refs_are_explicit_version_level_fallback(self):
  d=fixture('sbom.syft.json')
  for row in d['artifacts']:row.pop('id')
  rows=packages_from_sbom(d)[1]
  self.assertEqual(len(rows),2)
  self.assertTrue(all(p['source']['ref_sha256'] is None for p in rows))
  d['artifacts'][2]['name']='conflicting-alias'
  with self.assertRaisesRegex(RadarError,'conflicting occurrence'):packages_from_sbom(d)
 def test_location_evidence_not_silently_collapsed_without_ref(self):
  for name,key,ref,field,value in [
   ('sbom.syft.json','artifacts','id','locations',[{'path':'SYNTHETIC/path'}]),
   ('sbom.cdx.json','components','bom-ref','evidence',{'occurrences':[{'location':'SYNTHETIC/path'}]}),
   ('sbom.spdx.json','packages','SPDXID','packageFileName','SYNTHETIC/path')]:
   d=fixture(name);d[key]=d[key][:1];d[key][0].pop(ref);d[key][0][field]=value
   with self.assertRaisesRegex(RadarError,'native reference required'):packages_from_sbom(d)
 def test_purl_version_conflict_rejected_and_missing_version_derived(self):
  d=fixture('sbom.syft.json');d['artifacts']=d['artifacts'][:1]
  d['artifacts'][0]['version']='2.0.0'
  with self.assertRaisesRegex(RadarError,'version conflicts'):packages_from_sbom(d)
  d['artifacts'][0].pop('version')
  self.assertEqual(packages_from_sbom(d)[1][0]['version'],'1.0.0')
 def test_reordering_does_not_change_occurrences(self):
  a=fixture('sbom.cdx.json');b=copy.deepcopy(a);b['components'].reverse()
  self.assertEqual(compare(report(a,'a'),report(b,'b'))['packages'],{'added':[],'removed':[]})
 def test_remove_one_version_preserves_other_occurrences(self):
  a=fixture('sbom.syft.json');b=copy.deepcopy(a);b['artifacts']=[p for p in b['artifacts'] if p['version']!='2.0.0']
  delta=compare(report(a,'a'),report(b,'b'))
  self.assertEqual(len(delta['packages']['removed']),1)
  self.assertEqual(delta['packages']['removed'][0]['version'],'2.0.0')
  self.assertEqual(delta['packages']['added'],[])
  self.assertEqual(delta['vulnerabilities']['resolved'],[])
  self.assertTrue(delta['vulnerabilities']['status'].startswith('incomplete'))
 def test_no_upgrade_pairing_or_cross_format_occurrence_guess(self):
  a=report(fixture('sbom.syft.json'),'a');b=report(fixture('sbom.cdx.json'),'b')
  delta=compare(a,b)
  self.assertEqual(len(delta['packages']['added']),3);self.assertEqual(len(delta['packages']['removed']),3)
  self.assertNotIn('version_changed',delta['packages'])
 def test_legacy_schema_not_silently_migrated(self):
  legacy=json.loads((ROOT/'examples/report.json').read_text())
  current=report(fixture('sbom.cdx.json'),'a')
  with self.assertRaisesRegex(RadarError,'re-import original'):compare(legacy,current)
 def test_tampered_occurrence_reference_and_family_rejected(self):
  for mutate in [lambda p:p['source'].update(ref_sha256='0'*64),lambda p:p.update(family_id='0'*64)]:
   r=report(fixture('sbom.cdx.json'),'a');mutate(r['packages'][0])
   with self.assertRaises(RadarError):compare(r,r)
 def test_unscanned_summary_cannot_carry_findings(self):
  r=report(fixture('sbom.syft.json'),'a',fixture('grype-native.json'),'b')
  r['summary']['vulnerability_scan']='not-run'
  with self.assertRaisesRegex(RadarError,'unscanned report'):compare(r,r)
if __name__=='__main__':unittest.main()
