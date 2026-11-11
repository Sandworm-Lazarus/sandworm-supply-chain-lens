import os,sys,tempfile,unittest
from pathlib import Path
from sandworm_lens.safety import RadarError,parse_json,read_json,run_bounded,local_target,write_report,MAX_BYTES
class SafetyTests(unittest.TestCase):
 def test_duplicate_json(self):
  with self.assertRaises(RadarError):parse_json('{"a":1,"a":2}')
 def test_nonfinite_json(self):
  with self.assertRaises(RadarError):parse_json('{"a":NaN}')
 def test_invalid_utf8(self):
  with self.assertRaises(RadarError):parse_json(b'\xff')
 def test_deep_json(self):
  with self.assertRaises(RadarError):parse_json('['*60+'0'+']'*60)
 def test_size(self):
  with self.assertRaises(RadarError):parse_json(b' '*(MAX_BYTES+1))
 def test_symlink(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'a').write_text('x');(p/'b').symlink_to(p/'a')
   with self.assertRaises(RadarError):local_target(p)
 def test_nonexistent_target(self):
  with self.assertRaises(RadarError):local_target('/not-a-sandworm-path')
 def test_subprocess_bounded_stdout(self):
  with self.assertRaises(RadarError):run_bounded([sys.executable,'-c','print("SENSITIVE"*5000)'],limit=500)
 def test_subprocess_bounded_stderr(self):
  with self.assertRaises(RadarError):run_bounded([sys.executable,'-c','import sys;sys.stderr.write("SENSITIVE"*5000)'],limit=500)
 def test_subprocess_timeout(self):
  with self.assertRaises(RadarError):run_bounded([sys.executable,'-c','import time;time.sleep(5)'],timeout=0.1)
 def test_subprocess_missing(self):
  with self.assertRaises(RadarError):run_bounded(['/not-an-engine'])
 def test_protect_input_file(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'input.json';p.write_text('{}')
   with self.assertRaises(RadarError):write_report(p,{},[p])
 def test_report_never_overwrites_existing(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'output.json';p.write_text('keep')
   with self.assertRaises(RadarError):write_report(p,{})
   self.assertEqual(p.read_text(),'keep')
 def test_read_fifo_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'pipe';os.mkfifo(p)
   with self.assertRaises(RadarError):read_json(p)
 def test_read_symlink_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'a').write_text('{}');(p/'b').symlink_to(p/'a')
   with self.assertRaises(RadarError):read_json(p/'b')
 def test_target_fifo_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);os.mkfifo(p/'pipe')
   with self.assertRaises(RadarError):local_target(p)
 def test_output_symlink_never_follows(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'a').write_text('keep');(p/'b').symlink_to(p/'a')
   with self.assertRaises(RadarError):write_report(p/'b',{})
   self.assertEqual((p/'a').read_text(),'keep')
