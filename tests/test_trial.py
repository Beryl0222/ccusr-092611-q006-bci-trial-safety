import os,tempfile,unittest
from bci_trial_safety.trial import TrialService,TrialError
class TrialServiceTests(unittest.TestCase):
 def setUp(self):
  self.svc=TrialService()
  self.svc.register_staff("doc1","clinician",["s1","s2"])
  self.svc.register_staff("res1","researcher",["s1"])
  self.svc.register_device("wheelchair",{"gain":1.0})
 def tearDown(self):self.svc.close()
 def _open_ready(self,session="ss1",subject="s1",device="wheelchair"):
  self.svc.grant_authorization("auth-"+session,subject,"doc1")
  self.svc.calibrate("cal-"+session,device,"doc1")
  self.svc.open_session(session,subject,device,"res1")
 def test_session_requires_authorization(self):
  self.svc.calibrate("cal-1","wheelchair","doc1")
  with self.assertRaises(TrialError):self.svc.open_session("ss1","s1","wheelchair","res1")
 def test_command_rejected_before_calibration(self):
  self.svc.grant_authorization("auth-1","s1","doc1")
  self.svc.open_session("ss1","s1","wheelchair","res1")
  r=self.svc.submit_command("ss1",1,{"move":"forward"},"res1")
  self.assertEqual(r["state"],"rejected")
  self.assertEqual(self.svc.submit_command("ss1",1,{"move":"forward"},"res1"),r)
  self.svc.calibrate("cal-1","wheelchair","doc1")
  self.assertEqual(self.svc.submit_command("ss1",2,{"move":"forward"},"res1")["state"],"queued")
 def test_command_rejected_after_authorization_revoked(self):
  self._open_ready()
  self.svc.revoke_authorization("auth-ss1","doc1")
  self.assertEqual(self.svc.submit_command("ss1",1,{"move":"forward"},"res1")["state"],"rejected")
 def test_stop_cancels_queued_and_rejects_late(self):
  self._open_ready()
  self.svc.submit_command("ss1",1,{"move":"forward"},"res1")
  self.svc.submit_command("ss1",2,{"move":"left"},"res1")
  outcome=self.svc.emergency_stop("ss1","doc1")
  self.assertEqual(outcome["cancelled"],[1,2])
  self.assertEqual(self.svc.dispatch_pending("ss1","res1"),[])
  late=self.svc.submit_command("ss1",3,{"move":"back"},"res1")
  self.assertEqual(late["state"],"rejected")
  self.assertEqual(self.svc.get_session("ss1")["state"],"stopped")
  replay=self.svc.submit_command("ss1",1,{"move":"forward"},"res1")
  self.assertEqual(replay["state"],"cancelled")
  again=self.svc.emergency_stop("ss1","doc1")
  self.assertEqual(again["cancelled"],[])
 def test_dispatch_executes_in_seq_order_and_replay_is_stable(self):
  self._open_ready()
  self.svc.submit_command("ss1",2,{"move":"left"},"res1")
  self.svc.submit_command("ss1",1,{"move":"forward"},"res1")
  results=self.svc.dispatch_pending("ss1","res1")
  self.assertEqual([r["seq"] for r in results],[1,2])
  self.assertTrue(all(r["state"]=="executed" for r in results))
  again=self.svc.submit_command("ss1",1,{"move":"forward"},"res1")
  self.assertEqual(again["state"],"executed")
  kinds=[e["kind"] for e in self.svc.export_audit("ss1")]
  self.assertEqual(kinds.count("command_executed"),2)
 def test_param_change_invalidates_calibration(self):
  self._open_ready()
  self.svc.set_device_params("wheelchair",{"gain":2.0})
  r=self.svc.submit_command("ss1",1,{"move":"forward"},"res1")
  self.assertEqual(r["state"],"rejected")
  self.svc.calibrate("cal-2","wheelchair","doc1")
  self.assertEqual(self.svc.submit_command("ss1",2,{"move":"forward"},"res1")["state"],"queued")
 def test_staff_scope_enforced(self):
  self.svc.grant_authorization("auth-2","s2","doc1")
  with self.assertRaises(TrialError):self.svc.open_session("ss2","s2","wheelchair","res1")
  self._open_ready()
  self.svc.register_staff("res2","researcher",["s2"])
  with self.assertRaises(TrialError):self.svc.submit_command("ss1",1,{"move":"x"},"res2")
  with self.assertRaises(TrialError):self.svc.emergency_stop("ss1","res2")
  with self.assertRaises(TrialError):self.svc.grant_authorization("auth-3","s2","res1")
 def test_state_survives_reopen(self):
  fd,path=tempfile.mkstemp(suffix=".db");os.close(fd)
  try:
   svc=TrialService(path)
   svc.register_staff("doc1","clinician",["s1"]);svc.register_device("wheelchair",{"gain":1.0})
   svc.grant_authorization("auth-1","s1","doc1");svc.calibrate("cal-1","wheelchair","doc1")
   svc.open_session("ss1","s1","wheelchair","doc1")
   svc.submit_command("ss1",1,{"move":"forward"},"doc1");svc.dispatch_pending("ss1","doc1")
   svc.emergency_stop("ss1","doc1");svc.close()
   reopened=TrialService(path)
   self.assertEqual(reopened.get_session("ss1")["state"],"stopped")
   replay=reopened.submit_command("ss1",1,{"move":"forward"},"doc1")
   self.assertEqual(replay["state"],"executed")
   late=reopened.submit_command("ss1",9,{"move":"back"},"doc1")
   self.assertEqual(late["state"],"rejected")
   kinds=[e["kind"] for e in reopened.export_audit("ss1")]
   self.assertIn("emergency_stop",kinds);self.assertIn("command_executed",kinds)
   reopened.close()
  finally:os.unlink(path)
 def test_export_audit_time_order(self):
  self._open_ready()
  self.svc.submit_command("ss1",1,{"move":"forward"},"res1")
  self.svc.dispatch_pending("ss1","res1")
  self.svc.emergency_stop("ss1","doc1")
  events=self.svc.export_audit("ss1")
  ids=[e["id"] for e in events]
  self.assertEqual(ids,sorted(ids))
  kinds=[e["kind"] for e in events]
  self.assertEqual(kinds,["session_opened","command_queued","command_executed","emergency_stop"])
if __name__=="__main__":unittest.main()
