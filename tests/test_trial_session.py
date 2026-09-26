import os
import tempfile
import unittest

from bci_trial_safety.service import ServiceError
from bci_trial_safety.trial import TrialSessionService


def make_clock():
    state = {"n": 0}

    def tick():
        state["n"] += 1
        return "2026-09-26T08:00:%02d+00:00" % state["n"]

    return tick


class TrialSessionTests(unittest.TestCase):
    def setUp(self):
        self.svc = TrialSessionService(clock=make_clock())
        self.svc.register_staff("res-1", "researcher")
        self.svc.register_staff("res-2", "researcher")
        self.svc.register_staff("doc-1", "clinician")
        self.svc.grant_scope("res-1", "subj-A")
        self.svc.grant_scope("res-2", "subj-B")
        self.svc.grant_scope("doc-1", "subj-A")

    def tearDown(self):
        self.svc.close()

    def open_session(self, session_id="s1", subject="subj-A", by="res-1"):
        return self.svc.open_session(session_id, subject, "wheelchair-01",
                                     {"gain": 1.0, "channel_map": [1, 2, 3]}, by)

    def ready_session(self, session_id="s1"):
        self.open_session(session_id)
        self.svc.authorize(session_id, "doc-1", "知情同意书 v3")
        self.svc.calibrate(session_id, "res-1")

    def test_reject_before_authorization_and_calibration(self):
        self.open_session()
        r1 = self.svc.submit_command("s1", 1, "forward", "res-1")
        self.assertEqual((r1["status"], r1["reason"]), ("rejected", "not_authorized"))
        self.svc.authorize("s1", "doc-1")
        r2 = self.svc.submit_command("s1", 2, "forward", "res-1")
        self.assertEqual((r2["status"], r2["reason"]), ("rejected", "calibration_invalid"))
        self.svc.calibrate("s1", "res-1")
        r3 = self.svc.submit_command("s1", 3, "forward", "res-1")
        self.assertEqual(r3["status"], "queued")
        # 授权与校准补齐后，旧序号重放仍返回最初的拒绝结果
        self.assertEqual(self.svc.submit_command("s1", 1, "forward", "res-1"), r1)
        self.assertEqual(self.svc.submit_command("s1", 2, "forward", "res-1"), r2)

    def test_execution_in_seq_order(self):
        self.ready_session()
        for i in (1, 2, 3):
            self.svc.submit_command("s1", i, "move-%d" % i, "res-1")
        executed = self.svc.run_pending("s1", "res-1")
        self.assertEqual([e["seq"] for e in executed], [1, 2, 3])
        self.assertTrue(all(e["status"] == "executed" for e in executed))
        again = self.svc.submit_command("s1", 2, "move-2", "res-1")
        self.assertEqual(again["status"], "executed")

    def test_delayed_command_never_overrides_emergency_stop(self):
        self.ready_session()
        self.svc.submit_command("s1", 1, "forward", "res-1")  # 排队未执行
        stop = self.svc.stop("s1", "doc-1", "受试者不适")
        self.assertEqual(stop["status"], "stopped")
        self.assertEqual(stop["preempted"], [1])
        # 延迟到达的旧指令（重放）：只返回原结果，不执行
        replay = self.svc.submit_command("s1", 1, "forward", "res-1")
        self.assertEqual((replay["status"], replay["reason"]), ("preempted", "emergency_stop"))
        # 停止前发出、停止后才到达的新序号：拒绝并留痕
        late = self.svc.submit_command("s1", 2, "forward", "res-1")
        self.assertEqual((late["status"], late["reason"]), ("rejected", "session_stopped"))
        with self.assertRaises(ServiceError):
            self.svc.run_pending("s1", "res-1")
        kinds = [e["kind"] for e in self.svc.export_log("s1")]
        self.assertNotIn("command_executed", kinds)
        self.assertIn("command_preempted", kinds)
        # 停止幂等：重复按下返回首次结果，不重复写事件
        again = self.svc.stop("s1", "res-1", "再次按下")
        self.assertEqual(again["stopped_at"], stop["stopped_at"])
        self.assertEqual(kinds.count("emergency_stop"), 1)

    def test_replay_returns_original_result(self):
        self.ready_session()
        first = self.svc.submit_command("s1", 1, "grasp", "res-1")
        self.assertEqual(self.svc.submit_command("s1", 1, "grasp", "res-1"), first)
        self.svc.run_pending("s1", "res-1")
        executed = self.svc.submit_command("s1", 1, "grasp", "res-1")
        self.assertEqual(executed["status"], "executed")
        self.assertEqual(self.svc.submit_command("s1", 1, "grasp", "res-1"), executed)
        submitted = [e for e in self.svc.export_log("s1") if e["kind"] == "command_submitted"]
        self.assertEqual(len(submitted), 1)

    def test_param_change_invalidates_calibration(self):
        self.ready_session()
        self.svc.submit_command("s1", 1, "forward", "res-1")
        change = self.svc.update_device_params("s1", {"gain": 2.0}, "res-1")
        self.assertTrue(change["calibration_invalidated"])
        self.assertFalse(self.svc.get_session("s1")["calibration_valid"])
        # 已排队但未执行的指令在派发时被门控拦下，不得执行
        self.assertEqual(self.svc.run_pending("s1", "res-1"), [])
        r1 = self.svc.submit_command("s1", 1, "forward", "res-1")
        self.assertEqual((r1["status"], r1["reason"]), ("rejected", "calibration_invalid"))
        r2 = self.svc.submit_command("s1", 2, "forward", "res-1")
        self.assertEqual(r2["reason"], "calibration_invalid")
        # 重新校准后恢复
        self.svc.calibrate("s1", "res-1")
        r3 = self.svc.submit_command("s1", 3, "forward", "res-1")
        self.assertEqual(r3["status"], "queued")
        kinds = [e["kind"] for e in self.svc.export_log("s1")]
        self.assertIn("calibration_invalidated", kinds)

    def test_scope_and_role_limits(self):
        self.open_session()
        with self.assertRaises(ServiceError):  # res-2 未获准 subj-A
            self.svc.open_session("s2", "subj-A", "arm-01", {}, "res-2")
        with self.assertRaises(ServiceError):
            self.svc.submit_command("s1", 1, "forward", "res-2")
        with self.assertRaises(ServiceError):
            self.svc.stop("s1", "res-2")
        with self.assertRaises(ServiceError):  # 授权仅限临床人员
            self.svc.authorize("s1", "res-1")
        with self.assertRaises(ServiceError):  # 未登记人员
            self.svc.submit_command("s1", 1, "forward", "ghost")
        # 获准范围内可以正常操作
        self.svc.open_session("s3", "subj-B", "arm-02", {}, "res-2")
        self.assertEqual(self.svc.get_session("s3")["state"], "active")

    def test_close_session_preempts_and_is_terminal(self):
        self.ready_session()
        self.svc.submit_command("s1", 1, "forward", "res-1")
        closed = self.svc.close_session("s1", "res-1")
        self.assertEqual(closed["state"], "closed")
        self.assertEqual(closed["preempted"], [1])
        r1 = self.svc.submit_command("s1", 1, "forward", "res-1")
        self.assertEqual((r1["status"], r1["reason"]), ("preempted", "session_closed"))
        r2 = self.svc.submit_command("s1", 2, "forward", "res-1")
        self.assertEqual(r2["reason"], "session_closed")
        with self.assertRaises(ServiceError):
            self.svc.stop("s1", "doc-1")

    def test_invalid_command_input(self):
        self.ready_session()
        with self.assertRaises(ServiceError):
            self.svc.submit_command("s1", -1, "forward", "res-1")
        with self.assertRaises(ServiceError):
            self.svc.submit_command("s1", 1, "", "res-1")

    def test_restart_persists_stop_results_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "trial.db")
            svc = TrialSessionService(path, clock=make_clock())
            svc.register_staff("res-1", "researcher")
            svc.register_staff("doc-1", "clinician")
            svc.grant_scope("res-1", "subj-A")
            svc.grant_scope("doc-1", "subj-A")
            svc.open_session("s1", "subj-A", "wheelchair-01", {"gain": 1.0}, "res-1")
            svc.authorize("s1", "doc-1")
            svc.calibrate("s1", "res-1")
            svc.submit_command("s1", 1, "forward", "res-1")
            svc.run_pending("s1", "res-1")
            svc.submit_command("s1", 2, "turn-left", "res-1")
            svc.stop("s1", "doc-1", "异常退出前的停止")
            svc.submit_command("s1", 3, "forward", "res-1")  # 停止后拒绝
            svc.close()  # 进程消失，模拟异常退出后重开

            reopened = TrialSessionService(path, clock=make_clock())
            try:
                view = reopened.get_session("s1")
                self.assertEqual(view["state"], "stopped")
                self.assertTrue(view["authorized"])
                # 指令结果原样保留：重放返回原结果
                self.assertEqual(reopened.submit_command("s1", 1, "forward", "res-1")["status"],
                                 "executed")
                r2 = reopened.submit_command("s1", 2, "turn-left", "res-1")
                self.assertEqual((r2["status"], r2["reason"]), ("preempted", "emergency_stop"))
                r3 = reopened.submit_command("s1", 3, "forward", "res-1")
                self.assertEqual((r3["status"], r3["reason"]), ("rejected", "session_stopped"))
                # 停止状态保持：新指令依旧被拒绝
                r4 = reopened.submit_command("s1", 4, "forward", "res-1")
                self.assertEqual((r4["status"], r4["reason"]), ("rejected", "session_stopped"))
                # 审核证据完整且有序
                log = reopened.export_log("s1")
                self.assertTrue(log)
                self.assertTrue(reopened.verify_chain())
                seqs = [e["event_seq"] for e in reopened.export_log()]
                self.assertEqual(seqs, sorted(seqs))
            finally:
                reopened.close()

    def test_export_in_time_order_and_tamper_evidence(self):
        self.ready_session()
        self.svc.submit_command("s1", 1, "forward", "res-1")
        self.svc.run_pending("s1", "res-1")
        self.svc.stop("s1", "doc-1")
        log = self.svc.export_log("s1")
        kinds = [e["kind"] for e in log]
        self.assertEqual(kinds, ["session_opened", "subject_authorized",
                                 "device_calibrated", "command_submitted",
                                 "command_executed", "emergency_stop"])
        times = [e["created_at"] for e in log]
        self.assertEqual(times, sorted(times))
        self.assertTrue(self.svc.verify_chain())
        # 篡改任一事件体即破坏证据链
        self.svc._conn.execute("UPDATE events SET body='{}' WHERE event_seq=1")
        self.svc._conn.commit()
        self.assertFalse(self.svc.verify_chain())


if __name__ == "__main__":
    unittest.main()
