"""脑机接口试验会话服务：授权、校准、指令与停止的同链审计。

安全不变量：
- 受试者授权与当前参数版本下的有效校准完成前，控制指令一律拒绝并留痕；
- 紧急停止立即使会话进入停止态，尚未执行的排队指令在同一事务内被抢占，
  延迟到达的旧指令无论是重放还是新序号都无法越过停止；
- 指令按 (会话, 序号) 幂等，重放只返回该序号已记录的结果，绝不重复执行或改判；
- 设备参数变更使参数版本递增，旧版本校准立即失效；
- 研究人员与临床人员分别受限于各自获准的受试者范围，授权仅限临床人员；
- 全部状态变化写入带哈希链的事件表，服务重启后仍保持停止状态、指令结果
  与审核证据，并可按时间顺序导出复核。
"""
import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager

from .domain import utc_now
from .service import ServiceError

ROLE_RESEARCHER = "researcher"
ROLE_CLINICIAN = "clinician"

SESSION_ACTIVE = "active"
SESSION_STOPPED = "stopped"
SESSION_CLOSED = "closed"

CMD_QUEUED = "queued"
CMD_EXECUTED = "executed"
CMD_PREEMPTED = "preempted"
CMD_REJECTED = "rejected"

GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS staff(
 principal_id TEXT PRIMARY KEY,
 role TEXT NOT NULL CHECK(role IN ('researcher','clinician')));
CREATE TABLE IF NOT EXISTS grants(
 principal_id TEXT NOT NULL REFERENCES staff(principal_id),
 subject_id TEXT NOT NULL,
 granted_by TEXT NOT NULL,
 created_at TEXT NOT NULL,
 PRIMARY KEY(principal_id,subject_id));
CREATE TABLE IF NOT EXISTS sessions(
 session_id TEXT PRIMARY KEY,
 subject_id TEXT NOT NULL,
 device_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','stopped','closed')),
 params_version INTEGER NOT NULL,
 device_params TEXT NOT NULL,
 opened_by TEXT NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS authorizations(
 session_id TEXT PRIMARY KEY REFERENCES sessions(session_id),
 subject_id TEXT NOT NULL,
 authorized_by TEXT NOT NULL,
 note TEXT NOT NULL,
 created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS calibrations(
 calibration_id TEXT PRIMARY KEY,
 session_id TEXT NOT NULL REFERENCES sessions(session_id),
 params_version INTEGER NOT NULL,
 calibrated_by TEXT NOT NULL,
 created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS commands(
 session_id TEXT NOT NULL REFERENCES sessions(session_id),
 seq INTEGER NOT NULL,
 action TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('queued','executed','preempted','rejected')),
 result TEXT NOT NULL,
 submitted_by TEXT NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(session_id,seq));
CREATE TABLE IF NOT EXISTS stops(
 session_id TEXT PRIMARY KEY REFERENCES sessions(session_id),
 stopped_by TEXT NOT NULL,
 reason TEXT NOT NULL,
 created_at TEXT NOT NULL,
 result TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
 event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
 session_id TEXT,
 kind TEXT NOT NULL,
 actor TEXT,
 body TEXT NOT NULL,
 created_at TEXT NOT NULL,
 prev_hash TEXT NOT NULL,
 hash TEXT NOT NULL);
"""


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class TrialSessionService:
    """试验会话的事务边界、权限检查与审计链。"""

    def __init__(self, database=":memory:", clock=utc_now):
        self._conn = sqlite3.connect(database)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._clock = clock
        self._lock = threading.RLock()

    def close(self):
        with self._lock:
            self._conn.close()

    @contextmanager
    def _tx(self):
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                yield
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ---- 审计链 ----

    def _record_event(self, session_id, kind, actor, body):
        """在事务内把一条事件追加到全局哈希链上。"""
        now = self._clock()
        body_json = _canonical(body)
        last = self._conn.execute(
            "SELECT hash FROM events ORDER BY event_seq DESC LIMIT 1").fetchone()
        prev_hash = last["hash"] if last else GENESIS_HASH
        payload = _canonical({"prev_hash": prev_hash, "session_id": session_id,
                              "kind": kind, "actor": actor, "body": body_json,
                              "created_at": now})
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self._conn.execute(
            "INSERT INTO events(session_id,kind,actor,body,created_at,prev_hash,hash)"
            " VALUES(?,?,?,?,?,?,?)",
            (session_id, kind, actor, body_json, now, prev_hash, digest))

    def export_log(self, session_id=None):
        """按时间（追加）顺序导出事件，供复核；不带会话号时导出全量。"""
        with self._lock:
            if session_id is None:
                rows = self._conn.execute(
                    "SELECT * FROM events ORDER BY event_seq").fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM events WHERE session_id=? ORDER BY event_seq",
                    (session_id,)).fetchall()
            return [{"event_seq": r["event_seq"], "session_id": r["session_id"],
                     "kind": r["kind"], "actor": r["actor"],
                     "body": json.loads(r["body"]), "created_at": r["created_at"],
                     "hash": r["hash"]} for r in rows]

    def verify_chain(self):
        """重放全量事件校验哈希链，任何篡改都会使校验失败。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY event_seq").fetchall()
            prev = GENESIS_HASH
            for r in rows:
                if r["prev_hash"] != prev:
                    return False
                payload = _canonical({"prev_hash": prev, "session_id": r["session_id"],
                                      "kind": r["kind"], "actor": r["actor"],
                                      "body": r["body"], "created_at": r["created_at"]})
                if hashlib.sha256(payload.encode("utf-8")).hexdigest() != r["hash"]:
                    return False
                prev = r["hash"]
            return True

    # ---- 人员与权限 ----

    def register_staff(self, principal_id, role):
        if role not in (ROLE_RESEARCHER, ROLE_CLINICIAN):
            raise ServiceError("未知角色")
        with self._tx():
            row = self._conn.execute(
                "SELECT role FROM staff WHERE principal_id=?", (principal_id,)).fetchone()
            if row is not None:
                if row["role"] != role:
                    raise ServiceError("人员角色已登记且不一致")
                return {"principal_id": principal_id, "role": role}
            self._conn.execute("INSERT INTO staff VALUES(?,?)", (principal_id, role))
            self._record_event(None, "staff_registered", principal_id, {"role": role})
            return {"principal_id": principal_id, "role": role}

    def grant_scope(self, principal_id, subject_id, granted_by="system"):
        """把某个受试者纳入某人员的获准范围；重复授权幂等。"""
        with self._tx():
            staff = self._conn.execute(
                "SELECT 1 FROM staff WHERE principal_id=?", (principal_id,)).fetchone()
            if staff is None:
                raise ServiceError("人员未登记")
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO grants VALUES(?,?,?,?)",
                (principal_id, subject_id, granted_by, self._clock()))
            if cur.rowcount:
                self._record_event(None, "scope_granted", granted_by,
                                   {"principal_id": principal_id, "subject_id": subject_id})
            return {"principal_id": principal_id, "subject_id": subject_id}

    def _require_scope(self, principal_id, subject_id, roles=(ROLE_RESEARCHER, ROLE_CLINICIAN)):
        staff = self._conn.execute(
            "SELECT role FROM staff WHERE principal_id=?", (principal_id,)).fetchone()
        if staff is None:
            raise ServiceError("人员未登记")
        if staff["role"] not in roles:
            raise ServiceError("角色无权执行该操作")
        grant = self._conn.execute(
            "SELECT 1 FROM grants WHERE principal_id=? AND subject_id=?",
            (principal_id, subject_id)).fetchone()
        if grant is None:
            raise ServiceError("超出获准的受试者范围")
        return staff["role"]

    # ---- 会话 ----

    def _session_row(self, session_id):
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        if row is None:
            raise ServiceError("会话不存在")
        return row

    def _current_calibration(self, session_row):
        """与当前参数版本匹配的最近一次校准；参数一变即失配，旧校准立即失效。"""
        return self._conn.execute(
            "SELECT * FROM calibrations WHERE session_id=? AND params_version=?"
            " ORDER BY rowid DESC LIMIT 1",
            (session_row["session_id"], session_row["params_version"])).fetchone()

    def open_session(self, session_id, subject_id, device_id, params=None, by=None):
        params = params or {}
        with self._tx():
            self._require_scope(by, subject_id)
            exists = self._conn.execute(
                "SELECT 1 FROM sessions WHERE session_id=?", (session_id,)).fetchone()
            if exists:
                raise ServiceError("会话已存在")
            now = self._clock()
            self._conn.execute(
                "INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?)",
                (session_id, subject_id, device_id, SESSION_ACTIVE, 1,
                 _canonical(params), by, now, now))
            self._record_event(session_id, "session_opened", by,
                               {"subject_id": subject_id, "device_id": device_id,
                                "params": params})
        return self.get_session(session_id)

    def get_session(self, session_id):
        with self._lock:
            row = self._session_row(session_id)
            authorized = self._conn.execute(
                "SELECT 1 FROM authorizations WHERE session_id=?",
                (session_id,)).fetchone() is not None
            return {"session_id": row["session_id"], "subject_id": row["subject_id"],
                    "device_id": row["device_id"], "state": row["state"],
                    "params_version": row["params_version"], "authorized": authorized,
                    "calibration_valid": self._current_calibration(row) is not None}

    def close_session(self, session_id, by):
        with self._tx():
            row = self._session_row(session_id)
            self._require_scope(by, row["subject_id"])
            if row["state"] == SESSION_CLOSED:
                return {"session_id": session_id, "state": SESSION_CLOSED}
            now = self._clock()
            preempted = self._preempt_queued(session_id, by, "session_closed", now)
            self._conn.execute(
                "UPDATE sessions SET state=?, updated_at=? WHERE session_id=?",
                (SESSION_CLOSED, now, session_id))
            self._record_event(session_id, "session_closed", by, {"preempted": preempted})
            return {"session_id": session_id, "state": SESSION_CLOSED,
                    "preempted": preempted}

    # ---- 授权与校准 ----

    def authorize(self, session_id, by, note=""):
        """记录受试者授权；仅限临床人员，重复调用返回首次授权。"""
        with self._tx():
            row = self._session_row(session_id)
            self._require_scope(by, row["subject_id"], roles=(ROLE_CLINICIAN,))
            if row["state"] != SESSION_ACTIVE:
                raise ServiceError("会话已停止或关闭，无法授权")
            existing = self._conn.execute(
                "SELECT * FROM authorizations WHERE session_id=?", (session_id,)).fetchone()
            if existing is not None:
                return {"session_id": session_id, "authorized": True,
                        "authorized_by": existing["authorized_by"],
                        "authorized_at": existing["created_at"]}
            now = self._clock()
            self._conn.execute(
                "INSERT INTO authorizations VALUES(?,?,?,?,?)",
                (session_id, row["subject_id"], by, note, now))
            self._record_event(session_id, "subject_authorized", by, {"note": note})
            return {"session_id": session_id, "authorized": True,
                    "authorized_by": by, "authorized_at": now}

    def calibrate(self, session_id, by):
        """记录一次设备校准，校准绑定当时的参数版本。"""
        with self._tx():
            row = self._session_row(session_id)
            self._require_scope(by, row["subject_id"])
            if row["state"] != SESSION_ACTIVE:
                raise ServiceError("会话已停止或关闭，无法校准")
            calibration_id = uuid.uuid4().hex
            now = self._clock()
            self._conn.execute(
                "INSERT INTO calibrations VALUES(?,?,?,?,?)",
                (calibration_id, session_id, row["params_version"], by, now))
            self._record_event(session_id, "device_calibrated", by,
                               {"calibration_id": calibration_id,
                                "params_version": row["params_version"]})
            return {"session_id": session_id, "calibration_id": calibration_id,
                    "params_version": row["params_version"], "calibrated_at": now}

    def update_device_params(self, session_id, params, by):
        """变更设备参数：参数版本递增，旧版本校准立即失效并留痕。"""
        with self._tx():
            row = self._session_row(session_id)
            self._require_scope(by, row["subject_id"])
            if row["state"] != SESSION_ACTIVE:
                raise ServiceError("会话已停止或关闭，无法修改设备参数")
            old_version = row["params_version"]
            new_version = old_version + 1
            now = self._clock()
            invalidated = self._conn.execute(
                "SELECT COUNT(*) AS n FROM calibrations"
                " WHERE session_id=? AND params_version=?",
                (session_id, old_version)).fetchone()["n"] > 0
            self._conn.execute(
                "UPDATE sessions SET params_version=?, device_params=?, updated_at=?"
                " WHERE session_id=?",
                (new_version, _canonical(params), now, session_id))
            self._record_event(session_id, "device_params_changed", by,
                               {"params": params, "from_version": old_version,
                                "to_version": new_version})
            if invalidated:
                self._record_event(session_id, "calibration_invalidated", by,
                                   {"params_version": old_version,
                                    "reason": "device_params_changed"})
            return {"session_id": session_id, "params_version": new_version,
                    "calibration_invalidated": invalidated}

    # ---- 控制指令 ----

    def _command_gate(self, session_row):
        """指令门控：返回拒绝原因，允许执行时返回 None。"""
        if session_row["state"] == SESSION_STOPPED:
            return "session_stopped"
        if session_row["state"] == SESSION_CLOSED:
            return "session_closed"
        session_id = session_row["session_id"]
        authorized = self._conn.execute(
            "SELECT 1 FROM authorizations WHERE session_id=?",
            (session_id,)).fetchone()
        if authorized is None:
            return "not_authorized"
        if self._current_calibration(session_row) is None:
            return "calibration_invalid"
        return None

    def submit_command(self, session_id, seq, action, by):
        """提交控制指令。

        同一 (会话, 序号) 只记录一次：重放返回已记录的结果，绝不重复执行；
        门控不满足时拒绝并留痕，该序号此后重放仍返回同一拒绝结果。
        """
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ServiceError("指令序号必须是非负整数")
        if not isinstance(action, str) or not action:
            raise ServiceError("指令内容不能为空")
        with self._tx():
            row = self._session_row(session_id)
            self._require_scope(by, row["subject_id"])
            seen = self._conn.execute(
                "SELECT result FROM commands WHERE session_id=? AND seq=?",
                (session_id, seq)).fetchone()
            if seen is not None:
                return json.loads(seen["result"])
            now = self._clock()
            reason = self._command_gate(row)
            if reason is None:
                status, kind = CMD_QUEUED, "command_submitted"
                result = {"status": status, "session_id": session_id,
                          "seq": seq, "action": action}
            else:
                status, kind = CMD_REJECTED, "command_rejected"
                result = {"status": status, "reason": reason,
                          "session_id": session_id, "seq": seq, "action": action}
            self._conn.execute(
                "INSERT INTO commands VALUES(?,?,?,?,?,?,?,?)",
                (session_id, seq, action, status, _canonical(result), by, now, now))
            body = {"seq": seq, "action": action}
            if reason is not None:
                body["reason"] = reason
            self._record_event(session_id, kind, by, body)
            return result

    def run_pending(self, session_id, by):
        """按序号顺序派发排队指令；派发前复查门控，失效的指令拒绝而非执行。"""
        with self._tx():
            row = self._session_row(session_id)
            self._require_scope(by, row["subject_id"])
            if row["state"] != SESSION_ACTIVE:
                raise ServiceError("会话已停止或关闭，无法执行指令")
            now = self._clock()
            reason = self._command_gate(row)
            if reason is not None:
                for cmd in self._queued_commands(session_id):
                    self._settle_command(session_id, cmd, CMD_REJECTED, by, now,
                                         reason=reason)
                return []
            executed = []
            for cmd in self._queued_commands(session_id):
                result = self._settle_command(session_id, cmd, CMD_EXECUTED, by, now)
                executed.append(result)
            return executed

    def _queued_commands(self, session_id):
        return self._conn.execute(
            "SELECT seq, action FROM commands WHERE session_id=? AND status=?"
            " ORDER BY seq", (session_id, CMD_QUEUED)).fetchall()

    def _settle_command(self, session_id, cmd, status, actor, now, reason=None):
        result = {"status": status, "session_id": session_id,
                  "seq": cmd["seq"], "action": cmd["action"]}
        if status == CMD_EXECUTED:
            result["executed_at"] = now
            kind = "command_executed"
        else:
            result["reason"] = reason
            kind = "command_rejected"
        self._conn.execute(
            "UPDATE commands SET status=?, result=?, updated_at=?"
            " WHERE session_id=? AND seq=?",
            (status, _canonical(result), now, session_id, cmd["seq"]))
        body = {"seq": cmd["seq"], "action": cmd["action"]}
        if reason is not None:
            body["reason"] = reason
        self._record_event(session_id, kind, actor, body)
        return result

    # ---- 停止 ----

    def stop(self, session_id, by, reason=""):
        """紧急停止：会话转入停止态，同事务抢占全部未执行指令。

        停止按会话幂等：重复停止返回首次停止的结果，不重复写事件。
        停止后到达的旧指令若是重放则返回原结果，若是新序号则拒绝留痕，
        任何情况下都不会再执行。
        """
        with self._tx():
            row = self._session_row(session_id)
            self._require_scope(by, row["subject_id"])
            existing = self._conn.execute(
                "SELECT result FROM stops WHERE session_id=?", (session_id,)).fetchone()
            if existing is not None:
                return json.loads(existing["result"])
            if row["state"] == SESSION_CLOSED:
                raise ServiceError("会话已关闭")
            now = self._clock()
            self._conn.execute(
                "UPDATE sessions SET state=?, updated_at=? WHERE session_id=?",
                (SESSION_STOPPED, now, session_id))
            self._record_event(session_id, "emergency_stop", by, {"reason": reason})
            preempted = self._preempt_queued(session_id, by, "emergency_stop", now)
            result = {"status": SESSION_STOPPED, "session_id": session_id,
                      "stopped_by": by, "reason": reason, "stopped_at": now,
                      "preempted": preempted}
            self._conn.execute(
                "INSERT INTO stops VALUES(?,?,?,?,?)",
                (session_id, by, reason, now, _canonical(result)))
            return result

    def _preempt_queued(self, session_id, actor, reason, now):
        seqs = []
        for cmd in self._queued_commands(session_id):
            result = {"status": CMD_PREEMPTED, "reason": reason,
                      "session_id": session_id, "seq": cmd["seq"],
                      "action": cmd["action"]}
            self._conn.execute(
                "UPDATE commands SET status=?, result=?, updated_at=?"
                " WHERE session_id=? AND seq=?",
                (CMD_PREEMPTED, _canonical(result), now, session_id, cmd["seq"]))
            self._record_event(session_id, "command_preempted", actor,
                               {"seq": cmd["seq"], "reason": reason})
            seqs.append(cmd["seq"])
        return seqs
