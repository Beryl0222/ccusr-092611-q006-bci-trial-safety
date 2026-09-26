"""脑机试验会话服务：授权、校准、控制指令和停止操作共用一条可审计链路。

安全不变量：
- 受试者授权或设备校准未完成前，控制指令一律被拒绝并留痕；
- 紧急停止立即取消尚未执行的指令，之后到达的指令一律拒绝，停止不被旧指令越过；
- 指令按(会话,序号)幂等，带序号的重放只返回首次记录的结果，不重复执行；
- 设备参数变化在同一事务内使旧校准立即失效；
- 研究人员与临床人员只能操作各自获准范围内的受试者；
- 全部状态与审核证据落库，会话异常退出后重开不丢失，可按时间顺序导出复核。
"""
import json,sqlite3
from contextlib import contextmanager
from .domain import utc_now
class TrialError(Exception):pass
ROLES=("researcher","clinician")
SCHEMA="""
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS staff(staff_id TEXT PRIMARY KEY,role TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS staff_scope(staff_id TEXT NOT NULL,subject_id TEXT NOT NULL,PRIMARY KEY(staff_id,subject_id));
CREATE TABLE IF NOT EXISTS authorizations(auth_id TEXT PRIMARY KEY,subject_id TEXT NOT NULL,state TEXT NOT NULL,version INTEGER NOT NULL,granted_by TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices(device_id TEXT PRIMARY KEY,params TEXT NOT NULL,params_version INTEGER NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS calibrations(calibration_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,params_version INTEGER NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(session_id TEXT PRIMARY KEY,subject_id TEXT NOT NULL,device_id TEXT NOT NULL,state TEXT NOT NULL,version INTEGER NOT NULL,opened_by TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS commands(session_id TEXT NOT NULL,seq INTEGER NOT NULL,staff_id TEXT NOT NULL,action TEXT NOT NULL,state TEXT NOT NULL,result TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(session_id,seq));
CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,session_id TEXT,kind TEXT NOT NULL,body TEXT NOT NULL,created_at TEXT NOT NULL);
"""
class TrialService:
 """试验会话状态机，每次写入在单事务内完成并追加审计事件。"""
 def __init__(self,database=":memory:",clock=utc_now):
  self.connection=sqlite3.connect(database);self.connection.row_factory=sqlite3.Row;self.clock=clock
  self.connection.executescript(SCHEMA);self.connection.commit()
 @contextmanager
 def transaction(self):
  try:self.connection.execute("BEGIN IMMEDIATE");yield;self.connection.commit()
  except Exception:self.connection.rollback();raise
 def close(self):self.connection.close()
 def _audit(self,kind,body,session_id=None):
  self.connection.execute("INSERT INTO audit_events(session_id,kind,body,created_at) VALUES(?,?,?,?)",(session_id,kind,json.dumps(body,ensure_ascii=False),self.clock()))
 def _staff(self,staff_id):
  row=self.connection.execute("SELECT * FROM staff WHERE staff_id=?",(staff_id,)).fetchone()
  if row is None:raise TrialError("人员未注册")
  return row
 def _check_scope(self,staff_id,subject_id):
  self._staff(staff_id)
  if self.connection.execute("SELECT 1 FROM staff_scope WHERE staff_id=? AND subject_id=?",(staff_id,subject_id)).fetchone() is None:raise TrialError("无权访问该受试者")
 def _session(self,session_id):
  row=self.connection.execute("SELECT * FROM sessions WHERE session_id=?",(session_id,)).fetchone()
  if row is None:raise TrialError("会话不存在")
  return row
 def _device(self,device_id):
  row=self.connection.execute("SELECT * FROM devices WHERE device_id=?",(device_id,)).fetchone()
  if row is None:raise TrialError("设备不存在")
  return row
 def _active_auth(self,subject_id):
  return self.connection.execute("SELECT * FROM authorizations WHERE subject_id=? AND state='active'",(subject_id,)).fetchone()
 def _valid_calibration(self,device):
  return self.connection.execute("SELECT * FROM calibrations WHERE device_id=? AND state='valid' AND params_version=?",(device["device_id"],device["params_version"])).fetchone()
 def _reject_reason(self,session):
  if session["state"]=="stopped":return "会话已紧急停止"
  if session["state"]=="closed":return "会话已关闭"
  if self._active_auth(session["subject_id"]) is None:return "受试者授权未完成"
  if self._valid_calibration(self._device(session["device_id"])) is None:return "设备校准未完成或已失效"
  return None
 def register_staff(self,staff_id,role,subjects=()):
  if role not in ROLES:raise TrialError("未知角色")
  with self.transaction():
   if self.connection.execute("SELECT 1 FROM staff WHERE staff_id=?",(staff_id,)).fetchone():raise TrialError("人员已注册")
   self.connection.execute("INSERT INTO staff VALUES(?,?,?)",(staff_id,role,self.clock()))
   for subject_id in subjects:self.connection.execute("INSERT INTO staff_scope VALUES(?,?)",(staff_id,subject_id))
   self._audit("staff_registered",{"staff_id":staff_id,"role":role,"subjects":list(subjects)})
 def grant_authorization(self,auth_id,subject_id,staff_id):
  with self.transaction():
   self._check_scope(staff_id,subject_id)
   if self.connection.execute("SELECT 1 FROM authorizations WHERE auth_id=?",(auth_id,)).fetchone():raise TrialError("授权记录已存在")
   self.connection.execute("INSERT INTO authorizations VALUES(?,?,?,?,?,?)",(auth_id,subject_id,"active",1,staff_id,self.clock()))
   self._audit("authorization_granted",{"auth_id":auth_id,"subject_id":subject_id,"staff_id":staff_id})
 def revoke_authorization(self,auth_id,staff_id):
  with self.transaction():
   row=self.connection.execute("SELECT * FROM authorizations WHERE auth_id=?",(auth_id,)).fetchone()
   if row is None:raise TrialError("授权记录不存在")
   self._check_scope(staff_id,row["subject_id"])
   if row["state"]!="active":raise TrialError("授权已失效")
   self.connection.execute("UPDATE authorizations SET state='revoked',version=?,updated_at=? WHERE auth_id=?",(row["version"]+1,self.clock(),auth_id))
   self._audit("authorization_revoked",{"auth_id":auth_id,"subject_id":row["subject_id"],"staff_id":staff_id})
 def register_device(self,device_id,params):
  with self.transaction():
   if self.connection.execute("SELECT 1 FROM devices WHERE device_id=?",(device_id,)).fetchone():raise TrialError("设备已注册")
   self.connection.execute("INSERT INTO devices VALUES(?,?,?,?)",(device_id,json.dumps(params,ensure_ascii=False,sort_keys=True),1,self.clock()))
   self._audit("device_registered",{"device_id":device_id,"params":params})
 def set_device_params(self,device_id,params):
  with self.transaction():
   device=self._device(device_id);version=device["params_version"]+1
   self.connection.execute("UPDATE devices SET params=?,params_version=?,updated_at=? WHERE device_id=?",(json.dumps(params,ensure_ascii=False,sort_keys=True),version,self.clock(),device_id))
   cur=self.connection.execute("UPDATE calibrations SET state='invalidated' WHERE device_id=? AND state='valid'",(device_id,))
   self._audit("device_params_changed",{"device_id":device_id,"params_version":version,"invalidated":cur.rowcount})
 def calibrate(self,calibration_id,device_id,staff_id):
  with self.transaction():
   self._staff(staff_id);device=self._device(device_id)
   if self.connection.execute("SELECT 1 FROM calibrations WHERE calibration_id=?",(calibration_id,)).fetchone():raise TrialError("校准记录已存在")
   self.connection.execute("UPDATE calibrations SET state='superseded' WHERE device_id=? AND state='valid'",(device_id,))
   self.connection.execute("INSERT INTO calibrations VALUES(?,?,?,?,?)",(calibration_id,device_id,device["params_version"],"valid",self.clock()))
   self._audit("calibration_completed",{"calibration_id":calibration_id,"device_id":device_id,"params_version":device["params_version"],"staff_id":staff_id})
 def open_session(self,session_id,subject_id,device_id,staff_id):
  with self.transaction():
   self._check_scope(staff_id,subject_id);self._device(device_id)
   if self.connection.execute("SELECT 1 FROM sessions WHERE session_id=?",(session_id,)).fetchone():raise TrialError("会话已存在")
   if self._active_auth(subject_id) is None:raise TrialError("受试者授权未完成")
   self.connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?)",(session_id,subject_id,device_id,"active",1,staff_id,self.clock()))
   self._audit("session_opened",{"subject_id":subject_id,"device_id":device_id,"staff_id":staff_id},session_id)
 def submit_command(self,session_id,seq,action,staff_id):
  with self.transaction():
   session=self._session(session_id);self._check_scope(staff_id,session["subject_id"])
   old=self.connection.execute("SELECT result FROM commands WHERE session_id=? AND seq=?",(session_id,seq)).fetchone()
   if old is not None:return json.loads(old["result"])
   reason=self._reject_reason(session);now=self.clock()
   state="rejected" if reason else "queued"
   result={"session_id":session_id,"seq":seq,"state":state}
   if reason:result["reason"]=reason
   self.connection.execute("INSERT INTO commands VALUES(?,?,?,?,?,?,?,?)",(session_id,seq,staff_id,json.dumps(action,ensure_ascii=False),state,json.dumps(result,ensure_ascii=False),now,now))
   self._audit("command_"+state,{"seq":seq,"action":action,"staff_id":staff_id,"reason":reason},session_id)
   return result
 def dispatch_pending(self,session_id,staff_id):
  with self.transaction():
   session=self._session(session_id);self._check_scope(staff_id,session["subject_id"])
   results=[]
   for row in self.connection.execute("SELECT * FROM commands WHERE session_id=? AND state='queued' ORDER BY seq",(session_id,)).fetchall():
    reason=self._reject_reason(session);now=self.clock()
    state="rejected" if reason else "executed"
    result={"session_id":session_id,"seq":row["seq"],"state":state}
    if reason:result["reason"]=reason
    else:result["executed_at"]=now
    self.connection.execute("UPDATE commands SET state=?,result=?,updated_at=? WHERE session_id=? AND seq=?",(state,json.dumps(result,ensure_ascii=False),now,session_id,row["seq"]))
    self._audit("command_"+state,{"seq":row["seq"],"staff_id":staff_id,"reason":reason},session_id)
    results.append(result)
   return results
 def emergency_stop(self,session_id,staff_id):
  with self.transaction():
   session=self._session(session_id);self._check_scope(staff_id,session["subject_id"])
   if session["state"]=="closed":raise TrialError("会话已关闭")
   if session["state"]=="stopped":return {"session_id":session_id,"state":"stopped","cancelled":[]}
   now=self.clock();cancelled=[]
   for row in self.connection.execute("SELECT * FROM commands WHERE session_id=? AND state='queued' ORDER BY seq",(session_id,)).fetchall():
    result={"session_id":session_id,"seq":row["seq"],"state":"cancelled","reason":"紧急停止"}
    self.connection.execute("UPDATE commands SET state='cancelled',result=?,updated_at=? WHERE session_id=? AND seq=?",(json.dumps(result,ensure_ascii=False),now,session_id,row["seq"]))
    self._audit("command_cancelled",{"seq":row["seq"],"reason":"紧急停止"},session_id);cancelled.append(row["seq"])
   self.connection.execute("UPDATE sessions SET state='stopped',version=?,updated_at=? WHERE session_id=?",(session["version"]+1,now,session_id))
   self._audit("emergency_stop",{"staff_id":staff_id,"cancelled":cancelled},session_id)
   return {"session_id":session_id,"state":"stopped","cancelled":cancelled}
 def close_session(self,session_id,staff_id):
  with self.transaction():
   session=self._session(session_id);self._check_scope(staff_id,session["subject_id"])
   if session["state"]=="closed":raise TrialError("会话已关闭")
   now=self.clock()
   for row in self.connection.execute("SELECT * FROM commands WHERE session_id=? AND state='queued' ORDER BY seq",(session_id,)).fetchall():
    result={"session_id":session_id,"seq":row["seq"],"state":"cancelled","reason":"会话关闭"}
    self.connection.execute("UPDATE commands SET state='cancelled',result=?,updated_at=? WHERE session_id=? AND seq=?",(json.dumps(result,ensure_ascii=False),now,session_id,row["seq"]))
    self._audit("command_cancelled",{"seq":row["seq"],"reason":"会话关闭"},session_id)
   self.connection.execute("UPDATE sessions SET state='closed',version=?,updated_at=? WHERE session_id=?",(session["version"]+1,now,session_id))
   self._audit("session_closed",{"staff_id":staff_id},session_id)
   return {"session_id":session_id,"state":"closed"}
 def get_session(self,session_id):
  session=self._session(session_id)
  commands=[{"seq":row["seq"],"action":json.loads(row["action"]),"state":row["state"],"result":json.loads(row["result"]),"staff_id":row["staff_id"]} for row in self.connection.execute("SELECT * FROM commands WHERE session_id=? ORDER BY seq",(session_id,)).fetchall()]
  return {"session_id":session_id,"subject_id":session["subject_id"],"device_id":session["device_id"],"state":session["state"],"version":session["version"],"commands":commands}
 def export_audit(self,session_id=None):
  if session_id is None:rows=self.connection.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
  else:rows=self.connection.execute("SELECT * FROM audit_events WHERE session_id=? ORDER BY id",(session_id,)).fetchall()
  return [{"id":row["id"],"session_id":row["session_id"],"kind":row["kind"],"body":json.loads(row["body"]),"created_at":row["created_at"]} for row in rows]
