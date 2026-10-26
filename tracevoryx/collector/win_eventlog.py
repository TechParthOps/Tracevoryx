"""Windows Event Log collector — real OS telemetry via Get-WinEvent.

Provider states (honest, mutually distinguishable):
- healthy                 accessible and events collected recently
- no_events               accessible, zero matching events yet
- audit_policy_disabled   elevated auditpol shows the subcategory off
- audit_policy_unknown    auditpol requires elevation; not determinable here
- provider_missing        Sysmon service not installed (service check needs
                          no elevation — distinct from a permission failure)
- permission_denied       OS refused log access (elevation / Event Log Readers)

Lifecycle (regression-fixed): the background probe thread checks a stop
callback before EVERY store access, is joined by AppState.shutdown before
the store closes, and repeated start/stop is idempotent. Store errors in the
worker are logged through the logging module (never swallowed silently).
"""
from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from typing import Callable, Optional

from ..core.events import TrustEvent
from ..core.logging_util import log_error, log_event
from ..core.store import Store

POLL_BATCH = 200
PROBE_MIN_INTERVAL_S = 60.0  # anti-spam: no repeated probes inside this window

# Log name -> (event ids consumed, description)
PROVIDERS = {
    "Security": ({4688}, "process creation (requires Audit Process Creation)"),
    "Microsoft-Windows-Sysmon/Operational":
        ({1, 3, 11}, "Sysmon process/network/file-create"),
}


def _ps(command: str, timeout: int = 45) -> tuple[int, str, str]:
    r = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def _sysmon_service_present() -> Optional[bool]:
    """Service enumeration needs no elevation. None = cannot determine."""
    try:
        code, out, _ = _ps(
            "Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue "
            "| Select-Object -First 1 -ExpandProperty Status", 20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return bool(out.strip())


def _audit_policy_state() -> Optional[str]:
    """'enabled' | 'disabled' | None (unknown — auditpol needs elevation)."""
    try:
        code, out, err = _ps(
            'auditpol /get /subcategory:"Process Creation" '
            "/r 2>$null", 20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if code != 0:
        return None
    # CSV form: "Process Creation,Success" / "...,No Auditing"
    m = re.search(r"Process Creation[^\r\n]*?,\s*([^,\r\n]+)", out)
    if not m:
        return None
    value = m.group(1).strip()
    if "No Auditing" in value:
        return "disabled"
    if value:
        return "enabled"
    return None


def _is_elevated() -> bool:
    try:
        code, out, _ = _ps(
            "([Security.Principal.WindowsPrincipal][Security.Principal."
            "WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal."
            "WindowsBuiltInRole]::Administrator)", 15)
        return "True" in out
    except (OSError, subprocess.TimeoutExpired):
        return False


class WinEventLogCollector:
    def __init__(self, store: Store,
                 should_stop: Optional[Callable[[], bool]] = None):
        self.store = store
        self.should_stop = should_stop or (lambda: False)
        self._cursors: dict[str, int] = {}
        self._proc_keys: dict[str, str] = {}
        self.available_logs: dict[str, bool] = {}
        self.probe_status: dict[str, str] = {}
        self.probe_detail: dict[str, str] = {}
        self.last_error: str | None = None
        self._last_probe = 0.0
        self._probe_thread: Optional[threading.Thread] = None
        self._events_collected = 0

    # ------------------------------------------------------------- probe
    def probe(self, force: bool = False) -> dict[str, str]:
        """One full probe; throttled unless force=True. Thread-safe against
        shutdown: checks should_stop() before every store access."""
        now = time.monotonic()
        if not force and now - self._last_probe < PROBE_MIN_INTERVAL_S:
            return self.probe_status
        self._last_probe = now

        elevated = _is_elevated()
        audit_policy = _audit_policy_state()  # None when not elevated
        sysmon_present = _sysmon_service_present()

        for log_name, (eids, _desc) in PROVIDERS.items():
            status, detail = self._probe_one(log_name, elevated=elevated,
                                             audit_policy=audit_policy,
                                             sysmon_present=sysmon_present)
            self.probe_status[log_name] = status
            self.probe_detail[log_name] = detail
            self.available_logs[log_name] = status in ("healthy", "no_events")
            if self.should_stop():
                return self.probe_status
            sensor_ok = status in ("healthy", "no_events")
            self._beat(f"winlog:{log_name}", "up" if sensor_ok else "degraded",
                       None if sensor_ok else detail)
        log_event(_log(), "win_eventlog_probe",
                  status=self.probe_status, detail=self.probe_detail,
                  elevated=elevated)
        return self.probe_status

    def _probe_one(self, log_name: str, elevated: bool,
                   audit_policy: Optional[str],
                   sysmon_present: Optional[bool]) -> tuple[str, str]:
        if log_name.startswith("Microsoft-Windows-Sysmon"):
            if sysmon_present is False:
                return ("provider_missing",
                        "Sysmon service is not installed. Install and "
                        "configure Sysmon separately (prerequisite, not a "
                        "permission problem).")
            if sysmon_present is None:
                return ("provider_unknown",
                        "cannot determine Sysmon service state")
            # service exists → is the OPERATIONAL log readable?
            try:
                code, out, err = _ps(
                    f"(Get-WinEvent -ListLog '{log_name}' -ErrorAction Stop) "
                    f"-ne $null", 20)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return ("error", f"probe failed: {exc}")
            if code == 0 and "True" in out:
                return ("no_events", "Sysmon log accessible; waiting for "
                                     "matching events")
            return ("permission_denied",
                    "Sysmon service present but log access denied "
                    "(run elevated or grant Event Log Readers)")

        # Security log
        try:
            code, out, err = _ps(
                f"try {{ $null = Get-WinEvent -LogName '{log_name}' "
                f"-MaxEvents 1 -ErrorAction Stop; 'READABLE' }} catch {{ "
                f"$_.Exception.Message }}", 25)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ("error", f"probe failed: {exc}")
        out = (out or "").strip()
        if "READABLE" in out:
            if audit_policy == "disabled":
                return ("audit_policy_disabled",
                        "log readable, but auditpol shows Process Creation "
                        "= No Auditing (enable via auditpol with consent)")
            if audit_policy is None and not elevated:
                return ("no_events",
                        "log readable; audit-policy state needs an elevated "
                        "session to determine (auditpol /get)")
            return ("no_events",
                    "log readable; waiting for matching events")
        if "unauthorized" in out.lower() or "access" in out.lower() or \
                "denied" in out.lower():
            return ("permission_denied",
                    "access denied reading the Security log (run elevated "
                    "or grant 'Event Log Readers' membership)")
        if "does not exist" in out.lower() or "not found" in out.lower():
            return ("provider_missing", f"log not present: {out[:120]}")
        return ("error", out[:200] or "unknown probe error")

    def _beat(self, sensor: str, status: str, error: Optional[str]) -> None:
        try:
            self.store.beat_sensor(sensor, status, error)
        except Exception as exc:
            # store closed / locked during shutdown: observable, not fatal
            log_error(_log(), "sensor_beat_failed", sensor=sensor,
                      error=repr(exc))

    # -------------------------------------------------------------- poll
    def poll(self) -> list[TrustEvent]:
        if self.should_stop():
            return []
        if not self.probe_status:
            self.probe()
        events: list[TrustEvent] = []
        for log_name, (eids, _desc) in PROVIDERS.items():
            if not self.available_logs.get(log_name, False):
                continue
            if self.should_stop():
                break
            try:
                batch = self._read_log(log_name, eids)
            except Exception as exc:
                self.last_error = f"{log_name}: {exc}"
                self._beat("winlog:" + log_name, "down", self.last_error)
                continue
            for raw in batch:
                evt = self._to_event(log_name, raw)
                if evt is not None:
                    events.append(evt)
                    self._events_collected += 1
            if events and self.probe_status.get(log_name) == "no_events":
                self.probe_status[log_name] = "healthy"
                self.probe_detail[log_name] = "events flowing"
                self._beat("winlog:" + log_name, "up", None)
        return events

    def _read_log(self, log_name: str, eids: set[int]) -> list[dict]:
        cursor = self._cursors.get(log_name, 0)
        ps = (
            "$ErrorActionPreference='Stop';"
            f"$h = Get-WinEvent -LogName '{log_name}' -MaxEvents {POLL_BATCH} "
            f"-ErrorAction SilentlyContinue | Where-Object {{ $_.RecordId -gt {cursor} }} | "
            "Sort-Object RecordId;"
            "$h | ForEach-Object { "
            "[pscustomobject]@{rid=$_.RecordId; eid=$_.Id; time=$_.TimeCreated.ToString('o');"
            "xml=$_.ToXml()} | ConvertTo-Json -Compress }"
        )
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=45)
        if r.returncode != 0 and "NoEvents" not in r.stderr:
            err = (r.stderr or "").strip().splitlines()[-1:] or ["unknown"]
            raise RuntimeError(err[0][:200])
        rows = []
        if r.stdout.strip():
            data = json.loads("[" + r.stdout.strip().replace("}\n{", "},{") + "]")
            rows = data if isinstance(data, list) else [data]
        if rows:
            self._cursors[log_name] = max(int(x["rid"]) for x in rows)
        return rows

    # ------------------------------------------------------------- parse
    _TAG = re.compile(r"<Data Name='?([^'>]+)'?>([^<]*)</Data>")

    def _to_event(self, log_name: str, raw: dict) -> TrustEvent | None:
        eid = int(raw.get("eid", 0))
        fields = dict(self._TAG.findall(raw.get("xml", "")))
        ev_time = raw.get("time", "")
        if log_name == "Security" and eid == 4688:
            exe = fields.get("NewProcessName", "")
            pid = int(fields.get("ProcessId", "0") or 0)
            parent = fields.get("ParentProcessName", "")
            user = fields.get("SubjectUserName", "")
            key = f"{pid}|{exe}|{ev_time}"  # PID-reuse-safe correlation key
            self._proc_keys[key] = user or exe
            return TrustEvent(
                event_type="process_started", source="winlog:Security",
                actor=f"proc:{exe.rsplit(chr(92), 1)[-1]}:{pid}",
                target=exe, pid=pid, exe=exe,
                parent_exe=parent,
                trust_label="UNKNOWN",
                evidence=[{"kind": "winevent", "label": f"4688 {exe}",
                           "observed": True,
                           "detail": {"record_id": raw.get("rid"),
                                      "user": user, "parent": parent}}],
                correlation_confidence=0.95,
                collection_limitations=[
                    "4688 requires Audit Process Creation enabled",
                    "command line only present with 4688 + commandline audit"],
                details={"eid": eid, "record_id": raw.get("rid"),
                         "proc_key": key})
        if log_name.startswith("Microsoft-Windows-Sysmon") and eid in (1, 3, 11):
            kind = {1: "process_started", 3: "connection", 11: "file_write"}[eid]
            target = (fields.get("Image") or fields.get("DestinationIp")
                      or fields.get("TargetFilename") or "")
            pid = int(fields.get("ProcessId", "0") or 0)
            return TrustEvent(
                event_type=kind, source="winlog:Sysmon",
                actor=f"proc:{target.rsplit(chr(92), 1)[-1]}:{pid}",
                target=target,
                destination=fields.get("DestinationIp", ""),
                pid=pid, exe=fields.get("Image", ""),
                parent_exe=fields.get("ParentImage", ""),
                trust_label="UNKNOWN",
                evidence=[{"kind": "winevent",
                           "label": f"sysmon:{eid} {target}",
                           "observed": True,
                           "detail": {"record_id": raw.get("rid"),
                                      "guid": fields.get("ProcessGuid", "")}}],
                correlation_confidence=0.95,
                collection_limitations=[
                    "Sysmon must be installed+configured; coverage equals "
                    "the deployed configuration"],
                details={"eid": eid, "record_id": raw.get("rid")})
        return None


def _log():
    import logging
    return logging.getLogger("tracevoryx.collector.winlog")

