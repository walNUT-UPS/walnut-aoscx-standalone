# SPDX-License-Identifier: MIT
# AOS-CX (Standalone) REST-first driver for WalNUT Integration Framework
#
# Implements cookie-session auth (w/ CSRF token if present), strict login→ops→logout
# on every operation, API version negotiation against /rest, and dry-run planning.
# Adds structured logging for requests, responses, errors, dry-run plans, and timings.
#
# Refs:
# - WalNUT driver contract & manifest schema (capability→method mapping, test_connection)
# - AOS-CX: enumerate REST API versions via GET https://<host>/rest
# - AOS-CX: login/logout and cookie session on /rest/v10.xx/login|logout
# - AOS-CX: configuration backup & save via /rest/v10.xx/fullconfigs/*
# - AOS-CX: interfaces state via /rest/v10.xx/system/interfaces (admin/link attributes)
#
# See citations in the proposal message.
#
# Notes on CSRF:
# Aruba AOS-CX 10.09+ may require a CSRF token in addition to the session cookie.
# We accept any of the common header names from the login response (X-CSRF-Token or X-XSRF-TOKEN)
# and echo it back on subsequent requests if present. (Developer doc mentions CSRF for CX 10.09+.)

from __future__ import annotations
import time
import json
import re
from typing import Any, Dict, List, Optional, Tuple
import requests
import logging
import math
from time import perf_counter_ns  # monotonic timer for accurate durations (ns)


class AoscxRestDriver:
    """
    Constructor signature is not enforced by WalNUT yet; orchestrator passes config+secrets.
    """
    def __init__(self, config: Dict[str, Any], secrets: Dict[str, str], logger=None):
        self.config = dict(config or {})
        self.secrets = dict(secrets or {})
        self.log = logger or self._default_logger()
        self.session = requests.Session()
        self.session.verify = bool(self.config.get("verify_tls", True))
        # Will be set by _negotiate_version()
        self.base = None           # e.g. "https://host/rest/v10.13"
        self.version = None        # e.g. "v10.13"
        # Allow external override for testing
        self._api_path_hint = self.config.get("api_path_hint", "/rest")

    # --------------- WalNUT required base method ---------------

    def test_connection(self) -> dict:
        """
        Negotiates version, performs a cheap GET of system info, logs timing.
        Returns {status, latency_ms, details?}.
        """
        t0 = perf_counter_ns()
        try:
            host = self.config["hostname"]
            self.log.info("phase=test_connection event=start host=%s", host)
            self._negotiate_version(host)
            # cheap GET of system info attributes (works across 10.x)
            sys_info = self._request("GET", f"/system", params={"attributes": "platform_name,software_version"})
            latency_ms = int((perf_counter_ns() - t0) / 1_000_000)
            self.log.info("phase=test_connection event=success host=%s version=%s latency_ms=%d",
                          host, self.version, latency_ms)
            return {
                "status": "connected",
                "latency_ms": latency_ms,
                "details": json.dumps({"version_chosen": self.version, "platform": sys_info.get("platform_name")})
            }
        except Exception as e:
            latency_ms = int((perf_counter_ns() - t0) / 1_000_000)
            self.log.error("phase=test_connection event=error host=%s latency_ms=%d error=%s",
                           self.config.get("hostname"), latency_ms, repr(e))
            return {"status": "error", "latency_ms": latency_ms, "details": str(e)}

    # --------------- Capabilities (manifest → methods) ---------------

    def inventory_list(self, target_type: str, active_only: bool = True, options: dict = None) -> list:
        """
        targets: switch | stack-member | port
        - switch: optional facts (serial/platform/os)
        - stack-member: VSF/VSX members when present
        - port: active ports by default (link up OR PoE delivering)
        """
        host = self.config["hostname"]
        self._negotiate_version(host)

        if target_type in ("switch", "switches"):
            sys = self._request("GET", "/system", params={"attributes": "platform_name,software_version,serial_number"})
            return [{
                "type": "switch",
                "external_id": host,
                "name": sys.get("platform_name") or host,
                "attrs": {
                    "platform": sys.get("platform_name"),
                    "os_version": sys.get("software_version"),
                    "serial": sys.get("serial_number"),
                },
                "labels": {}
            }]

        if target_type in ("stack-member", "stack_member"):
            # VSX/VSF membership varies by model; probe both resources if present.
            members: List[dict] = []
            try:
                vsx = self._request("GET", "/system/vsx", accept_404=True) or {}
                peer = vsx.get("peer_role") or vsx.get("role")
                if vsx:
                    members.append({
                        "type": "stack_member",
                        "external_id": "vsx-primary" if vsx.get("role") == "primary" else "vsx-secondary",
                        "name": vsx.get("system_mac") or "VSX",
                        "attrs": {"status": "active", "role": vsx.get("role")}
                    })
                    if peer:
                        members.append({
                            "type": "stack_member",
                            "external_id": "vsx-peer",
                            "name": "VSX-peer",
                            "attrs": {"status": "active", "role": peer}
                        })
            except Exception as e:
                self.log.warning("phase=inventory target=stack-member probe=vsx event=error error=%s", repr(e))

            try:
                vsf = self._request("GET", "/system/vsf", accept_404=True) or {}
                # Some builds expose /system/vsf/members; fall back to controller id otherwise.
                mems = self._request("GET", "/system/vsf/members", accept_404=True) or []
                for m in mems:
                    members.append({
                        "type": "stack_member",
                        "external_id": str(m.get("member_id") or m.get("id")),
                        "name": m.get("hostname") or f"Member-{m.get('member_id')}",
                        "attrs": {k: v for k, v in {
                            "model": m.get("platform_name"),
                            "status": m.get("status"),
                            "role": m.get("role")
                        }.items() if v is not None}
                    })
            except Exception as e:
                self.log.warning("phase=inventory target=stack-member probe=vsf event=error error=%s", repr(e))

            return members

        if target_type == "port":
            # Pull interfaces; filter to active if requested. Aruba supports attribute filtering. 10.x docs.
            attrs = "name,admin_state,link_state,link_speed,poe_status,poe_power,description"
            data = self._request("GET", "/system/interfaces", params={"attributes": attrs})
            items = []
            for ifname, iface in (data.get("interfaces") or data.items() if isinstance(data, dict) else []):
                # Different builds return {"interfaces": { "1/1/1": {...}}} or a flat dict of IFs.
                obj = iface if isinstance(iface, dict) else {}
                name = obj.get("name") or ifname
                link = (obj.get("link_state") or obj.get("oper_state") or "down")
                poe_power = float(obj.get("poe_power") or 0.0)
                poe_status = (obj.get("poe_status") or "").lower()
                active = (link == "up") or (poe_power > 0.0) or (poe_status == "delivering")
                if (not active_only) or active:
                    items.append({
                        "type": "port",
                        "external_id": ifname,
                        "name": obj.get("description") or name or ifname,
                        "attrs": {
                            "link": link,
                            "speed_mbps": self._parse_speed(obj.get("link_speed")),
                            "poe": poe_status in ("delivering", "searching") or poe_power > 0.0,
                            "poe_power_w": poe_power
                        },
                        "labels": {}
                    })
            return items

        # Unknown target
        return []

    def poe_port(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        Enable/disable PoE on a port.
        params: state = "enable"|"disable"
        """
        state = (params.get("state") or "").lower()
        if state not in ("enable", "disable"):
            return self._validation("state must be enable|disable")

        if_id = target.get("external_id") or target.get("id")
        host = self.config["hostname"]
        self._negotiate_version(host)

        # Inspect current interface to determine writable field names.
        before = self._get_interface(if_id)
        patch_body, write_hint = self._build_poe_patch(before, state)

        plan = {
            "steps": [{
                "method": "PATCH",
                "path": f"{self.base}/system/interfaces/{self._q(if_id)}",
                "body": patch_body,
                "expected_effect": f"poe -> {state}",
                "write_hint": write_hint
            }]
        }
        if dry_run:
            self.log.info("phase=poe.port event=dry_run target=%s plan_steps=%d", if_id, len(plan["steps"]))
            return {"status": "planned", "plan": plan}

        self._login()
        try:
            self._request("PATCH", f"/system/interfaces/{self._q(if_id)}", json=patch_body)
            self.log.info("phase=poe.port event=success target=%s state=%s", if_id, state)
            return {"status": "ok", "changed": True, "plan": plan}
        finally:
            self._logout()

    def poe_priority(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        Set PoE priority on a port.
        params: level = "low"|"normal"|"high"
        Note: AOS-CX exposes three levels commonly named low/high/critical in CLI; we map:
              normal -> high (middle) for user friendliness per requested capability shape.
        """
        level = (params.get("level") or "").lower()
        if level not in ("low", "normal", "high"):
            return self._validation("level must be low|normal|high")
        aoscx_level = {"low": "low", "normal": "high", "high": "critical"}.get(level, level)

        if_id = target.get("external_id") or target.get("id")
        host = self.config["hostname"]
        self._negotiate_version(host)

        before = self._get_interface(if_id)
        patch_body, write_hint = self._build_poe_priority_patch(before, aoscx_level)

        plan = {
            "steps": [{
                "method": "PATCH",
                "path": f"{self.base}/system/interfaces/{self._q(if_id)}",
                "body": patch_body,
                "expected_effect": f"poe_priority -> {level} (maps to {aoscx_level})",
                "write_hint": write_hint
            }]
        }
        if dry_run:
            self.log.info("phase=poe.priority event=dry_run target=%s level=%s", if_id, level)
            return {"status": "planned", "plan": plan}

        self._login()
        try:
            self._request("PATCH", f"/system/interfaces/{self._q(if_id)}", json=patch_body)
            self.log.info("phase=poe.priority event=success target=%s level=%s mapped=%s", if_id, level, aoscx_level)
            return {"status": "ok", "changed": True, "plan": plan}
        finally:
            self._logout()

    def net_interface(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        Shutdown / no-shutdown
        params: admin = "up"|"down"
        """
        admin = (params.get("admin") or "").lower()
        if admin not in ("up", "down"):
            self.log.warning("phase=net.interface event=validation_error reason=bad_admin_value value=%s", admin)
            return self._validation("admin must be up|down")

        if_id = target.get("external_id") or target.get("id")
        host = self.config["hostname"]
        self._negotiate_version(host)

        before = self._get_interface(if_id)
        # Prefer 'admin_state' if present; else fallback to 'admin'
        body_key = "admin_state" if "admin_state" in before else "admin"
        patch_body = {body_key: ("up" if admin == "up" else "down")}
        plan = {
            "steps": [{
                "method": "PATCH",
                "path": f"{self.base}/system/interfaces/{self._q(if_id)}",
                "body": patch_body,
                "expected_effect": f"{body_key}: {before.get(body_key)} -> {patch_body[body_key]}"
            }]
        }
        if dry_run:
            self.log.info("phase=net.interface event=dry_run target=%s admin=%s", if_id, admin)
            return {"status": "planned", "plan": plan}

        self._login()
        try:
            self._request("PATCH", f"/system/interfaces/{self._q(if_id)}", json=patch_body)
            self.log.info("phase=net.interface event=success target=%s admin=%s", if_id, admin)
            return {"status": "ok", "changed": before.get(body_key) != patch_body[body_key], "plan": plan}
        finally:
            self._logout()

    def switch_config(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        save: running -> startup
        backup: return running-config artifact as JSON (if supported by build)
        """
        host = self.config["hostname"]
        self._negotiate_version(host)

        if verb == "save":
            path = f"/fullconfigs/startup-config"
            query = {"from": f"{self.base}/fullconfigs/running-config"}
            plan = {"steps": [{"method": "PUT", "path": f"{self.base}{path}", "query": query,
                               "expected_effect": "Copy running-config -> startup-config"}]}
            if dry_run:
                self.log.info("phase=switch.config verb=save event=dry_run")
                return {"status": "planned", "plan": plan}
            self._login()
            try:
                self._request("PUT", path, params=query)
                self.log.info("phase=switch.config verb=save event=success")
                return {"status": "ok", "changed": True, "plan": plan}
            finally:
                self._logout()

        if verb == "backup":
            path = f"/fullconfigs/running-config"
            plan = {"steps": [{"method": "GET", "path": f"{self.base}{path}", "expected_effect": "Download running-config"}]}
            if dry_run:
                self.log.info("phase=switch.config verb=backup event=dry_run")
                return {"status": "planned", "plan": plan}
            self._login()
            try:
                cfg = self._request("GET", path)
                # Return artifact-like dict per WalNUT conventions
                fname = f"aoscx-running-config-{host}-{self.version}-{int(time.time())}.json"
                return {"status": "ok", "artifact": {"filename": fname, "mime": "application/json", "content": cfg}, "plan": plan}
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    self.log.error("phase=switch.config verb=backup event=error status=404 hint=read_only_or_unsupported")
                    return self._read_only_or_not_supported(e)
                raise
            finally:
                self._logout()

        return self._validation("unsupported verb for switch.config")

    def switch_reboot(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        Simple reboot (no image selection). Many CX builds expose /system/reboot.
        """
        confirm = params.get("confirm")
        if confirm is not True:
            self.log.warning("phase=switch.reboot event=validation_error reason=confirm_required")
            return self._validation("confirm=true required")

        host = self.config["hostname"]
        self._negotiate_version(host)
        path = "/system/reboot"
        plan = {"steps": [{"method": "POST", "path": f"{self.base}{path}", "expected_effect": "Switch will reboot"}]}
        if dry_run:
            self.log.info("phase=switch.reboot event=dry_run")
            return {"status": "planned", "plan": plan}

        self._login()
        try:
            self._request("POST", path, json={})
            self.log.info("phase=switch.reboot event=success")
            return {"status": "ok", "changed": True, "plan": plan}
        finally:
            self._logout()

    # --------------- Internals ---------------

    def _negotiate_version(self, host: str):
        if self.base and self.version:
            return
        # Probe https://<host>/rest for supported versions; pick highest v10.xx
        scheme = "https://"
        base_root = f"{scheme}{host}"
        # Some users may set api_path_hint="/api" but real REST base is /rest; we always probe /rest.
        url = f"{base_root}/rest"
        try:
            t0 = perf_counter_ns()
            r = self.session.get(url, timeout=8)
            r.raise_for_status()
            data = r.json()
            # Prefer explicit "latest" if returned, else select max v10.xx
            cand = None
            if isinstance(data, dict):
                cand = data.get("latest") or data.get("preferred")
                if not cand:
                    versions = [k for k in data.keys() if re.match(r"^v10\.\d{2}$", k)]
                    cand = sorted(versions, key=lambda s: tuple(map(int, s[1:].split("."))), reverse=True)[0] if versions else None
            if not cand:
                raise RuntimeError("No v10.xx API versions advertised at /rest")
            self.version = cand
            self.base = f"{base_root}/rest/{self.version}"
            self.log.info("phase=negotiate event=success version=%s base=%s latency_ms=%d",
                          self.version, self.base, int((perf_counter_ns() - t0)/1_000_000))
        except Exception as e:
            self.log.error("phase=negotiate event=error host=%s error=%s", host, repr(e))
            raise RuntimeError(f"api_version_mismatch: failed to enumerate /rest on {host}: {e}")

    def _login(self):
        # Always fresh session per op to respect per-user/global caps (docs emphasize logout).
        # POST /rest/v10.xx/login with JSON {username, password}
        url = f"{self.base}/login"
        payload = {"username": self.config["username"], "password": self.secrets.get("password") or self.config.get("password")}
        t0 = perf_counter_ns()
        self.log.info("phase=auth event=login start url=%s", url)
        r = self.session.post(url, json=payload, timeout=10)
        if r.status_code in (401, 403):
            self.log.error("phase=auth event=login error=status_%d", r.status_code)
            raise RuntimeError("auth_error: login failed")
        r.raise_for_status()
        # Capture CSRF tokens if present (10.09+)
        csrf = r.headers.get("X-CSRF-Token") or r.headers.get("X-XSRF-TOKEN")
        if csrf:
            self.session.headers.update({"X-CSRF-Token": csrf, "X-XSRF-TOKEN": csrf})

        self.log.info("phase=auth event=login success latency_ms=%d csrf=%s",
                      int((perf_counter_ns() - t0)/1_000_000), bool(csrf))

    def _logout(self):
        try:
            t0 = perf_counter_ns()
            r = self.session.post(f"{self.base}/logout", json={}, timeout=6)
            # 200/204 acceptable; ignore other statuses
            self.log.info("phase=auth event=logout status=%d latency_ms=%d",
                          r.status_code, int((perf_counter_ns() - t0)/1_000_000))
        except Exception as e:
            self.log.error("phase=auth event=logout error=%s", repr(e))

    def _request(self, method: str, path: str, params: dict = None, json: dict = None, accept_404: bool = False):
        url = f"{self.base}{path}"
        t0 = perf_counter_ns()
        self.log.debug("phase=request event=start method=%s path=%s", method, path)
        r = self.session.request(method, url, params=params, json=json, timeout=12)
        latency_ms = int((perf_counter_ns() - t0) / 1_000_000)
        if accept_404 and r.status_code == 404:
            self.log.debug("phase=request event=404_accepted method=%s path=%s latency_ms=%d", method, path, latency_ms)
            return None
        # Map error semantics
        if r.status_code in (401, 403):
            self.log.error("phase=request event=auth_error method=%s path=%s status=%d latency_ms=%d", method, path, r.status_code, latency_ms)
            raise RuntimeError("auth_error")
        if r.status_code == 404 and method != "GET":
            # 404 for writes is the read-only symptom on some CX builds
            self.log.error("phase=request event=read_only_mode method=%s path=%s latency_ms=%d", method, path, latency_ms)
            raise RuntimeError("read_only_mode")
        if r.status_code in (409, 422):
            self.log.error("phase=request event=validation_error method=%s path=%s status=%d latency_ms=%d", method, path, r.status_code, latency_ms)
            raise RuntimeError("validation_error")
        if 500 <= r.status_code < 600:
            self.log.error("phase=request event=device_error method=%s path=%s status=%d latency_ms=%d", method, path, r.status_code, latency_ms)
            raise RuntimeError("device_error")
        r.raise_for_status()
        self.log.debug("phase=request event=success method=%s path=%s status=%d latency_ms=%d", method, path, r.status_code, latency_ms)
        if r.headers.get("Content-Type", "").startswith("application/json"):
            return r.json()
        # For backups we may get JSON body without header; attempt decode
        try:
            return r.json()
        except Exception:
            return r.text

    def _get_interface(self, if_id: str) -> dict:
        data = self._request("GET", f"/system/interfaces/{self._q(if_id)}")
        if isinstance(data, dict):
            return data
        return {}

    def _build_poe_patch(self, before: dict, state: str) -> Tuple[dict, str]:
        """
        Attempt to adapt to minor version differences:
        - known patterns:
          * flat keys: "poe_admin_enable": true|false
          * nested:    {"poe": {"admin": "enable"|"disable"}}
        """
        # try flat bool
        if "poe_admin_enable" in before:
            return {"poe_admin_enable": (state == "enable")}, "poe_admin_enable"
        # try nested
        poe = before.get("poe") or {}
        if isinstance(poe, dict) and "admin" in poe:
            return {"poe": {"admin": state}}, "poe.admin"
        # last resort: known alternate
        if "poe_enable" in before:
            return {"poe_enable": (state == "enable")}, "poe_enable"
        raise RuntimeError("validation_error: PoE control fields not found on this interface model")

    def _build_poe_priority_patch(self, before: dict, aoscx_level: str) -> Tuple[dict, str]:
        """
        Known patterns:
          * flat:  "poe_priority": "low|high|critical"
          * nested: {"poe": {"priority": "..."}} 
        """
        if "poe_priority" in before:
            return {"poe_priority": aoscx_level}, "poe_priority"
        poe = before.get("poe") or {}
        if isinstance(poe, dict) and "priority" in poe:
            return {"poe": {"priority": aoscx_level}}, "poe.priority"
        raise RuntimeError("validation_error: PoE priority field not found on this interface model")

    @staticmethod
    def _parse_speed(x: Any) -> Optional[int]:
        if x is None:
            return None
        # examples: "1000", "1G", "10G"
        s = str(x).upper()
        if s.endswith("G"):
            try:
                return int(float(s[:-1]) * 1000)
            except Exception:
                return None
        try:
            return int(s)
        except Exception:
            return None

    @staticmethod
    def _q(ifname: str) -> str:
        # path-safe interface id (e.g., 1/1/24)
        return requests.utils.quote(str(ifname), safe='')

    @staticmethod
    def _validation(msg: str) -> dict:
        return {"status": "error", "error": "validation_error", "details": msg}

    @staticmethod
    def _read_only_or_not_supported(err: requests.HTTPError) -> dict:
        # Some builds return 404 for read-only mode; others genuinely lack endpoint
        return {"status": "error", "error": "read_only_mode", "details": "REST write or resource not available on this build"}

    @staticmethod
    def _default_logger():
        logger = logging.getLogger("aoscx_driver")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger