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
import urllib3
from time import perf_counter_ns  # monotonic timer for accurate durations (ns)


class AoscxRestDriver:
    """
    Compatible constructor for different WalNUT driver invocation styles.

    Supports:
    - __init__(config, secrets, logger=None, instance=None, **kwargs)
    - __init__(instance, secrets, logger=None, **kwargs) where instance.config holds values
    - Keyword forms: config=..., secrets=..., instance=..., logger=...

    Notes:
    - If password is present in config and secrets is empty, it will be copied to secrets.
    - Additional kwargs are accepted for forward compatibility and ignored here.
    """
    def __init__(self, config=None, secrets: Optional[Dict[str, str]] = None, logger=None, instance=None, **kwargs):
        """Initialize AoscxRestDriver with WalNUT framework compatibility"""

        # Normalize inputs across invocation styles
        inferred_instance = None
        inferred_config: Dict[str, Any] = {}
        inferred_secrets: Dict[str, Any] = {}

        # Case 1: First positional is an instance-like object
        if config is not None and not isinstance(config, dict) and hasattr(config, 'config'):
            inferred_instance = config
            inferred_config = getattr(config, 'config', {}) or {}
            # Some frameworks may place secrets on instance
            if hasattr(config, 'secrets') and isinstance(config.secrets, dict):
                inferred_secrets = config.secrets
            # Shift positional args: the second positional is actually secrets
            inferred_secrets = secrets or inferred_secrets or {}
        else:
            # Case 2: Standard form with config dict provided
            inferred_instance = instance
            inferred_config = config or {}
            inferred_secrets = secrets or {}

        # If password got placed in config, lift it into secrets when missing
        if 'password' in inferred_config and 'password' not in inferred_secrets:
            inferred_secrets['password'] = inferred_config.get('password')

        # Store resolved attributes
        self.instance = inferred_instance
        self.config = inferred_config
        self.secrets = inferred_secrets

        # Validate required configuration fields
        required_config = ['hostname', 'username']
        missing_config = [field for field in required_config if not self.config.get(field)]
        if missing_config:
            raise ValueError(f"Missing required configuration fields: {missing_config}")

        # Validate required secrets (allow empty password)
        required_secrets = ['password']
        missing_secrets = [field for field in required_secrets if field not in self.secrets]
        if missing_secrets:
            raise ValueError(f"Missing required secret fields: {missing_secrets}")

        # Set up logging (walNUT framework pattern)
        self.log = logger or self._default_logger()
        self.session = requests.Session()
        self.session.verify = bool(self.config.get("verify_tls", True))
        
        # Suppress SSL warnings when verify_tls is disabled
        if not self.session.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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
        self._validate_operational_state()
        t0 = perf_counter_ns()
        try:
            host = self.config["hostname"]
            self.log.info("phase=test_connection event=start host=%s", host)
            self._negotiate_version(host)
            # cheap GET of system info attributes (works across 10.x)
            self._login()
            try:
                sys_info = self._request("GET", f"/system", params={"attributes": "platform_name,software_version"})
            finally:
                self._logout()
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

    def heartbeat(self) -> dict:
        """Lightweight health check for walNUT framework"""
        self._validate_operational_state()
        import time
        
        start_time = time.time()
        try:
            # Quick connectivity test - just check if we can reach the REST API
            host = self.config.get("hostname", "")
            if not host:
                return {"state": "error", "latency_ms": 0}

            # Use existing session but don't do full login - just test reachability
            response = self.session.get(
                f"https://{host}/rest",
                timeout=5,
                verify=self.config.get("verify_tls", True)
            )

            latency_ms = int((time.time() - start_time) * 1000)

            # Return walNUT standard format
            if response.status_code == 200:
                return {"state": "connected", "latency_ms": latency_ms}
            elif response.status_code in [401, 403]:
                # Authentication issues but device is reachable
                return {"state": "degraded", "latency_ms": latency_ms}
            else:
                return {"state": "error", "latency_ms": latency_ms}

        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            return {
                "state": "error",
                "latency_ms": latency_ms,
                "error": str(e)
            }

    # --------------- Capabilities (manifest → methods) ---------------

    def inventory_list(self, target_type: str, active_only: bool = True, options: dict = None) -> list:
        """
        targets: switch | stack-member | port
        - switch: optional facts (serial/platform/os)
        - stack-member: VSF/VSX members when present
        - port: active ports by default (link up OR PoE delivering)
        """
        self._validate_operational_state()
        # Normalize target type aliases from orchestrator
        target_type = (target_type or "").strip().lower().replace(" ", "_")
        if target_type in ("switches", "system"):
            target_type = "switch"
        if target_type in ("stack-member", "stackmember"):
            target_type = "stack_member"
        if target_type in ("ports", "interfaces"):
            target_type = "port"

        host = self.config["hostname"]
        self._negotiate_version(host)

        # Accept "system" as alias for switch facts
        if target_type == "switch":
            self._login()
            try:
                sys = self._request("GET", "/system", params={"attributes": "platform_name,software_version,serial_number"})
                
                # Add system power monitoring
                system_power = {}
                try:
                    power_data = self._get_system_power_details()
                    if power_data.get("status") == "ok":
                        system_power = power_data.get("system_power", {})
                except:
                    # Continue without power data if unavailable
                    pass
                    
            finally:
                self._logout()
            
            switch_attrs = {
                "platform": sys.get("platform_name"),
                "os_version": sys.get("software_version"),
                "serial": sys.get("serial_number"),
            }
            
            if system_power:
                switch_attrs["power_monitoring"] = system_power
                
            return [{
                "type": "switch",
                "id": host,
                "external_id": host,
                "name": sys.get("platform_name") or host,
                "attrs": switch_attrs,
                "labels": {}
            }]

        if target_type == "stack_member":
            # VSX/VSF membership varies by model; probe both resources if present.
            members: List[dict] = []
            self._login()
            try:
                try:
                    vsx = self._request("GET", "/system/vsx", accept_404=True) or {}
                    peer = vsx.get("peer_role") or vsx.get("role")
                    if vsx:
                        vsx_id = "vsx-primary" if vsx.get("role") == "primary" else "vsx-secondary"
                        members.append({
                            "type": "stack_member",
                            "id": vsx_id,
                            "external_id": vsx_id,
                            "name": vsx.get("system_mac") or "VSX",
                            "attrs": {"status": "active", "role": vsx.get("role")}
                        })
                        if peer:
                            members.append({
                                "type": "stack_member",
                                "id": "vsx-peer",
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
                        member_id = str(m.get("member_id") or m.get("id"))
                        members.append({
                            "type": "stack_member",
                            "id": member_id,
                            "external_id": member_id,
                            "name": m.get("hostname") or f"Member-{m.get('member_id')}",
                            "attrs": {k: v for k, v in {
                                "model": m.get("platform_name"),
                                "status": m.get("status"),
                                "role": m.get("role")
                            }.items() if v is not None}
                        })
                except Exception as e:
                    self.log.warning("phase=inventory target=stack-member probe=vsf event=error error=%s", repr(e))
            finally:
                self._logout()

            return members

        if target_type == "port":
            # Pull interfaces; filter to active if requested. Aruba supports attribute filtering. 10.x docs.
            attrs = "name,admin_state,link_state,link_speed,poe_status,poe_power,description"
            self._login()
            try:
                data = self._request("GET", "/system/interfaces", params={"attributes": attrs})
                
                # Enhance with detailed power monitoring for PoE-capable ports
                items = []
                for ifname, iface in (data.get("interfaces") or data.items() if isinstance(data, dict) else []):
                    # Different builds return {"interfaces": { "1/1/1": {...}}} or a flat dict of IFs.
                    obj = iface if isinstance(iface, dict) else {}
                    name = obj.get("name") or ifname
                    link = (obj.get("link_state") or obj.get("oper_state") or "down")
                    poe_power = float(obj.get("poe_power") or 0.0)
                    poe_status = (obj.get("poe_status") or "").lower()
                    active = (link == "up") or (poe_power > 0.0) or (poe_status == "delivering")
                    
                    port_attrs = {
                        "link": link,
                        "speed_mbps": self._parse_speed(obj.get("link_speed")),
                        "poe": poe_status in ("delivering", "searching") or poe_power > 0.0,
                        "poe_power_w": poe_power,
                    }
                    
                    # Add detailed power monitoring for PoE-capable ports
                    if poe_power > 0.0 or poe_status in ("delivering", "searching"):
                        try:
                            poe_details = self._request("GET", f"/system/interfaces/{self._q(ifname)}/poe_interface")
                            if poe_details:
                                port_attrs["power_monitoring"] = {
                                    "average_power_w": poe_details.get("config", {}).get("average_power", 0),
                                    "peak_power_w": poe_details.get("config", {}).get("peak_power", 0),
                                    "priority": poe_details.get("config", {}).get("priority", "unknown"),
                                    "power_class": poe_details.get("config", {}).get("power_class", "unknown"),
                                    "status": poe_details.get("config", {}).get("status", "unknown")
                                }
                        except:
                            # Continue without detailed power data if unavailable
                            pass
                    
                    if (not active_only) or active:
                        items.append({
                            "type": "port",
                            "id": ifname,
                            "external_id": ifname,
                            "name": obj.get("description") or name or ifname,
                            "attrs": port_attrs,
                            "labels": {}
                        })
            finally:
                self._logout()
            return items

        # Unknown target
        return []

    def poe_port(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        Enable/disable PoE on a port.
        params: state = "enable"|"disable"
        """
        # Normalize state: enable/disable, on/off, true/false, 1/0
        raw_state = params.get("state")
        if raw_state is None and "enabled" in params:
            raw_state = params.get("enabled")
        state = self._normalize_state_enable_disable(raw_state)
        if state not in ("enable", "disable"):
            return self._validation("state must be enable|disable (accepts on/off/true/false)")

        if_id = self._target_id(target)
        host = self.config["hostname"]
        self._negotiate_version(host)

        # Get current PoE interface state
        self._login()
        try:
            before = self._request("GET", f"/system/interfaces/{self._q(if_id)}/poe_interface")
        finally:
            self._logout()
        patch_body, write_hint = self._build_poe_patch(before, state)

        plan = {
            "steps": [{
                "method": "PATCH",
                "path": f"{self.base}/system/interfaces/{self._q(if_id)}/poe_interface",
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
            self._request("PATCH", f"/system/interfaces/{self._q(if_id)}/poe_interface", json=patch_body)
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
        level = self._normalize_priority(params.get("level"))
        if level not in ("low", "normal", "high"):
            return self._validation("level must be low|normal|high (aliases: med/medium=normal)")
        aoscx_level = {"low": "low", "normal": "high", "high": "critical"}.get(level, level)

        if_id = self._target_id(target)
        host = self.config["hostname"]
        self._negotiate_version(host)

        self._login()
        try:
            before = self._request("GET", f"/system/interfaces/{self._q(if_id)}/poe_interface")
        finally:
            self._logout()
        patch_body, write_hint = self._build_poe_priority_patch(before, aoscx_level)

        plan = {
            "steps": [{
                "method": "PATCH",
                "path": f"{self.base}/system/interfaces/{self._q(if_id)}/poe_interface",
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
            self._request("PATCH", f"/system/interfaces/{self._q(if_id)}/poe_interface", json=patch_body)
            self.log.info("phase=poe.priority event=success target=%s level=%s mapped=%s", if_id, level, aoscx_level)
            return {"status": "ok", "changed": True, "plan": plan}
        finally:
            self._logout()

    def net_interface(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        Shutdown / no-shutdown
        params: admin = "up"|"down"
        """
        # Accept a wider set of inputs: admin/state/up/down/enable/disable/shutdown/no-shutdown/true/false
        admin = self._normalize_admin(params)
        if admin not in ("up", "down"):
            self.log.warning("phase=net.interface event=validation_error reason=bad_admin_value value=%s", admin)
            return self._validation("admin must be up|down (aliases: enable/disable, shutdown/no-shutdown)")

        if_id = self._target_id(target)
        host = self.config["hostname"]
        self._negotiate_version(host)

        self._login()
        try:
            before = self._get_interface(if_id)
        finally:
            self._logout()
        # Use 'admin' field for configuration (admin_state is read-only)
        body_key = "admin"
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
            query = {"from": "/fullconfigs/running-config"}
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
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 400:
                    self.log.error("phase=switch.config verb=save event=error status=400 hint=startup_config_not_supported")
                    return {"status": "error", "error": "not_supported", "details": "Config save not supported on this device/configuration"}
                raise
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

    def get_power_monitoring(self, target_type: str = "system", target_id: str = None) -> dict:
        """
        Get power monitoring data for ports or system.
        target_type: "port" for individual port, "system" for total switch power
        target_id: port ID if target_type is "port"
        """
        self._validate_operational_state()
        host = self.config["hostname"]
        self._negotiate_version(host)

        if target_type == "port" and target_id:
            # Get individual port power monitoring
            return self._get_port_power_details(target_id)
        
        elif target_type == "system":
            # Get total switch power monitoring
            return self._get_system_power_details()
            
        else:
            return {"error": "Invalid target_type. Use 'port' with target_id or 'system'"}

    def _get_port_power_details(self, port_id: str) -> dict:
        """Get detailed power monitoring for a specific port"""
        try:
            encoded_port = self._q(port_id)
            poe_data = self._request("GET", f"/system/interfaces/{encoded_port}/poe_interface", accept_404=True)
            
            if not poe_data:
                return {"available": False, "reason": "No PoE interface"}
            
            measurements = poe_data.get('measurements', {})
            status = poe_data.get('status', {})
            
            # Extract power measurements
            power_details = {
                "available": True,
                "powering_status": status.get('port', {}).get('powering_status', 'unknown'),
                "measurements": {}
            }
            
            # Get real-time power measurements
            if measurements:
                power_fields = {
                    'average_power': 'average_power_w',
                    'peak_power': 'peak_power_w', 
                    'power_drawn': 'power_drawn_w',
                    'current': 'current_a',
                    'voltage': 'voltage_v'
                }
                
                for api_field, output_field in power_fields.items():
                    if api_field in measurements:
                        power_details["measurements"][output_field] = float(measurements[api_field])
            
            # Add PoE configuration info
            config = poe_data.get('config', {})
            if config:
                power_details["config"] = {
                    "admin_enabled": not config.get('admin_disable', True),
                    "priority": config.get('priority', 'unknown'),
                    "allocated_class": config.get('cfg_assigned_class', 'unknown')
                }
            
            return power_details
            
        except Exception as e:
            return {"available": False, "reason": f"Error retrieving power data: {str(e)}"}

    def _get_system_power_details(self) -> dict:
        """Get system-level power monitoring and PoE totals"""
        try:
            # Get system info
            system_data = self._request("GET", "/system")
            
            system_power = {
                "available": True,
                "poe_system": {},
                "port_power_summary": {}
            }
            
            # Extract PoE system settings
            poe_threshold = system_data.get('poe_threshold')
            if poe_threshold:
                system_power["poe_system"]["threshold_percent"] = poe_threshold
            
            # Calculate total PoE consumption across all ports
            total_power = 0.0
            active_poe_ports = 0
            port_details = {}
            
            # Get power data from all PoE-capable ports (1-18 for this switch)
            for i in range(1, 19):
                port_id = f"1/1/{i}"
                power_data = self._get_port_power_details(port_id)
                
                if power_data.get("available") and power_data.get("powering_status") == "delivering":
                    measurements = power_data.get("measurements", {})
                    if "average_power_w" in measurements:
                        port_power = measurements["average_power_w"]
                        total_power += port_power
                        active_poe_ports += 1
                        
                        port_details[port_id] = {
                            "power_w": port_power,
                            "status": "delivering"
                        }
            
            system_power["port_power_summary"] = {
                "total_poe_consumption_w": round(total_power, 2),
                "active_poe_ports": active_poe_ports,
                "port_details": port_details
            }
            
            return system_power
            
        except Exception as e:
            return {"available": False, "reason": f"Error retrieving system power data: {str(e)}"}

        return self._validation("unsupported verb for switch.config")

    def switch_reboot(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        Simple reboot (no image selection). Many CX builds expose /system/reboot.
        """
        confirm = params.get("confirm")
        # Accept alternate keys and truthy strings
        if confirm is None:
            confirm = params.get("force") or params.get("yes") or params.get("ack")
        if not self._is_truthy(confirm):
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

    # --------------- Power Monitoring ---------------

    def power_monitoring(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        Get power monitoring data for ports or switch.
        verb: get
        target: port or switch
        """
        if verb != "get":
            return {"status": "error", "error": "invalid_verb", 
                   "details": f"Only 'get' verb supported, got: {verb}"}
        
        # Handle target properly - can be dict or Target object
        if hasattr(target, 'type'):
            target_type = target.type
            target_id = target.external_id
        elif target and isinstance(target, dict):
            target_type = target.get("type", "switch")
            target_id = target.get("external_id")
        else:
            target_type = "switch"
            target_id = None
        
        return self.get_power_monitoring(target_type, target_id)

    def get_power_monitoring(self, target_type: str = "system", target_id: str = None) -> dict:
        """Get power monitoring data for ports or system."""
        self._validate_operational_state()
        
        # Ensure version negotiation is done
        host = self.config["hostname"]
        self._negotiate_version(host)
        
        self._login()
        try:
            if target_type == "port" and target_id:
                return self._get_port_power_details(target_id)
            elif target_type in ("system", "switch"):
                return self._get_system_power_details()
            else:
                return {"status": "error", "error": "invalid_target", 
                       "details": f"Unsupported target_type: {target_type}"}
        finally:
            self._logout()

    def _get_port_power_details(self, port_id: str) -> dict:
        """Get detailed power information for a specific port."""
        try:
            # Get PoE interface data directly - we know the port exists from inventory
            path = f"system/interfaces/{self._q(port_id)}/poe_interface"
            poe_data = self._request("GET", path)
            
            if not poe_data:
                return {"status": "error", "error": "no_poe_data", 
                       "details": f"No PoE data found for port {port_id}"}
            
            # Extract power measurements
            power_info = {
                "port_id": port_id,
                "power_enabled": not poe_data.get("config", {}).get("admin_disable", False),
                "power_status": poe_data.get("config", {}).get("status", "unknown"),
                "average_power_w": poe_data.get("config", {}).get("average_power", 0),
                "peak_power_w": poe_data.get("config", {}).get("peak_power", 0),
                "priority": poe_data.get("config", {}).get("priority", "unknown"),
                "power_class": poe_data.get("config", {}).get("power_class", "unknown")
            }
            
            return {"status": "ok", "power_data": power_info}
            
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return {"status": "error", "error": "no_poe_capability", 
                       "details": f"Port {port_id} has no PoE capability or doesn't exist"}
            return {"status": "error", "error": "api_error", 
                   "details": f"API error: {e.response.status_code} - {e.response.text if hasattr(e.response, 'text') else ''}"}
        except Exception as e:
            return {"status": "error", "error": "unexpected_error", "details": str(e)}

    def _get_system_power_details(self) -> dict:
        """Get system-wide power consumption details."""
        try:
            # Get system power statistics
            path = "system/power_supplies"
            power_supplies = self._request("GET", path)
            
            total_consumed = 0
            total_available = 0
            supply_details = []
            
            for ps_name, ps_data in power_supplies.items():
                if isinstance(ps_data, dict):
                    consumed = ps_data.get("power_consumed", 0)
                    available = ps_data.get("power_available", 0)
                    total_consumed += consumed
                    total_available += available
                    
                    supply_details.append({
                        "name": ps_name,
                        "power_consumed_w": consumed,
                        "power_available_w": available,
                        "status": ps_data.get("status", "unknown")
                    })
            
            # Also get PoE power consumption across all ports
            poe_total = 0
            try:
                interfaces_path = "system/interfaces"
                interfaces = self._request("GET", interfaces_path)
                
                for if_name, if_data in interfaces.items():
                    if isinstance(if_data, dict) and if_data.get("type") == "1000base-t":
                        try:
                            poe_path = f"system/interfaces/{self._q(if_name)}/poe_interface"
                            poe_data = self._request("GET", poe_path)
                            if poe_data and not poe_data.get("config", {}).get("admin_disable", False):
                                poe_total += poe_data.get("config", {}).get("average_power", 0)
                        except:
                            continue  # Skip ports without PoE
            except:
                pass  # Continue without PoE data if not available
            
            system_power = {
                "total_consumed_w": total_consumed,
                "total_available_w": total_available,
                "utilization_percent": (total_consumed / total_available * 100) if total_available > 0 else 0,
                "poe_consumed_w": poe_total,
                "power_supplies": supply_details
            }
            
            return {"status": "ok", "system_power": system_power}
            
        except requests.HTTPError as e:
            return {"status": "error", "error": "api_error", 
                   "details": f"API error: {e.response.status_code}"}
        except Exception as e:
            return {"status": "error", "error": "unexpected_error", "details": str(e)}

    # --------------- LLDP Neighbor Discovery ---------------

    def lldp_neighbors(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        Get LLDP neighbor information for ports or switch.
        verb: get
        target: port or switch
        """
        if verb != "get":
            return {"status": "error", "error": "invalid_verb", 
                   "details": f"Only 'get' verb supported, got: {verb}"}
        
        # Handle target properly - can be dict or Target object
        if hasattr(target, 'type'):
            target_type = target.type
            target_id = target.external_id
        elif target and isinstance(target, dict):
            target_type = target.get("type", "switch")
            target_id = target.get("external_id")
        else:
            target_type = "switch"
            target_id = None
        
        return self.get_lldp_neighbors(target_type, target_id)

    def get_lldp_neighbors(self, target_type: str = "switch", target_id: str = None) -> dict:
        """Get LLDP neighbor information for ports or entire switch."""
        self._validate_operational_state()
        
        # Ensure version negotiation is done
        host = self.config["hostname"]
        self._negotiate_version(host)
        
        self._login()
        try:
            if target_type == "port" and target_id:
                return self._get_port_lldp_neighbors(target_id)
            elif target_type in ("system", "switch"):
                return self._get_all_lldp_neighbors()
            else:
                return {"status": "error", "error": "invalid_target", 
                       "details": f"Unsupported target_type: {target_type}"}
        finally:
            self._logout()

    def _get_port_lldp_neighbors(self, port_id: str) -> dict:
        """Get LLDP neighbors for a specific port."""
        try:
            # Get LLDP neighbors for specific port
            path = f"system/interfaces/{self._q(port_id)}/lldp_neighbors"
            neighbors = self._request("GET", path)
            
            if not neighbors:
                return {"status": "ok", "neighbors": [], "port_id": port_id}
            
            neighbor_list = []
            for neighbor_id, neighbor_data in neighbors.items():
                if isinstance(neighbor_data, dict):
                    neighbor_info = {
                        "neighbor_id": neighbor_id,
                        "chassis_id": neighbor_data.get("chassis_id", "unknown"),
                        "system_name": neighbor_data.get("system_name", ""),
                        "system_description": neighbor_data.get("system_description", ""),
                        "port_id": neighbor_data.get("port_id", "unknown"),
                        "port_description": neighbor_data.get("port_description", ""),
                        "management_address": neighbor_data.get("management_address", ""),
                        "capabilities": neighbor_data.get("system_capabilities", [])
                    }
                    neighbor_list.append(neighbor_info)
            
            return {"status": "ok", "neighbors": neighbor_list, "port_id": port_id}
            
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return {"status": "error", "error": "port_not_found_or_no_lldp", 
                       "details": f"Port {port_id} not found or has no LLDP neighbors"}
            return {"status": "error", "error": "api_error", 
                   "details": f"API error: {e.response.status_code}"}
        except Exception as e:
            return {"status": "error", "error": "unexpected_error", "details": str(e)}

    def _get_all_lldp_neighbors(self) -> dict:
        """Get LLDP neighbors for all ports on the switch."""
        try:
            # Get all LLDP neighbors
            neighbors = self._request("GET", "system/interfaces/*/lldp_neighbors")
            
            if not neighbors:
                return {"status": "ok", "neighbors": {}}
            
            all_neighbors = {}
            for port_path, port_neighbors in neighbors.items():
                # Extract port ID from the path (e.g., "1/1/24" from interface path)
                port_id = port_path.split("/")[-2] if "/" in port_path else port_path
                
                port_neighbor_list = []
                if isinstance(port_neighbors, dict):
                    for neighbor_id, neighbor_data in port_neighbors.items():
                        if isinstance(neighbor_data, dict):
                            neighbor_info = {
                                "neighbor_id": neighbor_id,
                                "chassis_id": neighbor_data.get("chassis_id", "unknown"),
                                "system_name": neighbor_data.get("system_name", ""),
                                "system_description": neighbor_data.get("system_description", ""),
                                "port_id": neighbor_data.get("port_id", "unknown"),
                                "port_description": neighbor_data.get("port_description", ""),
                                "management_address": neighbor_data.get("management_address", ""),
                                "capabilities": neighbor_data.get("system_capabilities", [])
                            }
                            port_neighbor_list.append(neighbor_info)
                
                if port_neighbor_list:
                    all_neighbors[port_id] = port_neighbor_list
            
            return {"status": "ok", "neighbors": all_neighbors}
            
        except requests.HTTPError as e:
            return {"status": "error", "error": "api_error", 
                   "details": f"API error: {e.response.status_code}"}
        except Exception as e:
            return {"status": "error", "error": "unexpected_error", "details": str(e)}

    # --------------- Internals ---------------

    def _validate_operational_state(self):
        """Validate driver is properly configured for operations"""
        if not hasattr(self, 'config') or not self.config:
            raise RuntimeError("Driver not properly initialized - missing config")

        if not self.config.get('hostname'):
            raise RuntimeError("Missing required hostname in config")

        if 'password' not in self.secrets:
            raise RuntimeError("Missing required password in secrets")

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
                # Handle case where response contains version info objects
                latest_entry = data.get("latest") or data.get("preferred")
                if latest_entry:
                    # If it's a dict with version info, extract the version
                    if isinstance(latest_entry, dict) and 'version' in latest_entry:
                        cand = latest_entry['version']
                    else:
                        cand = latest_entry
                else:
                    # Look for version keys in the response
                    versions = []
                    for k, v in data.items():
                        if re.match(r"^v10\.\d{2}$", k):
                            versions.append(k)
                        elif isinstance(v, dict) and 'version' in v and re.match(r"^v10\.\d{2}$", v['version']):
                            versions.append(v['version'])
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
        # POST /rest/v10.xx/login with form data {username, password}
        url = f"{self.base}/login"
        payload = {"username": self.config["username"], "password": self.secrets.get("password") or self.config.get("password")}
        t0 = perf_counter_ns()
        self.log.info("phase=auth event=login start url=%s", url)
        r = self.session.post(url, data=payload, timeout=10)
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

    @staticmethod
    def _target_id(target: dict) -> str:
        if not isinstance(target, dict):
            return str(target)
        for k in ("external_id", "id", "name", "port", "port_id", "interface", "if_id"):
            v = target.get(k)
            if v:
                return str(v)
        return ""

    @staticmethod
    def _is_truthy(x: Any) -> bool:
        if isinstance(x, bool):
            return x
        if x is None:
            return False
        s = str(x).strip().lower()
        return s in ("1", "true", "yes", "y", "on", "enable", "enabled")

    @staticmethod
    def _normalize_state_enable_disable(x: Any) -> str:
        if isinstance(x, bool):
            return "enable" if x else "disable"
        s = str(x or "").strip().lower()
        if s in ("1", "true", "yes", "y", "on", "enable", "enabled"):
            return "enable"
        if s in ("0", "false", "no", "n", "off", "disable", "disabled"):
            return "disable"
        return s

    @staticmethod
    def _normalize_priority(x: Any) -> str:
        s = str(x or "").strip().lower()
        if s in ("med", "medium", "mid"):
            return "normal"
        if s in ("crit", "critical"):
            return "high"
        if s in ("0",):
            return "low"
        if s in ("1",):
            return "normal"
        if s in ("2",):
            return "high"
        return s

    @staticmethod
    def _normalize_admin(params: dict) -> str:
        # Prefer explicit admin, else look for common synonyms
        v = params.get("admin")
        if v is None:
            v = params.get("state")
        if v is None and "shutdown" in params:
            # shutdown True => down
            return "down" if AoscxRestDriver._is_truthy(params.get("shutdown")) else "up"
        s = str(v or "").strip().lower()
        if s in ("up", "enable", "enabled", "no-shutdown", "no_shutdown"):
            return "up"
        if s in ("down", "disable", "disabled", "shutdown"):
            return "down"
        if s in ("1", "true", "yes", "on"):
            return "up"
        if s in ("0", "false", "no", "off"):
            return "down"
        return s

    def _build_poe_patch(self, before: dict, state: str) -> Tuple[dict, str]:
        """
        Build PoE patch for AOS-CX using PoE interface API.
        Uses config.admin_disable field (inverted logic).
        """
        # AOS-CX uses admin_disable in PoE interface config (inverted logic)
        admin_disable = (state == "disable")  # disable=True means PoE off
        return {"config": {"admin_disable": admin_disable}}, "config.admin_disable"

    def _build_poe_priority_patch(self, before: dict, aoscx_level: str) -> Tuple[dict, str]:
        """
        Build PoE priority patch for AOS-CX using PoE interface API.
        Uses config.priority field.
        """
        # AOS-CX uses priority in PoE interface config
        return {"config": {"priority": aoscx_level}}, "config.priority"

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
