# AOS-CX (Standalone) Integration for WalNUT

**Talk directly to AOS-CX switches via REST.**  
A lean, REST-first driver that mirrors AOS-S behavior using cookie-session auth, tight version negotiator, clean dry-runs—and always logs out.

## Repository Structure

```
com.aruba.aoscx.standalone/
├── plugin.yaml          # WalNUT manifest declaring capabilities & schema
├── driver.py            # Handles negotiation, HTTP ops, logging, dry-run logic
└── README.md            # (this file) How to configure, use & extend
```

## What & Why?

You're not just talking to a switch—you're dancing with it.

- **Discover v10.x REST API versions** via `/rest`, pick the newest working one.
- **Login → operations → mandatory logout** to avoid cookie exhaustion.
- **Inventory**: list ports, stack members (VSF/VSX), and switch facts.
- **Controls**: PoE toggle, priority, interface shutdown, reboot, config save/backup.
- **Dry-run for any mutating action**, with clear planned steps and minimal risk.
- **Structured logging**: every request, response, error, operation, timing—all neatly key=value tagged.
- **Friendly error mapping**: 401→auth_error, 404 write→read_only_mode, 404 negotiation→api_version_mismatch, etc.

## Installation & Usage

1. **Drop into your WalNUT plugin directory**:
   ```bash
   mv com.aruba.aoscx.standalone /path/to/walnut/plugins/
   ```

2. **Ensure Python runtime dependencies**:
   - `requests`
   - `python3` (3.8+)
   
   *(Requirements are standard; you might already have them from core.)*

3. **Configure in WalNUT**:
   ```yaml
   plugin_id: com.aruba.aoscx.standalone
   config:
     hostname: 192.0.2.1
     username: admin
     password: s3cr3t
     verify_tls: false  # optional
   ```

4. **Test the connection**:
   ```python
   result = driver.test_connection()
   print(result)
   # → {status: "connected", latency_ms: 120, details: "..."}
   ```

5. **Dry-run a config save**:
   ```python
   result = driver.switch_config("save", target=switch_target, dry_run=True)
   print(result["plan"])
   ```

6. **Execute a real change** (with confirmation flags where required):
   ```python
   result = driver.poe_port("set", target=port_target, params={"state":"disable"}, dry_run=False)
   ```

## Logging & Debug Options

By default, logs go to stderr in structured format via logger `aoscx_driver`:

- **INFO**: successful operations, dry-run summaries, login/logout.
- **DEBUG**: HTTP request intent, response timing/size (without bodies).
- **WARNING / ERROR**: validation issues, mapping errors, probe failures.

To get verbose HTTP details, set your logger to DEBUG:

```python
import logging
logging.getLogger("aoscx_driver").setLevel(logging.DEBUG)
```

Later, we can add options like `--log-level`, `--log-http-bodies`, and header redaction via plugin params—just ask.

## Examples

### Listing Ports (active only)

```python
ports = driver.inventory_list("port")
for p in ports:
    print(f"{p['external_id']} → link: {p['attrs']['link']}, PoE: {p['attrs']['poe']}")
```

### Doing a Dry-Run, Setting PoE Priority

```python
plan = driver.poe_priority("set", target=low_prio_port, params={"level": "low"}, dry_run=True)
print(plan["steps"])
```

### Backing Up Configuration

```python
backup = driver.switch_config("backup", target=switch_target, dry_run=False)
content = backup["artifact"]["content"]
filename = backup["artifact"]["filename"]
with open(filename, "w") as f:
    f.write(json.dumps(content, indent=2))
```

## Maintenance & Extensibility

- **Dry-run patterns** follow plan → verify → execute.
- **Session discipline** ensures no resource leaks on exception.
- **Version negotiation** smartly handles fallback on bad versions.
- You can thread in CSRF token overrides, add body redaction, or support interactive CLI debugging easily.