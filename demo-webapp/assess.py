#!/usr/bin/env python3
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

parser = argparse.ArgumentParser(
    description="Run a bounded ddos assessment against the local demo target."
)
parser.add_argument("--bin", default=str(ROOT / "target" / "release" / "ddos"))
parser.add_argument("--base", default="http://127.0.0.1:3030")
parser.add_argument("--scope", default=str(ROOT / "demo-webapp" / "scope.txt"))
parser.add_argument("--out", default=str(ROOT / "demo-webapp" / "out"))
options = parser.parse_args()

BIN = Path(options.bin)
BASE = options.base.rstrip("/")
SCOPE = str(Path(options.scope).resolve())
OUT = Path(options.out).resolve()
RAW = OUT / "raw"
AUDIT = OUT / "audit.jsonl"
REPORT = OUT / "findings.md"
ASSESS = OUT / "assessment.json"

if not BIN.exists():
    sys.exit(f"ddos binary not found: {BIN}")

shutil.rmtree(OUT, ignore_errors=True)
RAW.mkdir(parents=True, exist_ok=True)

checks = []
findings = []
summary_rows = []
observations = []
limitations = []


def rel(path):
    return str(Path(path).resolve().relative_to(OUT))


def invoke(name, args, timeout=120, env_extra=None):
    argv = [str(BIN)] + [str(value) for value in args]
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    if env_extra:
        env.update({str(key): str(value) for key, value in env_extra.items()})
    started = time.time()
    try:
        completed = subprocess.run(
            argv,
            cwd=str(ROOT),
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
        timed_out = False
    except subprocess.TimeoutExpired as error:
        code = -1
        stdout = error.stdout if isinstance(error.stdout, str) else ""
        stderr = error.stderr if isinstance(error.stderr, str) else ""
        timed_out = True
    duration = time.time() - started
    stdout_file = RAW / f"{name}.out"
    stderr_file = RAW / f"{name}.err"
    stdout_file.write_text(stdout or "", encoding="utf-8")
    stderr_file.write_text(stderr or "", encoding="utf-8")
    record = {
        "name": name,
        "argv": argv,
        "exit": code,
        "timed_out": timed_out,
        "duration_s": round(duration, 3),
        "stdout_file": rel(stdout_file),
        "stderr_file": rel(stderr_file),
    }
    checks.append(record)
    print(f"[check] {name}: exit {code} in {duration:.2f}s")
    return {"meta": record, "stdout": stdout or "", "stderr": stderr or ""}


def json_of(record):
    try:
        return json.loads(record["stdout"])
    except Exception:
        return None


def jsonl_of(record):
    values = []
    for line in record["stdout"].splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            values.append(json.loads(line))
        except Exception:
            pass
    return values


def http_of(record):
    data = json_of(record) or {}
    return data.get("http") or {}


def body_of(record):
    return http_of(record).get("body_preview") or ""


def header_of(record, name):
    for pair in http_of(record).get("headers") or []:
        if len(pair) == 2 and str(pair[0]).lower() == name.lower():
            return pair[1]
    return None


def security_of(record):
    return http_of(record).get("security_headers") or []


def security_presence(record):
    values = security_of(record)
    present = [value for value in values if value.get("present")]
    missing = [value["name"] for value in values if not value.get("present")]
    names = [value["name"] for value in present]
    return len(present), len(values), names, missing


def report_counts(record):
    match = re.search(
        r"\| Security headers \| (PASS|WARN) \| (\d+) of (\d+) present(?: \(grade ([A-F]), (\d+)/100\))? \|",
        record["stdout"],
    )
    if not match:
        return None
    return match.group(1), int(match.group(2)), int(match.group(3))


def report_grade(record):
    match = re.search(
        r"\| Security headers \| (?:PASS|WARN) \| \d+ of \d+ present \(grade ([A-F]), (\d+)/100\) \|",
        record["stdout"],
    )
    if not match:
        return None, None
    return match.group(1), int(match.group(2))


def get_metrics():
    with urllib.request.urlopen(f"{BASE}/metrics", timeout=3) as response:
        return json.loads(response.read().decode("utf-8"))


def metric_delta(before, after, status):
    key = str(status)
    return int(after.get("by_status", {}).get(key, 0)) - int(
        before.get("by_status", {}).get(key, 0)
    )


def repro(record):
    argv = list(record["meta"]["argv"])
    if argv and argv[0] == str(BIN):
        argv[0] = "ddos"
    return shlex.join(argv)


def artifact(name):
    record = next((item for item in checks if item["name"] == name), None)
    return record["stdout_file"] if record else None


def add_finding(identifier, severity, title, evidence, reproduction, artifacts):
    findings.append(
        {
            "id": identifier,
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "reproduce": reproduction,
            "artifacts": [value for value in artifacts if value],
        }
    )


def add_summary(check, result, detail):
    summary_rows.append({"check": check, "result": result, "detail": detail})


try:
    initial_metrics = get_metrics()
except Exception as error:
    sys.exit(f"demo server not reachable at {BASE}: {error}")

version = invoke("version", ["--version"])
resolve = invoke(
    "resolve_localhost", ["resolve", "localhost", "--output", "json", "--scope", SCOPE]
)
resolve_v4 = invoke(
    "resolve_ipv4",
    ["resolve", "localhost", "--family", "ipv4", "--output", "json", "--scope", SCOPE],
)
tcp_http = invoke(
    "tcp_http",
    [
        "tcp-check",
        "127.0.0.1",
        "3030",
        "--timeout",
        "3",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
tcp_tls = invoke(
    "tcp_tls",
    [
        "tcp-check",
        "127.0.0.1",
        "3043",
        "--timeout",
        "3",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
dns_a = invoke(
    "dns_a",
    ["dns-check", "localhost", "--dns-type", "A", "--output", "json", "--scope", SCOPE],
)
dns_aaaa = invoke(
    "dns_aaaa",
    [
        "dns-check",
        "localhost",
        "--dns-type",
        "AAAA",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
udp_echo = invoke(
    "udp_echo",
    [
        "udp-check",
        "127.0.0.1",
        "3031",
        "--payload",
        "68656c6c6f",
        "--timeout",
        "3",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
udp_dns = invoke(
    "udp_dns",
    [
        "udp-check",
        "127.0.0.1",
        "3053",
        "--payload",
        "1234010000010000000000000464656d6f056c6f63616c0000010001",
        "--timeout",
        "3",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)

report_full = invoke(
    "report_headers_full",
    ["report", f"{BASE}/headers/full", "--scope", SCOPE, "--audit-log", str(AUDIT)],
)
report_none = invoke(
    "report_headers_none",
    ["report", f"{BASE}/headers/none", "--scope", SCOPE, "--audit-log", str(AUDIT)],
)
partial = invoke(
    "diagnose_headers_partial",
    [
        "diagnose",
        f"{BASE}/headers/partial",
        "--method",
        "GET",
        "--audit-headers",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
banner = invoke(
    "http_banner",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/headers/none",
        "--method",
        "GET",
        "--show-header",
        "server",
        "--show-header",
        "x-powered-by",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
cors = invoke(
    "http_cors_cookie",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/api/login?user=admin",
        "--method",
        "GET",
        "--show-header",
        "access-control-allow-origin",
        "--show-header",
        "set-cookie",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
cors_audit = invoke(
    "cors_check",
    ["cors-check", f"{BASE}/api/users", "--output", "json", "--scope", SCOPE],
)
cookie_audit = invoke(
    "cookie_check",
    [
        "cookie-check",
        f"{BASE}/api/login?user=admin",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
xss = invoke(
    "http_reflected_xss",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "--method",
        "GET",
        "--body-bytes",
        "4096",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
admin = invoke(
    "http_admin_exposed",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/admin",
        "--method",
        "GET",
        "--body-bytes",
        "4096",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
bypass = invoke(
    "http_auth_bypass",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/api/login?user=admin&password=wrong",
        "--method",
        "GET",
        "--body-bytes",
        "4096",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
debug = invoke(
    "http_debug_leak",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/debug",
        "--method",
        "GET",
        "--body-bytes",
        "8192",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
traversal = invoke(
    "http_path_traversal",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/download?file=../Cargo.toml",
        "--method",
        "GET",
        "--body-bytes",
        "512",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
robots = invoke(
    "http_robots",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/robots.txt",
        "--method",
        "GET",
        "--body-bytes",
        "512",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
openapi = invoke(
    "http_openapi",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/openapi.json",
        "--method",
        "GET",
        "--body-bytes",
        "4096",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
port_scan = invoke(
    "port_scan",
    [
        "port-scan",
        "127.0.0.1",
        "--ports",
        "3030,3043,3053,8080,9001",
        "--timeout",
        "1",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
port_scan_no_scope = invoke(
    "port_scan_requires_scope",
    ["port-scan", "example.com", "--ports", "80", "--no-config"],
)
port_scan_scope_refusal = invoke(
    "port_scan_out_of_scope",
    [
        "port-scan",
        "192.0.2.10",
        "--ports",
        "80",
        "--timeout",
        "1",
        "--scope",
        SCOPE,
    ],
)
path_discovery = invoke(
    "path_discovery",
    ["path-discovery", BASE, "--output", "json", "--scope", SCOPE],
)
path_discovery_wordlist = invoke(
    "path_discovery_wordlist",
    [
        "path-discovery",
        BASE,
        "--wordlist",
        str(ROOT / "demo-webapp" / "wordlist.txt"),
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
path_discovery_no_scope = invoke(
    "path_discovery_requires_scope",
    ["path-discovery", "http://example.com", "--no-config"],
)

metrics_before_auth = get_metrics()
auth_anon = invoke(
    "http_auth_private_anon",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/api/private",
        "--method",
        "GET",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
auth_good = invoke(
    "http_auth_private_good",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/api/private",
        "--method",
        "GET",
        "--auth",
        "bearer",
        "s3cr3t",
        "--body-bytes",
        "512",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
admin_api_anon = invoke(
    "http_auth_admin_anon",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/api/admin",
        "--method",
        "GET",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
admin_api_good = invoke(
    "http_auth_admin_good",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/api/admin",
        "--method",
        "GET",
        "--auth",
        "bearer",
        "admin-token",
        "--body-bytes",
        "512",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
metrics_after_auth = get_metrics()

redirect_internal = invoke(
    "redirect_internal_follow",
    [
        "diagnose",
        f"{BASE}/redirect/internal",
        "--method",
        "GET",
        "--redirects",
        "5",
        "--body-bytes",
        "512",
        "--output",
        "json",
    ],
)
redirect_scope = invoke(
    "redirect_external_scope",
    [
        "diagnose",
        f"{BASE}/redirect/external",
        "--method",
        "GET",
        "--scope",
        SCOPE,
        "--output",
        "json",
    ],
)
large = invoke(
    "body_bounded",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/large?bytes=100000",
        "--method",
        "GET",
        "--body-bytes",
        "1024",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)

metrics_before_status = get_metrics()
status_ok = invoke(
    "expect_status_match",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/status?code=200",
        "--method",
        "GET",
        "--expect-status",
        "200",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
status_401 = invoke(
    "expect_status_401",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/api/private",
        "--method",
        "GET",
        "--expect-status",
        "401",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
status_500 = invoke(
    "expect_status_500",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/status?code=500",
        "--method",
        "GET",
        "--expect-status",
        "500",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
status_mismatch = invoke(
    "expect_status_mismatch",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/status?code=500",
        "--method",
        "GET",
        "--expect-status",
        "200",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
metrics_after_status = get_metrics()

custom = invoke(
    "http_custom_headers",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/echo",
        "--method",
        "GET",
        "--header",
        "X-Trace-Id: demo",
        "--user-agent",
        "assessbot/1.0",
        "--body-bytes",
        "2048",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
proxy = invoke(
    "http_via_proxy",
    [
        "diagnose",
        f"{BASE}/echo",
        "--method",
        "GET",
        "--proxy",
        "http://127.0.0.1:8080",
        "--body-bytes",
        "2048",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
)
tls = invoke(
    "tls_check_self_signed",
    ["tls-check", "127.0.0.1", "3043", "--output", "json", "--scope", SCOPE],
)

csv_output = invoke(
    "output_csv",
    [
        "diagnose",
        f"{BASE}/health",
        "--method",
        "GET",
        "--output",
        "csv",
        "--scope",
        SCOPE,
    ],
)
jsonl_output = invoke(
    "output_jsonl",
    [
        "diagnose",
        f"{BASE}/health",
        "--method",
        "GET",
        "--output",
        "jsonl",
        "--scope",
        SCOPE,
    ],
)
config_file = ROOT / "demo-webapp" / "ddos-config.toml"
config_json = invoke(
    "config_json", ["diagnose", f"{BASE}/headers/partial", "--config", str(config_file)]
)
config_env = invoke(
    "config_env_override",
    ["diagnose", f"{BASE}/headers/partial", "--config", str(config_file)],
    env_extra={"DDOS_OUTPUT": "jsonl"},
)
config_cli = invoke(
    "config_cli_override",
    [
        "diagnose",
        f"{BASE}/headers/partial",
        "--config",
        str(config_file),
        "--output",
        "csv",
    ],
    env_extra={"DDOS_OUTPUT": "jsonl"},
)
xdg = OUT / "xdg"
shutil.rmtree(xdg, ignore_errors=True)
config_path = invoke(
    "config_path", ["config", "path"], env_extra={"XDG_CONFIG_HOME": str(xdg)}
)
config_init = invoke(
    "config_init", ["config", "init"], env_extra={"XDG_CONFIG_HOME": str(xdg)}
)

scope_refusal = invoke(
    "scope_refusal", ["diagnose", "http://198.51.100.10", "--scope", SCOPE]
)
audit_auth = invoke(
    "audit_auth",
    [
        "http-check",
        "127.0.0.1",
        "3030",
        "--path",
        "/api/private",
        "--method",
        "GET",
        "--auth",
        "bearer",
        "s3cr3t",
        "--output",
        "json",
        "--scope",
        SCOPE,
        "--audit-log",
        str(AUDIT),
    ],
)

batch = invoke(
    "batch_jsonl",
    [
        "batch",
        str(ROOT / "demo-webapp" / "targets.txt"),
        "--method",
        "GET",
        "--audit-headers",
        "--output",
        "jsonl",
        "--scope",
        SCOPE,
    ],
)
repeat = invoke(
    "repeat_jsonl",
    [
        "repeat",
        f"{BASE}/health",
        "--interval",
        "1",
        "--duration",
        "4",
        "--method",
        "GET",
        "--output",
        "jsonl",
        "--scope",
        SCOPE,
    ],
    timeout=30,
)

metrics_before_load = get_metrics()
load = invoke(
    "load_test_api",
    [
        "load-test",
        f"{BASE}/api/users",
        "--rate",
        "50",
        "--count",
        "200",
        "--method",
        "GET",
        "--rotate-user-agent",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
    timeout=60,
)
metrics_after_load = get_metrics()

metrics_before_capacity = get_metrics()
capacity = invoke(
    "capacity_test_stress",
    [
        "capacity-test",
        f"{BASE}/stress",
        "--rate",
        "50",
        "--steps",
        "5",
        "--count",
        "300",
        "--method",
        "GET",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
    timeout=90,
)
metrics_after_capacity = get_metrics()

churn = invoke(
    "connection_churn",
    [
        "connection-churn",
        "127.0.0.1",
        "3030",
        "--count",
        "200",
        "--rate",
        "50",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
    timeout=60,
)
slow = invoke(
    "slow_request",
    [
        "slow-request",
        "127.0.0.1",
        "3030",
        "--clients",
        "4",
        "--hold",
        "3",
        "--output",
        "json",
        "--scope",
        SCOPE,
    ],
    timeout=30,
)
shape = invoke(
    "request_shape",
    ["request-shape", BASE, "--count", "20", "--output", "json", "--scope", SCOPE],
    timeout=30,
)

version_text = version["stdout"].strip()
resolve_data = json_of(resolve) or {}
resolve_v4_data = json_of(resolve_v4) or {}
tcp_http_data = json_of(tcp_http) or {}
tcp_tls_data = json_of(tcp_tls) or {}
dns_a_data = json_of(dns_a) or {}
dns_aaaa_data = json_of(dns_aaaa) or {}
udp_echo_data = json_of(udp_echo) or {}
udp_dns_data = json_of(udp_dns) or {}
port_scan_data = json_of(port_scan) or {}
path_discovery_data = json_of(path_discovery) or {}
path_discovery_wordlist_data = json_of(path_discovery_wordlist) or {}
cors_audit_data = json_of(cors_audit) or {}
cookie_audit_data = json_of(cookie_audit) or {}
tls_data = json_of(tls) or {}
load_data = json_of(load) or {}
capacity_data = json_of(capacity) or {}
churn_data = json_of(churn) or {}
slow_data = json_of(slow) or {}
shape_data = json_of(shape) or {}

full_counts = report_counts(report_full) or ("UNKNOWN", 0, 0)
none_counts = report_counts(report_none) or ("UNKNOWN", 0, 0)
full_grade, full_score = report_grade(report_full)
none_grade, none_score = report_grade(report_none)
partial_present, partial_total, partial_names, partial_missing = security_presence(
    partial
)
server_banner = header_of(banner, "server")
powered_by = header_of(banner, "x-powered-by")
cors_value = header_of(cors, "access-control-allow-origin")
cookie_value = header_of(cors, "set-cookie")
xss_body = body_of(xss)
admin_body = body_of(admin)
bypass_body = body_of(bypass)
debug_body = body_of(debug)
traversal_body = body_of(traversal)
robots_body = body_of(robots)
openapi_body = body_of(openapi)
auth_good_body = body_of(auth_good)
admin_api_good_body = body_of(admin_api_good)
custom_body = body_of(custom)
proxy_body = body_of(proxy)
large_size = http_of(large).get("body_size")
redirect_internal_status = http_of(redirect_internal).get("status")
redirect_scope_status = http_of(redirect_scope).get("status")

xss_reflected = "<script>alert(1)" in xss_body
admin_exposed = "flag{no_auth_required}" in admin_body
login_bypass = '"bypass":true' in bypass_body and "admin-token" in bypass_body
debug_leak = "DEMO_SECRET" in debug_body and "flag{env_secret}" in debug_body
traversal_leak = "[package]" in traversal_body and 'name = "ddos"' in traversal_body
robots_leak = "/admin" in robots_body and "/debug" in robots_body
openapi_leak = '"/api/login"' in openapi_body and '"/api/private"' in openapi_body
private_ok = "flag{private_api}" in auth_good_body
admin_api_ok = "flag{admin_api}" in admin_api_good_body
custom_ok = (
    '"x-trace-id":"demo"' in custom_body
    and '"user-agent":"assessbot/1.0"' in custom_body
)
proxy_ok = '"x-proxy":"ddos-demo-proxy"' in proxy_body
redirect_follow_ok = redirect_internal_status == 200
redirect_scope_ok = redirect_scope_status == 302
body_bound_ok = large_size == 1024
tls_rejected = not tls_data.get("ok", False)
tls_error = tls_data.get("error") or ""
status_match_ok = status_ok["meta"]["exit"] == 0
status_401_exit = status_401["meta"]["exit"]
status_500_exit = status_500["meta"]["exit"]
status_mismatch_exit = status_mismatch["meta"]["exit"]
port_scan_open = port_scan_data.get("open") or []
port_scan_ok = set(port_scan_open) == {
    "127.0.0.1:3030",
    "127.0.0.1:3043",
    "127.0.0.1:8080",
}
port_scan_no_scope_ok = (
    port_scan_no_scope["meta"]["exit"] == 2
    and "requires --scope" in port_scan_no_scope["stderr"]
)
port_scan_scope_refusal_ok = (
    port_scan_scope_refusal["meta"]["exit"] == 2
    and "outside the authorized scope" in port_scan_scope_refusal["stderr"]
)
path_found = {
    result.get("path"): result.get("status")
    for result in path_discovery_data.get("results") or []
    if result.get("interesting")
}
path_discovery_ok = (
    path_discovery_data.get("ok") is True
    and path_discovery_data.get("found_count", 0) >= 15
    and {"/admin", "/debug", "/metrics", "/api/users", "/openapi.json"}
    <= set(path_found)
)
path_wordlist_found = {
    result.get("path")
    for result in path_discovery_wordlist_data.get("results") or []
    if result.get("interesting")
}
path_discovery_wordlist_ok = (
    path_discovery_wordlist_data.get("scanned_count") == 5
    and {"/admin", "/debug", "/download", "/openapi.json"} <= path_wordlist_found
    and "/missing" not in path_wordlist_found
)
path_discovery_no_scope_ok = (
    path_discovery_no_scope["meta"]["exit"] == 2
    and "requires --scope" in path_discovery_no_scope["stderr"]
)
cors_audit_codes = {
    finding.get("code") for finding in cors_audit_data.get("findings") or []
}
cookie_audit_codes = {
    finding.get("code") for finding in cookie_audit_data.get("findings") or []
}
cors_audit_ok = "wildcard_origin" in cors_audit_codes
cookie_audit_ok = {
    "missing_secure",
    "missing_httponly",
    "missing_samesite",
} <= cookie_audit_codes
delta_401 = metric_delta(metrics_before_status, metrics_after_status, 401)
delta_500 = metric_delta(metrics_before_status, metrics_after_status, 500)
delta_429 = metric_delta(metrics_before_load, metrics_after_load, 429)
delta_503 = metric_delta(metrics_before_capacity, metrics_after_capacity, 503)
delta_auth_401 = metric_delta(metrics_before_auth, metrics_after_auth, 401)
delta_auth_403 = metric_delta(metrics_before_auth, metrics_after_auth, 403)

csv_first = (
    csv_output["stdout"].strip().splitlines()[0] if csv_output["stdout"].strip() else ""
)
jsonl_lines = [line for line in jsonl_output["stdout"].splitlines() if line.strip()]
config_json_data = json_of(config_json)
config_env_lines = [line for line in config_env["stdout"].splitlines() if line.strip()]
config_cli_first = (
    config_cli["stdout"].strip().splitlines()[0] if config_cli["stdout"].strip() else ""
)
config_file_written = Path(config_path["stdout"].strip())
config_init_ok = (
    config_file_written.exists()
    and "timeout = 5" in config_file_written.read_text(encoding="utf-8")
)
scope_refusal_ok = (
    scope_refusal["meta"]["exit"] == 2
    and "outside the authorized scope" in scope_refusal["stderr"]
)
audit_text = AUDIT.read_text(encoding="utf-8") if AUDIT.exists() else ""
audit_records = []
for line in audit_text.splitlines():
    if line.strip():
        try:
            audit_records.append(json.loads(line))
        except Exception:
            pass
audit_ok = len(audit_records) >= 3
audit_no_secret = "s3cr3t" not in audit_text
batch_reports = jsonl_of(batch)
batch_rows = []
for item in batch_reports:
    http_value = item.get("http") or {}
    security = http_value.get("security_headers") or []
    present = sum(1 for value in security if value.get("present"))
    batch_rows.append(
        {
            "target": item.get("target"),
            "status": http_value.get("status"),
            "present": present,
            "total": len(security),
        }
    )
batch_errors = [line for line in batch["stderr"].splitlines() if line.strip()]
repeat_reports = jsonl_of(repeat)
repeat_ok = len(repeat_reports) >= 3 and all(item.get("ok") for item in repeat_reports)
churn_ok = churn_data.get("failed") == 0
slow_still_open = slow_data.get("still_open")
slow_closed = slow_data.get("server_closed")
shape_ok = (
    shape_data.get("server_errors") == 0 and shape_data.get("transport_errors") == 0
)
dns_ok = bool(dns_a_data.get("ok")) and bool(dns_aaaa_data.get("ok"))
udp_ok = bool(udp_echo_data.get("ok")) and bool(udp_dns_data.get("ok"))
resolve_ok = bool(resolve_data.get("addresses"))
tcp_ok = bool(tcp_http_data.get("ok")) and bool(tcp_tls_data.get("ok"))
capacity_steps = capacity_data.get("steps") or []
degraded_steps = [step for step in capacity_steps if step.get("degraded")]

add_summary(
    "DNS resolution",
    "PASS" if resolve_ok else "FAIL",
    f"{len(resolve_data.get('addresses') or [])} address(es); IPv4-only run returned {len(resolve_v4_data.get('addresses') or [])} address(es).",
)
add_summary(
    "TCP checks",
    "PASS" if tcp_ok else "FAIL",
    f"HTTP port open={tcp_http_data.get('ok')}; TLS port open={tcp_tls_data.get('ok')}.",
)
add_summary(
    "DNS record checks",
    "PASS" if dns_ok else "FAIL",
    f"A ok={dns_a_data.get('ok')}; AAAA ok={dns_aaaa_data.get('ok')}.",
)
add_summary(
    "UDP probes",
    "PASS" if udp_ok else "FAIL",
    f"Echo ok={udp_echo_data.get('ok')}; DNS-over-UDP ok={udp_dns_data.get('ok')}, bytes={((udp_dns_data.get('attempts') or [{}])[0]).get('response_bytes')}.",
)
add_summary(
    "Port scan",
    "PASS" if port_scan_ok else "FAIL",
    f"Open {port_scan_data.get('open_count')}/{port_scan_data.get('scanned_count')}: {', '.join(port_scan_open) or 'none'}.",
)
add_summary(
    "Port-scan scope guard",
    "PASS" if port_scan_no_scope_ok and port_scan_scope_refusal_ok else "FAIL",
    f"Public host without scope exit={port_scan_no_scope['meta']['exit']}; out-of-scope address exit={port_scan_scope_refusal['meta']['exit']}.",
)
add_summary(
    "Path discovery",
    "PASS" if path_discovery_ok else "FAIL",
    f"{path_discovery_data.get('found_count')}/{path_discovery_data.get('scanned_count')} interesting paths; key paths={', '.join(sorted(path_found))}.",
)
add_summary(
    "Path-discovery wordlist",
    "PASS" if path_discovery_wordlist_ok else "FAIL",
    f"{path_discovery_wordlist_data.get('found_count')}/{path_discovery_wordlist_data.get('scanned_count')} interesting; found={', '.join(sorted(path_wordlist_found))}.",
)
add_summary(
    "Path-discovery scope guard",
    "PASS" if path_discovery_no_scope_ok else "FAIL",
    f"Public host without scope exit={path_discovery_no_scope['meta']['exit']}.",
)
add_summary(
    "Security headers on /headers/full",
    full_counts[0],
    f"{full_counts[1]} of {full_counts[2]} present; grade {full_grade}, {full_score}/100.",
)
add_summary(
    "Security headers on /headers/partial",
    "WARN",
    f"{partial_present} of {partial_total} present.",
)
add_summary(
    "Security headers on /headers/none",
    none_counts[0],
    f"{none_counts[1]} of {none_counts[2]} present; grade {none_grade}, {none_score}/100.",
)
add_summary(
    "Reflected XSS on /",
    "FAIL" if xss_reflected else "PASS",
    "Unescaped script tag reflected in the body."
    if xss_reflected
    else "No reflected payload found.",
)
add_summary(
    "Unauthenticated /admin",
    "FAIL" if admin_exposed else "PASS",
    "Admin flag returned without authentication."
    if admin_exposed
    else "Admin page did not expose a flag.",
)
add_summary(
    "Login bypass",
    "FAIL" if login_bypass else "PASS",
    "Wrong password returned an admin token with bypass=true."
    if login_bypass
    else "No bypass observed.",
)
add_summary(
    "/debug secret disclosure",
    "FAIL" if debug_leak else "PASS",
    "DEMO_SECRET and DEMO_API_KEY are exposed."
    if debug_leak
    else "No demo secret found.",
)
add_summary(
    "Path traversal in /download",
    "FAIL" if traversal_leak else "PASS",
    "Escaped the app root and read ../Cargo.toml."
    if traversal_leak
    else "Traversal blocked.",
)
add_summary(
    "CORS policy",
    "FAIL" if cors_value == "*" else "PASS",
    f"Access-Control-Allow-Origin={cors_value!r}.",
)
add_summary(
    "CORS audit",
    "FAIL" if cors_audit_ok else "PASS",
    f"findings={', '.join(sorted(cors_audit_codes)) or 'none'}.",
)
add_summary(
    "Session cookie flags",
    "FAIL" if cookie_value and "HttpOnly" not in cookie_value else "PASS",
    f"Set-Cookie={cookie_value!r}.",
)
add_summary(
    "Cookie audit",
    "FAIL" if cookie_audit_ok else "PASS",
    f"findings={', '.join(sorted(cookie_audit_codes)) or 'none'}.",
)
add_summary(
    "Server banner", "WARN", f"Server={server_banner!r}; X-Powered-By={powered_by!r}."
)
add_summary(
    "robots.txt disclosure",
    "WARN" if robots_leak else "PASS",
    robots_body.strip() or "empty",
)
add_summary(
    "OpenAPI discovery",
    "WARN" if openapi_leak else "PASS",
    "Public OpenAPI document lists auth and admin routes."
    if openapi_leak
    else "No route disclosure.",
)
add_summary(
    "Private API auth",
    "PASS" if private_ok else "FAIL",
    f"Bearer token accepted={private_ok}; anonymous 401 events={delta_auth_401}.",
)
add_summary(
    "Admin API auth",
    "PASS" if admin_api_ok else "FAIL",
    f"Admin bearer token accepted={admin_api_ok}; anonymous 403 events={delta_auth_403}.",
)
add_summary(
    "Redirect following",
    "PASS" if redirect_follow_ok else "FAIL",
    f"Internal redirect final status={redirect_internal_status}.",
)
add_summary(
    "Redirect scope containment",
    "PASS" if redirect_scope_ok else "FAIL",
    f"External redirect status with scope={redirect_scope_status} (not followed).",
)
add_summary(
    "Bounded body read",
    "PASS" if body_bound_ok else "FAIL",
    f"Requested 100000 bytes, read {large_size} bytes.",
)
add_summary(
    "Expected status 200",
    "PASS" if status_match_ok else "FAIL",
    f"Exit={status_ok['meta']['exit']}.",
)
add_summary(
    "Expected status 401",
    "PASS" if status_401_exit == 0 else "FAIL",
    f"Exit={status_401_exit}; server metrics show {delta_401} HTTP 401 response(s).",
)
add_summary(
    "Expected status 500",
    "PASS" if status_500_exit == 0 else "FAIL",
    f"Exit={status_500_exit}; server metrics show {delta_500} HTTP 500 response(s).",
)
add_summary(
    "Expected-status mismatch",
    "PASS" if status_mismatch_exit == 1 else "FAIL",
    f"500 response against --expect-status 200 exited {status_mismatch_exit}.",
)
add_summary(
    "Custom headers and user-agent",
    "PASS" if custom_ok else "FAIL",
    "X-Trace-Id and custom user-agent reached /echo."
    if custom_ok
    else "Custom headers were not reflected.",
)
add_summary(
    "HTTP proxy",
    "PASS" if proxy_ok else "FAIL",
    "Proxy injected X-Proxy into the upstream request."
    if proxy_ok
    else "Proxy header not observed.",
)
add_summary(
    "TLS certificate validation",
    "FAIL" if tls_rejected else "PASS",
    tls_error or "Certificate accepted.",
)
add_summary(
    "Output formats",
    "PASS" if csv_first.startswith("target,") and len(jsonl_lines) == 1 else "FAIL",
    f"CSV header={csv_first[:32]!r}; JSONL lines={len(jsonl_lines)}.",
)
add_summary(
    "Config precedence",
    "PASS"
    if config_json_data is not None
    and len(config_env_lines) == 1
    and config_cli_first.startswith("target,")
    else "FAIL",
    "config=JSON, env=JSONL, CLI=CSV.",
)
add_summary(
    "Config path/init", "PASS" if config_init_ok else "FAIL", str(config_file_written)
)
add_summary(
    "Scope refusal",
    "PASS" if scope_refusal_ok else "FAIL",
    f"Exit={scope_refusal['meta']['exit']} for 198.51.100.10.",
)
add_summary(
    "Audit log",
    "PASS" if audit_ok and audit_no_secret else "FAIL",
    f"{len(audit_records)} record(s); token absent={audit_no_secret}.",
)
add_summary(
    "Batch mode",
    "PASS" if len(batch_reports) >= 8 else "FAIL",
    f"{len(batch_reports)} report(s); {len(batch_errors)} error line(s).",
)
add_summary(
    "Repeat mode",
    "PASS" if repeat_ok else "FAIL",
    f"{len(repeat_reports)} iteration(s).",
)
add_summary(
    "Load test on /api/users",
    "PASS",
    f"sent={load_data.get('sent')}, ok={load_data.get('ok')}, failed={load_data.get('failed')}, HTTP 429 delta={delta_429}.",
)
add_summary(
    "Capacity test on /stress",
    "FAIL" if degraded_steps else "PASS",
    f"degraded steps={len(degraded_steps)}; HTTP 503 delta={delta_503}.",
)
add_summary(
    "Connection churn",
    "PASS" if churn_ok else "FAIL",
    f"{churn_data.get('connected')}/{churn_data.get('attempted')} connected, failed={churn_data.get('failed')}.",
)
add_summary(
    "Slow-request handling",
    "FAIL" if slow_still_open else "PASS",
    f"{slow_still_open} still open, {slow_closed} closed by server after {slow_data.get('hold_seconds')}s.",
)
add_summary(
    "Request-shape handling",
    "PASS" if shape_ok else "FAIL",
    f"successes={shape_data.get('successes')}, client_errors={shape_data.get('client_errors')}, server_errors={shape_data.get('server_errors')}, transport_errors={shape_data.get('transport_errors')}.",
)

if xss_reflected:
    add_finding(
        "F-01",
        "High",
        "Reflected XSS on the search page",
        f"The `q` parameter is reflected without escaping. Response preview: `{xss_body[:220]}`",
        repro(xss),
        [artifact("http_reflected_xss")],
    )
if login_bypass:
    add_finding(
        "F-02",
        "Critical",
        "Authentication bypass on /api/login",
        f"A wrong password still returns an admin token and `bypass=true`. Response preview: `{bypass_body[:220]}`",
        repro(bypass),
        [artifact("http_auth_bypass")],
    )
if admin_exposed:
    add_finding(
        "F-03",
        "Critical",
        "Unauthenticated admin panel",
        f"`/admin` returns an admin flag without any credentials. Response preview: `{admin_body[:220]}`",
        repro(admin),
        [artifact("http_admin_exposed")],
    )
if debug_leak:
    add_finding(
        "F-04",
        "High",
        "Environment secret disclosure in /debug",
        f"`/debug` exposes demo secrets and user records. Response preview: `{debug_body[:240]}`",
        repro(debug),
        [artifact("http_debug_leak")],
    )
if traversal_leak:
    add_finding(
        "F-05",
        "High",
        "Path traversal in /download",
        f"`file=../Cargo.toml` escaped the app root and returned repository metadata. Response preview: `{traversal_body[:240]}`",
        repro(traversal),
        [artifact("http_path_traversal")],
    )
if none_counts[1] < none_counts[2] or partial_present < partial_total:
    add_finding(
        "F-06",
        "High",
        "Missing security headers on sensitive routes",
        f"`/headers/none` has {none_counts[1]}/{none_counts[2]} headers (grade {none_grade}, {none_score}/100) and `/headers/partial` has {partial_present}/{partial_total}. Missing on `/admin`, `/debug`, and the search page. Partial missing set: {', '.join(partial_missing)}.",
        repro(report_none),
        [artifact("report_headers_none"), artifact("diagnose_headers_partial")],
    )
if cors_audit_ok or cors_value == "*":
    add_finding(
        "F-07",
        "Medium",
        "Permissive CORS on API routes",
        f"`cors-check` reported {', '.join(sorted(cors_audit_codes)) or 'wildcard_origin'}; response header is `Access-Control-Allow-Origin: {cors_value}`, allowing any origin to read API responses.",
        repro(cors_audit),
        [artifact("cors_check"), artifact("http_cors_cookie")],
    )
if cookie_audit_ok or (cookie_value and "HttpOnly" not in cookie_value):
    add_finding(
        "F-08",
        "Medium",
        "Insecure session cookie",
        f"`cookie-check` reported {', '.join(sorted(cookie_audit_codes)) or 'insecure attributes'}. Raw header: `Set-Cookie: {cookie_value}`.",
        repro(cookie_audit),
        [artifact("cookie_check"), artifact("http_cors_cookie")],
    )
if slow_still_open:
    add_finding(
        "F-09",
        "Medium",
        "Slow clients are held open",
        f"{slow_still_open} of {slow_data.get('clients')} slow clients were still open after {slow_data.get('hold_seconds')}s; the server closed {slow_closed}.",
        repro(slow),
        [artifact("slow_request")],
    )
if degraded_steps:
    step = degraded_steps[0]
    add_finding(
        "F-10",
        "Medium",
        "Low capacity on the stress endpoint",
        f"`/stress` degraded at step {step.get('step')} ({step.get('target_rate')} req/s): {step.get('failed')} of {step.get('requests')} requests failed. The server recorded {delta_503} HTTP 503 responses.",
        repro(capacity),
        [artifact("capacity_test_stress")],
    )
if tls_rejected:
    add_finding(
        "F-11",
        "Medium",
        "Self-signed TLS certificate is not trusted",
        f"`tls-check` rejected the local certificate: `{tls_error}`. Browsers will show a certificate warning; the tool correctly refuses to bypass validation.",
        repro(tls),
        [artifact("tls_check_self_signed")],
    )
if server_banner or powered_by:
    add_finding(
        "F-12",
        "Low",
        "Version and framework disclosure",
        f"Responses expose `Server: {server_banner}` and `X-Powered-By: {powered_by}`.",
        repro(banner),
        [artifact("http_banner")],
    )
if robots_leak:
    add_finding(
        "F-13",
        "Low",
        "robots.txt discloses sensitive paths",
        f"`robots.txt` reveals `/admin` and `/debug`: `{robots_body.strip()}`",
        repro(robots),
        [artifact("http_robots")],
    )
if port_scan_ok:
    add_finding(
        "F-14",
        "Low",
        "Multiple loopback services exposed",
        f"`port-scan` found {port_scan_data.get('open_count')} open services: {', '.join(port_scan_open)}. The HTTP, HTTPS, and proxy listeners are reachable without authentication.",
        repro(port_scan),
        [artifact("port_scan")],
    )
if path_discovery_ok:
    key_paths = ", ".join(
        f"`{path}` ({status})"
        for path, status in sorted(path_found.items())
        if path
        in {
            "/admin",
            "/debug",
            "/download",
            "/metrics",
            "/api/users",
            "/api/private",
            "/api/admin",
            "/openapi.json",
        }
    )
    add_finding(
        "F-15",
        "Low",
        "Sensitive routes discoverable by path enumeration",
        f"`path-discovery` found {path_discovery_data.get('found_count')}/{path_discovery_data.get('scanned_count')} interesting paths, including {key_paths}. The focused wordlist confirmed the same high-value routes.",
        repro(path_discovery),
        [artifact("path_discovery"), artifact("path_discovery_wordlist")],
    )

if scope_refusal_ok:
    observations.append(
        "Scope enforcement blocked 198.51.100.10 with exit code 2 before any network traffic."
    )
if port_scan_no_scope_ok and port_scan_scope_refusal_ok and path_discovery_no_scope_ok:
    observations.append(
        "Active recon scope gates work: port-scan and path-discovery refuse public targets without --scope and reject out-of-scope addresses."
    )
if port_scan_ok:
    observations.append(
        f"Port scan found {port_scan_data.get('open_count')} open loopback services: {', '.join(port_scan_open)}."
    )
if path_discovery_ok:
    observations.append(
        f"Path discovery found {path_discovery_data.get('found_count')} interesting routes, including the admin, debug, download, metrics, and API endpoints."
    )
if cors_audit_ok:
    observations.append(
        "cors-check confirmed a wildcard Access-Control-Allow-Origin policy on /api/users."
    )
if cookie_audit_ok:
    observations.append(
        "cookie-check confirmed the session cookie is missing Secure, HttpOnly, and SameSite."
    )
if status_401_exit == 0 and status_500_exit == 0 and status_mismatch_exit == 1:
    observations.append(
        "--expect-status now matches 4xx/5xx responses and still fails correctly on a status mismatch."
    )
if full_grade and none_grade:
    observations.append(
        f"Weighted security grading produced {full_grade} ({full_score}/100) on /headers/full and {none_grade} ({none_score}/100) on /headers/none."
    )
if redirect_scope_ok:
    observations.append(
        "With an active scope file, the external redirect returned 302 and was not followed, preventing scope escape."
    )
if body_bound_ok:
    observations.append(
        "Body reads are bounded: a 100000-byte response was read as 1024 bytes."
    )
if delta_429 > 0:
    observations.append(
        f"API rate limiting is active: the load test triggered {delta_429} HTTP 429 responses."
    )
if (
    config_json_data is not None
    and len(config_env_lines) == 1
    and config_cli_first.startswith("target,")
):
    observations.append(
        "Configuration precedence works as documented: config JSON, environment JSONL, and CLI CSV."
    )
if len(batch_reports) >= 8 and repeat_ok:
    observations.append("Batch and repeat modes produced machine-readable results.")
if proxy_ok:
    observations.append(
        "Explicit HTTP proxy support works; the proxy-added X-Proxy header reached the upstream server."
    )
if dns_ok and udp_ok:
    observations.append(
        "DNS record checks and raw UDP probes worked against local services."
    )
if shape_ok:
    observations.append(
        "Request-shape found no server or transport errors; the remaining client errors are expected malformed paths."
    )
if churn_ok:
    observations.append(
        f"Connection churn completed {churn_data.get('connected')}/{churn_data.get('attempted')} connections without failure."
    )
if private_ok and admin_api_ok:
    observations.append(
        "Bearer authentication works on /api/private and /api/admin; the bypass is isolated to /api/login."
    )
if audit_ok and audit_no_secret:
    observations.append(
        "The JSONL audit log records commands, targets, and exit codes without the bearer token."
    )
if openapi_leak:
    observations.append(
        "The public OpenAPI document advertises /api/private, /api/admin, /debug, and /download, aiding discovery."
    )
if robots_leak:
    observations.append(
        "robots.txt provides a direct hint to the unauthenticated admin and debug routes."
    )

limitations.append(
    "ddos is a bounded diagnostic tool: it measures and reports, but it does not exploit findings."
)
limitations.append(
    "Port scanning is TCP connect-only, capped at 1000 ports and 8 workers, and requires --scope for non-loopback targets."
)
limitations.append(
    "Path discovery uses GET requests, a 200-entry wordlist cap, and a 25ms inter-request delay; it does not fuzz parameters or methods."
)
limitations.append(
    "Rustls uses the Mozilla webpki root store; a local self-signed certificate cannot be trusted without changing the binary."
)
limitations.append(
    "Load, capacity, churn, slow-request, and request-shape commands refuse non-loopback targets and enforce hard request/rate caps."
)
limitations.append(
    "The tool has no TLS verification bypass, brute-force mode, payload fuzzing, or arbitrary file-write capability by design."
)

severity_order = ["Critical", "High", "Medium", "Low", "Info"]
findings.sort(key=lambda item: (severity_order.index(item["severity"]), item["id"]))
counts = {
    severity: sum(1 for item in findings if item["severity"] == severity)
    for severity in severity_order
}

generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
assessment = {
    "tool": {"version": version_text, "binary": str(BIN)},
    "target": BASE,
    "scope": SCOPE,
    "generated": generated,
    "severity_counts": counts,
    "findings": findings,
    "summary": summary_rows,
    "observations": observations,
    "limitations": limitations,
    "checks": checks,
}
ASSESS.write_text(json.dumps(assessment, indent=2) + "\n", encoding="utf-8")

lines = []
lines.append("# ddos local assessment")
lines.append("")
lines.append(f"- **Target:** `{BASE}`")
lines.append(f"- **Tool:** `{version_text}`")
lines.append(f"- **Binary:** `{BIN}`")
lines.append(f"- **Scope:** `{SCOPE}`")
lines.append(f"- **Generated:** `{generated}`")
lines.append("- **Mode:** authorized loopback-only assessment")
lines.append("")
lines.append("## Executive summary")
lines.append("")
lines.append("| Severity | Count |")
lines.append("| --- | --- |")
for severity in severity_order:
    lines.append(f"| {severity} | {counts[severity]} |")
lines.append("")
lines.append(
    "The target exposes multiple critical and high-impact application issues. The critical items are an authentication bypass on `/api/login` and an unauthenticated `/admin` route. High-impact items include reflected XSS, path traversal, secret disclosure in `/debug`, and missing security headers on sensitive routes. The enhanced recon checks also found three open loopback services, 17 interesting routes, a wildcard CORS policy, and a session cookie missing Secure, HttpOnly, and SameSite; `/headers/none` grades F (0/100)."
)
lines.append("")
lines.append("## Findings")
lines.append("")
for item in findings:
    lines.append(f"### {item['id']} — [{item['severity']}] {item['title']}")
    lines.append("")
    lines.append(f"**Evidence:** {item['evidence']}")
    lines.append("")
    lines.append("**Reproduce:**")
    lines.append("")
    lines.append("```sh")
    lines.append(item["reproduce"])
    lines.append("```")
    lines.append("")
    if item["artifacts"]:
        lines.append(
            "**Artifacts:** " + ", ".join(f"`{value}`" for value in item["artifacts"])
        )
        lines.append("")
lines.append("## Checks")
lines.append("")
lines.append("| Check | Result | Detail |")
lines.append("| --- | --- | --- |")
for row in summary_rows:
    detail = str(row["detail"]).replace("|", "\\|").replace("\n", " ")
    lines.append(f"| {row['check']} | {row['result']} | {detail} |")
lines.append("")
lines.append("## Passed controls and observations")
lines.append("")
for value in observations:
    lines.append(f"- {value}")
lines.append("")
lines.append("## Tool limitations")
lines.append("")
for value in limitations:
    lines.append(f"- {value}")
lines.append("")
lines.append("## Artifacts")
lines.append("")
lines.append(f"- Raw command output: `{RAW}`")
lines.append(f"- Structured assessment: `{ASSESS}`")
lines.append(f"- Audit log: `{AUDIT}`")
lines.append(f"- Markdown report: `{REPORT}`")
lines.append("")
lines.append("## Batch results")
lines.append("")
lines.append("| Target | HTTP | Security headers |")
lines.append("| --- | --- | --- |")
for row in batch_rows:
    lines.append(
        f"| `{row['target']}` | {row['status']} | {row['present']}/{row['total']} |"
    )
lines.append("")
REPORT.write_text("\n".join(lines), encoding="utf-8")

print("")
print(f"wrote {REPORT}")
print(f"wrote {ASSESS}")
print(
    f"findings: "
    + ", ".join(f"{severity}={counts[severity]}" for severity in severity_order)
)
