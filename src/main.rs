use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;
use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const USER_AGENT: &str = concat!("ddos/", env!("CARGO_PKG_VERSION"));
const DEFAULT_TIMEOUT: u64 = 5;
const MAX_TIMEOUT: u64 = 120;
const MAX_RETRIES: u32 = 5;
const MAX_BATCH: usize = 100;
const MAX_CONCURRENCY: usize = 8;
const MAX_REPEAT_SECONDS: u64 = 3600;
const MAX_REDIRECTS: u32 = 10;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_LOAD_RATE: u64 = 50;
const MAX_LOAD_COUNT: u64 = 5000;
const DEFAULT_LOAD_RATE: u64 = 10;
const DEFAULT_LOAD_COUNT: u64 = 20;
const MAX_CAPACITY_STEPS: u64 = 10;
const MAX_CAPACITY_REQUESTS: u64 = 2000;
const MAX_CHURN_CONNECTIONS: u64 = 1000;
const MAX_SLOW_CLIENTS: u64 = 8;
const MAX_SLOW_HOLD_SECONDS: u64 = 10;
const MAX_SHAPE_REQUESTS: u64 = 500;
const DEGRADED_ERROR_PERCENT: u64 = 20;
const DEGRADED_LATENCY_MS: u128 = 1000;
const MAX_HEADERS: usize = 20;
const MAX_HEADER_NAME: usize = 64;
const MAX_HEADER_VALUE: usize = 2048;
const MAX_AUTH_VALUE: usize = 1024;
const MAX_PORT_SCAN_PORTS: usize = 1000;
const MAX_PORT_SCAN_ADDRESSES: usize = 4;
const MAX_PORT_SCAN_TIMEOUT_SECONDS: u64 = 3;
const MAX_PATH_DISCOVERY_PATHS: usize = 200;
const PATH_DISCOVERY_DELAY_MS: u64 = 25;
const DEFAULT_CORS_ORIGIN: &str = "https://evil.example";
const DEFAULT_SCAN_PORTS: &str = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1080,1433,1521,1723,2049,2375,2376,3000,3030,3043,3053,3306,3389,5000,5432,5900,6379,8000,8008,8080,8081,8443,8888,9000,9090,9200,9300,10000,11211,27017";
const DEFAULT_DISCOVERY_PATHS: [&str; 69] = [
    "/",
    "/admin",
    "/admin/login",
    "/login",
    "/dashboard",
    "/debug",
    "/metrics",
    "/health",
    "/healthz",
    "/status",
    "/ping",
    "/version",
    "/info",
    "/config",
    "/settings",
    "/system",
    "/internal",
    "/private",
    "/secret",
    "/token",
    "/tokens",
    "/api",
    "/api/v1",
    "/api/docs",
    "/api/users",
    "/api/private",
    "/api/admin",
    "/api/login",
    "/graphql",
    "/graphiql",
    "/swagger",
    "/swagger-ui",
    "/openapi.json",
    "/docs",
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/config",
    "/.well-known/security.txt",
    "/server-status",
    "/actuator",
    "/actuator/health",
    "/console",
    "/phpmyadmin",
    "/wp-admin",
    "/backup",
    "/backup.zip",
    "/download",
    "/export",
    "/files",
    "/uploads",
    "/static",
    "/assets",
    "/users",
    "/user",
    "/account",
    "/accounts",
    "/orders",
    "/profile",
    "/session",
    "/sessions",
    "/cookies",
    "/set-cookie",
    "/cors",
    "/headers",
    "/headers/none",
    "/redirect",
    "/stress",
    "/slow",
];
const MAX_UDP_PAYLOAD: usize = 1400;
const UDP_PREVIEW_BYTES: usize = 256;
const MAX_DNS_LABEL: usize = 63;
const MAX_DNS_HOST: usize = 255;
const CONFIG_DIR_NAME: &str = "ddos";
const CONFIG_FILE_NAME: &str = "config.toml";
const INSTALL_SH: &str = "https://raw.githubusercontent.com/rkriad585/ddos/main/installer.sh";
const INSTALL_PS1: &str = "https://raw.githubusercontent.com/rkriad585/ddos/main/installer.ps1";
const COMPLETION_BASH: &str = include_str!("../completions/ddos.bash");
const COMPLETION_ZSH: &str = include_str!("../completions/ddos.zsh");
const COMPLETION_FISH: &str = include_str!("../completions/ddos.fish");
const COMPLETION_POWERSHELL: &str = include_str!("../completions/ddos.ps1");
const COMPLETION_NUSHELL: &str = include_str!("../completions/ddos.nu");

#[derive(Clone, Copy, PartialEq, Debug)]
enum Output {
    Text,
    Json,
    Jsonl,
    Csv,
}

impl Output {
    fn parse(value: &str) -> Result<Output, String> {
        match value {
            "text" => Ok(Output::Text),
            "json" => Ok(Output::Json),
            "jsonl" => Ok(Output::Jsonl),
            "csv" => Ok(Output::Csv),
            other => Err(format!(
                "unsupported output format: {other} (use text, json, jsonl, or csv)"
            )),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Family {
    Any,
    Ipv4,
    Ipv6,
}

impl Family {
    fn parse(value: &str) -> Result<Family, String> {
        match value {
            "any" => Ok(Family::Any),
            "ipv4" => Ok(Family::Ipv4),
            "ipv6" => Ok(Family::Ipv6),
            other => Err(format!("unsupported address family: {other}")),
        }
    }
    fn matches(self, address: &SocketAddr) -> bool {
        match self {
            Family::Any => true,
            Family::Ipv4 => address.is_ipv4(),
            Family::Ipv6 => address.is_ipv6(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum DnsType {
    A,
    Aaaa,
    Cname,
    Txt,
    Mx,
    Ns,
}

impl DnsType {
    fn parse(value: &str) -> Result<DnsType, String> {
        match value.to_ascii_uppercase().as_str() {
            "A" => Ok(DnsType::A),
            "AAAA" => Ok(DnsType::Aaaa),
            "CNAME" => Ok(DnsType::Cname),
            "TXT" => Ok(DnsType::Txt),
            "MX" => Ok(DnsType::Mx),
            "NS" => Ok(DnsType::Ns),
            _ => Err("unsupported DNS record type: use A, AAAA, CNAME, TXT, MX, or NS".into()),
        }
    }
    fn from_code(code: u16) -> Option<DnsType> {
        match code {
            1 => Some(DnsType::A),
            28 => Some(DnsType::Aaaa),
            5 => Some(DnsType::Cname),
            16 => Some(DnsType::Txt),
            15 => Some(DnsType::Mx),
            2 => Some(DnsType::Ns),
            _ => None,
        }
    }
    fn code(self) -> u16 {
        match self {
            DnsType::A => 1,
            DnsType::Aaaa => 28,
            DnsType::Cname => 5,
            DnsType::Txt => 16,
            DnsType::Mx => 15,
            DnsType::Ns => 2,
        }
    }
    fn name(self) -> &'static str {
        match self {
            DnsType::A => "A",
            DnsType::Aaaa => "AAAA",
            DnsType::Cname => "CNAME",
            DnsType::Txt => "TXT",
            DnsType::Mx => "MX",
            DnsType::Ns => "NS",
        }
    }
}

#[derive(Clone)]
struct Auth {
    scheme: String,
    credential: String,
}

/// Standard base64 (RFC 4648, with padding) used for Basic auth.
fn b64encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

impl Auth {
    fn header_value(&self) -> Result<String, String> {
        match self.scheme.as_str() {
            "basic" => {
                let (user, secret) = self
                    .credential
                    .split_once(':')
                    .ok_or("basic auth requires \"user:pass\"")?;
                Ok(format!(
                    "Basic {}",
                    b64encode(format!("{user}:{secret}").as_bytes())
                ))
            }
            "bearer" => Ok(format!("Bearer {}", self.credential)),
            other => Err(format!("unsupported auth scheme: {other}")),
        }
    }
}

#[derive(Clone)]
struct Options {
    timeout: Duration,
    retries: u32,
    output: Output,
    verbose: bool,
    quiet: bool,
    path: String,
    method: String,
    expect_status: Option<u16>,
    show_headers: Vec<String>,
    redirects: u32,
    proxy: Option<String>,
    headers: Vec<(String, String)>,
    auth: Option<Auth>,
    user_agent: Option<String>,
    body_bytes: u64,
    family: Family,
    payload: Option<Vec<u8>>,
    dns_type: Option<DnsType>,
    dns_server: Option<IpAddr>,
    rate: u32,
    count: u32,
    steps: u32,
    clients: u32,
    hold_seconds: u64,
    rotate_user_agent: bool,
    random_user_agent: bool,
    audit_headers: bool,
    concurrency: u32,
    ports: Option<String>,
    wordlist: Option<PathBuf>,
    origin: Option<String>,
    skip_certificate: bool,
    show_all_headers: bool,
    scope: Option<Scope>,
    scope_path: Option<PathBuf>,
}

#[derive(Clone)]
struct Scope {
    source: PathBuf,
    hosts: Vec<String>,
    networks: Vec<(IpAddr, u8)>,
    addresses: Vec<IpAddr>,
}

#[derive(Serialize, Clone)]
struct HeaderCheck {
    name: String,
    present: bool,
    value: Option<String>,
}

#[derive(Serialize, Clone)]
struct AddressResult {
    address: String,
    family: String,
    connected: bool,
    elapsed_ms: u128,
    error: Option<String>,
}
#[derive(Serialize, Clone)]
struct HttpResult {
    url: String,
    status: Option<u16>,
    status_text: Option<String>,
    elapsed_ms: u128,
    error: Option<String>,
    headers: Vec<(String, String)>,
    status_ok: bool,
    body_size: Option<u64>,
    body_read_error: Option<String>,
    body_preview: Option<String>,
    certificate: Option<CertificateSummary>,
    certificate_error: Option<String>,
    security_headers: Option<Vec<HeaderCheck>>,
    security_score: Option<u8>,
    security_grade: Option<String>,
}
#[derive(Serialize, Clone)]
struct CertificateSummary {
    subject: String,
    issuer: String,
    serial: String,
    sans: Vec<String>,
    not_before: String,
    not_after: String,
    expired: bool,
    protocol: Option<String>,
    cipher_suite: Option<String>,
}
#[derive(Serialize, Clone)]
struct DiagnosticReport {
    schema_version: u8,
    version: String,
    target: String,
    host: String,
    port: u16,
    resolved: Vec<AddressResult>,
    http: Option<HttpResult>,
    ok: bool,
    total_elapsed_ms: u128,
    error: Option<String>,
}
#[derive(Serialize)]
struct ResolveReport {
    schema_version: u8,
    version: String,
    host: String,
    addresses: Vec<String>,
}

#[derive(Serialize, Clone)]
struct UdpAttempt {
    address: String,
    family: String,
    sent: bool,
    received: bool,
    elapsed_ms: u128,
    response_bytes: Option<u64>,
    response_preview: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct UdpReport {
    schema_version: u8,
    version: String,
    target: String,
    host: String,
    port: u16,
    attempts: Vec<UdpAttempt>,
    ok: bool,
    total_elapsed_ms: u128,
    error: Option<String>,
}

#[derive(Serialize, Clone)]
struct DnsAnswer {
    name: String,
    record_type: String,
    ttl_seconds: Option<u32>,
    data: String,
}

#[derive(Serialize)]
struct DnsReport {
    schema_version: u8,
    version: String,
    host: String,
    dns_type: String,
    dns_server: String,
    answers: Vec<DnsAnswer>,
    ok: bool,
    total_elapsed_ms: u128,
    error: Option<String>,
}

#[derive(Serialize)]
struct TlsReport {
    schema_version: u8,
    version: String,
    host: String,
    port: u16,
    certificate: Option<CertificateSummary>,
    ok: bool,
    total_elapsed_ms: u128,
    error: Option<String>,
}

#[derive(Serialize)]
struct UserAgentsReport {
    schema_version: u8,
    version: String,
    user_agents: Vec<String>,
}

fn usage() {
    let text = format!(
        "ddos {VERSION} — bounded network diagnostics

Usage:
  ddos resolve <host> [options]
  ddos tcp-check <host> <port> [--timeout <seconds>] [--retry <count>] [options]
  ddos http-check <host> [port] [--path /path] [--method HEAD|GET] [options]
  ddos diagnose <url|host:port> [--method HEAD|GET] [--expect-status <code>] [options]
  ddos report <url|host:port> [options]
  ddos udp-check <host> <port> [--payload <hex>] [--retry <count>] [options]
  ddos dns-check <host> [--dns-type <type>] [--dns-server <ip>] [options]
  ddos tls-check <host> [port] [options]
  ddos user-agents [--output text|json|jsonl|csv]
  ddos batch <file|-> [--timeout <seconds>] [--retry <count>] [options]
  ddos repeat <url|host:port> --interval <seconds> --duration <seconds> [options]
  ddos load-test <url|host:port> [--rate <req/s>] [--count <requests>] [options]
  ddos capacity-test <url|host:port> [--rate <req/s>] [--steps <n>] [--count <requests>] [options]
  ddos connection-churn <host> <port> [--count <connections>] [--rate <conn/s>] [options]
  ddos slow-request <host> <port> [--clients <n>] [--hold <seconds>] [options]
  ddos request-shape <url|host:port> [--count <requests>] [options]
  ddos port-scan <host> [--ports <spec>] [--concurrency <n>] [options]
  ddos path-discovery <url|host:port> [--wordlist <file>] [options]
  ddos cors-check <url|host:port> [--origin <origin>] [options]
  ddos cookie-check <url|host:port> [options]
  ddos method-check <url|host:port> [options]
  ddos completion <bash|zsh|fish|powershell|nushell>
  ddos config <path|init>
  ddos self-update
  ddos self-uninstall
  ddos --version
  ddos --help

Common options:
  --timeout 1-120               per-attempt socket timeout in seconds
  --retry 0-5                   bounded retries with exponential backoff
  --output text|json|jsonl|csv  machine-readable output modes
  --family any|ipv4|ipv6        only resolve the selected address family
  --quiet                       suppress human-readable text output
  --no-color                    accepted for compatibility; output is plain text
  --scope <file>                only allow targets listed in an authorization scope file
  --audit-log <path>            append one JSONL audit record per run
  --concurrency 1-8             worker count for port-scan (default 8)
  --ports <spec>                ports for port-scan: 80,443,8000-8100 (max 1000)
  --wordlist <file>             custom paths for path-discovery (max 200)
  --origin <origin>             Origin header for cors-check (default https://evil.example)
  --config <path>               use this config file (key = value lines)
  --no-config                   skip the default config file for this run

HTTP options:
  --method HEAD|GET             request method (default HEAD)
  --path /path                  request path for http-check (max 2048 bytes)
  --header \"Name: value\"        send a custom request header; repeatable, max {MAX_HEADERS}
  --auth basic <user:pass>      Basic Authorization header
  --auth bearer <token>         Bearer Authorization header
  --user-agent <string>         override the default user agent
  --body-bytes <count>          with GET, read up to N body bytes (max {MAX_BODY_BYTES})
  --expect-status <code>        require this exact HTTP status for success
  --show-header <name>          print this response header; repeatable
  --audit-headers               report common HTTP security headers
  --redirects 0-10              redirect limit (default 5)
  --proxy <url>                 HTTP/HTTPS proxy for the request

UDP/DNS options:
  --payload <hex>               bytes to send with udp-check (max {MAX_UDP_PAYLOAD} bytes)
  --dns-type A|AAAA|CNAME|TXT|MX|NS   record type for dns-check (default A)
  --dns-server <ip>             resolver for dns-check (defaults to the system resolver on Unix)

TLS check:
  ddos tls-check <host> [port]  validated certificate metadata (default port 443)
  ddos user-agents              list the built-in realistic browser user agents

Reporting:
  ddos report <url|host:port>   Markdown assessment report with HTTP security headers

Load-test options:
  --rate 1-{MAX_LOAD_RATE}                requests per second (sequential pacing, no concurrency)
  --count 1-{MAX_LOAD_COUNT}              total requests within budget
  --rotate-user-agent           cycle through realistic browser user agents per request
  --random-user-agent           pick a realistic browser user agent per request

Recon and web security checks (bounded; non-loopback requires --scope):
  ddos port-scan <host>         bounded TCP port scan; --ports accepts CSV and ranges
  ddos path-discovery <url>     built-in or custom path wordlist; reports interesting statuses
  ddos cors-check <url>         test wildcard/reflected CORS and credential combinations
  ddos cookie-check <url>       audit Set-Cookie Secure, HttpOnly, SameSite, and prefixes
  ddos method-check <url>       audit OPTIONS/HEAD/TRACE behavior and advertised methods
  Limits: port-scan {MAX_PORT_SCAN_PORTS} ports x {MAX_PORT_SCAN_ADDRESSES} addresses,
  path-discovery {MAX_PATH_DISCOVERY_PATHS} paths, 25 ms between requests.

Capacity and resilience tests (loopback only):
  ddos capacity-test <url>       ramp the rate in steps and report where the target degrades
  ddos connection-churn <host> <port>  open and close connections to probe backlog limits
  ddos slow-request <host> <port>     hold slow requests open to measure server timeouts
  ddos request-shape <url>       send odd methods, paths, headers, and bodies
  --steps 1-{MAX_CAPACITY_STEPS}       ramp steps for capacity-test
  --clients 1-{MAX_SLOW_CLIENTS}       slow clients for slow-request
  --hold 1-{MAX_SLOW_HOLD_SECONDS}     seconds to hold slow requests open
  Budgets: capacity-test {MAX_CAPACITY_REQUESTS} requests, connection-churn {MAX_CHURN_CONNECTIONS} connections,
  request-shape {MAX_SHAPE_REQUESTS} requests; all four refuse non-loopback targets.

Exit codes: 0 success, 1 diagnostic failure, 2 invalid usage.
Limits: batch 100 targets, concurrency 8, repeat 1 hour, load-test {MAX_LOAD_RATE} req/s x {MAX_LOAD_COUNT} requests, body read {MAX_BODY_BYTES} bytes.
load-test hard restrictions: loopback targets only (localhost, 127.0.0.1, ::1); other hosts are refused.
Config file: $XDG_CONFIG_HOME/ddos/config.toml (or ~/.config/ddos/config.toml),
%APPDATA%\\ddos\\config.toml on Windows. Precedence: CLI args > DDOS_* env vars > config file.
Env vars: DDOS_TIMEOUT, DDOS_RETRIES, DDOS_OUTPUT, DDOS_PATH, DDOS_METHOD,
DDOS_FAMILY, DDOS_EXPECT_STATUS, DDOS_REDIRECTS, DDOS_PROXY, DDOS_USER_AGENT,
DDOS_SHOW_HEADER (comma separated), DDOS_HEADER (semicolon separated \"Name: value\" items),
DDOS_AUTH (\"basic:USER:PASS\" or \"bearer:TOKEN\"), DDOS_BODY_BYTES,
DDOS_DNS_TYPE, DDOS_DNS_SERVER, DDOS_PAYLOAD, DDOS_VERBOSE, DDOS_QUIET,
DDOS_SCOPE, DDOS_AUDIT_HEADERS, DDOS_AUDIT_LOG,
DDOS_RATE, DDOS_COUNT, DDOS_ROTATE_USER_AGENT (true/false),
DDOS_RANDOM_USER_AGENT (true/false), DDOS_STEPS, DDOS_CLIENTS, DDOS_HOLD,
DDOS_CONCURRENCY, DDOS_PORTS, DDOS_WORDLIST, DDOS_ORIGIN.

Scope file: one host, *.domain, IP address, or CIDR range per line; # starts a comment.
When a scope file is active, HTTP redirects are not followed.
Audit log: JSONL with timestamp, command, target, status, and exit code (never credentials).

Only use this tool against systems you own or are authorized to test."
    );
    println!("{text}");
}

fn number(value: Option<&String>, name: &str, min: u64, max: u64) -> Result<u64, String> {
    let value = value.ok_or_else(|| format!("{name} requires a value"))?;
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an integer"))?;
    if value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(value)
}

/// Validate a numeric value that came from a config file or env var.
fn bare_number(name: &str, value: &str, min: u64, max: u64) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an integer"))?;
    if parsed < min || parsed > max {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(parsed)
}

fn validate_header_pair(name: &str, value: &str) -> Result<(String, String), String> {
    let name = name.trim().to_ascii_lowercase();
    let value = value.trim();
    if name.is_empty()
        || name.len() > MAX_HEADER_NAME
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err("header name must be 1-64 ASCII letters, digits, or '-'".into());
    }
    if value.is_empty() || value.len() > MAX_HEADER_VALUE || value.chars().any(|c| c.is_control()) {
        return Err(format!(
            "header value for {name} must be 1-{MAX_HEADER_VALUE} bytes with no control characters"
        ));
    }
    Ok((name, value.to_string()))
}

/// Validate `Name: value` as a custom request header.
fn parse_header(value: &str) -> Result<(String, String), String> {
    let (name, header_value) = value
        .split_once(':')
        .ok_or("--header requires \"Name: value\"")?;
    let pair = validate_header_pair(name, header_value)?;
    match pair.0.as_str() {
        "host" | "connection" | "content-length" | "transfer-encoding" | "expect" => Err(format!(
            "--header cannot override {name}: it is managed by the transport"
        )),
        "authorization" => Err("use --auth instead of a custom Authorization header".into()),
        _ => Ok(pair),
    }
}

/// Validate a scheme/credential pair for `--auth`.
fn parse_auth(scheme: &str, credential: &str) -> Result<Auth, String> {
    let scheme = scheme.to_ascii_lowercase();
    if credential.is_empty()
        || credential.len() > MAX_AUTH_VALUE
        || credential.chars().any(|c| c.is_control())
    {
        return Err("auth credential must be 1-1024 characters with no control characters".into());
    }
    match scheme.as_str() {
        "basic" => {
            if credential.split(':').count() != 2 {
                return Err("basic auth requires \"user:pass\"".into());
            }
            Ok(Auth {
                scheme,
                credential: credential.to_string(),
            })
        }
        "bearer" => Ok(Auth {
            scheme,
            credential: credential.to_string(),
        }),
        other => Err(format!("unsupported auth scheme: {other}")),
    }
}

/// Decode a hex string into bytes (used for `--payload`).
fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("payload must contain an even number of hex digits".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| "payload must be hex digits (0-9, a-f, A-F)".to_string())
        })
        .collect()
}

/// Validate a proxy URL once up front.
fn validate_proxy(url: &str) -> Result<(), String> {
    ureq::Proxy::new(url)
        .map(|_| ())
        .map_err(|_| "--proxy must be an http:// or https:// URL".to_string())
}

fn validate_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.contains(['\r', '\n']) || path.len() > 2048 {
        return Err(
            "path must start with '/', contain no newlines, and be at most 2048 bytes".into(),
        );
    }
    Ok(())
}

fn validate_user_agent(agent: &str) -> Result<(), String> {
    if agent.is_empty() || agent.len() > MAX_HEADER_VALUE || agent.chars().any(|c| c.is_control()) {
        return Err(format!(
            "user agent must be 1-{MAX_HEADER_VALUE} printable bytes"
        ));
    }
    Ok(())
}

fn validate_show_header(name: &str) -> Result<String, String> {
    let name = name.to_ascii_lowercase();
    if name.is_empty() || name.contains(':') || name.contains(['\r', '\n']) {
        return Err("--show-header must be a valid header name".into());
    }
    Ok(name)
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("invalid port: {value}"))?;
    if port == 0 {
        return Err("port must be 1-65535".into());
    }
    Ok(port)
}

/// Parse a port spec such as `80,443,8000-8100` into a sorted, deduplicated list.
fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("ports must not be empty".into());
    }
    let mut ports = Vec::new();
    for item in spec.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err("ports contains an empty item".into());
        }
        if let Some((start, end)) = item.split_once('-') {
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                return Err(format!("port range start must be <= end: {item}"));
            }
            let count = usize::from(end) - usize::from(start) + 1;
            if ports.len() + count > MAX_PORT_SCAN_PORTS {
                return Err(format!(
                    "port scan is limited to {MAX_PORT_SCAN_PORTS} ports"
                ));
            }
            ports.extend(start..=end);
        } else {
            ports.push(parse_port(item)?);
            if ports.len() > MAX_PORT_SCAN_PORTS {
                return Err(format!(
                    "port scan is limited to {MAX_PORT_SCAN_PORTS} ports"
                ));
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err("ports must contain at least one port".into());
    }
    Ok(ports)
}

fn validate_origin(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value == "null" {
        return Ok(());
    }
    if value.is_empty()
        || value.len() > MAX_HEADER_VALUE
        || value.chars().any(|c| c.is_control())
        || !(value.starts_with("http://") || value.starts_with("https://"))
    {
        return Err("origin must be http://..., https://..., or null".into());
    }
    Ok(())
}

fn validate_dns_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > MAX_DNS_HOST {
        return Err(format!("host must be 1-{MAX_DNS_HOST} bytes"));
    }
    if host.contains(['/', '\\', '\r', '\n', ' ']) {
        return Err("host contains characters that are not allowed".into());
    }
    for label in host.trim_matches('.').split('.') {
        if label.is_empty() {
            return Err("host contains an empty label".into());
        }
        if label.len() > MAX_DNS_LABEL {
            return Err(format!("host labels must be at most {MAX_DNS_LABEL} bytes"));
        }
    }
    Ok(())
}

fn csv_escape(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    if escaped.contains(',') || escaped.contains('"') || escaped.contains('\n') {
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

enum ScopeEntry {
    Host(String),
    Address(IpAddr),
    Network(IpAddr, u8),
}

impl Scope {
    fn load(path: &Path) -> Result<Scope, String> {
        let source = fs::read_to_string(path)
            .map_err(|error| format!("could not read scope {}: {error}", path.display()))?;
        let mut scope = Scope {
            source: path.to_path_buf(),
            hosts: Vec::new(),
            networks: Vec::new(),
            addresses: Vec::new(),
        };
        for (index, raw) in source.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let entry = parse_scope_entry(line)
                .map_err(|error| format!("{}: line {}: {error}", path.display(), index + 1))?;
            match entry {
                ScopeEntry::Host(host) => scope.hosts.push(host),
                ScopeEntry::Address(address) => scope.addresses.push(address),
                ScopeEntry::Network(network, prefix) => scope.networks.push((network, prefix)),
            }
        }
        if scope.hosts.is_empty() && scope.networks.is_empty() && scope.addresses.is_empty() {
            return Err(format!("scope file has no entries: {}", path.display()));
        }
        Ok(scope)
    }

    fn allows_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.hosts
            .iter()
            .any(|pattern| match pattern.strip_prefix("*.") {
                Some(suffix) => host.ends_with(&format!(".{suffix}")),
                None => host == *pattern,
            })
    }

    fn allows_ip(&self, address: IpAddr) -> bool {
        self.addresses.contains(&address)
            || self
                .networks
                .iter()
                .any(|(network, prefix)| ip_in_cidr(address, *network, *prefix))
    }

    fn allows(&self, host: &str, addresses: &[SocketAddr]) -> bool {
        self.allows_host(host) || addresses.iter().any(|value| self.allows_ip(value.ip()))
    }
}

fn parse_scope_entry(value: &str) -> Result<ScopeEntry, String> {
    if let Some((address, prefix)) = value.split_once('/') {
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid CIDR address: {value}"))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| format!("invalid CIDR prefix: {value}"))?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("CIDR prefix must be 0-{max}: {value}"));
        }
        return Ok(ScopeEntry::Network(address, prefix));
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(ScopeEntry::Address(address));
    }
    let host = value.trim_end_matches('.').to_ascii_lowercase();
    let host = if let Some(suffix) = host.strip_prefix("*.") {
        validate_scope_hostname(suffix)?;
        format!("*.{suffix}")
    } else if let Some(suffix) = host.strip_prefix('.') {
        validate_scope_hostname(suffix)?;
        format!("*.{suffix}")
    } else {
        validate_scope_hostname(&host)?;
        host
    };
    Ok(ScopeEntry::Host(host))
}

fn validate_scope_hostname(host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > MAX_DNS_HOST {
        return Err(format!("scope host must be 1-{MAX_DNS_HOST} bytes"));
    }
    if host.contains(['/', '\\', '\r', '\n', ' ', '*', ':']) {
        return Err(format!("scope host contains invalid characters: {host}"));
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > MAX_DNS_LABEL {
            return Err(format!("scope host has an invalid label: {host}"));
        }
    }
    Ok(())
}

fn ip_in_cidr(address: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(address) & mask) == (u32::from(network) & mask)
        }
        (IpAddr::V6(address), IpAddr::V6(network)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(address) & mask) == (u128::from(network) & mask)
        }
        _ => false,
    }
}

fn scope_error(host: &str, scope: &Scope) -> String {
    format!(
        "target {host} is outside the authorized scope in {}",
        scope.source.display()
    )
}

fn scope_precheck_host(host: &str, opts: &Options) -> Result<(), String> {
    let Some(scope) = &opts.scope else {
        return Ok(());
    };
    if scope.allows_host(host) {
        return Ok(());
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return if scope.allows_ip(address) {
            Ok(())
        } else {
            Err(scope_error(host, scope))
        };
    }
    if scope.networks.is_empty() && scope.addresses.is_empty() {
        return Err(scope_error(host, scope));
    }
    Ok(())
}

fn scope_allows(host: &str, addresses: &[SocketAddr], opts: &Options) -> Result<(), String> {
    let Some(scope) = &opts.scope else {
        return Ok(());
    };
    if scope.allows(host, addresses) {
        Ok(())
    } else {
        Err(scope_error(host, scope))
    }
}

fn ensure_scope_host(host: &str, opts: &Options) -> Result<(), String> {
    let Some(scope) = &opts.scope else {
        return Ok(());
    };
    if scope.allows_host(host) {
        return Ok(());
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return if scope.allows_ip(address) {
            Ok(())
        } else {
            Err(scope_error(host, scope))
        };
    }
    if scope.networks.is_empty() && scope.addresses.is_empty() {
        return Err(scope_error(host, scope));
    }
    let resolved = resolve(host, 0, Family::Any)
        .map_err(|error| format!("scope check could not resolve {host}: {error}"))?;
    if resolved.iter().any(|address| scope.allows_ip(address.ip())) {
        Ok(())
    } else {
        Err(scope_error(host, scope))
    }
}

fn is_loopback_target(host: &str) -> bool {
    host.parse::<IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or_else(|_| host.eq_ignore_ascii_case("localhost"))
}

/// Active recon commands are allowed on loopback by default, but require an
/// explicit authorization scope file for every non-loopback target.
fn require_active_scope(host: &str, opts: &Options, command: &str) -> Result<(), String> {
    if opts.scope.is_none() && !is_loopback_target(host) {
        return Err(format!(
            "{command} requires --scope <file> for non-loopback targets"
        ));
    }
    ensure_scope_host(host, opts)
}

fn fresh_options() -> Options {
    Options {
        timeout: Duration::from_secs(DEFAULT_TIMEOUT),
        retries: 0,
        output: Output::Text,
        verbose: false,
        quiet: false,
        path: "/".into(),
        method: "HEAD".into(),
        expect_status: None,
        show_headers: Vec::new(),
        redirects: 5,
        proxy: None,
        headers: Vec::new(),
        auth: None,
        user_agent: None,
        body_bytes: 0,
        family: Family::Any,
        payload: None,
        dns_type: None,
        dns_server: None,
        rate: DEFAULT_LOAD_RATE as u32,
        count: DEFAULT_LOAD_COUNT as u32,
        steps: 4,
        clients: 4,
        hold_seconds: 5,
        rotate_user_agent: false,
        random_user_agent: false,
        audit_headers: false,
        concurrency: MAX_CONCURRENCY as u32,
        ports: None,
        wordlist: None,
        origin: None,
        skip_certificate: false,
        show_all_headers: false,
        scope: None,
        scope_path: None,
    }
}

impl Options {
    fn try_header(&mut self, name: &str, value: &str) -> Result<(), String> {
        if self.headers.len() >= MAX_HEADERS {
            return Err(format!("at most {MAX_HEADERS} custom headers are allowed"));
        }
        let pair = validate_header_pair(name, value)?;
        self.headers.push(pair);
        Ok(())
    }

    fn try_family(&mut self, value: &str) -> Result<(), String> {
        self.family = Family::parse(value)?;
        Ok(())
    }

    fn try_method(&mut self, value: &str) -> Result<(), String> {
        let method = value.to_ascii_uppercase();
        if method != "HEAD" && method != "GET" {
            return Err("method must be HEAD or GET".into());
        }
        self.method = method;
        Ok(())
    }
}

/// Apply one `key = value` config pair on top of existing options.
fn apply_config_pair(opts: &mut Options, key: &str, value: &str) -> Result<(), String> {
    match key {
        "timeout" => {
            opts.timeout = Duration::from_secs(bare_number("timeout", value, 1, MAX_TIMEOUT)?);
        }
        "retries" => {
            opts.retries = bare_number("retries", value, 0, MAX_RETRIES as u64)? as u32;
        }
        "output" => {
            opts.output = Output::parse(value)?;
        }
        "family" => {
            opts.family = Family::parse(value)?;
        }
        "path" => {
            validate_path(value)?;
            opts.path = value.to_string();
        }
        "method" => {
            opts.try_method(value)?;
        }
        "redirects" => {
            opts.redirects = bare_number("redirects", value, 0, MAX_REDIRECTS as u64)? as u32;
        }
        "proxy" => {
            validate_proxy(value)?;
            opts.proxy = Some(value.to_string());
        }
        "user-agent" => {
            validate_user_agent(value)?;
            opts.user_agent = Some(value.to_string());
        }
        "auth-basic" => {
            opts.auth = Some(parse_auth("basic", value)?);
        }
        "auth-bearer" => {
            opts.auth = Some(parse_auth("bearer", value)?);
        }
        "header" => {
            let (name, header_value) = parse_header(value)?;
            opts.try_header(&name, &header_value)?;
        }
        "show-header" => {
            opts.show_headers.push(validate_show_header(value)?);
        }
        "expect-status" => {
            opts.expect_status = Some(bare_number("expect-status", value, 100, 599)? as u16);
        }
        "body-bytes" => {
            opts.body_bytes = bare_number("body-bytes", value, 0, MAX_BODY_BYTES as u64)?;
        }
        "rate" => {
            opts.rate = bare_number("rate", value, 1, MAX_LOAD_RATE)? as u32;
        }
        "count" => {
            opts.count = bare_number("count", value, 1, MAX_LOAD_COUNT)? as u32;
        }
        "steps" => {
            opts.steps = bare_number("steps", value, 1, MAX_CAPACITY_STEPS)? as u32;
        }
        "clients" => {
            opts.clients = bare_number("clients", value, 1, MAX_SLOW_CLIENTS)? as u32;
        }
        "hold" => {
            opts.hold_seconds = bare_number("hold", value, 1, MAX_SLOW_HOLD_SECONDS)?;
        }
        "rotate-user-agent" => match value.trim() {
            "true" => opts.rotate_user_agent = true,
            "false" => opts.rotate_user_agent = false,
            _ => return Err("rotate-user-agent must be true or false".into()),
        },
        "random-user-agent" => match value.trim() {
            "true" => opts.random_user_agent = true,
            "false" => opts.random_user_agent = false,
            _ => return Err("random-user-agent must be true or false".into()),
        },
        "audit-headers" => match value.trim() {
            "true" => opts.audit_headers = true,
            "false" => opts.audit_headers = false,
            _ => return Err("audit-headers must be true or false".into()),
        },
        "concurrency" => {
            opts.concurrency = bare_number("concurrency", value, 1, MAX_CONCURRENCY as u64)? as u32;
        }
        "ports" => {
            parse_ports(value)?;
            opts.ports = Some(value.trim().to_string());
        }
        "wordlist" => {
            if value.trim().is_empty() {
                return Err("wordlist must be a file path".into());
            }
            opts.wordlist = Some(PathBuf::from(value.trim()));
        }
        "origin" => {
            validate_origin(value)?;
            opts.origin = Some(value.trim().to_string());
        }
        "scope" => {
            if value.trim().is_empty() {
                return Err("scope must be a file path".into());
            }
            opts.scope_path = Some(PathBuf::from(value.trim()));
        }
        "dns-type" => {
            opts.dns_type = Some(DnsType::parse(value)?);
        }
        "dns-server" => {
            opts.dns_server = Some(
                value
                    .parse()
                    .map_err(|_| "dns-server must be an IPv4 or IPv6 address")?,
            );
        }
        "payload" => {
            let bytes = decode_hex(value)?;
            if bytes.is_empty() || bytes.len() > MAX_UDP_PAYLOAD {
                return Err(format!("payload must be 1-{MAX_UDP_PAYLOAD} bytes"));
            }
            opts.payload = Some(bytes);
        }
        "verbose" => match value.trim() {
            "true" => opts.verbose = true,
            "false" => opts.verbose = false,
            _ => return Err("verbose must be true or false".into()),
        },
        "quiet" => match value.trim() {
            "true" => opts.quiet = true,
            "false" => opts.quiet = false,
            _ => return Err("quiet must be true or false".into()),
        },
        other => {
            return Err(format!("unknown config key: {other}"));
        }
    }
    Ok(())
}

/// Parse a `key = value` config file on top of existing options.
fn apply_config_file(opts: &mut Options, source: &str, origin: &Path) -> Result<(), String> {
    for (index, raw) in source.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index + 1;
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{}: line {number} must be 'key = value'", origin.display()))?;
        let key = key.trim().to_ascii_lowercase();
        let mut value = value.trim();
        if value.len() >= 2 {
            let first = value.as_bytes()[0] as char;
            if (first == '"' || first == '\'') && value.ends_with(first) {
                value = &value[1..value.len() - 1];
            }
        }
        apply_config_pair(opts, &key, value)
            .map_err(|e| format!("{}: line {number}: {e}", origin.display()))?;
    }
    Ok(())
}

fn default_config_path() -> Option<PathBuf> {
    if cfg!(windows) {
        return env::var_os("APPDATA").map(|base| {
            PathBuf::from(base)
                .join(CONFIG_DIR_NAME)
                .join(CONFIG_FILE_NAME)
        });
    }
    let base = match env::var_os("XDG_CONFIG_HOME") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => {
            let home = env::var_os("HOME").filter(|v| !v.is_empty())?;
            PathBuf::from(home).join(".config")
        }
    };
    Some(base.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME))
}

/// Find `--config <path>` and `--no-config` without consuming other flags.
fn config_directory_args(args: &[String]) -> Result<(Option<PathBuf>, bool), String> {
    let flags_with_value: &[&str] = &[
        "--timeout",
        "--retry",
        "--output",
        "--path",
        "--method",
        "--expect-status",
        "--show-header",
        "--redirects",
        "--proxy",
        "--interval",
        "--duration",
        "--header",
        "--user-agent",
        "--body-bytes",
        "--family",
        "--payload",
        "--dns-type",
        "--dns-server",
        "--scope",
        "--audit-log",
        "--config",
        "--concurrency",
        "--ports",
        "--wordlist",
        "--origin",
    ];
    let mut path = None;
    let mut disabled = false;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--config" {
            path = Some(
                args.get(i + 1)
                    .ok_or("--config requires a file path")?
                    .into(),
            );
            i += 2;
        } else if arg == "--no-config" {
            disabled = true;
            i += 1;
        } else if arg == "--auth" {
            i += 3;
        } else if flags_with_value.contains(&arg) {
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok((path, disabled))
}

/// Build options starting from defaults, applying the config file if present.
/// An explicit `--config` path must exist; the default config file is optional.
fn load_config(args: &[String]) -> Result<Options, String> {
    let mut opts = fresh_options();
    let (path, disabled) = config_directory_args(args)?;
    if disabled {
        return Ok(opts);
    }
    let path = match path {
        Some(explicit) if !explicit.exists() => {
            return Err(format!("config file not found: {}", explicit.display()))
        }
        Some(explicit) => explicit,
        None => match default_config_path() {
            Some(default_path) if default_path.exists() => default_path,
            _ => return Ok(opts),
        },
    };
    let source = fs::read_to_string(&path)
        .map_err(|e| format!("could not read config {}: {e}", path.display()))?;
    apply_config_file(&mut opts, &source, &path)?;
    Ok(opts)
}

fn env_value(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

/// Apply DDOS_* environment overrides on top of existing options.
fn apply_env(opts: &mut Options) -> Result<(), String> {
    if let Some(value) = env_value("DDOS_OUTPUT") {
        opts.output = Output::parse(&value).map_err(|e| format!("DDOS_OUTPUT: {e}"))?;
    }
    if let Some(value) = env_value("DDOS_TIMEOUT") {
        opts.timeout = Duration::from_secs(
            bare_number("DDOS_TIMEOUT", &value, 1, MAX_TIMEOUT)
                .map_err(|e| format!("DDOS_TIMEOUT: {e}"))?,
        );
    }
    if let Some(value) = env_value("DDOS_RETRIES") {
        opts.retries = bare_number("DDOS_RETRIES", &value, 0, MAX_RETRIES as u64)
            .map_err(|e| format!("DDOS_RETRIES: {e}"))? as u32;
    }
    if let Some(value) = env_value("DDOS_PATH") {
        validate_path(&value).map_err(|e| format!("DDOS_PATH: {e}"))?;
        opts.path = value;
    }
    if let Some(value) = env_value("DDOS_METHOD") {
        opts.try_method(&value)
            .map_err(|e| format!("DDOS_METHOD: {e}"))?;
    }
    if let Some(value) = env_value("DDOS_FAMILY") {
        opts.try_family(&value)
            .map_err(|e| format!("DDOS_FAMILY: {e}"))?;
    }
    if let Some(value) = env_value("DDOS_EXPECT_STATUS") {
        opts.expect_status = Some(
            bare_number("DDOS_EXPECT_STATUS", &value, 100, 599)
                .map_err(|e| format!("DDOS_EXPECT_STATUS: {e}"))? as u16,
        );
    }
    if let Some(value) = env_value("DDOS_REDIRECTS") {
        opts.redirects = bare_number("DDOS_REDIRECTS", &value, 0, MAX_REDIRECTS as u64)
            .map_err(|e| format!("DDOS_REDIRECTS: {e}"))? as u32;
    }
    if let Some(value) = env_value("DDOS_PROXY") {
        validate_proxy(&value).map_err(|e| format!("DDOS_PROXY: {e}"))?;
        opts.proxy = Some(value);
    }
    if let Some(value) = env_value("DDOS_USER_AGENT") {
        validate_user_agent(&value).map_err(|e| format!("DDOS_USER_AGENT: {e}"))?;
        opts.user_agent = Some(value);
    }
    if let Some(value) = env_value("DDOS_BODY_BYTES") {
        opts.body_bytes = bare_number("DDOS_BODY_BYTES", &value, 0, MAX_BODY_BYTES as u64)
            .map_err(|e| format!("DDOS_BODY_BYTES: {e}"))?;
    }
    if let Some(value) = env_value("DDOS_DNS_TYPE") {
        opts.dns_type = Some(DnsType::parse(&value).map_err(|e| format!("DDOS_DNS_TYPE: {e}"))?);
    }
    if let Some(value) = env_value("DDOS_DNS_SERVER") {
        opts.dns_server = Some(
            value
                .parse()
                .map_err(|_| "DDOS_DNS_SERVER must be an IPv4 or IPv6 address".to_string())?,
        );
    }
    if let Some(value) = env_value("DDOS_PAYLOAD") {
        let bytes = decode_hex(&value).map_err(|e| format!("DDOS_PAYLOAD: {e}"))?;
        if bytes.is_empty() || bytes.len() > MAX_UDP_PAYLOAD {
            return Err(format!("DDOS_PAYLOAD must be 1-{MAX_UDP_PAYLOAD} bytes"));
        }
        opts.payload = Some(bytes);
    }
    if let Some(value) = env_value("DDOS_VERBOSE") {
        match value.trim() {
            "true" => opts.verbose = true,
            "false" => opts.verbose = false,
            _ => return Err("DDOS_VERBOSE must be true or false".into()),
        }
    }
    if let Some(value) = env_value("DDOS_QUIET") {
        match value.trim() {
            "true" => opts.quiet = true,
            "false" => opts.quiet = false,
            _ => return Err("DDOS_QUIET must be true or false".into()),
        }
    }
    if let Some(value) = env_value("DDOS_RATE") {
        opts.rate = bare_number("DDOS_RATE", &value, 1, MAX_LOAD_RATE)
            .map_err(|e| format!("DDOS_RATE: {e}"))? as u32;
    }
    if let Some(value) = env_value("DDOS_COUNT") {
        opts.count = bare_number("DDOS_COUNT", &value, 1, MAX_LOAD_COUNT)
            .map_err(|e| format!("DDOS_COUNT: {e}"))? as u32;
    }
    if let Some(value) = env_value("DDOS_STEPS") {
        opts.steps = bare_number("DDOS_STEPS", &value, 1, MAX_CAPACITY_STEPS)
            .map_err(|e| format!("DDOS_STEPS: {e}"))? as u32;
    }
    if let Some(value) = env_value("DDOS_CLIENTS") {
        opts.clients = bare_number("DDOS_CLIENTS", &value, 1, MAX_SLOW_CLIENTS)
            .map_err(|e| format!("DDOS_CLIENTS: {e}"))? as u32;
    }
    if let Some(value) = env_value("DDOS_HOLD") {
        opts.hold_seconds = bare_number("DDOS_HOLD", &value, 1, MAX_SLOW_HOLD_SECONDS)
            .map_err(|e| format!("DDOS_HOLD: {e}"))?;
    }
    if let Some(value) = env_value("DDOS_ROTATE_USER_AGENT") {
        match value.trim() {
            "true" => opts.rotate_user_agent = true,
            "false" => opts.rotate_user_agent = false,
            _ => return Err("DDOS_ROTATE_USER_AGENT must be true or false".into()),
        }
    }
    if let Some(value) = env_value("DDOS_RANDOM_USER_AGENT") {
        match value.trim() {
            "true" => opts.random_user_agent = true,
            "false" => opts.random_user_agent = false,
            _ => return Err("DDOS_RANDOM_USER_AGENT must be true or false".into()),
        }
    }
    if let Some(value) = env_value("DDOS_AUDIT_HEADERS") {
        match value.trim() {
            "true" => opts.audit_headers = true,
            "false" => opts.audit_headers = false,
            _ => return Err("DDOS_AUDIT_HEADERS must be true or false".into()),
        }
    }
    if let Some(value) = env_value("DDOS_CONCURRENCY") {
        opts.concurrency = bare_number("DDOS_CONCURRENCY", &value, 1, MAX_CONCURRENCY as u64)
            .map_err(|e| format!("DDOS_CONCURRENCY: {e}"))? as u32;
    }
    if let Some(value) = env_value("DDOS_PORTS") {
        parse_ports(&value).map_err(|e| format!("DDOS_PORTS: {e}"))?;
        opts.ports = Some(value);
    }
    if let Some(value) = env_value("DDOS_WORDLIST") {
        opts.wordlist = Some(PathBuf::from(value));
    }
    if let Some(value) = env_value("DDOS_ORIGIN") {
        validate_origin(&value).map_err(|e| format!("DDOS_ORIGIN: {e}"))?;
        opts.origin = Some(value);
    }
    if let Some(value) = env_value("DDOS_SCOPE") {
        opts.scope_path = Some(PathBuf::from(value));
    }
    if let Some(value) = env_value("DDOS_SHOW_HEADER") {
        for name in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            opts.show_headers
                .push(validate_show_header(name).map_err(|e| format!("DDOS_SHOW_HEADER: {e}"))?);
        }
    }
    if let Some(value) = env_value("DDOS_HEADER") {
        for item in value.split(';').filter(|v| !v.trim().is_empty()) {
            let (name, header_value) =
                parse_header(item.trim()).map_err(|e| format!("DDOS_HEADER: {e}"))?;
            opts.try_header(&name, &header_value)
                .map_err(|e| format!("DDOS_HEADER: {e}"))?;
        }
    }
    if let Some(value) = env_value("DDOS_AUTH") {
        let (scheme, credential) = value
            .split_once(':')
            .ok_or("DDOS_AUTH must be basic:USER:PASS or bearer:TOKEN")?;
        opts.auth = Some(parse_auth(scheme, credential).map_err(|e| format!("DDOS_AUTH: {e}"))?);
    }
    Ok(())
}

/// Apply CLI arguments on top of an options baseline and return positionals.
fn apply_args(opts: &mut Options, args: &[String]) -> Result<Vec<String>, String> {
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout" => {
                opts.timeout =
                    Duration::from_secs(number(args.get(i + 1), "--timeout", 1, MAX_TIMEOUT)?);
                i += 2;
            }
            "--retry" => {
                opts.retries = number(args.get(i + 1), "--retry", 0, MAX_RETRIES as u64)? as u32;
                i += 2;
            }
            "--output" => {
                opts.output = Output::parse(args.get(i + 1).ok_or("--output requires a format")?)?;
                i += 2;
            }
            "--config" => {
                args.get(i + 1).ok_or("--config requires a file path")?;
                i += 2;
            }
            "--no-config" => {
                i += 1;
            }
            "--path" => {
                let path = args.get(i + 1).ok_or("--path requires a URL path")?;
                validate_path(path)?;
                opts.path = path.clone();
                i += 2;
            }
            "--method" => {
                let method = args
                    .get(i + 1)
                    .ok_or("--method requires HEAD or GET")?
                    .to_ascii_uppercase();
                if method != "HEAD" && method != "GET" {
                    return Err("--method must be HEAD or GET".into());
                }
                opts.method = method;
                i += 2;
            }
            "--expect-status" => {
                opts.expect_status =
                    Some(number(args.get(i + 1), "--expect-status", 100, 599)? as u16);
                i += 2;
            }
            "--show-header" => {
                let name = args.get(i + 1).ok_or("--show-header requires a name")?;
                opts.show_headers.push(validate_show_header(name)?);
                i += 2;
            }
            "--redirects" => {
                opts.redirects =
                    number(args.get(i + 1), "--redirects", 0, MAX_REDIRECTS as u64)? as u32;
                i += 2;
            }
            "--proxy" => {
                let proxy = args.get(i + 1).ok_or("--proxy requires a URL")?;
                validate_proxy(proxy)?;
                opts.proxy = Some(proxy.clone());
                i += 2;
            }
            "--interval" => {
                number(args.get(i + 1), "--interval", 1, MAX_REPEAT_SECONDS)?;
                i += 2;
            }
            "--duration" => {
                number(args.get(i + 1), "--duration", 1, MAX_REPEAT_SECONDS)?;
                i += 2;
            }
            "--verbose" => {
                opts.verbose = true;
                i += 1;
            }
            "--quiet" => {
                opts.quiet = true;
                i += 1;
            }
            "--no-color" => {
                i += 1;
            }
            "--header" => {
                let header = args.get(i + 1).ok_or("--header requires \"Name: value\"")?;
                let (name, value) = parse_header(header)?;
                opts.try_header(&name, &value)?;
                i += 2;
            }
            "--auth" => {
                let scheme = args
                    .get(i + 1)
                    .ok_or("--auth requires a scheme (basic or bearer)")?
                    .to_ascii_lowercase();
                if scheme != "basic" && scheme != "bearer" {
                    return Err("--auth scheme must be basic or bearer".into());
                }
                let credential = args
                    .get(i + 2)
                    .ok_or_else(|| match scheme.as_str() {
                        "basic" => "--auth basic requires \"user:pass\"".to_string(),
                        _ => "--auth bearer requires a token".to_string(),
                    })?
                    .clone();
                opts.auth = Some(parse_auth(&scheme, &credential)?);
                i += 3;
            }
            "--user-agent" => {
                let agent = args
                    .get(i + 1)
                    .ok_or("--user-agent requires a value")?
                    .clone();
                validate_user_agent(&agent)?;
                opts.user_agent = Some(agent);
                i += 2;
            }
            "--body-bytes" => {
                opts.body_bytes =
                    number(args.get(i + 1), "--body-bytes", 0, MAX_BODY_BYTES as u64)?;
                i += 2;
            }
            "--rate" => {
                opts.rate = number(args.get(i + 1), "--rate", 1, MAX_LOAD_RATE)? as u32;
                i += 2;
            }
            "--count" => {
                opts.count = number(args.get(i + 1), "--count", 1, MAX_LOAD_COUNT)? as u32;
                i += 2;
            }
            "--steps" => {
                opts.steps = number(args.get(i + 1), "--steps", 1, MAX_CAPACITY_STEPS)? as u32;
                i += 2;
            }
            "--clients" => {
                opts.clients = number(args.get(i + 1), "--clients", 1, MAX_SLOW_CLIENTS)? as u32;
                i += 2;
            }
            "--hold" => {
                opts.hold_seconds = number(args.get(i + 1), "--hold", 1, MAX_SLOW_HOLD_SECONDS)?;
                i += 2;
            }
            "--rotate-user-agent" => {
                opts.rotate_user_agent = true;
                i += 1;
            }
            "--random-user-agent" => {
                opts.random_user_agent = true;
                i += 1;
            }
            "--audit-headers" => {
                opts.audit_headers = true;
                i += 1;
            }
            "--scope" => {
                let scope = args.get(i + 1).ok_or("--scope requires a file path")?;
                if scope.trim().is_empty() {
                    return Err("--scope requires a file path".into());
                }
                opts.scope_path = Some(PathBuf::from(scope));
                i += 2;
            }
            "--concurrency" => {
                opts.concurrency =
                    number(args.get(i + 1), "--concurrency", 1, MAX_CONCURRENCY as u64)? as u32;
                i += 2;
            }
            "--ports" => {
                let ports = args.get(i + 1).ok_or("--ports requires a spec")?;
                parse_ports(ports)?;
                opts.ports = Some(ports.trim().to_string());
                i += 2;
            }
            "--wordlist" => {
                let wordlist = args.get(i + 1).ok_or("--wordlist requires a file path")?;
                if wordlist.trim().is_empty() {
                    return Err("--wordlist requires a file path".into());
                }
                opts.wordlist = Some(PathBuf::from(wordlist));
                i += 2;
            }
            "--origin" => {
                let origin = args.get(i + 1).ok_or("--origin requires an origin URL")?;
                validate_origin(origin)?;
                opts.origin = Some(origin.trim().to_string());
                i += 2;
            }
            "--audit-log" => {
                let path = args.get(i + 1).ok_or("--audit-log requires a file path")?;
                if path.trim().is_empty() {
                    return Err("--audit-log requires a file path".into());
                }
                i += 2;
            }
            "--family" => {
                let family = args
                    .get(i + 1)
                    .ok_or("--family requires any, ipv4, or ipv6")?;
                opts.try_family(family)?;
                i += 2;
            }
            "--payload" => {
                let payload = args.get(i + 1).ok_or("--payload requires hex bytes")?;
                let bytes = decode_hex(payload)?;
                if bytes.is_empty() || bytes.len() > MAX_UDP_PAYLOAD {
                    return Err(format!("payload must be 1-{MAX_UDP_PAYLOAD} bytes"));
                }
                opts.payload = Some(bytes);
                i += 2;
            }
            "--dns-type" => {
                let record = args.get(i + 1).ok_or("--dns-type requires a record type")?;
                opts.dns_type = Some(DnsType::parse(record)?);
                i += 2;
            }
            "--dns-server" => {
                let server = args
                    .get(i + 1)
                    .ok_or("--dns-server requires an IPv4 or IPv6 address")?;
                opts.dns_server = Some(
                    server
                        .parse()
                        .map_err(|_| "--dns-server must be an IPv4 or IPv6 address")?,
                );
                i += 2;
            }
            value if value.starts_with('-') && value != "-" => {
                return Err(format!("unknown option: {value}"))
            }
            value => {
                positional.push(value.to_string());
                i += 1;
            }
        }
    }
    Ok(positional)
}

/// Build options: defaults → config file → env vars → CLI arguments.
fn options(args: &[String]) -> Result<(Options, Vec<String>), String> {
    let mut opts = load_config(args)?;
    apply_env(&mut opts)?;
    let positional = apply_args(&mut opts, args)?;
    if let Some(path) = &opts.scope_path {
        opts.scope = Some(Scope::load(path)?);
    }
    Ok((opts, positional))
}

fn resolve(host: &str, port: u16, family: Family) -> io::Result<Vec<SocketAddr>> {
    let collected: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    Ok(collected
        .into_iter()
        .filter(|address| family.matches(address))
        .collect())
}
fn family(address: &SocketAddr) -> &'static str {
    if address.is_ipv4() {
        "ipv4"
    } else {
        "ipv6"
    }
}

fn addresses(addresses: &[SocketAddr], opts: &Options) -> Vec<AddressResult> {
    addresses
        .iter()
        .map(|address| {
            let started = Instant::now();
            let mut error = None;
            for attempt in 0..=opts.retries {
                match TcpStream::connect_timeout(address, opts.timeout) {
                    Ok(stream) => {
                        drop(stream);
                        return AddressResult {
                            address: address.to_string(),
                            family: family(address).into(),
                            connected: true,
                            elapsed_ms: started.elapsed().as_millis(),
                            error: None,
                        };
                    }
                    Err(e) => {
                        error = Some(e.to_string());
                        if attempt < opts.retries {
                            thread::sleep(Duration::from_millis(50 * 2u64.pow(attempt)));
                        }
                    }
                }
            }
            AddressResult {
                address: address.to_string(),
                family: family(address).into(),
                connected: false,
                elapsed_ms: started.elapsed().as_millis(),
                error,
            }
        })
        .collect()
}

fn target(value: &str) -> Result<(String, u16, Option<String>), String> {
    for (scheme, default_port) in [("http://", 80), ("https://", 443)] {
        if let Some(rest) = value.strip_prefix(scheme) {
            let authority = rest.split('/').next().unwrap_or(rest);
            let authority = authority.rsplit('@').next().unwrap_or(authority);
            let (host, port) = if authority.starts_with('[') {
                let end = authority.find(']').ok_or("invalid bracketed host")?;
                let host = &authority[1..end];
                let port = authority[end + 1..]
                    .strip_prefix(':')
                    .map(|value| value.parse().map_err(|_| "port must be 1-65535"))
                    .transpose()?
                    .unwrap_or(default_port);
                (host.to_string(), port)
            } else if let Some((host, port)) = authority.rsplit_once(':') {
                match port.parse::<u16>() {
                    Ok(port) => (host.to_string(), port),
                    Err(_) => (authority.to_string(), default_port),
                }
            } else {
                (authority.to_string(), default_port)
            };
            if host.is_empty() {
                return Err("target must contain a valid host".into());
            }
            return Ok((host, port, Some(format!("{scheme}{rest}"))));
        }
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.is_empty() {
            return Ok((
                host.trim_matches(['[', ']']).into(),
                port.parse().map_err(|_| "port must be 1-65535")?,
                None,
            ));
        }
    }
    Ok((value.into(), 80, None))
}

//
// Minimal DNS-over-UDP client (bounded: single query per attempt).
//

struct DnsQuery {
    id: u16,
    message: Vec<u8>,
}

fn dns_query(record: DnsType, host: &str) -> Result<DnsQuery, String> {
    validate_dns_host(host)?;
    let id = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|value| value.subsec_nanos() as u16)
        .unwrap_or(0)
        ^ (std::process::id() as u16);
    let mut message = Vec::with_capacity(12 + host.len() + 6);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&[0x01, 0x00]);
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    for label in host.trim_matches('.').split('.') {
        let label = label.as_bytes();
        if label.is_empty() || label.len() > MAX_DNS_LABEL {
            return Err(format!("host labels must be 1-{MAX_DNS_LABEL} bytes"));
        }
        message.push(label.len() as u8);
        message.extend_from_slice(label);
    }
    message.push(0);
    message.extend_from_slice(&record.code().to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    Ok(DnsQuery { id, message })
}

fn u16_at(message: &[u8], offset: usize) -> Option<u16> {
    let bytes = message.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn u32_at(message: &[u8], offset: usize) -> Option<u32> {
    let bytes = message.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read one wire-format name, following up to 16 compression pointers.
fn parse_dns_name(message: &[u8], start: usize) -> Option<(String, usize)> {
    let mut offset = start;
    let mut name = String::new();
    let mut followed = None;
    let mut jumps = 0;
    loop {
        let length = *message.get(offset)?;
        if length == 0 {
            offset += 1;
            break;
        }
        if length & 0xC0 == 0xC0 {
            let low = *message.get(offset + 1)?;
            let pointer = ((length & 0x3F) as usize) << 8 | low as usize;
            if followed.is_none() {
                followed = Some(offset + 2);
            }
            offset = pointer;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        if length & 0xC0 != 0 {
            return None;
        }
        let label = message.get(offset + 1..offset + 1 + length as usize)?;
        if !name.is_empty() {
            name.push('.');
        }
        let label = std::str::from_utf8(label).ok()?;
        name.push_str(&label.to_ascii_lowercase());
        offset += 1 + length as usize;
    }
    Some((name, followed.unwrap_or(offset)))
}

fn decode_rdata(
    message: &[u8],
    record_type: u16,
    offset: usize,
    length: usize,
) -> Result<String, String> {
    let data = message
        .get(offset..offset + length)
        .ok_or("truncated DNS answer data")?;
    match record_type {
        1 if length == 4 => Ok(format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3])),
        28 if length == 16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(data);
            Ok(Ipv6Addr::from(octets).to_string())
        }
        2 | 5 | 12 => Ok(parse_dns_name(message, offset)
            .map(|(name, _)| name)
            .unwrap_or_default()),
        16 => {
            let mut text = String::new();
            let mut cursor = 0;
            while cursor < length {
                let chunk = *message.get(offset + cursor).unwrap_or(&0) as usize;
                cursor += 1;
                let chunk = message
                    .get(offset + cursor..offset + cursor + chunk)
                    .unwrap_or(&[]);
                text.push_str(
                    &chunk
                        .iter()
                        .map(|byte| {
                            if byte.is_ascii_graphic() || *byte == b' ' {
                                *byte as char
                            } else {
                                '\u{00b7}'
                            }
                        })
                        .collect::<String>(),
                );
                cursor += chunk.len();
            }
            Ok(text)
        }
        15 => {
            let preference = u16_at(data, 0).unwrap_or(0);
            let host = parse_dns_name(message, offset + 2)
                .map(|(name, _)| name)
                .unwrap_or_default();
            Ok(format!("{preference} {host}"))
        }
        _ => Ok(data
            .iter()
            .take(32)
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<String>>()
            .join(" ")),
    }
}

/// Parse the DNS header plus answer records, returning the response code,
/// answer count, and decoded answers.
fn parse_dns_answers(message: &[u8]) -> Result<(u16, u16, Vec<DnsAnswer>), String> {
    if message.len() < 12 {
        return Err("DNS response is too short".into());
    }
    let question_count = u16_at(message, 4).unwrap_or(0);
    let answer_count = u16_at(message, 6).unwrap_or(0);
    let rcode = message[3] & 0x0F;
    let mut offset = 12;
    for _ in 0..question_count {
        let (_, next) = parse_dns_name(message, offset).ok_or("malformed DNS question section")?;
        offset = next + 4;
    }
    let mut answers = Vec::new();
    for _ in 0..answer_count {
        let (name, next) = parse_dns_name(message, offset).ok_or("malformed DNS answer name")?;
        offset = next;
        let record_type = u16_at(message, offset).ok_or("truncated DNS answer")?;
        let _class = u16_at(message, offset + 2).ok_or("truncated DNS answer")?;
        let ttl = u32_at(message, offset + 4).ok_or("truncated DNS answer")?;
        let length = u16_at(message, offset + 8).ok_or("truncated DNS answer")? as usize;
        offset += 10;
        if record_type == 1
            || record_type == 28
            || record_type == 12
            || record_type == 2
            || record_type == 5
            || record_type == 15
            || record_type == 16
        {
            let data = decode_rdata(message, record_type, offset, length)?;
            let record_type = DnsType::from_code(record_type)
                .map(|value| value.name())
                .unwrap_or("TYPE?")
                .to_string();
            answers.push(DnsAnswer {
                name,
                record_type,
                ttl_seconds: Some(ttl),
                data,
            });
        }
        offset += length;
    }
    Ok((rcode as u16, answer_count, answers))
}

/// Read the first resolver from /etc/resolv.conf (Unix-like systems).
fn system_resolver() -> Result<IpAddr, String> {
    let source = fs::read_to_string("/etc/resolv.conf")
        .map_err(|_| "no system resolver available; pass --dns-server <ip>".to_string())?;
    for raw in source.lines() {
        let line = raw.trim();
        if let Some(nameserver) = line.strip_prefix("nameserver ") {
            let nameserver = nameserver.trim();
            if let Ok(address) = nameserver.parse::<IpAddr>() {
                return Ok(address);
            }
            break;
        }
    }
    Err("no nameserver found in /etc/resolv.conf; pass --dns-server <ip>".into())
}

fn rcode_text(rcode: u16) -> String {
    match rcode {
        0 => "resolver returned status 0".to_string(),
        1 => "form error".to_string(),
        2 => "server failure (SERVFAIL)".to_string(),
        3 => "name does not exist (NXDOMAIN)".to_string(),
        4 => "not implemented".to_string(),
        5 => "query refused".to_string(),
        other => format!("unknown DNS status {other}"),
    }
}

/// Send one bounded UDP datagram and wait for a reply or ICMP error.
fn udp_attempt(address: &SocketAddr, opts: &Options, payload: &[u8]) -> UdpAttempt {
    let started = Instant::now();
    let bind_address = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = match UdpSocket::bind(bind_address) {
        Ok(socket) => socket,
        Err(error) => {
            return UdpAttempt {
                address: address.to_string(),
                family: family(address).into(),
                sent: false,
                received: false,
                elapsed_ms: 0,
                response_bytes: None,
                response_preview: None,
                error: Some(error.to_string()),
            }
        }
    };
    if let Err(error) = socket.connect(address) {
        return UdpAttempt {
            address: address.to_string(),
            family: family(address).into(),
            sent: false,
            received: false,
            elapsed_ms: started.elapsed().as_millis(),
            response_bytes: None,
            response_preview: None,
            error: Some(error.to_string()),
        };
    }
    let _ = socket.set_read_timeout(Some(opts.timeout));
    let _ = socket.set_write_timeout(Some(opts.timeout));
    for attempt in 0..=opts.retries {
        if let Err(error) = socket.send(payload) {
            return UdpAttempt {
                address: address.to_string(),
                family: family(address).into(),
                sent: false,
                received: false,
                elapsed_ms: started.elapsed().as_millis(),
                response_bytes: None,
                response_preview: None,
                error: Some(error.to_string()),
            };
        }
        let mut buffer = [0_u8; 4096];
        match socket.recv(&mut buffer) {
            Ok(count) => {
                return UdpAttempt {
                    address: address.to_string(),
                    family: family(address).into(),
                    sent: true,
                    received: true,
                    elapsed_ms: started.elapsed().as_millis(),
                    response_bytes: Some(count as u64),
                    response_preview: Some(preview_bytes(&buffer[..count], UDP_PREVIEW_BYTES)),
                    error: None,
                }
            }
            Err(error) => {
                let refused = error.kind() == io::ErrorKind::ConnectionRefused;
                let timed_out = error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut;
                if refused || (timed_out && attempt == opts.retries) {
                    return UdpAttempt {
                        address: address.to_string(),
                        family: family(address).into(),
                        sent: true,
                        received: false,
                        elapsed_ms: started.elapsed().as_millis(),
                        response_bytes: None,
                        response_preview: None,
                        error: Some(if refused {
                            "ICMP port unreachable: no service is listening on this UDP port".into()
                        } else {
                            "timed out waiting for a response".to_string()
                        }),
                    };
                }
                if timed_out {
                    thread::sleep(Duration::from_millis(50 * 2u64.pow(attempt)));
                }
            }
        }
    }
    UdpAttempt {
        address: address.to_string(),
        family: family(address).into(),
        sent: true,
        received: false,
        elapsed_ms: started.elapsed().as_millis(),
        response_bytes: None,
        response_preview: None,
        error: Some("no response received".into()),
    }
}

fn certificate_probe(host: &str, port: u16, opts: &Options) -> Result<CertificateSummary, String> {
    let address = resolve(host, port, opts.family)
        .map_err(|error| error.to_string())?
        .first()
        .copied()
        .ok_or("no address available for TLS")?;
    let stream =
        TcpStream::connect_timeout(&address, opts.timeout).map_err(|error| error.to_string())?;
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string()).map_err(|error| error.to_string())?;
    let connection =
        ClientConnection::new(Arc::new(config), name).map_err(|error| error.to_string())?;
    let mut tls = StreamOwned::new(connection, stream);
    tls.write_all(
        format!(
            "{} / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
            opts.method
        )
        .as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let mut response = [0_u8; 1];
    let _ = tls.read(&mut response);
    let protocol = tls
        .conn
        .protocol_version()
        .map(|value| format!("{value:?}"));
    let cipher_suite = tls
        .conn
        .negotiated_cipher_suite()
        .map(|value| format!("{:?}", value.suite()));
    let certificate = tls
        .conn
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or("TLS peer did not provide a certificate")?;
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|error| error.to_string())?;
    let sans = parsed
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectAlternativeName(value) => Some(
                value
                    .general_names
                    .iter()
                    .filter_map(|name| match name {
                        x509_parser::extensions::GeneralName::DNSName(value) => {
                            Some(value.to_string())
                        }
                        x509_parser::extensions::GeneralName::URI(value) => Some(value.to_string()),
                        _ => None,
                    })
                    .take(32)
                    .collect::<Vec<String>>(),
            ),
            _ => None,
        })
        .unwrap_or_default();
    let now_unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    let not_after_unix = parsed.validity().not_after.timestamp();
    Ok(CertificateSummary {
        subject: parsed.subject().to_string(),
        issuer: parsed.issuer().to_string(),
        serial: parsed.tbs_certificate.raw_serial_as_string(),
        sans,
        not_before: parsed.validity().not_before.to_string(),
        not_after: parsed.validity().not_after.to_string(),
        expired: now_unix > not_after_unix as u64,
        protocol,
        cipher_suite,
    })
}

const SECURITY_HEADERS: [(&str, u8); 8] = [
    ("strict-transport-security", 15),
    ("content-security-policy", 25),
    ("x-content-type-options", 10),
    ("x-frame-options", 10),
    ("referrer-policy", 10),
    ("permissions-policy", 10),
    ("cross-origin-opener-policy", 10),
    ("cross-origin-embedder-policy", 10),
];

fn security_grade(checks: &[HeaderCheck]) -> (u8, String) {
    let score = checks
        .iter()
        .filter(|check| check.present)
        .map(|check| {
            SECURITY_HEADERS
                .iter()
                .find(|(name, _)| *name == check.name)
                .map(|(_, weight)| *weight)
                .unwrap_or(0)
        })
        .fold(0_u8, u8::saturating_add);
    let grade = match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    };
    (score, grade.to_string())
}

fn http_probe(url: &str, host: &str, port: u16, opts: &Options) -> HttpResult {
    let started = Instant::now();
    let auth_header = match &opts.auth {
        Some(auth) => match auth.header_value() {
            Ok(value) => value,
            Err(error) => return probe_error(url, &started, error),
        },
        None => String::new(),
    };
    let redirects = if opts.scope.is_some() {
        0
    } else {
        opts.redirects
    };
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(opts.timeout)
        .timeout_read(opts.timeout)
        .timeout_write(opts.timeout)
        .redirects(redirects);
    builder = match opts.user_agent.as_deref() {
        Some(agent) => builder.user_agent(agent),
        None if opts.random_user_agent => builder.user_agent(pick_random_user_agent()),
        None => builder.user_agent(USER_AGENT),
    };
    if let Some(proxy) = &opts.proxy {
        builder = builder
            .proxy(ureq::Proxy::new(proxy).expect("proxy was validated during argument parsing"));
    }
    let agent = builder.build();
    let mut request = agent.request(&opts.method, url);
    if !auth_header.is_empty() {
        request = request.set("Authorization", &auth_header);
    }
    for (name, value) in &opts.headers {
        request = request.set(name, value);
    }
    // ureq reports 4xx/5xx as Error::Status; recover the response so that
    // --expect-status, path discovery, and CORS/cookie audits can inspect it.
    let response = match request.call() {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(error) => return probe_error(url, &started, error.to_string()),
    };
    let status = response.status();
    let status_text = response.status_text().to_string();
    let headers = if opts.show_all_headers {
        opts.show_headers
            .iter()
            .flat_map(|name| {
                response
                    .all(name)
                    .into_iter()
                    .map(|value| (name.clone(), value.to_string()))
                    .collect::<Vec<_>>()
            })
            .collect()
    } else {
        opts.show_headers
            .iter()
            .filter_map(|name| {
                response
                    .header(name)
                    .map(|value| (name.clone(), value.into()))
            })
            .collect()
    };
    let security_headers = if opts.audit_headers {
        Some(
            SECURITY_HEADERS
                .iter()
                .map(|(name, _)| {
                    let value = response.header(name).map(|value| value.to_string());
                    HeaderCheck {
                        name: (*name).into(),
                        present: value.is_some(),
                        value,
                    }
                })
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    let (security_score, security_grade) =
        security_headers.as_deref().map_or((None, None), |checks| {
            let (score, grade) = security_grade(checks);
            (Some(score), Some(grade))
        });
    let mut body_size = None;
    let mut body_read_error = None;
    let mut body_preview = None;
    if opts.method == "GET" && opts.body_bytes > 0 {
        let mut reader = response
            .into_reader()
            .take(opts.body_bytes.min(MAX_BODY_BYTES as u64));
        let mut buffer = Vec::new();
        match reader.read_to_end(&mut buffer) {
            Ok(_) => {
                body_size = Some(buffer.len() as u64);
                body_preview = Some(preview_bytes(&buffer, UDP_PREVIEW_BYTES));
            }
            Err(error) => body_read_error = Some(error.to_string()),
        }
    }
    HttpResult {
        url: url.into(),
        status: Some(status),
        status_text: Some(status_text),
        elapsed_ms: started.elapsed().as_millis(),
        error: None,
        headers,
        status_ok: opts
            .expect_status
            .map_or(status < 500, |expected| status == expected),
        body_size,
        body_read_error,
        body_preview,
        certificate: if url.starts_with("https://") && !opts.skip_certificate {
            match certificate_probe(host, port, opts) {
                Ok(value) => Some(value),
                Err(error) => {
                    return HttpResult {
                        certificate_error: Some(error),
                        ..probe_error(url, &started, "TLS certificate probe failed".into())
                    }
                }
            }
        } else {
            None
        },
        certificate_error: None,
        security_headers,
        security_score,
        security_grade,
    }
}

fn probe_error(url: &str, started: &Instant, error: String) -> HttpResult {
    HttpResult {
        url: url.into(),
        status: None,
        status_text: None,
        elapsed_ms: started.elapsed().as_millis(),
        error: Some(error),
        headers: Vec::new(),
        status_ok: false,
        body_size: None,
        body_read_error: None,
        body_preview: None,
        certificate: None,
        certificate_error: None,
        security_headers: None,
        security_score: None,
        security_grade: None,
    }
}

fn preview_bytes(payload: &[u8], limit: usize) -> String {
    payload[..payload.len().min(limit)]
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '\u{00b7}'
            }
        })
        .collect()
}

// --- Bounded reconnaissance and web security checks ------------------------
//
// These commands are diagnostic and bounded. Port scans and path discovery
// accept loopback targets without extra authorization, but every non-loopback
// target must be listed in an explicit --scope file.

#[derive(Serialize, Clone)]
struct PortResult {
    address: String,
    port: u16,
    open: bool,
    elapsed_ms: u128,
    error: Option<String>,
}

#[derive(Serialize)]
struct PortScanReport {
    schema_version: u8,
    version: String,
    host: String,
    addresses: Vec<String>,
    ports: Vec<u16>,
    results: Vec<PortResult>,
    open: Vec<String>,
    open_count: usize,
    scanned_count: usize,
    total_elapsed_ms: u128,
    ok: bool,
    error: Option<String>,
}

fn port_scan(host: &str, opts: &Options) -> Result<PortScanReport, String> {
    let started = Instant::now();
    require_active_scope(host, opts, "port-scan")?;
    let ports = parse_ports(opts.ports.as_deref().unwrap_or(DEFAULT_SCAN_PORTS))?;
    let resolved =
        resolve(host, 0, opts.family).map_err(|error| format!("DNS resolution failed: {error}"))?;
    let mut addresses: Vec<SocketAddr> = Vec::new();
    for address in resolved {
        if addresses.iter().any(|value| value.ip() == address.ip()) {
            continue;
        }
        addresses.push(address);
        if addresses.len() >= MAX_PORT_SCAN_ADDRESSES {
            break;
        }
    }
    if addresses.is_empty() {
        return Err(format!("no address found for {host}"));
    }
    if ports.len().saturating_mul(addresses.len()) > MAX_PORT_SCAN_PORTS {
        addresses.truncate(1);
    }
    let timeout = opts
        .timeout
        .min(Duration::from_secs(MAX_PORT_SCAN_TIMEOUT_SECONDS));
    let worker_count = (opts.concurrency as usize)
        .clamp(1, MAX_CONCURRENCY)
        .min(ports.len().max(1));
    let total = ports.len() * addresses.len();
    let ports = Arc::new(ports);
    let addresses = Arc::new(addresses);
    let next = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = mpsc::channel();
    for _ in 0..worker_count {
        let ports = Arc::clone(&ports);
        let addresses = Arc::clone(&addresses);
        let next = Arc::clone(&next);
        let sender = sender.clone();
        thread::spawn(move || loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            if index >= ports.len() * addresses.len() {
                break;
            }
            let port = ports[index % ports.len()];
            let address = addresses[index / ports.len()];
            let target = SocketAddr::new(address.ip(), port);
            let scan_started = Instant::now();
            let (open, error) = match TcpStream::connect_timeout(&target, timeout) {
                Ok(stream) => {
                    drop(stream);
                    (true, None)
                }
                Err(error) => (false, Some(error.to_string())),
            };
            let result = PortResult {
                address: address.ip().to_string(),
                port,
                open,
                elapsed_ms: scan_started.elapsed().as_millis(),
                error,
            };
            if sender.send(result).is_err() {
                break;
            }
        });
    }
    drop(sender);
    let mut results: Vec<PortResult> = receiver.into_iter().collect();
    results.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then(left.port.cmp(&right.port))
    });
    let open = results
        .iter()
        .filter(|result| result.open)
        .map(|result| format!("{}:{}", result.address, result.port))
        .collect::<Vec<_>>();
    Ok(PortScanReport {
        schema_version: 1,
        version: VERSION.into(),
        host: host.into(),
        addresses: addresses
            .iter()
            .map(|value| value.ip().to_string())
            .collect(),
        ports: ports.to_vec(),
        results: results.clone(),
        open_count: open.len(),
        open,
        scanned_count: total,
        total_elapsed_ms: started.elapsed().as_millis(),
        ok: results.len() == total,
        error: if results.len() == total {
            None
        } else {
            Some("some scan workers did not return a result".into())
        },
    })
}

fn print_port_scan_report(report: &PortScanReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Json => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        Output::Jsonl => {
            if let Ok(line) = serde_json::to_string(report) {
                println!("{line}");
            }
        }
        Output::Csv => {
            println!("host,address,port,open,elapsed_ms,error");
            for result in &report.results {
                println!(
                    "{},{},{},{},{},{}",
                    csv_escape(&report.host),
                    csv_escape(&result.address),
                    result.port,
                    result.open,
                    result.elapsed_ms,
                    csv_escape(result.error.as_deref().unwrap_or_default())
                );
            }
        }
        Output::Text => {
            println!(
                "PORT-SCAN {} ({} address(es), {} port(s), {} open, {} ms)",
                report.host,
                report.addresses.len(),
                report.ports.len(),
                report.open_count,
                report.total_elapsed_ms
            );
            for result in &report.results {
                if result.open {
                    println!(
                        "  {}:{}/tcp open ({} ms)",
                        result.address, result.port, result.elapsed_ms
                    );
                } else if opts.verbose {
                    println!(
                        "  {}:{}/tcp closed ({} ms){}",
                        result.address,
                        result.port,
                        result.elapsed_ms,
                        result
                            .error
                            .as_deref()
                            .map(|error| format!(": {error}"))
                            .unwrap_or_default()
                    );
                }
            }
        }
    }
}

#[derive(Serialize, Clone)]
struct PathResult {
    path: String,
    url: String,
    status: Option<u16>,
    status_text: Option<String>,
    content_length: Option<u64>,
    location: Option<String>,
    elapsed_ms: u128,
    interesting: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct PathDiscoveryReport {
    schema_version: u8,
    version: String,
    target: String,
    base_url: String,
    host: String,
    port: u16,
    results: Vec<PathResult>,
    scanned_count: usize,
    found_count: usize,
    total_elapsed_ms: u128,
    ok: bool,
    error: Option<String>,
}

fn validate_discovery_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/')
        || path.len() > 2048
        || path
            .chars()
            .any(|character| character.is_control() || character == ' ')
    {
        return Err(
            "path must start with '/', contain no spaces/control characters, and be <= 2048 bytes"
                .into(),
        );
    }
    Ok(())
}

fn read_discovery_paths(opts: &Options) -> Result<Vec<String>, String> {
    let paths = match &opts.wordlist {
        Some(path) => {
            let source = fs::read_to_string(path)
                .map_err(|error| format!("could not read wordlist {}: {error}", path.display()))?;
            let mut paths = Vec::new();
            for (index, raw) in source.lines().enumerate() {
                let line = raw.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                validate_discovery_path(line)
                    .map_err(|error| format!("{}: line {}: {error}", path.display(), index + 1))?;
                paths.push(line.to_string());
                if paths.len() > MAX_PATH_DISCOVERY_PATHS {
                    return Err(format!(
                        "path discovery is limited to {MAX_PATH_DISCOVERY_PATHS} paths"
                    ));
                }
            }
            paths
        }
        None => DEFAULT_DISCOVERY_PATHS
            .iter()
            .map(|path| (*path).to_string())
            .collect(),
    };
    if paths.is_empty() {
        return Err("path discovery requires at least one path".into());
    }
    Ok(paths)
}

fn interesting_status(status: u16) -> bool {
    (200..400).contains(&status) || matches!(status, 401 | 403 | 405 | 500)
}

fn path_discovery(value: &str, opts: &Options) -> Result<PathDiscoveryReport, String> {
    let started = Instant::now();
    let (host, port, url) = target(value)?;
    let base_url = url.unwrap_or_else(|| format!("http://{host}:{port}{}", opts.path));
    require_active_scope(&host, opts, "path-discovery")?;
    let paths = read_discovery_paths(opts)?;
    let base = base_url.trim_end_matches('/');
    let mut results = Vec::new();
    let mut found_count = 0;
    for path in &paths {
        let url = format!("{base}{path}");
        let mut probe = opts.clone();
        probe.method = "GET".into();
        probe.body_bytes = 0;
        probe.audit_headers = false;
        probe.expect_status = None;
        probe.skip_certificate = true;
        probe.show_all_headers = false;
        probe.show_headers = vec![
            "content-length".into(),
            "content-type".into(),
            "location".into(),
        ];
        let result = http_probe(&url, &host, port, &probe);
        let content_length = result
            .headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| value.parse::<u64>().ok());
        let location = result
            .headers
            .iter()
            .find(|(name, _)| name == "location")
            .map(|(_, value)| value.clone());
        let interesting = result.status.map(interesting_status).unwrap_or(false);
        if interesting {
            found_count += 1;
        }
        results.push(PathResult {
            path: path.clone(),
            url,
            status: result.status,
            status_text: result.status_text,
            content_length,
            location,
            elapsed_ms: result.elapsed_ms,
            interesting,
            error: result.error,
        });
        thread::sleep(Duration::from_millis(PATH_DISCOVERY_DELAY_MS));
    }
    Ok(PathDiscoveryReport {
        schema_version: 1,
        version: VERSION.into(),
        target: value.into(),
        base_url,
        host,
        port,
        scanned_count: results.len(),
        found_count,
        ok: results.iter().all(|result| result.error.is_none()),
        results,
        total_elapsed_ms: started.elapsed().as_millis(),
        error: None,
    })
}

fn print_path_discovery_report(report: &PathDiscoveryReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Json => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        Output::Jsonl => {
            if let Ok(line) = serde_json::to_string(report) {
                println!("{line}");
            }
        }
        Output::Csv => {
            println!("target,path,status,content_length,elapsed_ms,interesting,error");
            for result in &report.results {
                println!(
                    "{},{},{},{},{},{},{}",
                    csv_escape(&report.target),
                    csv_escape(&result.path),
                    result
                        .status
                        .map(|status| status.to_string())
                        .unwrap_or_default(),
                    result
                        .content_length
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    result.elapsed_ms,
                    result.interesting,
                    csv_escape(result.error.as_deref().unwrap_or_default())
                );
            }
        }
        Output::Text => {
            println!(
                "PATH-DISCOVERY {} ({} scanned, {} interesting, {} ms)",
                report.base_url, report.scanned_count, report.found_count, report.total_elapsed_ms
            );
            let mut printed = 0;
            for result in &report.results {
                if result.interesting || opts.verbose {
                    printed += 1;
                    let location = result
                        .location
                        .as_deref()
                        .map(|value| format!(" -> {value}"))
                        .unwrap_or_default();
                    println!(
                        "  {} {} ({} bytes, {} ms){}",
                        result
                            .status
                            .map(|status| status.to_string())
                            .unwrap_or_else(|| "ERR".into()),
                        result.path,
                        result
                            .content_length
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "?".into()),
                        result.elapsed_ms,
                        location
                    );
                }
            }
            if printed == 0 {
                println!("  no interesting paths");
            }
        }
    }
}

#[derive(Serialize, Clone)]
struct CorsFinding {
    code: String,
    severity: String,
    detail: String,
}

#[derive(Serialize)]
struct CorsReport {
    schema_version: u8,
    version: String,
    target: String,
    url: String,
    origin: String,
    status: Option<u16>,
    allow_origin: Option<String>,
    allow_credentials: Option<String>,
    allow_methods: Option<String>,
    allow_headers: Option<String>,
    vary: Option<String>,
    findings: Vec<CorsFinding>,
    ok: bool,
    total_elapsed_ms: u128,
    error: Option<String>,
}

fn analyze_cors(
    allow_origin: Option<&str>,
    allow_credentials: Option<&str>,
    vary: Option<&str>,
    origin: &str,
) -> Vec<CorsFinding> {
    let mut findings = Vec::new();
    let credentials = allow_credentials
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    match allow_origin {
        None => {}
        Some("*") => {
            if credentials {
                findings.push(CorsFinding {
                    code: "wildcard_with_credentials".into(),
                    severity: "high".into(),
                    detail: "Access-Control-Allow-Origin is '*' with credentials enabled".into(),
                });
            } else {
                findings.push(CorsFinding {
                    code: "wildcard_origin".into(),
                    severity: "medium".into(),
                    detail: "Access-Control-Allow-Origin is '*' for any origin".into(),
                });
            }
        }
        Some("null") => findings.push(CorsFinding {
            code: "null_origin".into(),
            severity: "high".into(),
            detail: "Access-Control-Allow-Origin accepts the opaque 'null' origin".into(),
        }),
        Some(value) if value.eq_ignore_ascii_case(origin) => {
            if credentials {
                findings.push(CorsFinding {
                    code: "reflected_with_credentials".into(),
                    severity: "critical".into(),
                    detail: "arbitrary Origin is reflected while credentials are enabled".into(),
                });
            } else {
                findings.push(CorsFinding {
                    code: "reflected_origin".into(),
                    severity: "medium".into(),
                    detail: "arbitrary Origin is reflected in Access-Control-Allow-Origin".into(),
                });
            }
            let vary_ok = vary
                .map(|value| {
                    value
                        .split(',')
                        .any(|item| item.trim().eq_ignore_ascii_case("origin"))
                })
                .unwrap_or(false);
            if !vary_ok {
                findings.push(CorsFinding {
                    code: "missing_vary_origin".into(),
                    severity: "low".into(),
                    detail: "reflected CORS response does not include Vary: Origin".into(),
                });
            }
        }
        Some(_) => {}
    }
    findings
}

fn cors_check(value: &str, opts: &Options) -> Result<CorsReport, String> {
    let started = Instant::now();
    let (host, port, url) = target(value)?;
    let url = url.unwrap_or_else(|| format!("http://{host}:{port}{}", opts.path));
    ensure_scope_host(&host, opts)?;
    let origin = opts
        .origin
        .clone()
        .unwrap_or_else(|| DEFAULT_CORS_ORIGIN.into());
    let mut probe = opts.clone();
    probe.method = "GET".into();
    probe.body_bytes = 0;
    probe.audit_headers = false;
    probe.expect_status = None;
    probe.skip_certificate = true;
    probe.show_all_headers = false;
    probe.show_headers = vec![
        "access-control-allow-origin".into(),
        "access-control-allow-credentials".into(),
        "access-control-allow-methods".into(),
        "access-control-allow-headers".into(),
        "vary".into(),
    ];
    probe.headers.retain(|(name, _)| name != "origin");
    probe.headers.push(("origin".into(), origin.clone()));
    let result = http_probe(&url, &host, port, &probe);
    let header = |name: &str| {
        result
            .headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let allow_origin = header("access-control-allow-origin");
    let allow_credentials = header("access-control-allow-credentials");
    let allow_methods = header("access-control-allow-methods");
    let allow_headers = header("access-control-allow-headers");
    let vary = header("vary");
    let findings = if result.status.is_some() {
        analyze_cors(
            allow_origin.as_deref(),
            allow_credentials.as_deref(),
            vary.as_deref(),
            &origin,
        )
    } else {
        vec![CorsFinding {
            code: "request_failed".into(),
            severity: "high".into(),
            detail: result
                .error
                .clone()
                .unwrap_or_else(|| "HTTP request failed".into()),
        }]
    };
    Ok(CorsReport {
        schema_version: 1,
        version: VERSION.into(),
        target: value.into(),
        url,
        origin,
        status: result.status,
        allow_origin,
        allow_credentials,
        allow_methods,
        allow_headers,
        vary,
        ok: findings.is_empty(),
        findings,
        total_elapsed_ms: started.elapsed().as_millis(),
        error: result.error,
    })
}

fn print_cors_report(report: &CorsReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Json => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        Output::Jsonl => {
            if let Ok(line) = serde_json::to_string(report) {
                println!("{line}");
            }
        }
        Output::Csv => {
            println!("target,status,origin,allow_origin,allow_credentials,findings,ok,error");
            println!(
                "{},{},{},{},{},{},{},{}",
                csv_escape(&report.target),
                report
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_default(),
                csv_escape(&report.origin),
                csv_escape(report.allow_origin.as_deref().unwrap_or_default()),
                csv_escape(report.allow_credentials.as_deref().unwrap_or_default()),
                report.findings.len(),
                report.ok,
                csv_escape(report.error.as_deref().unwrap_or_default())
            );
        }
        Output::Text => {
            println!(
                "CORS-CHECK {} (status {}, {} ms)",
                report.url,
                report
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "failed".into()),
                report.total_elapsed_ms
            );
            println!("  origin sent: {}", report.origin);
            for (label, value) in [
                ("allow-origin", &report.allow_origin),
                ("allow-credentials", &report.allow_credentials),
                ("allow-methods", &report.allow_methods),
                ("allow-headers", &report.allow_headers),
                ("vary", &report.vary),
            ] {
                if let Some(value) = value {
                    println!("  {label}: {value}");
                }
            }
            if report.findings.is_empty() {
                println!("  no CORS misconfiguration detected");
            } else {
                for finding in &report.findings {
                    println!(
                        "  FINDING [{}] {}: {}",
                        finding.severity, finding.code, finding.detail
                    );
                }
            }
        }
    }
}

#[derive(Serialize, Clone)]
struct CookieInfo {
    name: String,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    domain: Option<String>,
    path: Option<String>,
    max_age: Option<String>,
    expires: Option<String>,
}

#[derive(Serialize, Clone)]
struct CookieFinding {
    cookie: String,
    code: String,
    severity: String,
    detail: String,
}

#[derive(Serialize)]
struct CookieReport {
    schema_version: u8,
    version: String,
    target: String,
    url: String,
    status: Option<u16>,
    cookies: Vec<CookieInfo>,
    findings: Vec<CookieFinding>,
    ok: bool,
    total_elapsed_ms: u128,
    error: Option<String>,
}

fn analyze_set_cookie(values: &[String]) -> (Vec<CookieInfo>, Vec<CookieFinding>) {
    let mut cookies = Vec::new();
    let mut findings = Vec::new();
    if values.is_empty() {
        findings.push(CookieFinding {
            cookie: String::new(),
            code: "no_cookies".into(),
            severity: "info".into(),
            detail: "response did not set any cookies".into(),
        });
        return (cookies, findings);
    }
    for value in values {
        let mut parts = value.split(';');
        let first = parts.next().unwrap_or("").trim();
        let (name, _) = first.split_once('=').unwrap_or((first, ""));
        let name = name.trim();
        if name.is_empty() {
            findings.push(CookieFinding {
                cookie: String::new(),
                code: "malformed_cookie".into(),
                severity: "medium".into(),
                detail: "Set-Cookie header has no cookie name".into(),
            });
            continue;
        }
        let mut secure = false;
        let mut http_only = false;
        let mut same_site = None;
        let mut domain = None;
        let mut path = None;
        let mut max_age = None;
        let mut expires = None;
        for attribute in parts {
            let attribute = attribute.trim();
            if attribute.is_empty() {
                continue;
            }
            let (key, attribute_value) = attribute
                .split_once('=')
                .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_string()))
                .unwrap_or_else(|| (attribute.to_ascii_lowercase(), String::new()));
            match key.as_str() {
                "secure" => secure = true,
                "httponly" => http_only = true,
                "samesite" => same_site = Some(attribute_value),
                "domain" => domain = Some(attribute_value),
                "path" => path = Some(attribute_value),
                "max-age" => max_age = Some(attribute_value),
                "expires" => expires = Some(attribute_value),
                _ => {}
            }
        }
        let lower_name = name.to_ascii_lowercase();
        if lower_name.starts_with("__host-")
            && (!secure || path.as_deref() != Some("/") || domain.is_some())
        {
            findings.push(CookieFinding {
                cookie: name.into(),
                code: "host_prefix_violation".into(),
                severity: "high".into(),
                detail: "__Host- cookie must be Secure, use Path=/, and omit Domain".into(),
            });
        } else if lower_name.starts_with("__secure-") && !secure {
            findings.push(CookieFinding {
                cookie: name.into(),
                code: "secure_prefix_violation".into(),
                severity: "high".into(),
                detail: "__Secure- cookie is missing the Secure attribute".into(),
            });
        }
        if !secure {
            findings.push(CookieFinding {
                cookie: name.into(),
                code: "missing_secure".into(),
                severity: "high".into(),
                detail: "cookie is missing the Secure attribute".into(),
            });
        }
        if !http_only {
            findings.push(CookieFinding {
                cookie: name.into(),
                code: "missing_httponly".into(),
                severity: "medium".into(),
                detail: "cookie is missing the HttpOnly attribute".into(),
            });
        }
        match same_site.as_deref().map(str::to_ascii_lowercase).as_deref() {
            None => findings.push(CookieFinding {
                cookie: name.into(),
                code: "missing_samesite".into(),
                severity: "medium".into(),
                detail: "cookie is missing the SameSite attribute".into(),
            }),
            Some("none") if !secure => findings.push(CookieFinding {
                cookie: name.into(),
                code: "samesite_none_without_secure".into(),
                severity: "high".into(),
                detail: "SameSite=None requires the Secure attribute".into(),
            }),
            Some("lax") | Some("strict") | Some("none") => {}
            Some(_) => findings.push(CookieFinding {
                cookie: name.into(),
                code: "invalid_samesite".into(),
                severity: "low".into(),
                detail: "SameSite value is not Lax, Strict, or None".into(),
            }),
        }
        cookies.push(CookieInfo {
            name: name.into(),
            secure,
            http_only,
            same_site,
            domain,
            path,
            max_age,
            expires,
        });
    }
    (cookies, findings)
}

fn cookie_check(value: &str, opts: &Options) -> Result<CookieReport, String> {
    let started = Instant::now();
    let (host, port, url) = target(value)?;
    let url = url.unwrap_or_else(|| format!("http://{host}:{port}{}", opts.path));
    ensure_scope_host(&host, opts)?;
    let mut probe = opts.clone();
    probe.method = "GET".into();
    probe.body_bytes = 0;
    probe.audit_headers = false;
    probe.expect_status = None;
    probe.skip_certificate = true;
    probe.show_all_headers = true;
    probe.show_headers = vec!["set-cookie".into()];
    let result = http_probe(&url, &host, port, &probe);
    let values = result
        .headers
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .map(|(_, value)| value.clone())
        .collect::<Vec<_>>();
    let (cookies, findings) = analyze_set_cookie(&values);
    let ok = !findings.iter().any(|finding| finding.severity != "info");
    Ok(CookieReport {
        schema_version: 1,
        version: VERSION.into(),
        target: value.into(),
        url,
        status: result.status,
        cookies,
        findings,
        ok,
        total_elapsed_ms: started.elapsed().as_millis(),
        error: result.error,
    })
}

fn print_cookie_report(report: &CookieReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Json => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        Output::Jsonl => {
            if let Ok(line) = serde_json::to_string(report) {
                println!("{line}");
            }
        }
        Output::Csv => {
            println!("target,status,cookies,findings,ok,error");
            println!(
                "{},{},{},{},{},{}",
                csv_escape(&report.target),
                report
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_default(),
                report.cookies.len(),
                report.findings.len(),
                report.ok,
                csv_escape(report.error.as_deref().unwrap_or_default())
            );
        }
        Output::Text => {
            println!(
                "COOKIE-CHECK {} (status {}, {} cookie(s), {} ms)",
                report.url,
                report
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "failed".into()),
                report.cookies.len(),
                report.total_elapsed_ms
            );
            for cookie in &report.cookies {
                println!(
                    "  cookie {}: secure={} httponly={} samesite={} path={}",
                    cookie.name,
                    cookie.secure,
                    cookie.http_only,
                    cookie.same_site.as_deref().unwrap_or("None"),
                    cookie.path.as_deref().unwrap_or("-")
                );
            }
            if report.findings.is_empty() {
                println!("  no cookie misconfiguration detected");
            } else {
                for finding in &report.findings {
                    let cookie = if finding.cookie.is_empty() {
                        String::new()
                    } else {
                        format!("{} ", finding.cookie)
                    };
                    println!(
                        "  FINDING [{}] {}{}: {}",
                        finding.severity, cookie, finding.code, finding.detail
                    );
                }
            }
        }
    }
}

#[derive(Serialize, Clone)]
struct MethodProbe {
    method: String,
    status: Option<u16>,
    status_text: Option<String>,
    elapsed_ms: u128,
    allowed: bool,
    error: Option<String>,
}

#[derive(Serialize, Clone)]
struct MethodFinding {
    code: String,
    severity: String,
    detail: String,
}

#[derive(Serialize)]
struct MethodReport {
    schema_version: u8,
    version: String,
    target: String,
    url: String,
    allow: Option<String>,
    advertised: Vec<String>,
    probes: Vec<MethodProbe>,
    findings: Vec<MethodFinding>,
    ok: bool,
    total_elapsed_ms: u128,
    error: Option<String>,
}

fn parse_allow_header(value: Option<&str>) -> Vec<String> {
    let mut methods = Vec::new();
    if let Some(value) = value {
        for part in value.split(',') {
            let method = part.trim().to_ascii_uppercase();
            if !method.is_empty() && !methods.contains(&method) {
                methods.push(method);
            }
        }
    }
    methods
}

fn analyze_methods(allow: Option<&str>, probes: &[MethodProbe]) -> Vec<MethodFinding> {
    let mut findings = Vec::new();
    let advertised = parse_allow_header(allow);
    let options_status = probes
        .iter()
        .find(|probe| probe.method == "OPTIONS")
        .and_then(|probe| probe.status);
    if options_status.is_some() && advertised.is_empty() {
        findings.push(MethodFinding {
            code: "allow_header_missing".into(),
            severity: "info".into(),
            detail: "OPTIONS response did not include an Allow header".into(),
        });
    }
    let dangerous = advertised
        .iter()
        .filter(|method| matches!(method.as_str(), "PUT" | "DELETE" | "PATCH" | "CONNECT"))
        .cloned()
        .collect::<Vec<_>>();
    if !dangerous.is_empty() {
        findings.push(MethodFinding {
            code: "dangerous_methods_advertised".into(),
            severity: "medium".into(),
            detail: format!(
                "Allow advertises state-changing or tunneling methods: {}",
                dangerous.join(", ")
            ),
        });
    }
    if probes
        .iter()
        .any(|probe| probe.method == "TRACE" && probe.status == Some(200))
    {
        findings.push(MethodFinding {
            code: "trace_enabled".into(),
            severity: "medium".into(),
            detail: "TRACE returned HTTP 200; cross-site tracing may expose request headers".into(),
        });
    }
    findings
}

fn method_check(value: &str, opts: &Options) -> Result<MethodReport, String> {
    let started = Instant::now();
    let (host, port, url) = target(value)?;
    let url = url.unwrap_or_else(|| format!("http://{host}:{port}{}", opts.path));
    require_active_scope(&host, opts, "method-check")?;
    let mut probes = Vec::new();
    let mut allow = None;
    let mut error = None;
    for method in ["OPTIONS", "HEAD", "TRACE"] {
        let mut probe = opts.clone();
        probe.method = method.into();
        probe.body_bytes = 0;
        probe.audit_headers = false;
        probe.expect_status = None;
        probe.skip_certificate = true;
        probe.show_all_headers = true;
        probe.show_headers = vec!["allow".into(), "server".into(), "x-powered-by".into()];
        let result = http_probe(&url, &host, port, &probe);
        if method == "OPTIONS" {
            allow = result
                .headers
                .iter()
                .find(|(name, _)| name == "allow")
                .map(|(_, value)| value.clone());
        }
        if error.is_none() {
            error = result.error.clone();
        }
        probes.push(MethodProbe {
            method: method.into(),
            status: result.status,
            status_text: result.status_text,
            elapsed_ms: result.elapsed_ms,
            allowed: result
                .status
                .map(|status| !matches!(status, 405 | 501))
                .unwrap_or(false),
            error: result.error,
        });
    }
    let advertised = parse_allow_header(allow.as_deref());
    let findings = analyze_methods(allow.as_deref(), &probes);
    let ok = !findings
        .iter()
        .any(|finding| matches!(finding.severity.as_str(), "critical" | "high" | "medium"));
    Ok(MethodReport {
        schema_version: 1,
        version: VERSION.into(),
        target: value.into(),
        url,
        allow,
        advertised,
        probes,
        findings,
        ok,
        total_elapsed_ms: started.elapsed().as_millis(),
        error,
    })
}

fn print_method_report(report: &MethodReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Json => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        Output::Jsonl => {
            if let Ok(line) = serde_json::to_string(report) {
                println!("{line}");
            }
        }
        Output::Csv => {
            println!("target,status,allow,advertised,findings,ok,error");
            let status = report
                .probes
                .iter()
                .find(|probe| probe.method == "OPTIONS")
                .and_then(|probe| probe.status);
            println!(
                "{},{},{},{},{},{},{}",
                csv_escape(&report.target),
                status.map(|value| value.to_string()).unwrap_or_default(),
                csv_escape(report.allow.as_deref().unwrap_or_default()),
                csv_escape(&report.advertised.join(" ")),
                report.findings.len(),
                report.ok,
                csv_escape(report.error.as_deref().unwrap_or_default())
            );
        }
        Output::Text => {
            let status = report
                .probes
                .iter()
                .find(|probe| probe.method == "OPTIONS")
                .and_then(|probe| probe.status);
            println!(
                "METHOD-CHECK {} (status {}, {} probes, {} ms)",
                report.url,
                status
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "failed".into()),
                report.probes.len(),
                report.total_elapsed_ms
            );
            if report.advertised.is_empty() {
                println!("  advertised methods: none");
            } else {
                println!("  advertised methods: {}", report.advertised.join(", "));
            }
            for probe in &report.probes {
                println!(
                    "  {} {} ({} ms, allowed={})",
                    probe.method,
                    probe
                        .status
                        .map(|status| status.to_string())
                        .unwrap_or_else(|| "ERR".into()),
                    probe.elapsed_ms,
                    probe.allowed
                );
            }
            if report.findings.is_empty() {
                println!("  no method misconfiguration detected");
            } else {
                for finding in &report.findings {
                    println!(
                        "  FINDING [{}] {}: {}",
                        finding.severity, finding.code, finding.detail
                    );
                }
            }
        }
    }
}

//
// Consent-gated loopback load testing.
//
// Hard restrictions: only loopback targets (localhost/127.0.0.0/8/::1),
// sequential requests paced at a bounded rate (<= 50/s), and a bounded
// total request budget (<= 5000). No concurrency, no spoofing.
//

const ROTATING_USER_AGENTS: [&str; 16] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/138.0.0.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 15; Mobile; rv:140.0) Gecko/140.0 Firefox/140.0",
    "Mozilla/5.0 (iPad; CPU OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 OPR/122.0.0.0",
    "Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/138.0.0.0 Mobile Safari/537.36",
];

fn seed_random_state() -> u64 {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|value| value.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    time ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

fn random_index(state: &mut u64, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    ((*state >> 33) as usize) % len
}

fn pick_random_user_agent() -> &'static str {
    let mut state = seed_random_state();
    ROTATING_USER_AGENTS[random_index(&mut state, ROTATING_USER_AGENTS.len())]
}

fn ensure_loopback(host: &str, family: Family, command: &str) -> Result<(), String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !ip.is_loopback() {
            return Err(format!(
                "{command} only accepts loopback targets: localhost, 127.0.0.1, or ::1"
            ));
        }
    } else if !host.eq_ignore_ascii_case("localhost") {
        return Err(format!(
            "{command} refuses non-loopback target \"{host}\": only localhost, 127.0.0.1, or ::1 are allowed"
        ));
    }
    for address in resolve(host, 0, family)
        .map_err(|error| format!("DNS resolution failed: {error}"))?
        .iter()
    {
        if !address.ip().is_loopback() {
            return Err(format!("{command} refuses non-loopback address {address}"));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct LoadTestReport {
    schema_version: u8,
    version: String,
    target: String,
    rate: u32,
    requested: u32,
    sent: u32,
    ok: u32,
    failed: u32,
    statuses: BTreeMap<String, u32>,
    min_ms: Option<u128>,
    avg_ms: Option<u128>,
    max_ms: Option<u128>,
    rotate_user_agent: bool,
    random_user_agent: bool,
    first_error: Option<String>,
    total_elapsed_ms: u128,
    actual_rate: f64,
}

fn load_test(value: &str, opts: &Options) -> Result<LoadTestReport, String> {
    let started = Instant::now();
    let (host, port, url) = target(value)?;
    let url = url.unwrap_or_else(|| format!("http://{host}:{port}{}", opts.path));
    ensure_scope_host(&host, opts)?;
    ensure_loopback(&host, opts.family, "load-test")?;

    let interval = Duration::from_nanos(1_000_000_000 / u64::from(opts.rate).max(1));
    let mut sent = 0_u32;
    let mut ok = 0_u32;
    let mut latencies: Vec<u128> = Vec::new();
    let mut statuses: BTreeMap<String, u32> = BTreeMap::new();
    let mut first_error: Option<String> = None;
    let mut first_error_count = 0_u32;
    let mut ua_state = seed_random_state();

    for index in 0..opts.count {
        let tick = Instant::now();
        let effective = if opts.rotate_user_agent {
            let mut per_request = opts.clone();
            let index = if opts.random_user_agent {
                random_index(&mut ua_state, ROTATING_USER_AGENTS.len())
            } else {
                index as usize % ROTATING_USER_AGENTS.len()
            };
            per_request.user_agent = Some(ROTATING_USER_AGENTS[index].into());
            per_request
        } else {
            opts.clone()
        };
        let result = http_probe(&url, &host, port, &effective);
        sent += 1;
        match result.status {
            Some(status) => {
                if result.status_ok {
                    ok += 1;
                }
                *statuses.entry(status.to_string()).or_default() += 1;
            }
            None => {
                if first_error.is_some() {
                    first_error_count += 1;
                } else {
                    first_error_count = 1;
                    first_error = result.error.clone();
                }
            }
        }
        latencies.push(result.elapsed_ms);
        let spent = tick.elapsed();
        if spent < interval {
            thread::sleep(interval - spent);
        }
    }

    let total_elapsed = started.elapsed().as_millis().max(1);
    Ok(LoadTestReport {
        schema_version: 1,
        version: VERSION.into(),
        target: value.into(),
        rate: opts.rate,
        requested: opts.count,
        sent,
        ok,
        failed: sent - ok,
        statuses,
        min_ms: latencies.iter().min().copied(),
        avg_ms: Some(latencies.iter().sum::<u128>() / latencies.len().max(1) as u128),
        max_ms: latencies.iter().max().copied(),
        rotate_user_agent: opts.rotate_user_agent,
        random_user_agent: opts.random_user_agent,
        first_error: first_error.map(|error| {
            if first_error_count > 1 {
                format!("{error} (+{first_error_count} more times)")
            } else {
                error
            }
        }),
        total_elapsed_ms: total_elapsed,
        actual_rate: sent as f64 / (total_elapsed as f64 / 1000.0),
    })
}

fn diagnose(value: &str, opts: &Options) -> Result<DiagnosticReport, String> {
    let started = Instant::now();
    let (host, port, url) = target(value)?;
    scope_precheck_host(&host, opts)?;
    let resolved =
        resolve(&host, port, opts.family).map_err(|e| format!("DNS resolution failed: {e}"))?;
    if resolved.is_empty() {
        return Err("DNS resolution returned no addresses".into());
    }
    scope_allows(&host, &resolved, opts)?;
    let results = addresses(&resolved, opts);
    let connected = results.iter().any(|v| v.connected);
    let http = url.as_deref().map(|v| http_probe(v, &host, port, opts));
    let http_ok = http.as_ref().is_none_or(|v| v.status_ok);
    Ok(DiagnosticReport {
        schema_version: 1,
        version: VERSION.into(),
        target: value.into(),
        host,
        port,
        resolved: results,
        http,
        ok: connected && http_ok,
        total_elapsed_ms: started.elapsed().as_millis(),
        error: if connected && http_ok {
            None
        } else {
            Some("one or more diagnostic phases failed".into())
        },
    })
}

fn print_report(report: &DiagnosticReport, opts: &Options) {
    if opts.quiet {
        return;
    }
    if opts.output == Output::Json {
        println!("{}", serde_json::to_string_pretty(report).unwrap());
        return;
    }
    println!(
        "{} {} ({} ms)",
        if report.ok { "OK" } else { "FAIL" },
        report.target,
        report.total_elapsed_ms
    );
    println!("DNS: {} address(es)", report.resolved.len());
    for result in &report.resolved {
        if result.connected {
            println!(
                "  {} {} open ({} ms)",
                result.family, result.address, result.elapsed_ms
            );
        } else if opts.verbose {
            println!(
                "  {} {} failed ({} ms): {}",
                result.family,
                result.address,
                result.elapsed_ms,
                result.error.as_deref().unwrap_or("unknown error")
            );
        }
    }
    if let Some(http) = &report.http {
        println!(
            "HTTP: {}{}",
            http.status
                .map(|v| v.to_string())
                .unwrap_or_else(|| "failed".into()),
            http.status_text
                .as_deref()
                .map(|v| format!(" {v}"))
                .unwrap_or_default()
        );
        for (name, value) in &http.headers {
            println!("  {name}: {value}");
        }
        if let Some(checks) = &http.security_headers {
            let present = checks.iter().filter(|check| check.present).count();
            println!(
                "  security headers: {present}/{} (score {}/100, grade {})",
                checks.len(),
                http.security_score.unwrap_or(0),
                http.security_grade.as_deref().unwrap_or("?")
            );
            for check in checks {
                match &check.value {
                    Some(value) => println!("    {}: present ({value})", check.name),
                    None => println!("    {}: missing", check.name),
                }
            }
        }
        if let Some(size) = http.body_size {
            println!("  body: {size} bytes");
        }
        if let Some(error) = &http.body_read_error {
            println!("  body error: {error}");
        }
        if let Some(preview) = &http.body_preview {
            println!("  body preview: {preview}");
        }
        if let Some(certificate) = &http.certificate {
            println!(
                "TLS: {} -> {} (expires {}) serial {}",
                certificate.subject, certificate.issuer, certificate.not_after, certificate.serial
            );
            if !certificate.sans.is_empty() {
                println!("  SANs: {}", certificate.sans.join(", "));
            }
            if let Some(protocol) = &certificate.protocol {
                println!("  TLS protocol: {protocol}");
            }
            if let Some(cipher) = &certificate.cipher_suite {
                println!("  cipher suite: {cipher}");
            }
        }
        if let Some(error) = &http.certificate_error {
            println!("  TLS error: {error}");
        }
    }
}

fn md_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
}

fn md_code(value: &str) -> String {
    format!("`{}`", value.replace('`', "'"))
}

fn short_value(value: &str, limit: usize) -> String {
    let truncated = value.chars().take(limit).collect::<String>();
    if value.chars().count() > limit {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn format_unix_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3_600,
        (remainder % 3_600) / 60,
        remainder % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn markdown_report(report: &DiagnosticReport, opts: &Options) -> String {
    let generated = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    let connected = report
        .resolved
        .iter()
        .filter(|value| value.connected)
        .count();
    let mut out = String::new();
    out.push_str("# ddos assessment report\n\n");
    out.push_str(&format!("- **Target:** {}\n", md_code(&report.target)));
    out.push_str(&format!(
        "- **Tool version:** {}\n",
        md_code(&report.version)
    ));
    out.push_str(&format!(
        "- **Generated:** {}\n",
        md_code(&format_unix_utc(generated))
    ));
    if let Some(scope) = &opts.scope {
        out.push_str(&format!(
            "- **Scope:** {}\n",
            md_code(&scope.source.display().to_string())
        ));
    }
    out.push_str(&format!(
        "- **Result:** **{}**\n\n",
        if report.ok { "PASS" } else { "FAIL" }
    ));
    out.push_str("## Summary\n\n| Check | Result | Detail |\n| --- | --- | --- |\n");
    out.push_str(&format!(
        "| DNS | {} | {} address(es) |\n",
        if report.resolved.is_empty() {
            "FAIL"
        } else {
            "PASS"
        },
        report.resolved.len()
    ));
    out.push_str(&format!(
        "| TCP | {} | {} of {} addresses open |\n",
        if connected > 0 { "PASS" } else { "FAIL" },
        connected,
        report.resolved.len()
    ));
    if let Some(http) = &report.http {
        let status = match (http.status, &http.status_text) {
            (Some(code), Some(text)) => format!("{code} {text}"),
            (Some(code), None) => code.to_string(),
            _ => "request failed".into(),
        };
        out.push_str(&format!(
            "| HTTP | {} | {} |\n",
            if http.status_ok { "PASS" } else { "FAIL" },
            md_cell(&status)
        ));
    } else {
        out.push_str("| HTTP | N/A | no HTTP/HTTPS URL requested |\n");
    }
    if let Some(http) = &report.http {
        match (&http.certificate, &http.certificate_error) {
            (Some(certificate), _) => out.push_str(&format!(
                "| TLS | {} | {} expires {} |\n",
                if certificate.expired { "FAIL" } else { "PASS" },
                md_cell(&certificate.subject),
                md_cell(&certificate.not_after)
            )),
            (None, Some(error)) => out.push_str(&format!("| TLS | FAIL | {} |\n", md_cell(error))),
            (None, None) => out.push_str("| TLS | N/A | not an HTTPS target |\n"),
        }
        if let Some(checks) = &http.security_headers {
            let present = checks.iter().filter(|value| value.present).count();
            out.push_str(&format!(
                "| Security headers | {} | {} of {} present (grade {}, {}/100) |\n",
                if present == checks.len() {
                    "PASS"
                } else {
                    "WARN"
                },
                present,
                checks.len(),
                http.security_grade.as_deref().unwrap_or("?"),
                http.security_score.unwrap_or(0)
            ));
        } else {
            out.push_str("| Security headers | N/A | header audit not enabled |\n");
        }
    } else {
        out.push_str("| TLS | N/A | no HTTP/HTTPS URL requested |\n");
        out.push_str("| Security headers | N/A | no HTTP/HTTPS URL requested |\n");
    }
    out.push_str("\n## Addresses\n\n");
    if report.resolved.is_empty() {
        out.push_str("No addresses returned.\n");
    } else {
        out.push_str("| Family | Address | Open | Latency |\n| --- | --- | --- | --- |\n");
        for result in &report.resolved {
            out.push_str(&format!(
                "| {} | {} | {} | {} ms |\n",
                result.family,
                md_code(&result.address),
                if result.connected { "yes" } else { "no" },
                result.elapsed_ms
            ));
        }
    }
    if let Some(http) = &report.http {
        out.push_str("\n## HTTP\n\n");
        out.push_str(&format!("- **URL:** {}\n", md_code(&http.url)));
        out.push_str(&format!(
            "- **Status:** {}\n",
            http.status
                .map(|value| value.to_string())
                .unwrap_or_else(|| "failed".into())
        ));
        if let Some(text) = &http.status_text {
            out.push_str(&format!("- **Status text:** {}\n", md_cell(text)));
        }
        if let Some(size) = http.body_size {
            out.push_str(&format!("- **Body bytes read:** {size}\n"));
        }
        if let Some(error) = &http.error {
            out.push_str(&format!("- **Error:** {}\n", md_cell(error)));
        }
        if let Some(checks) = &http.security_headers {
            out.push_str(&format!(
                "\n### Security headers (grade {}, {}/100)\n\n| Header | Present | Value |\n| --- | --- | --- |\n",
                http.security_grade.as_deref().unwrap_or("?"),
                http.security_score.unwrap_or(0)
            ));
            for check in checks {
                let value = check
                    .value
                    .as_deref()
                    .map(|value| short_value(value, 120))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "| {} | {} | {} |\n",
                    md_code(&check.name),
                    if check.present { "yes" } else { "no" },
                    md_cell(&value)
                ));
            }
        }
    }
    if let Some(certificate) = report
        .http
        .as_ref()
        .and_then(|value| value.certificate.as_ref())
    {
        out.push_str("\n## TLS certificate\n\n");
        out.push_str(&format!(
            "- **Subject:** {}\n",
            md_cell(&certificate.subject)
        ));
        out.push_str(&format!("- **Issuer:** {}\n", md_cell(&certificate.issuer)));
        out.push_str(&format!("- **Serial:** {}\n", md_code(&certificate.serial)));
        out.push_str(&format!(
            "- **Valid from:** {}\n",
            md_cell(&certificate.not_before)
        ));
        out.push_str(&format!(
            "- **Expires:** {}\n",
            md_cell(&certificate.not_after)
        ));
        out.push_str(&format!("- **Expired:** {}\n", certificate.expired));
        if let Some(protocol) = &certificate.protocol {
            out.push_str(&format!("- **Protocol:** {}\n", md_code(protocol)));
        }
        if let Some(cipher) = &certificate.cipher_suite {
            out.push_str(&format!("- **Cipher suite:** {}\n", md_code(cipher)));
        }
        if !certificate.sans.is_empty() {
            out.push_str(&format!(
                "- **SANs:** {}\n",
                md_cell(&certificate.sans.join(", "))
            ));
        }
    }
    out.push_str("\n## Notes\n\nAutomated, bounded checks only. This report does not exploit findings, scan ranges, or replace a full manual assessment.\n");
    out
}

fn print_markdown_report(report: &DiagnosticReport, opts: &Options) {
    if opts.quiet {
        return;
    }
    print!("{}", markdown_report(report, opts));
}

fn print_report_csv_header() {
    println!("target,ok,host,port,total_elapsed_ms,addresses,connected,http_status,error");
}

fn print_report_csv_row(report: &DiagnosticReport) {
    let connected = report.resolved.iter().filter(|v| v.connected).count();
    println!(
        "{},{},{},{},{},{},{},{},{}",
        csv_escape(&report.target),
        report.ok,
        csv_escape(&report.host),
        report.port,
        report.total_elapsed_ms,
        report.resolved.len(),
        connected,
        report
            .http
            .as_ref()
            .and_then(|v| v.status)
            .map(|v| v.to_string())
            .unwrap_or_default(),
        csv_escape(report.error.as_deref().unwrap_or_default())
    );
}

fn print_report_csv(report: &DiagnosticReport) {
    print_report_csv_header();
    print_report_csv_row(report);
}

/// Emit one DiagnosticReport in the configured output format.
fn print_report_one(report: &DiagnosticReport, opts: &Options) {
    match opts.output {
        Output::Json => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        Output::Jsonl => {
            if let Ok(line) = serde_json::to_string(report) {
                println!("{line}");
            }
        }
        Output::Csv => print_report_csv(report),
        Output::Text => print_report(report, opts),
    }
}

fn print_udp_report(report: &UdpReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Text => {
            println!(
                "{} {} ({} ms)",
                if report.ok { "OK" } else { "FAIL" },
                report.target,
                report.total_elapsed_ms
            );
            for attempt in &report.attempts {
                if attempt.received {
                    println!(
                        "  {} {} answered ({} ms, {} bytes)",
                        attempt.family,
                        attempt.address,
                        attempt.elapsed_ms,
                        attempt.response_bytes.unwrap_or_default()
                    );
                } else if opts.verbose {
                    println!(
                        "  {} {} no answer ({} ms): {}",
                        attempt.family,
                        attempt.address,
                        attempt.elapsed_ms,
                        attempt.error.as_deref().unwrap_or("unknown error")
                    );
                }
            }
        }
        Output::Json => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        Output::Jsonl => {
            if let Ok(line) = serde_json::to_string(report) {
                println!("{line}");
            }
        }
        Output::Csv => {
            println!("target,address,family,sent,received,elapsed_ms,response_bytes,response_preview,error");
            for attempt in &report.attempts {
                println!(
                    "{},{},{},{},{},{},{},{},{}",
                    csv_escape(&report.target),
                    csv_escape(&attempt.address),
                    attempt.family,
                    attempt.sent,
                    attempt.received,
                    attempt.elapsed_ms,
                    attempt
                        .response_bytes
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                    csv_escape(attempt.response_preview.as_deref().unwrap_or_default()),
                    csv_escape(attempt.error.as_deref().unwrap_or_default()),
                );
            }
        }
    }
}

fn print_load_test_report(report: &LoadTestReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).expect("report serializes")
            );
        }
        Output::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(report).expect("report serializes")
            );
        }
        Output::Csv => {
            println!("target,requested,sent,ok,failed,avg_ms,max_ms,total_elapsed_ms,actual_rate");
            println!(
                "{},{},{},{},{},{},{},{},{:.1}",
                csv_escape(&report.target),
                report.requested,
                report.sent,
                report.ok,
                report.failed,
                report.avg_ms.unwrap_or_default(),
                report.max_ms.unwrap_or_default(),
                report.total_elapsed_ms,
                report.actual_rate
            );
        }
        Output::Text => {
            println!(
                "LOAD-TEST {} sent {} ok {} failed {} ({} ms total, {:.1} req/s actual, target {} req/s)",
                report.target,
                report.sent,
                report.ok,
                report.failed,
                report.total_elapsed_ms,
                report.actual_rate,
                report.rate
            );
            let statuses = report
                .statuses
                .iter()
                .map(|(status, count)| format!("{status}x{count}"))
                .collect::<Vec<_>>()
                .join(" ");
            if !statuses.is_empty() {
                println!("  statuses: {statuses}");
            }
            println!(
                "  latency min {} ms avg {} ms max {} ms{}",
                report.min_ms.unwrap_or_default(),
                report.avg_ms.unwrap_or_default(),
                report.max_ms.unwrap_or_default(),
                if report.random_user_agent {
                    " (user agents randomized)"
                } else if report.rotate_user_agent {
                    " (user agents rotated)"
                } else {
                    ""
                }
            );
            if let Some(error) = &report.first_error {
                println!("  first error: {error}");
            }
        }
    }
}

// --- Bounded capacity and resilience tests ---------------------------------
//
// Every command in this section is loopback-only, runs without concurrency,
// and stays inside hard request, connection, and duration budgets. They are
// measurement tools for servers you run yourself, not traffic generators.

fn percentile(values: &[u128], percent: u64) -> Option<u128> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (sorted.len() as u64 * percent.min(100)) / 100;
    let index = rank.saturating_sub(1) as usize;
    Some(sorted[index.min(sorted.len() - 1)])
}

fn loopback_address(host: &str, port: u16, opts: &Options) -> Result<SocketAddr, String> {
    let resolved = resolve(host, port, opts.family)
        .map_err(|error| format!("DNS resolution failed: {error}"))?;
    resolved
        .iter()
        .find(|address| address.ip().is_loopback())
        .copied()
        .ok_or_else(|| format!("no loopback address found for {host}"))
}

#[derive(Serialize)]
struct CapacityStep {
    step: u32,
    target_rate: u32,
    requests: u32,
    ok: u32,
    failed: u32,
    avg_ms: Option<u128>,
    p95_ms: Option<u128>,
    max_ms: Option<u128>,
    achieved_rate: f64,
    degraded: bool,
}

#[derive(Serialize)]
struct CapacityReport {
    schema_version: u8,
    version: String,
    target: String,
    max_rate: u32,
    budget: u32,
    steps: Vec<CapacityStep>,
    total_requests: u32,
    total_ok: u32,
    total_failed: u32,
    stopped_early: bool,
    stop_reason: Option<String>,
    total_elapsed_ms: u128,
}

/// Ramp the request rate in steps and record where the target starts to
/// degrade. Stops at the first step that shows errors or high latency.
fn capacity_test(value: &str, opts: &Options) -> Result<CapacityReport, String> {
    let started = Instant::now();
    let (host, port, url) = target(value)?;
    let url = url.unwrap_or_else(|| format!("http://{host}:{port}{}", opts.path));
    ensure_scope_host(&host, opts)?;
    ensure_loopback(&host, opts.family, "capacity-test")?;

    let max_rate = opts.rate.min(MAX_LOAD_RATE as u32).max(1);
    let budget = opts.count.min(MAX_CAPACITY_REQUESTS as u32);
    let step_count = opts.steps.clamp(1, MAX_CAPACITY_STEPS as u32);
    let per_step = (budget / step_count).max(1);

    let mut rows: Vec<CapacityStep> = Vec::new();
    let mut total_ok = 0_u32;
    let mut total_failed = 0_u32;
    let mut stopped_early = false;
    let mut stop_reason: Option<String> = None;

    for index in 0..step_count {
        let target_rate =
            ((u64::from(max_rate) * u64::from(index + 1)) / u64::from(step_count)).max(1) as u32;
        let interval = Duration::from_nanos(1_000_000_000 / u64::from(target_rate));
        let step_started = Instant::now();
        let mut ok = 0_u32;
        let mut failed = 0_u32;
        let mut latencies: Vec<u128> = Vec::new();
        for _ in 0..per_step {
            let tick = Instant::now();
            let result = http_probe(&url, &host, port, opts);
            match result.status {
                Some(status) if status < 500 => ok += 1,
                _ => failed += 1,
            }
            latencies.push(result.elapsed_ms);
            let spent = tick.elapsed();
            if spent < interval {
                thread::sleep(interval - spent);
            }
        }
        let elapsed = step_started.elapsed().as_millis().max(1);
        let avg = Some(latencies.iter().sum::<u128>() / latencies.len().max(1) as u128);
        let p95 = percentile(&latencies, 95);
        let max = latencies.iter().max().copied();
        let error_percent = u64::from(failed) * 100 / u64::from(per_step);
        let degraded = (failed > 0 && error_percent >= DEGRADED_ERROR_PERCENT)
            || p95
                .map(|value| value >= DEGRADED_LATENCY_MS)
                .unwrap_or(false);
        total_ok += ok;
        total_failed += failed;
        rows.push(CapacityStep {
            step: index + 1,
            target_rate,
            requests: per_step,
            ok,
            failed,
            avg_ms: avg,
            p95_ms: p95,
            max_ms: max,
            achieved_rate: f64::from(per_step) / (elapsed as f64 / 1000.0),
            degraded,
        });
        if degraded {
            stopped_early = true;
            stop_reason = Some(format!(
                "step {} degraded at {} req/s ({} of {} failed, p95 {} ms)",
                index + 1,
                target_rate,
                failed,
                per_step,
                p95.unwrap_or_default()
            ));
            break;
        }
    }

    Ok(CapacityReport {
        schema_version: 1,
        version: VERSION.into(),
        target: value.into(),
        max_rate,
        budget,
        total_requests: total_ok + total_failed,
        total_ok,
        total_failed,
        steps: rows,
        stopped_early,
        stop_reason,
        total_elapsed_ms: started.elapsed().as_millis(),
    })
}

#[derive(Serialize)]
struct ChurnReport {
    schema_version: u8,
    version: String,
    target: String,
    attempted: u32,
    connected: u32,
    failed: u32,
    avg_connect_ms: Option<u128>,
    p95_connect_ms: Option<u128>,
    max_connect_ms: Option<u128>,
    first_failure_at: Option<u32>,
    first_error: Option<String>,
    total_elapsed_ms: u128,
}

/// Open and immediately close TCP connections to expose accept-backlog and
/// file-descriptor limits. Sequential and rate limited.
fn connection_churn(host: &str, port: u16, opts: &Options) -> Result<ChurnReport, String> {
    let started = Instant::now();
    ensure_scope_host(host, opts)?;
    ensure_loopback(host, opts.family, "connection-churn")?;
    let address = loopback_address(host, port, opts)?;
    let count = opts.count.min(MAX_CHURN_CONNECTIONS as u32);
    let interval =
        Duration::from_nanos(1_000_000_000 / u64::from(opts.rate.clamp(1, MAX_LOAD_RATE as u32)));

    let mut connected = 0_u32;
    let mut failed = 0_u32;
    let mut latencies: Vec<u128> = Vec::new();
    let mut first_failure_at: Option<u32> = None;
    let mut first_error: Option<String> = None;

    for index in 0..count {
        let tick = Instant::now();
        match TcpStream::connect_timeout(&address, opts.timeout) {
            Ok(stream) => {
                connected += 1;
                latencies.push(tick.elapsed().as_millis());
                drop(stream);
            }
            Err(error) => {
                failed += 1;
                if first_failure_at.is_none() {
                    first_failure_at = Some(index + 1);
                    first_error = Some(error.to_string());
                }
            }
        }
        let spent = tick.elapsed();
        if spent < interval {
            thread::sleep(interval - spent);
        }
    }

    Ok(ChurnReport {
        schema_version: 1,
        version: VERSION.into(),
        target: format!("{host}:{port}"),
        attempted: count,
        connected,
        failed,
        avg_connect_ms: Some(latencies.iter().sum::<u128>() / latencies.len().max(1) as u128),
        p95_connect_ms: percentile(&latencies, 95),
        max_connect_ms: latencies.iter().max().copied(),
        first_failure_at,
        first_error,
        total_elapsed_ms: started.elapsed().as_millis(),
    })
}

#[derive(Serialize)]
struct SlowClientResult {
    id: u32,
    connected: bool,
    bytes_sent: usize,
    server_closed_after_ms: Option<u128>,
    elapsed_ms: u128,
    error: Option<String>,
}

#[derive(Serialize)]
struct SlowRequestReport {
    schema_version: u8,
    version: String,
    target: String,
    clients: u32,
    hold_seconds: u64,
    results: Vec<SlowClientResult>,
    server_closed: u32,
    still_open: u32,
    total_elapsed_ms: u128,
}

/// Hold a small number of incomplete HTTP requests open to find out how long
/// the server keeps a slow client before it times out. Client count and hold
/// time are hard-capped, and only loopback targets are accepted.
fn slow_request(host: &str, port: u16, opts: &Options) -> Result<SlowRequestReport, String> {
    let started = Instant::now();
    ensure_scope_host(host, opts)?;
    ensure_loopback(host, opts.family, "slow-request")?;
    let address = loopback_address(host, port, opts)?;
    let clients = opts.clients.clamp(1, MAX_SLOW_CLIENTS as u32);
    let hold = opts.hold_seconds.clamp(1, MAX_SLOW_HOLD_SECONDS);
    let path = opts.path.clone();
    let host_name = host.to_string();
    let timeout = opts.timeout;

    let mut handles = Vec::new();
    for index in 0..clients {
        let path = path.clone();
        let host_name = host_name.clone();
        handles.push(thread::spawn(move || {
            let client_started = Instant::now();
            let mut result = SlowClientResult {
                id: index + 1,
                connected: false,
                bytes_sent: 0,
                server_closed_after_ms: None,
                elapsed_ms: 0,
                error: None,
            };
            let mut stream = match TcpStream::connect_timeout(&address, timeout) {
                Ok(stream) => stream,
                Err(error) => {
                    result.error = Some(error.to_string());
                    result.elapsed_ms = client_started.elapsed().as_millis();
                    return result;
                }
            };
            result.connected = true;
            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
            let _ = stream.set_write_timeout(Some(timeout));
            let head = format!("GET {path} HTTP/1.1\r\nHost: {host_name}\r\n");
            if let Err(error) = stream.write_all(head.as_bytes()) {
                result.error = Some(error.to_string());
                result.elapsed_ms = client_started.elapsed().as_millis();
                return result;
            }
            result.bytes_sent += head.len();
            let deadline = Instant::now() + Duration::from_secs(hold);
            let mut last_send = Instant::now();
            while Instant::now() < deadline {
                let mut buffer = [0_u8; 64];
                match stream.read(&mut buffer) {
                    Ok(0) => {
                        result.server_closed_after_ms = Some(client_started.elapsed().as_millis());
                        break;
                    }
                    Ok(_) => {
                        result.server_closed_after_ms = Some(client_started.elapsed().as_millis());
                        break;
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            || error.kind() == io::ErrorKind::TimedOut => {}
                    Err(error) => {
                        result.error = Some(error.to_string());
                        break;
                    }
                }
                if last_send.elapsed() >= Duration::from_millis(500) {
                    let filler = b"X-Slow: a\r\n";
                    if let Err(error) = stream.write_all(filler) {
                        result.error = Some(error.to_string());
                        break;
                    }
                    result.bytes_sent += filler.len();
                    last_send = Instant::now();
                }
                thread::sleep(Duration::from_millis(50));
            }
            result.elapsed_ms = client_started.elapsed().as_millis();
            result
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(result) => results.push(result),
            Err(_) => results.push(SlowClientResult {
                id: 0,
                connected: false,
                bytes_sent: 0,
                server_closed_after_ms: None,
                elapsed_ms: 0,
                error: Some("client thread panicked".into()),
            }),
        }
    }
    results.sort_by_key(|result| result.id);
    let server_closed = results
        .iter()
        .filter(|result| result.server_closed_after_ms.is_some())
        .count() as u32;
    let still_open = results
        .iter()
        .filter(|result| result.connected && result.server_closed_after_ms.is_none())
        .count() as u32;

    Ok(SlowRequestReport {
        schema_version: 1,
        version: VERSION.into(),
        target: format!("{host}:{port}"),
        clients,
        hold_seconds: hold,
        results,
        server_closed,
        still_open,
        total_elapsed_ms: started.elapsed().as_millis(),
    })
}

#[derive(Clone)]
struct ShapeVariant {
    label: String,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Serialize)]
struct ShapeCase {
    index: u32,
    label: String,
    method: String,
    path: String,
    status: Option<u16>,
    elapsed_ms: u128,
    error: Option<String>,
}

#[derive(Serialize)]
struct ShapeReport {
    schema_version: u8,
    version: String,
    target: String,
    cases: Vec<ShapeCase>,
    total: u32,
    successes: u32,
    client_errors: u32,
    server_errors: u32,
    transport_errors: u32,
    first_error: Option<String>,
    total_elapsed_ms: u128,
}

fn shape_variants(path: &str) -> Vec<ShapeVariant> {
    let long_query = format!("/?q={}", "a".repeat(512));
    let long_path = format!("/{}", "segment/".repeat(96));
    let long_value = "v".repeat(1024);
    vec![
        ShapeVariant {
            label: "baseline GET".into(),
            method: "GET".into(),
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        },
        ShapeVariant {
            label: "HEAD request".into(),
            method: "HEAD".into(),
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        },
        ShapeVariant {
            label: "POST with small body".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: b"hello".to_vec(),
        },
        ShapeVariant {
            label: "PUT with json body".into(),
            method: "PUT".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: b"{\"probe\":1}".to_vec(),
        },
        ShapeVariant {
            label: "DELETE request".into(),
            method: "DELETE".into(),
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        },
        ShapeVariant {
            label: "OPTIONS request".into(),
            method: "OPTIONS".into(),
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        },
        ShapeVariant {
            label: "PATCH request".into(),
            method: "PATCH".into(),
            path: path.into(),
            headers: Vec::new(),
            body: b"x".to_vec(),
        },
        ShapeVariant {
            label: "long query string".into(),
            method: "GET".into(),
            path: long_query,
            headers: Vec::new(),
            body: Vec::new(),
        },
        ShapeVariant {
            label: "long path".into(),
            method: "GET".into(),
            path: long_path,
            headers: Vec::new(),
            body: Vec::new(),
        },
        ShapeVariant {
            label: "encoded space in path".into(),
            method: "GET".into(),
            path: "/path%20with%20spaces".into(),
            headers: Vec::new(),
            body: Vec::new(),
        },
        ShapeVariant {
            label: "null byte in path".into(),
            method: "GET".into(),
            path: "/a%00b".into(),
            headers: Vec::new(),
            body: Vec::new(),
        },
        ShapeVariant {
            label: "invalid utf-8 in path".into(),
            method: "GET".into(),
            path: "/%ff%fe".into(),
            headers: Vec::new(),
            body: Vec::new(),
        },
        ShapeVariant {
            label: "long header value".into(),
            method: "GET".into(),
            path: path.into(),
            headers: vec![("X-Long".into(), long_value)],
            body: Vec::new(),
        },
        ShapeVariant {
            label: "empty header value".into(),
            method: "GET".into(),
            path: path.into(),
            headers: vec![("X-Empty".into(), String::new())],
            body: Vec::new(),
        },
        ShapeVariant {
            label: "duplicate header names".into(),
            method: "GET".into(),
            path: path.into(),
            headers: vec![("X-Dup".into(), "1".into()), ("X-Dup".into(), "2".into())],
            body: Vec::new(),
        },
        ShapeVariant {
            label: "oversized body".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            body: vec![b'a'; 4096],
        },
    ]
}

/// Send a fixed set of request shapes to a server and record how it reacts to
/// unusual methods, paths, headers, and bodies.
fn request_shape(value: &str, opts: &Options) -> Result<ShapeReport, String> {
    let started = Instant::now();
    let (host, port, _url) = target(value)?;
    let scheme = if value.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    let base = format!("{scheme}://{host}:{port}");
    ensure_scope_host(&host, opts)?;
    ensure_loopback(&host, opts.family, "request-shape")?;

    let count = opts.count.min(MAX_SHAPE_REQUESTS as u32);
    let variants = shape_variants(&opts.path);
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(opts.timeout)
        .timeout_read(opts.timeout)
        .timeout_write(opts.timeout)
        .redirects(0)
        .user_agent(USER_AGENT)
        .build();

    let mut cases: Vec<ShapeCase> = Vec::new();
    let mut successes = 0_u32;
    let mut client_errors = 0_u32;
    let mut server_errors = 0_u32;
    let mut transport_errors = 0_u32;
    let mut first_error: Option<String> = None;

    for index in 0..count {
        let variant = &variants[(index as usize) % variants.len()];
        let url = format!("{base}{}", variant.path);
        let case_started = Instant::now();
        let mut request = agent.request(&variant.method, &url);
        for (name, value) in &variant.headers {
            request = request.set(name, value);
        }
        let outcome = if variant.body.is_empty() {
            request.call()
        } else {
            request.send_bytes(&variant.body)
        };
        let (status, error) = match outcome {
            Ok(response) => (Some(response.status()), None),
            Err(ureq::Error::Status(code, _)) => (Some(code), None),
            Err(error) => (None, Some(error.to_string())),
        };
        match status {
            Some(code) if (200..300).contains(&code) => successes += 1,
            Some(code) if (400..500).contains(&code) => client_errors += 1,
            Some(code) if code >= 500 => server_errors += 1,
            Some(_) => {}
            None => {
                transport_errors += 1;
                if first_error.is_none() {
                    first_error = error.clone();
                }
            }
        }
        cases.push(ShapeCase {
            index: index + 1,
            label: variant.label.clone(),
            method: variant.method.clone(),
            path: variant.path.clone(),
            status,
            elapsed_ms: case_started.elapsed().as_millis(),
            error,
        });
    }

    Ok(ShapeReport {
        schema_version: 1,
        version: VERSION.into(),
        target: value.into(),
        total: count,
        successes,
        client_errors,
        server_errors,
        transport_errors,
        cases,
        first_error,
        total_elapsed_ms: started.elapsed().as_millis(),
    })
}

fn print_capacity_report(report: &CapacityReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).expect("report serializes")
            );
        }
        Output::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(report).expect("report serializes")
            );
        }
        Output::Csv => {
            println!("target,step,target_rate,requests,ok,failed,avg_ms,p95_ms,max_ms,achieved_rate,degraded");
            for step in &report.steps {
                println!(
                    "{},{},{},{},{},{},{},{},{},{:.1},{}",
                    csv_escape(&report.target),
                    step.step,
                    step.target_rate,
                    step.requests,
                    step.ok,
                    step.failed,
                    step.avg_ms.unwrap_or_default(),
                    step.p95_ms.unwrap_or_default(),
                    step.max_ms.unwrap_or_default(),
                    step.achieved_rate,
                    step.degraded
                );
            }
        }
        Output::Text => {
            println!(
                "CAPACITY-TEST {} max {} req/s, {} requests, {} ok, {} failed ({} ms total)",
                report.target,
                report.max_rate,
                report.total_requests,
                report.total_ok,
                report.total_failed,
                report.total_elapsed_ms
            );
            for step in &report.steps {
                println!(
                    "  step {} target {} req/s: {} requests, {} ok, {} failed, avg {} ms, p95 {} ms, max {} ms, {:.1} req/s actual{}",
                    step.step,
                    step.target_rate,
                    step.requests,
                    step.ok,
                    step.failed,
                    step.avg_ms.unwrap_or_default(),
                    step.p95_ms.unwrap_or_default(),
                    step.max_ms.unwrap_or_default(),
                    step.achieved_rate,
                    if step.degraded { " [degraded]" } else { "" }
                );
            }
            if let Some(reason) = &report.stop_reason {
                println!("  stopped early: {reason}");
            }
        }
    }
}

fn print_churn_report(report: &ChurnReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).expect("report serializes")
            );
        }
        Output::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(report).expect("report serializes")
            );
        }
        Output::Csv => {
            println!("target,attempted,connected,failed,avg_connect_ms,p95_connect_ms,max_connect_ms,first_failure_at,total_elapsed_ms");
            println!(
                "{},{},{},{},{},{},{},{},{}",
                csv_escape(&report.target),
                report.attempted,
                report.connected,
                report.failed,
                report.avg_connect_ms.unwrap_or_default(),
                report.p95_connect_ms.unwrap_or_default(),
                report.max_connect_ms.unwrap_or_default(),
                report
                    .first_failure_at
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                report.total_elapsed_ms
            );
        }
        Output::Text => {
            println!(
                "CONNECTION-CHURN {} attempted {} connected {} failed {} ({} ms total)",
                report.target,
                report.attempted,
                report.connected,
                report.failed,
                report.total_elapsed_ms
            );
            println!(
                "  connect latency avg {} ms p95 {} ms max {} ms",
                report.avg_connect_ms.unwrap_or_default(),
                report.p95_connect_ms.unwrap_or_default(),
                report.max_connect_ms.unwrap_or_default()
            );
            if let Some(attempt) = report.first_failure_at {
                println!(
                    "  first failure at connection {attempt}: {}",
                    report.first_error.as_deref().unwrap_or("unknown error")
                );
            } else {
                println!("  no connection failures observed");
            }
        }
    }
}

fn print_slow_report(report: &SlowRequestReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).expect("report serializes")
            );
        }
        Output::Jsonl => {
            for result in &report.results {
                if let Ok(line) = serde_json::to_string(result) {
                    println!("{line}");
                }
            }
        }
        Output::Csv => {
            println!("target,client,connected,bytes_sent,server_closed_after_ms,elapsed_ms,error");
            for result in &report.results {
                println!(
                    "{},{},{},{},{},{},{}",
                    csv_escape(&report.target),
                    result.id,
                    result.connected,
                    result.bytes_sent,
                    result
                        .server_closed_after_ms
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    result.elapsed_ms,
                    csv_escape(result.error.as_deref().unwrap_or(""))
                );
            }
        }
        Output::Text => {
            println!(
                "SLOW-REQUEST {} clients {} hold {}s: {} closed by server, {} still open ({} ms total)",
                report.target,
                report.clients,
                report.hold_seconds,
                report.server_closed,
                report.still_open,
                report.total_elapsed_ms
            );
            for result in &report.results {
                println!(
                    "  client {}: connected {}, sent {} bytes, server closed after {} ms{}",
                    result.id,
                    result.connected,
                    result.bytes_sent,
                    result
                        .server_closed_after_ms
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "never".into()),
                    match &result.error {
                        Some(error) => format!(" (error: {error})"),
                        None => String::new(),
                    }
                );
            }
        }
    }
}

fn print_shape_report(report: &ShapeReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).expect("report serializes")
            );
        }
        Output::Jsonl => {
            for case in &report.cases {
                if let Ok(line) = serde_json::to_string(case) {
                    println!("{line}");
                }
            }
        }
        Output::Csv => {
            println!("index,label,method,path,status,elapsed_ms,error");
            for case in &report.cases {
                println!(
                    "{},{},{},{},{},{},{}",
                    case.index,
                    csv_escape(&case.label),
                    csv_escape(&case.method),
                    csv_escape(&case.path),
                    case.status
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    case.elapsed_ms,
                    csv_escape(case.error.as_deref().unwrap_or(""))
                );
            }
        }
        Output::Text => {
            println!(
                "REQUEST-SHAPE {} {} requests: {} ok, {} client errors, {} server errors, {} transport errors ({} ms total)",
                report.target,
                report.total,
                report.successes,
                report.client_errors,
                report.server_errors,
                report.transport_errors,
                report.total_elapsed_ms
            );
            for case in &report.cases {
                println!(
                    "  {:>3} {} {} {} -> {} ({} ms){}",
                    case.index,
                    case.method,
                    case.label,
                    case.path,
                    case.status
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "no response".into()),
                    case.elapsed_ms,
                    match &case.error {
                        Some(error) => format!(" ({error})"),
                        None => String::new(),
                    }
                );
            }
            if let Some(error) = &report.first_error {
                println!("  first transport error: {error}");
            }
        }
    }
}

fn print_dns_report(report: &DnsReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Text => {
            println!(
                "{} {} {} via {} ({} ms)",
                if report.ok { "OK" } else { "FAIL" },
                report.dns_type,
                report.host,
                report.dns_server,
                report.total_elapsed_ms
            );
            for answer in &report.answers {
                println!(
                    "  {} {} ttl {}s {}",
                    answer.record_type,
                    answer.name,
                    answer
                        .ttl_seconds
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into()),
                    answer.data
                );
            }
            if report.answers.is_empty() {
                if let Some(error) = &report.error {
                    println!("  error: {error}");
                }
            }
        }
        Output::Json => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        Output::Jsonl => {
            if let Ok(line) = serde_json::to_string(report) {
                println!("{line}");
            }
        }
        Output::Csv => {
            println!("name,record_type,ttl_seconds,data");
            for answer in &report.answers {
                println!(
                    "{},{},{},{}",
                    csv_escape(&answer.name),
                    answer.record_type,
                    answer
                        .ttl_seconds
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                    csv_escape(&answer.data)
                );
            }
        }
    }
}

fn print_tls_report(report: &TlsReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Text => {
            println!(
                "{} TLS {}:{} ({} ms)",
                if report.ok { "OK" } else { "FAIL" },
                report.host,
                report.port,
                report.total_elapsed_ms
            );
            if let Some(certificate) = &report.certificate {
                println!(
                    "TLS: {} -> {} (expires {}) serial {}",
                    certificate.subject,
                    certificate.issuer,
                    certificate.not_after,
                    certificate.serial
                );
                println!("  valid from: {}", certificate.not_before);
                println!("  expired: {}", certificate.expired);
                if let Some(protocol) = &certificate.protocol {
                    println!("  protocol: {protocol}");
                }
                if let Some(cipher) = &certificate.cipher_suite {
                    println!("  cipher suite: {cipher}");
                }
                if !certificate.sans.is_empty() {
                    println!("  SANs: {}", certificate.sans.join(", "));
                }
            }
            if let Some(error) = &report.error {
                println!("  error: {error}");
            }
        }
        Output::Json => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        Output::Jsonl => {
            if let Ok(line) = serde_json::to_string(report) {
                println!("{line}");
            }
        }
        Output::Csv => {
            println!("host,port,ok,subject,issuer,serial,not_before,not_after,expired,sans,error");
            let certificate = report.certificate.as_ref();
            println!(
                "{},{},{},{},{},{},{},{},{},{},{}",
                csv_escape(&report.host),
                report.port,
                report.ok,
                csv_escape(certificate.map_or("", |value| value.subject.as_str())),
                csv_escape(certificate.map_or("", |value| value.issuer.as_str())),
                csv_escape(certificate.map_or("", |value| value.serial.as_str())),
                csv_escape(certificate.map_or("", |value| value.not_before.as_str())),
                csv_escape(certificate.map_or("", |value| value.not_after.as_str())),
                certificate.is_some_and(|value| value.expired),
                csv_escape(
                    certificate
                        .map(|value| value.sans.join(";"))
                        .unwrap_or_default()
                        .as_str()
                ),
                csv_escape(report.error.as_deref().unwrap_or_default())
            );
        }
    }
}

fn print_user_agents_report(report: &UserAgentsReport, opts: &Options) {
    if opts.quiet && opts.output == Output::Text {
        return;
    }
    match opts.output {
        Output::Text => {
            for agent in &report.user_agents {
                println!("{agent}");
            }
        }
        Output::Json => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        Output::Jsonl => {
            if let Ok(line) = serde_json::to_string(report) {
                println!("{line}");
            }
        }
        Output::Csv => {
            println!("user_agent");
            for agent in &report.user_agents {
                println!("{}", csv_escape(agent));
            }
        }
    }
}

fn batch(file: &str, opts: &Options) -> Result<bool, String> {
    let input = if file == "-" {
        let mut value = String::new();
        io::stdin()
            .read_to_string(&mut value)
            .map_err(|e| e.to_string())?;
        value
    } else {
        fs::read_to_string(file).map_err(|e| format!("could not read batch file: {e}"))?
    };
    let targets: Vec<String> = input
        .lines()
        .map(str::trim)
        .filter(|v| !v.is_empty() && !v.starts_with('#'))
        .map(str::to_string)
        .collect();
    if targets.is_empty() || targets.len() > MAX_BATCH {
        return Err(format!("batch must contain 1-{MAX_BATCH} targets"));
    }
    let workers = MAX_CONCURRENCY.min(targets.len());
    let chunk_size = targets.len().div_ceil(workers);
    let (sender, receiver) = mpsc::channel();
    for (chunk_index, chunk) in targets.chunks(chunk_size).enumerate() {
        let sender = sender.clone();
        let opts = opts.clone();
        let chunk = chunk.to_vec();
        let start = chunk_index * chunk_size;
        thread::spawn(move || {
            for (offset, value) in chunk.into_iter().enumerate() {
                sender.send((start + offset, diagnose(&value, &opts))).ok();
            }
        });
    }
    drop(sender);
    let mut results: Vec<Option<Result<DiagnosticReport, String>>> =
        (0..targets.len()).map(|_| None).collect();
    for (index, result) in receiver {
        if let Some(slot) = results.get_mut(index) {
            *slot = Some(result);
        }
    }
    if opts.output == Output::Csv {
        print_report_csv_header();
    }
    let mut ok = true;
    for result in results {
        match result {
            Some(Ok(report)) => {
                ok &= report.ok;
                if opts.output == Output::Csv {
                    print_report_csv_row(&report);
                } else {
                    print_report_one(&report, opts);
                }
            }
            Some(Err(error)) => {
                ok = false;
                eprintln!("error: {error}");
            }
            None => {
                ok = false;
                eprintln!("error: batch worker did not return a result");
            }
        }
    }
    Ok(ok)
}

fn completion_script(shell: &str) -> Result<&'static str, String> {
    match shell.to_ascii_lowercase().as_str() {
        "bash" => Ok(COMPLETION_BASH),
        "zsh" => Ok(COMPLETION_ZSH),
        "fish" => Ok(COMPLETION_FISH),
        "powershell" | "pwsh" | "ps1" => Ok(COMPLETION_POWERSHELL),
        "nushell" | "nu" => Ok(COMPLETION_NUSHELL),
        other => Err(format!(
            "unsupported shell: {other} (use bash, zsh, fish, powershell, or nushell)"
        )),
    }
}

fn config_template() -> &'static str {
    "# ddos configuration\n\
     # Precedence: CLI arguments > DDOS_* environment variables > this file.\n\
     # Unknown keys are an error.\n\
     \n\
     timeout = 5\n\
     retries = 0\n\
     output = \"text\"\n\
     family = \"any\"\n\
     method = \"HEAD\"\n\
     redirects = 5\n\
     verbose = false\n\
     quiet = false\n\
     rate = 10\n\
     count = 20\n\
     concurrency = 8\n\
     rotate-user-agent = false\n\
     random-user-agent = false\n\
     audit-headers = false\n\
     # scope = \"/path/to/authorized-scope.txt\"\n\
     # path = \"/\"\n\
     # expect-status = 200\n\
     # show-header = \"server\"\n\
     # user-agent = \"healthbot/1.0\"\n\
     # auth-basic = \"user:pass\"\n\
     # auth-bearer = \"token\"\n\
     # header = \"X-Trace-Id: 8f14e45f\"\n\
     # body-bytes = 0\n\
     # dns-type = \"A\"\n\
     # dns-server = \"1.1.1.1\"\n\
     # payload = \"70696e670a\"\n\
     # ports = \"80,443,8000-8100\"\n\
     # wordlist = \"/path/to/paths.txt\"\n\
     # origin = \"https://evil.example\"\n"
}

fn maintenance_config_init() -> Result<(), String> {
    let path = default_config_path().ok_or("could not determine the config directory")?;
    if path.exists() {
        return Err(format!("config file already exists: {}", path.display()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }
    fs::write(&path, config_template())
        .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    println!("Wrote default config to {}", path.display());
    Ok(())
}

fn maintenance_update() -> Result<(), String> {
    let status = if cfg!(windows) {
        Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"])
            .arg(format!("irm {INSTALL_PS1} | iex"))
            .status()
    } else {
        Command::new("sh")
            .args(["-c", &format!("curl -fsSL '{INSTALL_SH}' | bash")])
            .status()
    }
    .map_err(|e| format!("could not start installer: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("installer exited with {status}"))
    }
}
fn maintenance_uninstall() -> Result<(), String> {
    let executable = env::current_exe().map_err(|e| format!("could not locate executable: {e}"))?;
    if cfg!(windows) {
        let path = executable.to_string_lossy().replace('\'', "''");
        Command::new("powershell")
            .args(["-NoProfile", "-Command"])
            .arg(format!(
                "Start-Sleep -Milliseconds 500; Remove-Item -LiteralPath '{path}' -Force"
            ))
            .spawn()
            .map_err(|e| format!("could not schedule removal: {e}"))?;
    } else {
        fs::remove_file(&executable).map_err(|e| format!("could not remove executable: {e}"))?;
    }
    println!("Uninstall scheduled for {}", executable.display());
    Ok(())
}

fn run(args: &[String]) -> Result<bool, String> {
    match args.first().map(String::as_str) {
        None | Some("--help") | Some("-h") => {
            usage();
            Ok(true)
        }
        Some("--version") | Some("-V") => {
            println!("ddos {VERSION}");
            Ok(true)
        }
        Some("self-update") => maintenance_update().map(|_| true),
        Some("self-uninstall") | Some("--selfuninstall") => maintenance_uninstall().map(|_| true),
        Some("resolve") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("resolve requires <host>")?;
            scope_precheck_host(host, &opts)?;
            let values =
                resolve(host, 0, opts.family).map_err(|e| format!("resolve failed: {e}"))?;
            scope_allows(host, &values, &opts)?;
            if opts.output == Output::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ResolveReport {
                        schema_version: 1,
                        version: VERSION.into(),
                        host: host.into(),
                        addresses: values.iter().map(|v| v.ip().to_string()).collect()
                    })
                    .unwrap()
                );
            } else if opts.output == Output::Jsonl {
                if let Ok(line) = serde_json::to_string(&ResolveReport {
                    schema_version: 1,
                    version: VERSION.into(),
                    host: host.clone(),
                    addresses: values.iter().map(|v| v.ip().to_string()).collect(),
                }) {
                    println!("{line}");
                }
            } else if opts.output == Output::Csv {
                println!("host,family,address");
                for value in &values {
                    println!("{},{},{}", csv_escape(host), family(value), value.ip());
                }
            } else {
                if !opts.quiet {
                    for value in &values {
                        println!("{} ({})", value.ip(), family(value));
                    }
                }
            }
            Ok(!values.is_empty())
        }
        Some("tcp-check") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("tcp-check requires <host>")?;
            let port = pos
                .get(1)
                .ok_or("tcp-check requires <port>")?
                .parse::<u16>()
                .map_err(|_| "port must be 1-65535")?;
            let report = diagnose(&format!("{host}:{port}"), &opts)?;
            print_report_one(&report, &opts);
            Ok(report.ok)
        }
        Some("http-check") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("http-check requires <host>")?;
            let port = match pos.get(1) {
                Some(value) => value.parse::<u16>().map_err(|_| "port must be 1-65535")?,
                None => 80,
            };
            let report = diagnose(&format!("http://{host}:{port}{}", opts.path), &opts)?;
            print_report_one(&report, &opts);
            Ok(report.ok)
        }
        Some("diagnose") => {
            let (opts, pos) = options(&args[1..])?;
            let value = pos.first().ok_or("diagnose requires <url|host:port>")?;
            let report = diagnose(value, &opts)?;
            print_report_one(&report, &opts);
            Ok(report.ok)
        }
        Some("report") => {
            let (mut opts, pos) = options(&args[1..])?;
            let value = pos.first().ok_or("report requires <url|host:port>")?;
            opts.audit_headers = true;
            let report = diagnose(value, &opts)?;
            if opts.output == Output::Text {
                print_markdown_report(&report, &opts);
            } else {
                print_report_one(&report, &opts);
            }
            Ok(report.ok)
        }
        Some("udp-check") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("udp-check requires <host>")?;
            let port = pos
                .get(1)
                .ok_or("udp-check requires <port>")?
                .parse::<u16>()
                .map_err(|_| "port must be 1-65535")?;
            let started = Instant::now();
            scope_precheck_host(host, &opts)?;
            let resolved = resolve(host, port, opts.family)
                .map_err(|e| format!("DNS resolution failed: {e}"))?;
            if resolved.is_empty() {
                return Err(format!(
                    "no {} address found for {host}",
                    match opts.family {
                        Family::Any => "usable",
                        Family::Ipv4 => "IPv4",
                        Family::Ipv6 => "IPv6",
                    }
                ));
            }
            scope_allows(host, &resolved, &opts)?;
            let payload = opts.payload.clone().unwrap_or_else(|| b"ping\n".to_vec());
            let attempts: Vec<UdpAttempt> = resolved
                .iter()
                .map(|address| udp_attempt(address, &opts, &payload))
                .collect();
            let ok = attempts.iter().any(|v| v.received);
            let report = UdpReport {
                schema_version: 1,
                version: VERSION.into(),
                target: format!("{host}:{port}"),
                host: host.clone(),
                port,
                attempts,
                ok,
                total_elapsed_ms: started.elapsed().as_millis(),
                error: if ok {
                    None
                } else {
                    Some("no UDP response received".into())
                },
            };
            print_udp_report(&report, &opts);
            Ok(report.ok)
        }
        Some("dns-check") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("dns-check requires <host>")?;
            ensure_scope_host(host, &opts)?;
            let record = opts.dns_type.unwrap_or(DnsType::A);
            let server = opts.dns_server.map(Ok).unwrap_or_else(system_resolver)?;
            validate_dns_host(host)?;
            let query = dns_query(record, host)?;
            let started = Instant::now();
            let bind = if server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket =
                UdpSocket::bind(bind).map_err(|e| format!("could not bind a UDP socket: {e}"))?;
            socket
                .connect(SocketAddr::new(server, 53))
                .map_err(|e| format!("could not reach {}: {e}", server))?;
            let _ = socket.set_read_timeout(Some(opts.timeout));
            let _ = socket.set_write_timeout(Some(opts.timeout));
            let mut response = None;
            let mut last_error = String::new();
            for attempt in 0..=opts.retries {
                if let Err(error) = socket.send(&query.message) {
                    last_error = format!("could not send DNS query: {error}");
                    break;
                }
                let mut buffer = vec![0_u8; 4096];
                match socket.recv(&mut buffer) {
                    Ok(count) => {
                        response = Some(buffer[..count].to_vec());
                        break;
                    }
                    Err(error) => {
                        if error.kind() == io::ErrorKind::ConnectionRefused {
                            last_error =
                                "resolver refused the connection (UDP port 53 blocked?)".into();
                            break;
                        }
                        let timed_out = error.kind() == io::ErrorKind::WouldBlock
                            || error.kind() == io::ErrorKind::TimedOut;
                        if timed_out {
                            last_error = format!(
                                "timed out waiting for a DNS response after {}s",
                                opts.timeout.as_secs()
                            );
                            if attempt < opts.retries {
                                thread::sleep(Duration::from_millis(50 * 2u64.pow(attempt)));
                                continue;
                            }
                            break;
                        }
                        last_error = format!("could not read DNS response: {error}");
                        break;
                    }
                }
            }
            let received = match response {
                Some(value) => value,
                None => return Err(last_error),
            };
            let id = u16_at(&received, 0).unwrap_or(0);
            if id != query.id {
                return Err("DNS response transaction id did not match the query".into());
            }
            if received.len() > 2 && received[2] & 0x80 == 0 {
                return Err("got a DNS response without the QR response flag".into());
            }
            let (rcode, _ancount, answers) = parse_dns_answers(&received)?;
            let empty = answers.is_empty();
            let error = if rcode != 0 {
                Some(rcode_text(rcode))
            } else if empty {
                Some(format!("no {} records returned", record.name()))
            } else {
                None
            };
            let report = DnsReport {
                schema_version: 1,
                version: VERSION.into(),
                host: host.clone(),
                dns_type: record.name().into(),
                dns_server: server.to_string(),
                answers,
                ok: rcode == 0 && !empty,
                total_elapsed_ms: started.elapsed().as_millis(),
                error,
            };
            print_dns_report(&report, &opts);
            Ok(report.ok)
        }
        Some("tls-check") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("tls-check requires <host>")?;
            ensure_scope_host(host, &opts)?;
            let port = match pos.get(1) {
                Some(value) => value.parse::<u16>().map_err(|_| "port must be 1-65535")?,
                None => 443,
            };
            let started = Instant::now();
            let (certificate, error) = match certificate_probe(host, port, &opts) {
                Ok(value) => (Some(value), None),
                Err(error) => (None, Some(error)),
            };
            let report = TlsReport {
                schema_version: 1,
                version: VERSION.into(),
                host: host.clone(),
                port,
                certificate,
                ok: error.is_none(),
                total_elapsed_ms: started.elapsed().as_millis(),
                error,
            };
            print_tls_report(&report, &opts);
            Ok(report.ok)
        }
        Some("user-agents") => {
            let (opts, _pos) = options(&args[1..])?;
            let report = UserAgentsReport {
                schema_version: 1,
                version: VERSION.into(),
                user_agents: ROTATING_USER_AGENTS
                    .iter()
                    .map(|value| value.to_string())
                    .collect(),
            };
            print_user_agents_report(&report, &opts);
            Ok(true)
        }
        Some("completion") => {
            let shell = args
                .get(1)
                .ok_or("completion requires a shell: bash, zsh, fish, powershell, or nushell")?;
            print!("{}", completion_script(shell)?);
            Ok(true)
        }
        Some("config") => match args.get(1).map(String::as_str) {
            Some("path") => {
                let path =
                    default_config_path().ok_or("could not determine the config directory")?;
                println!("{}", path.display());
                Ok(true)
            }
            Some("init") => maintenance_config_init().map(|_| true),
            Some(other) => Err(format!("unknown config action: {other} (use path or init)")),
            None => Err("config requires an action: path or init".into()),
        },
        Some("batch") => {
            let (opts, pos) = options(&args[1..])?;
            batch(pos.first().ok_or("batch requires <file|->")?, &opts)
        }
        Some("load-test") => {
            let (opts, pos) = options(&args[1..])?;
            let value = pos.first().ok_or("load-test requires <url|host:port>")?;
            let report = load_test(value, &opts)?;
            let ok = report.ok == report.sent;
            print_load_test_report(&report, &opts);
            Ok(ok)
        }
        Some("capacity-test") => {
            let (opts, pos) = options(&args[1..])?;
            let value = pos
                .first()
                .ok_or("capacity-test requires <url|host:port>")?;
            let report = capacity_test(value, &opts)?;
            let ok = report.total_failed == 0;
            print_capacity_report(&report, &opts);
            Ok(ok)
        }
        Some("connection-churn") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("connection-churn requires <host>")?;
            let port = pos
                .get(1)
                .ok_or("connection-churn requires <port>")?
                .parse::<u16>()
                .map_err(|_| "port must be 1-65535")?;
            let report = connection_churn(host, port, &opts)?;
            let ok = report.failed == 0;
            print_churn_report(&report, &opts);
            Ok(ok)
        }
        Some("slow-request") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("slow-request requires <host>")?;
            let port = pos
                .get(1)
                .ok_or("slow-request requires <port>")?
                .parse::<u16>()
                .map_err(|_| "port must be 1-65535")?;
            let report = slow_request(host, port, &opts)?;
            print_slow_report(&report, &opts);
            Ok(true)
        }
        Some("request-shape") => {
            let (opts, pos) = options(&args[1..])?;
            let value = pos
                .first()
                .ok_or("request-shape requires <url|host:port>")?;
            let report = request_shape(value, &opts)?;
            let ok = report.server_errors == 0 && report.transport_errors == 0;
            print_shape_report(&report, &opts);
            Ok(ok)
        }
        Some("port-scan") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("port-scan requires <host>")?;
            let report = port_scan(host, &opts)?;
            print_port_scan_report(&report, &opts);
            Ok(report.ok)
        }
        Some("path-discovery") => {
            let (opts, pos) = options(&args[1..])?;
            let value = pos
                .first()
                .ok_or("path-discovery requires <url|host:port>")?;
            let report = path_discovery(value, &opts)?;
            print_path_discovery_report(&report, &opts);
            Ok(report.ok)
        }
        Some("cors-check") => {
            let (opts, pos) = options(&args[1..])?;
            let value = pos.first().ok_or("cors-check requires <url|host:port>")?;
            let report = cors_check(value, &opts)?;
            print_cors_report(&report, &opts);
            Ok(report.ok)
        }
        Some("cookie-check") => {
            let (opts, pos) = options(&args[1..])?;
            let value = pos.first().ok_or("cookie-check requires <url|host:port>")?;
            let report = cookie_check(value, &opts)?;
            print_cookie_report(&report, &opts);
            Ok(report.ok)
        }
        Some("method-check") => {
            let (opts, pos) = options(&args[1..])?;
            let value = pos.first().ok_or("method-check requires <url|host:port>")?;
            let report = method_check(value, &opts)?;
            print_method_report(&report, &opts);
            Ok(report.ok)
        }
        Some("repeat") => {
            let (opts, pos) = options(&args[1..])?;
            let value = pos.first().ok_or("repeat requires <url|host:port>")?;
            let interval = args
                .windows(2)
                .find(|v| v[0] == "--interval")
                .ok_or("repeat requires --interval")?[1]
                .parse::<u64>()
                .map_err(|_| "--interval must be an integer")?;
            let duration = args
                .windows(2)
                .find(|v| v[0] == "--duration")
                .ok_or("repeat requires --duration")?[1]
                .parse::<u64>()
                .map_err(|_| "--duration must be an integer")?;
            if interval == 0 || duration == 0 || duration > MAX_REPEAT_SECONDS {
                return Err(format!(
                    "repeat duration must be 1-{MAX_REPEAT_SECONDS}s and interval must be positive"
                ));
            }
            let end = Instant::now() + Duration::from_secs(duration);
            let mut ok = true;
            while Instant::now() < end {
                let report = diagnose(value, &opts)?;
                ok &= report.ok;
                print_report_one(&report, &opts);
                let next = Instant::now() + Duration::from_secs(interval);
                if next >= end {
                    break;
                }
                thread::sleep(Duration::from_secs(interval));
            }
            Ok(ok)
        }
        Some(value) => Err(format!("unknown command: {value}")),
    }
}

fn audit_log_path(args: &[String]) -> Option<PathBuf> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--auth" {
            index += 3;
            continue;
        }
        if args[index] == "--audit-log" {
            return args.get(index + 1).map(PathBuf::from);
        }
        index += 1;
    }
    env_value("DDOS_AUDIT_LOG").map(PathBuf::from)
}

fn redact_url_credentials(value: &str) -> String {
    let Some(scheme_end) = value.find("://") else {
        return value.to_string();
    };
    let authority_start = scheme_end + 3;
    let rest = &value[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let Some(at) = authority.rfind('@') else {
        return value.to_string();
    };
    format!(
        "{}{}{}",
        &value[..authority_start],
        &authority[at + 1..],
        &rest[authority_end..]
    )
}

fn write_audit_entry(
    path: &Path,
    args: &[String],
    outcome: &Result<bool, String>,
    exit_code: u8,
) -> io::Result<()> {
    let timestamp_unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    let status = match outcome {
        Ok(true) => "ok",
        Ok(false) => "failed",
        Err(_) => "error",
    };
    let command = args.first().map(String::as_str).unwrap_or("");
    let target = args
        .get(1)
        .filter(|value| !value.starts_with('-'))
        .map(|value| redact_url_credentials(value));
    let error = outcome
        .as_ref()
        .err()
        .map(|value| redact_url_credentials(value));
    let entry = serde_json::json!({
        "timestamp_unix": timestamp_unix,
        "version": VERSION,
        "command": command,
        "target": target,
        "status": status,
        "exit_code": exit_code,
        "error": error,
    });
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(&entry).expect("audit entry serializes")
    )
}

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let audit_path = audit_log_path(&args);
    let outcome = run(&args);
    let exit_code = match &outcome {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(_) => 2,
    };
    if let Some(path) = audit_path {
        if let Err(error) = write_audit_entry(&path, &args, &outcome, exit_code) {
            eprintln!("warning: could not write audit log: {error}");
        }
    }
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("error: {error}\nTry 'ddos --help' for usage.");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ddos-{name}-{}-{}.txt",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn parses_https_target() {
        let parsed = target("https://example.com/health").unwrap();
        assert_eq!(parsed.0, "example.com");
        assert_eq!(parsed.1, 443);
        assert_eq!(parsed.2.as_deref(), Some("https://example.com/health"));
    }

    #[test]
    fn parses_host_and_port_target() {
        let parsed = target("localhost:8080").unwrap();
        assert_eq!(parsed.0, "localhost");
        assert_eq!(parsed.1, 8080);
        assert!(parsed.2.is_none());
    }

    #[test]
    fn rejects_timeout_outside_hard_limit() {
        let args = vec!["--timeout".into(), "121".into()];
        assert!(options(&args).is_err());
    }

    #[test]
    fn rejects_batch_over_hard_limit() {
        let targets = (0..=MAX_BATCH)
            .map(|n| format!("localhost:{n}"))
            .collect::<Vec<_>>()
            .join("\n");
        let path = std::env::temp_dir().join(format!("ddos-test-{}.txt", std::process::id()));
        fs::write(&path, targets).unwrap();
        let result = batch(path.to_str().unwrap(), &fresh_options());
        fs::remove_file(path).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn custom_request_headers_parse() {
        let args = vec![
            "--header".into(),
            "X-Api-Version: 2026.10".into(),
            "--header".into(),
            "Accept: */*".into(),
            "diagnose".into(),
        ];
        let (opts, positional) = options(&args).unwrap();
        assert_eq!(positional.first().map(String::as_str), Some("diagnose"));
        assert_eq!(opts.headers.len(), 2);
        let names: Vec<&str> = opts.headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["x-api-version", "accept"]);
    }

    #[test]
    fn forbids_transport_managed_headers() {
        for header in ["Host: attacker.example", "Connection: close"] {
            assert!(options(&["--header".to_string(), header.to_string()]).is_err());
        }
        assert!(
            options(&["--header".into(), "Authorization: Basic x".into()]).is_err(),
            "Authorization must go through --auth"
        );
    }

    #[test]
    fn rejects_header_without_colon() {
        let args = vec!["--header".into(), "value-without-name".into()];
        assert!(options(&args).is_err());
    }

    #[test]
    fn rejects_too_many_headers() {
        let mut args = Vec::new();
        for index in 0..(MAX_HEADERS + 1) {
            args.push("--header".into());
            args.push(format!("x-header-{index}: value"));
        }
        assert!(options(&args).is_err());
    }

    #[test]
    fn basic_auth_header_value() {
        let args = vec!["--auth".into(), "basic".into(), "user:password".into()];
        let (opts, _) = options(&args).unwrap();
        let value = opts.auth.and_then(|auth| auth.header_value().ok()).unwrap();
        assert_eq!(value, "Basic dXNlcjpwYXNzd29yZA==");
    }

    #[test]
    fn bearer_auth_header_value() {
        let args = vec!["--auth".into(), "bearer".into(), "token-1".into()];
        let (opts, _) = options(&args).unwrap();
        let value = opts.auth.and_then(|auth| auth.header_value().ok()).unwrap();
        assert_eq!(value, "Bearer token-1");
    }

    #[test]
    fn rejects_bad_basic_auth() {
        assert!(options(&["--auth".into(), "basic".into(), "no-separator".into()]).is_err());
        assert!(options(&["--auth".into(), "digest".into(), "x:y".into()]).is_err());
    }

    #[test]
    fn b64encode_matches_vectors() {
        assert_eq!(b64encode(b""), "");
        assert_eq!(b64encode(b"f"), "Zg==");
        assert_eq!(b64encode(b"fo"), "Zm8=");
        assert_eq!(b64encode(b"foo"), "Zm9v");
        assert_eq!(b64encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn hex_payload_validation() {
        let args = vec!["--payload".into(), "aabbcc".into()];
        let (opts, _) = options(&args).unwrap();
        assert_eq!(opts.payload.as_deref(), Some(&[0xaa, 0xbb, 0xcc][..]));
        assert!(options(&["--payload".into(), "abc".into()]).is_err());
        assert!(options(&["--payload".into(), "zz".into()]).is_err());
    }

    #[test]
    fn output_parsing_accepts_four_modes() {
        assert_eq!(Output::parse("text").unwrap(), Output::Text);
        assert_eq!(Output::parse("json").unwrap(), Output::Json);
        assert_eq!(Output::parse("jsonl").unwrap(), Output::Jsonl);
        assert_eq!(Output::parse("csv").unwrap(), Output::Csv);
        assert!(Output::parse("yaml").is_err());
    }

    #[test]
    fn family_filter_restriction() {
        assert_eq!(Family::parse("any").unwrap(), Family::Any);
        assert_eq!(Family::parse("ipv4").unwrap(), Family::Ipv4);
        assert_eq!(Family::parse("ipv6").unwrap(), Family::Ipv6);
        assert!(Family::parse("anyX").is_err());
        let args = vec!["--family".into(), "ipv6".into()];
        let (opts, _) = options(&args).unwrap();
        assert_eq!(opts.family, Family::Ipv6);
    }

    #[test]
    fn dns_type_flag_parse() {
        let args = vec!["--dns-type".into(), "aaaa".into()];
        let (opts, _) = options(&args).unwrap();
        assert_eq!(opts.dns_type, Some(DnsType::Aaaa));
        assert!(options(&["--dns-type".into(), "SRV".into()]).is_err());
    }

    #[test]
    fn body_bytes_validation() {
        let (opts, _) = options(&["--body-bytes".into(), "0".into()]).unwrap();
        assert_eq!(opts.body_bytes, 0);
        let too_big = format!("{}", MAX_BODY_BYTES as u64 + 1);
        assert!(options(&["--body-bytes".into(), too_big]).is_err());
    }

    #[test]
    fn user_agent_validation() {
        let (opts, _) = options(&["--user-agent".into(), "healthbot/1.0".into()]).unwrap();
        assert_eq!(opts.user_agent.as_deref(), Some("healthbot/1.0"));
        assert!(options(&["--user-agent".into(), "bad\nvalue".into()]).is_err());
    }

    #[test]
    fn csv_escape_quotes() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_escape("plain"), "plain");
    }

    #[test]
    fn dns_query_encoding_shape() {
        let view = dns_query(DnsType::A, "example.org").unwrap();
        assert_eq!(&view.message[..2], &view.id.to_be_bytes());
        assert_eq!(&view.message[2..4], &[0x01, 0x00]);
        assert_eq!(&view.message[4..6], &1_u16.to_be_bytes());
        assert_eq!(view.message.last(), Some(&1_u8));
        assert_eq!(view.message.len(), 12 + 4 + 8 + 5);
    }

    #[test]
    fn dns_query_rejects_bad_hosts() {
        assert!(dns_query(DnsType::A, "").is_err());
        assert!(dns_query(DnsType::A, "a a").is_err());
        assert!(
            dns_query(DnsType::A, "x".repeat(MAX_DNS_HOST + 1).as_str()).is_err(),
            "hosts longer than {MAX_DNS_HOST} bytes must be rejected"
        );
    }

    #[test]
    fn parse_name_extracts_labels_and_follows_pointers() {
        let mut message = vec![0_u8; 24];
        message.extend_from_slice(b"\x03www\x07example\x03com\x00");
        let (name, end_offset) = parse_dns_name(&message, 24).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(end_offset, message.len());
        let compressed = [0xC0u8, 24u8];
        let mut with_pointer = message.clone();
        with_pointer.extend_from_slice(&compressed);
        let pointer_offset = message.len();
        let (name, after_pointer) = parse_dns_name(&with_pointer, pointer_offset).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(after_pointer, pointer_offset + 2);
    }

    #[test]
    fn parse_name_rejects_pointer_loops() {
        let message = [0x03u8, b'a', b'b', b'c', 0xC0, 0x00];
        assert!(parse_dns_name(&message, 0).is_none());
    }

    #[test]
    fn parse_dns_answer_round_trip() {
        // header + question (example.com A IN) + one A answer.
        let mut message = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        message.extend_from_slice(b"\x07example\x03com\x00");
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&[0xC0, 0x0C]);
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&300_u32.to_be_bytes());
        message.extend_from_slice(&4_u16.to_be_bytes());
        message.extend_from_slice(&[1, 2, 3, 4]);
        let (rcode, ancount, answers) = parse_dns_answers(&message).unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(ancount, 1);
        assert_eq!(answers[0].record_type, "A");
        assert_eq!(answers[0].name, "example.com");
        assert_eq!(answers[0].data, "1.2.3.4");
        assert_eq!(answers[0].ttl_seconds, Some(300));
    }

    #[test]
    fn parse_ipv6_answer_round_trip() {
        let mut message = vec![0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
        message.extend_from_slice(b"\x07example\x03com\x00");
        message.extend_from_slice(&28_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&60_u32.to_be_bytes());
        message.extend_from_slice(&16_u16.to_be_bytes());
        message.extend_from_slice(&[
            0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ]);
        let (_, _, answers) = parse_dns_answers(&message).unwrap();
        assert_eq!(answers[0].record_type, "AAAA");
        assert_eq!(answers[0].data, "2001:4860::8888");
    }

    #[test]
    fn rcode_text_matches_expected_labels() {
        assert_eq!(rcode_text(3), "name does not exist (NXDOMAIN)");
        assert_eq!(rcode_text(2), "server failure (SERVFAIL)");
        assert!(rcode_text(42).contains("42"));
    }

    #[test]
    fn loopback_gate_refuses_public_hosts() {
        assert!(ensure_loopback("rkriad585.github.io", Family::Any, "test").is_err());
        assert!(ensure_loopback("1.1.1.1", Family::Any, "test").is_err());
        assert!(ensure_loopback("example.com", Family::Any, "test").is_err());
    }

    #[test]
    fn loopback_gate_accepts_loopback_only() {
        assert!(ensure_loopback("localhost", Family::Any, "test").is_ok());
        assert!(ensure_loopback("127.0.0.1", Family::Any, "test").is_ok());
        assert!(ensure_loopback("::1", Family::Any, "test").is_ok());
        assert!(ensure_loopback("LOCALHOST", Family::Any, "test").is_ok());
    }

    #[test]
    fn rate_and_count_are_validated() {
        assert!(options(&["--rate".into(), "0".into()]).is_err());
        assert!(options(&["--rate".into(), "51".into()]).is_err());
        assert!(options(&["--count".into(), "5001".into()]).is_err());
        assert!(options(&["--count".into(), "0".into()]).is_err());
        let (opts, _) = options(&[
            "--rate".into(),
            "50".into(),
            "--count".into(),
            "5000".into(),
        ])
        .unwrap();
        assert_eq!(opts.rate, 50);
        assert_eq!(opts.count, 5000);
    }

    #[test]
    fn rate_count_defaults_are_bounded() {
        let (opts, _) = options(&[]).unwrap();
        assert!((1..=50).contains(&opts.rate));
        assert!((1..=5000).contains(&opts.count));
        assert!(!opts.rotate_user_agent);
        assert!(!opts.random_user_agent);
    }

    #[test]
    fn allow_header_is_parsed_and_deduped() {
        assert_eq!(
            parse_allow_header(Some("GET, post, GET ,, HEAD")),
            vec!["GET", "POST", "HEAD"]
        );
        assert!(parse_allow_header(None).is_empty());
        assert!(parse_allow_header(Some("  ")).is_empty());
    }

    #[test]
    fn method_audit_flags_trace_and_dangerous_methods() {
        let probes = vec![
            MethodProbe {
                method: "OPTIONS".into(),
                status: Some(204),
                status_text: Some("No Content".into()),
                elapsed_ms: 1,
                allowed: true,
                error: None,
            },
            MethodProbe {
                method: "TRACE".into(),
                status: Some(200),
                status_text: Some("OK".into()),
                elapsed_ms: 1,
                allowed: true,
                error: None,
            },
        ];
        let findings = analyze_methods(Some("GET, PUT, TRACE"), &probes);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "trace_enabled"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "dangerous_methods_advertised"));
    }

    #[test]
    fn method_audit_accepts_clean_options() {
        let probes = vec![MethodProbe {
            method: "OPTIONS".into(),
            status: Some(204),
            status_text: Some("No Content".into()),
            elapsed_ms: 1,
            allowed: true,
            error: None,
        }];
        let findings = analyze_methods(Some("GET, HEAD, OPTIONS"), &probes);
        assert!(findings.is_empty());
    }

    #[test]
    fn method_audit_notes_missing_allow_header() {
        let probes = vec![MethodProbe {
            method: "OPTIONS".into(),
            status: Some(200),
            status_text: Some("OK".into()),
            elapsed_ms: 1,
            allowed: true,
            error: None,
        }];
        let findings = analyze_methods(None, &probes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "allow_header_missing");
        assert_eq!(findings[0].severity, "info");
    }

    #[test]
    fn rotate_user_agent_flag_is_absorbed() {
        let (opts, pos) = options(&["--rotate-user-agent".into()]).unwrap();
        assert!(opts.rotate_user_agent);
        assert!(pos.is_empty());
    }

    #[test]
    fn random_user_agent_flag_is_absorbed() {
        let (opts, pos) = options(&["--random-user-agent".into()]).unwrap();
        assert!(opts.random_user_agent);
        assert!(pos.is_empty());
    }

    #[test]
    fn rotating_browser_agents_are_valid_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for agent in ROTATING_USER_AGENTS {
            assert!(validate_user_agent(agent).is_ok());
            assert!(
                agent.starts_with("Mozilla/5.0"),
                "user agent should look like a real browser: {agent}"
            );
            assert!(
                !agent.contains("ddos/"),
                "placeholder user agents are not allowed: {agent}"
            );
            seen.insert(agent.to_string());
        }
        assert_eq!(seen.len(), ROTATING_USER_AGENTS.len());
    }

    #[test]
    fn random_index_stays_within_bounds() {
        let mut state = seed_random_state();
        for _ in 0..1000 {
            assert!(
                random_index(&mut state, ROTATING_USER_AGENTS.len()) < ROTATING_USER_AGENTS.len()
            );
        }
        assert_eq!(random_index(&mut state, 0), 0);
    }

    #[test]
    fn picked_random_user_agent_is_valid() {
        assert!(validate_user_agent(pick_random_user_agent()).is_ok());
    }

    #[test]
    fn quiet_and_no_color_flags_are_absorbed() {
        let (opts, pos) = options(&["--quiet".into(), "--no-color".into()]).unwrap();
        assert!(opts.quiet);
        assert!(pos.is_empty());
    }

    #[test]
    fn completion_scripts_are_embedded() {
        assert!(completion_script("bash")
            .unwrap()
            .contains("complete -F _ddos ddos"));
        assert!(completion_script("bash").unwrap().contains("report"));
        assert!(completion_script("pwsh").is_ok());
        assert!(completion_script("tcsh").is_err());
    }

    #[test]
    fn config_template_parses() {
        let mut opts = fresh_options();
        apply_config_file(&mut opts, config_template(), Path::new("template.toml")).unwrap();
        assert_eq!(opts.timeout, Duration::from_secs(5));
        assert!(!opts.quiet);
        assert!(!opts.verbose);
    }

    #[test]
    fn tcp_check_reaches_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let _ = listener.accept().unwrap();
        });
        let report = diagnose(&format!("127.0.0.1:{port}"), &fresh_options()).unwrap();
        handle.join().unwrap();
        assert!(report.ok);
        assert!(report.resolved.iter().any(|value| value.connected));
    }

    #[test]
    fn http_probe_reads_local_response() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Security-Policy: default-src 'none'\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let mut opts = fresh_options();
        opts.audit_headers = true;
        let result = http_probe(
            &format!("http://127.0.0.1:{port}/"),
            "127.0.0.1",
            port,
            &opts,
        );
        handle.join().unwrap();
        assert_eq!(result.status, Some(200));
        assert!(result.status_ok);
        let checks = result.security_headers.expect("header audit requested");
        assert!(checks
            .iter()
            .any(|check| check.name == "content-security-policy" && check.present));
        assert!(checks
            .iter()
            .any(|check| check.name == "x-content-type-options" && check.present));
        assert!(checks
            .iter()
            .any(|check| check.name == "strict-transport-security" && !check.present));
    }

    #[test]
    fn scope_file_matches_hosts_and_networks() {
        let path = temp_file(
            "scope",
            "# authorized targets\nlocalhost\n*.example.com\n192.0.2.0/24\n2001:db8::/32\n198.51.100.7\n",
        );
        let scope = Scope::load(&path).unwrap();
        assert!(scope.allows_host("localhost"));
        assert!(scope.allows_host("api.example.com"));
        assert!(scope.allows_host("deep.api.example.com"));
        assert!(!scope.allows_host("example.com"));
        assert!(scope.allows_ip("192.0.2.55".parse().unwrap()));
        assert!(!scope.allows_ip("192.0.3.55".parse().unwrap()));
        assert!(scope.allows_ip("2001:db8::1".parse().unwrap()));
        assert!(scope.allows_ip("198.51.100.7".parse().unwrap()));
        assert!(!scope.allows_ip("198.51.100.8".parse().unwrap()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn scope_and_audit_flags_are_absorbed() {
        let scope_path = temp_file("scope-flag", "example.com\n");
        let (opts, positional) = options(&[
            "--no-config".into(),
            "--scope".into(),
            scope_path.to_str().unwrap().into(),
            "--audit-log".into(),
            "audit.jsonl".into(),
            "--audit-headers".into(),
        ])
        .unwrap();
        assert!(opts.scope.is_some());
        assert!(opts.audit_headers);
        assert!(positional.is_empty());
        assert!(ensure_scope_host("example.com", &opts).is_ok());
        assert!(ensure_scope_host("outside.example", &opts).is_err());
        fs::remove_file(scope_path).unwrap();
    }

    #[test]
    fn audit_log_writes_jsonl() {
        let path = temp_file("audit", "");
        let args = vec!["diagnose".into(), "example.com".into()];
        write_audit_entry(&path, &args, &Ok(true), 0).unwrap();
        let line = fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["command"], "diagnose");
        assert_eq!(value["target"], "example.com");
        assert_eq!(value["status"], "ok");
        assert_eq!(value["exit_code"], 0);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn audit_log_redacts_url_credentials() {
        let path = temp_file("audit-redacted", "");
        let args = vec![
            "diagnose".into(),
            "https://user:secret@example.com/health".into(),
        ];
        write_audit_entry(&path, &args, &Err("failed".into()), 2).unwrap();
        let line = fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["target"], "https://example.com/health");
        assert!(!line.contains("secret"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn unix_time_formats_as_utc() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn markdown_report_contains_assessment_findings() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (first, _) = listener.accept().unwrap();
            drop(first);
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let mut opts = fresh_options();
        opts.audit_headers = true;
        let report = diagnose(&format!("http://127.0.0.1:{port}/"), &opts).unwrap();
        handle.join().unwrap();
        let markdown = markdown_report(&report, &opts);
        assert!(markdown.contains("# ddos assessment report"));
        assert!(markdown.contains("| HTTP | PASS | 200 OK |"));
        assert!(markdown.contains("### Security headers"));
        assert!(markdown.contains("content-security-policy"));
        assert!(markdown.contains("## Notes"));
    }

    #[test]
    fn port_spec_parses_ranges_and_deduplicates() {
        assert_eq!(
            parse_ports("80,443,8000-8002").unwrap(),
            vec![80, 443, 8000, 8001, 8002]
        );
        assert_eq!(parse_ports("443,80,443").unwrap(), vec![80, 443]);
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("65536").is_err());
        assert!(parse_ports("10-1").is_err());
        assert!(parse_ports("").is_err());
        assert!(parse_ports("1-1001").is_err());
    }

    #[test]
    fn default_scan_ports_fit_inside_budget() {
        let ports = parse_ports(DEFAULT_SCAN_PORTS).unwrap();
        assert!(!ports.is_empty());
        assert!(ports.len() <= MAX_PORT_SCAN_PORTS);
    }

    #[test]
    fn origin_validation_accepts_http_https_and_null() {
        assert!(validate_origin("https://evil.example").is_ok());
        assert!(validate_origin("http://127.0.0.1:3030").is_ok());
        assert!(validate_origin("null").is_ok());
        assert!(validate_origin("ftp://evil.example").is_err());
        assert!(validate_origin("evil.example").is_err());
        assert!(validate_origin("https://evil.example/\r\nX-Test: 1").is_err());
    }

    #[test]
    fn active_scope_requires_scope_for_public_targets() {
        assert!(require_active_scope("127.0.0.1", &fresh_options(), "port-scan").is_ok());
        assert!(require_active_scope("localhost", &fresh_options(), "port-scan").is_ok());
        assert!(require_active_scope("example.com", &fresh_options(), "port-scan").is_err());
        let path = temp_file("scan-scope", "example.com\n");
        let (opts, _) = options(&[
            "--no-config".into(),
            "--scope".into(),
            path.to_str().unwrap().into(),
        ])
        .unwrap();
        assert!(require_active_scope("example.com", &opts, "port-scan").is_ok());
        assert!(require_active_scope("outside.example", &opts, "port-scan").is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn security_grade_scores_weighted_headers() {
        let checks = SECURITY_HEADERS
            .iter()
            .map(|(name, _)| HeaderCheck {
                name: (*name).into(),
                present: true,
                value: None,
            })
            .collect::<Vec<_>>();
        assert_eq!(security_grade(&checks), (100, "A".into()));
        let mut partial = checks.clone();
        partial[1].present = false;
        assert_eq!(security_grade(&partial), (75, "B".into()));
        let mut none = checks;
        for check in &mut none {
            check.present = false;
        }
        assert_eq!(security_grade(&none), (0, "F".into()));
    }

    #[test]
    fn cors_analysis_flags_wildcard_and_reflection() {
        let wildcard = analyze_cors(Some("*"), Some("true"), None, "https://evil.example");
        assert!(wildcard.iter().any(
            |finding| finding.code == "wildcard_with_credentials" && finding.severity == "high"
        ));
        let reflected = analyze_cors(
            Some("https://evil.example"),
            Some("true"),
            None,
            "https://evil.example",
        );
        assert!(reflected
            .iter()
            .any(|finding| finding.code == "reflected_with_credentials"
                && finding.severity == "critical"));
        assert!(reflected
            .iter()
            .any(|finding| finding.code == "missing_vary_origin"));
        let fixed = analyze_cors(
            Some("https://good.example"),
            None,
            None,
            "https://evil.example",
        );
        assert!(fixed.is_empty());
    }

    #[test]
    fn cookie_analysis_flags_insecure_cookies() {
        let values = vec!["session=abc; Path=/; SameSite=None".to_string()];
        let (cookies, findings) = analyze_set_cookie(&values);
        assert_eq!(cookies[0].name, "session");
        assert!(!cookies[0].secure);
        assert!(!cookies[0].http_only);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "missing_secure"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "missing_httponly"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "samesite_none_without_secure"));
        let hardened =
            vec!["__Host-sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/".to_string()];
        let (cookies, findings) = analyze_set_cookie(&hardened);
        assert!(cookies[0].secure);
        assert!(cookies[0].http_only);
        assert!(findings.is_empty());
        let (_, findings) = analyze_set_cookie(&[]);
        assert_eq!(findings[0].code, "no_cookies");
        assert_eq!(findings[0].severity, "info");
    }

    #[test]
    fn discovery_paths_are_valid_and_bounded() {
        let (opts, _) = options(&[]).unwrap();
        let paths = read_discovery_paths(&opts).unwrap();
        assert_eq!(paths.len(), DEFAULT_DISCOVERY_PATHS.len());
        for path in &paths {
            assert!(validate_discovery_path(path).is_ok(), "{path}");
        }
        assert!(validate_discovery_path("admin").is_err());
        assert!(validate_discovery_path("/a b").is_err());
        assert!(validate_discovery_path("/ok\r\n").is_err());
    }

    #[test]
    fn new_options_are_parsed() {
        let wordlist = temp_file("wordlist-option", "/admin\n");
        let (opts, _) = options(&[
            "--no-config".into(),
            "--ports".into(),
            "80,443".into(),
            "--concurrency".into(),
            "2".into(),
            "--origin".into(),
            "https://evil.example".into(),
            "--wordlist".into(),
            wordlist.to_str().unwrap().into(),
        ])
        .unwrap();
        assert_eq!(opts.ports.as_deref(), Some("80,443"));
        assert_eq!(opts.concurrency, 2);
        assert_eq!(opts.origin.as_deref(), Some("https://evil.example"));
        assert_eq!(opts.wordlist.as_deref(), Some(wordlist.as_path()));
        fs::remove_file(wordlist).unwrap();
    }

    #[test]
    fn http_probe_preserves_4xx_for_expect_status() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let mut opts = fresh_options();
        opts.expect_status = Some(401);
        let result = http_probe(
            &format!("http://127.0.0.1:{port}/"),
            "127.0.0.1",
            port,
            &opts,
        );
        handle.join().unwrap();
        assert_eq!(result.status, Some(401));
        assert!(result.status_ok);
        assert!(result.error.is_none());
    }

    #[test]
    fn port_scan_finds_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let _ = listener.accept();
        });
        let mut opts = fresh_options();
        opts.ports = Some(port.to_string());
        opts.timeout = Duration::from_millis(200);
        let report = port_scan("127.0.0.1", &opts).unwrap();
        handle.join().unwrap();
        assert_eq!(report.open_count, 1);
        assert!(report
            .open
            .iter()
            .any(|value| value.ends_with(&format!(":{port}"))));
    }

    #[test]
    fn cors_check_flags_wildcard_credentials() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let report = cors_check(&format!("http://127.0.0.1:{port}/api"), &fresh_options()).unwrap();
        handle.join().unwrap();
        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "wildcard_with_credentials"));
    }

    #[test]
    fn cookie_check_collects_multiple_set_cookie_headers() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; Path=/\r\nSet-Cookie: theme=dark; Secure; HttpOnly; SameSite=Lax\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let report =
            cookie_check(&format!("http://127.0.0.1:{port}/login"), &fresh_options()).unwrap();
        handle.join().unwrap();
        assert_eq!(report.cookies.len(), 2);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "missing_secure" && finding.cookie == "session"));
    }

    #[test]
    fn path_discovery_reports_interesting_statuses() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 2048];
                let _ = stream.read(&mut request);
                let response = if String::from_utf8_lossy(&request).contains("/admin") {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nadmin"
                        .as_slice()
                } else {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .as_slice()
                };
                stream.write_all(response).unwrap();
            }
        });
        let wordlist = temp_file("wordlist-discovery", "/admin\n/missing\n");
        let mut opts = fresh_options();
        opts.wordlist = Some(wordlist.clone());
        let report = path_discovery(&format!("http://127.0.0.1:{port}"), &opts).unwrap();
        handle.join().unwrap();
        fs::remove_file(wordlist).unwrap();
        assert_eq!(report.scanned_count, 2);
        assert_eq!(report.found_count, 1);
        assert!(report.results.iter().any(|result| result.path == "/admin"
            && result.status == Some(200)
            && result.interesting));
    }
}
