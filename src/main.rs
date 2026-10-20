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
const MAX_HEADERS: usize = 20;
const MAX_HEADER_NAME: usize = 64;
const MAX_HEADER_VALUE: usize = 2048;
const MAX_AUTH_VALUE: usize = 1024;
const MAX_UDP_PAYLOAD: usize = 1400;
const UDP_PREVIEW_BYTES: usize = 256;
const MAX_DNS_LABEL: usize = 63;
const MAX_DNS_HOST: usize = 255;
const CONFIG_DIR_NAME: &str = "ddos";
const CONFIG_FILE_NAME: &str = "config.toml";
const INSTALL_SH: &str = "https://raw.githubusercontent.com/rkriad585/ddos/main/installer.sh";
const INSTALL_PS1: &str = "https://raw.githubusercontent.com/rkriad585/ddos/main/installer.ps1";

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
    rotate_user_agent: bool,
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

fn usage() {
    let text = format!(
        "ddos {VERSION} — bounded network diagnostics

Usage:
  ddos resolve <host> [options]
  ddos tcp-check <host> <port> [--timeout <seconds>] [--retry <count>] [options]
  ddos http-check <host> [port] [--path /path] [--method HEAD|GET] [options]
  ddos diagnose <url|host:port> [--method HEAD|GET] [--expect-status <code>] [options]
  ddos udp-check <host> <port> [--payload <hex>] [--retry <count>] [options]
  ddos dns-check <host> [--dns-type <type>] [--dns-server <ip>] [options]
  ddos batch <file|-> [--timeout <seconds>] [--retry <count>] [options]
  ddos repeat <url|host:port> --interval <seconds> --duration <seconds> [options]
  ddos load-test <url|host:port> [--rate <req/s>] [--count <requests>] [options]
  ddos self-update
  ddos self-uninstall
  ddos --version
  ddos --help

Common options:
  --timeout 1-120               per-attempt socket timeout in seconds
  --retry 0-5                   bounded retries with exponential backoff
  --output text|json|jsonl|csv  machine-readable output modes
  --family any|ipv4|ipv6        only resolve the selected address family
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
  --redirects 0-10              redirect limit (default 5)
  --proxy <url>                 HTTP/HTTPS proxy for the request

UDP/DNS options:
  --payload <hex>               bytes to send with udp-check (max {MAX_UDP_PAYLOAD} bytes)
  --dns-type A|AAAA|CNAME|TXT|MX|NS   record type for dns-check (default A)
  --dns-server <ip>             resolver for dns-check (defaults to the system resolver on Unix)

Load-test options:
  --rate 1-{MAX_LOAD_RATE}                requests per second (sequential pacing, no concurrency)
  --count 1-{MAX_LOAD_COUNT}              total requests within budget
  --rotate-user-agent           pick a different self-identifying user agent per request

Exit codes: 0 success, 1 diagnostic failure, 2 invalid usage.
Limits: batch 100 targets, concurrency 8, repeat 1 hour, load-test {MAX_LOAD_RATE} req/s x {MAX_LOAD_COUNT} requests, body read {MAX_BODY_BYTES} bytes.
load-test hard restrictions: loopback targets only (localhost, 127.0.0.1, ::1); other hosts are refused.
Config file: $XDG_CONFIG_HOME/ddos/config.toml (or ~/.config/ddos/config.toml),
%APPDATA%\\ddos\\config.toml on Windows. Precedence: CLI args > DDOS_* env vars > config file.
Env vars: DDOS_TIMEOUT, DDOS_RETRIES, DDOS_OUTPUT, DDOS_PATH, DDOS_METHOD,
DDOS_FAMILY, DDOS_EXPECT_STATUS, DDOS_REDIRECTS, DDOS_PROXY, DDOS_USER_AGENT,
DDOS_SHOW_HEADER (comma separated), DDOS_HEADER (semicolon separated \"Name: value\" items),
DDOS_AUTH (\"basic:USER:PASS\" or \"bearer:TOKEN\"), DDOS_BODY_BYTES,
DDOS_RATE, DDOS_COUNT, DDOS_ROTATE_USER_AGENT (true/false).

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

fn fresh_options() -> Options {
    Options {
        timeout: Duration::from_secs(DEFAULT_TIMEOUT),
        retries: 0,
        output: Output::Text,
        verbose: false,
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
        rotate_user_agent: false,
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
        "rotate-user-agent" => match value.trim() {
            "true" => opts.rotate_user_agent = true,
            "false" => opts.rotate_user_agent = false,
            _ => return Err("rotate-user-agent must be true or false".into()),
        },
        "dns-type" => {
            opts.dns_type = Some(DnsType::parse(value)?);
        }
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
        "--config",
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
    if let Some(value) = env_value("DDOS_RATE") {
        opts.rate = bare_number("DDOS_RATE", &value, 1, MAX_LOAD_RATE)
            .map_err(|e| format!("DDOS_RATE: {e}"))? as u32;
    }
    if let Some(value) = env_value("DDOS_COUNT") {
        opts.count = bare_number("DDOS_COUNT", &value, 1, MAX_LOAD_COUNT)
            .map_err(|e| format!("DDOS_COUNT: {e}"))? as u32;
    }
    if let Some(value) = env_value("DDOS_ROTATE_USER_AGENT") {
        match value.trim() {
            "true" => opts.rotate_user_agent = true,
            "false" => opts.rotate_user_agent = false,
            _ => return Err("DDOS_ROTATE_USER_AGENT must be true or false".into()),
        }
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
            "--rotate-user-agent" => {
                opts.rotate_user_agent = true;
                i += 1;
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
    })
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
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(opts.timeout)
        .timeout_read(opts.timeout)
        .timeout_write(opts.timeout)
        .redirects(opts.redirects);
    builder = match opts.user_agent.as_deref() {
        Some(agent) => builder.user_agent(agent),
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
    match request.call() {
        Ok(response) => {
            let status = response.status();
            let status_text = response.status_text().to_string();
            let headers = opts
                .show_headers
                .iter()
                .filter_map(|name| {
                    response
                        .header(name)
                        .map(|value| (name.clone(), value.into()))
                })
                .collect();
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
                certificate: if url.starts_with("https://") {
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
            }
        }
        Err(error) => probe_error(url, &started, error.to_string()),
    }
}

/// Build a failed HttpResult with consistent empty fields.
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

//
// Consent-gated loopback load testing.
//
// Hard restrictions: only loopback targets (localhost/127.0.0.0/8/::1),
// sequential requests paced at a bounded rate (<= 50/s), and a bounded
// total request budget (<= 5000). No concurrency, no spoofing.
//

const ROTATING_USER_AGENTS: [&str; 8] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
];

fn ensure_loopback(host: &str, family: Family) -> Result<(), String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !ip.is_loopback() {
            return Err(
                "load-test only accepts loopback targets: localhost, 127.0.0.1, or ::1".into(),
            );
        }
    } else if !host.eq_ignore_ascii_case("localhost") {
        return Err(format!(
            "load-test refuses non-loopback target \"{host}\": only localhost, 127.0.0.1, or ::1 are allowed"
        ));
    }
    for address in resolve(host, 0, family)
        .map_err(|error| format!("DNS resolution failed: {error}"))?
        .iter()
    {
        if !address.ip().is_loopback() {
            return Err(format!("load-test refuses non-loopback address {address}"));
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
    first_error: Option<String>,
    total_elapsed_ms: u128,
    actual_rate: f64,
}

fn load_test(value: &str, opts: &Options) -> Result<LoadTestReport, String> {
    let started = Instant::now();
    let (host, port, url) = target(value)?;
    let url = url.unwrap_or_else(|| format!("http://{host}:{port}{}", opts.path));
    ensure_loopback(&host, opts.family)?;

    let interval = Duration::from_nanos(1_000_000_000 / u64::from(opts.rate).max(1));
    let mut sent = 0_u32;
    let mut ok = 0_u32;
    let mut latencies: Vec<u128> = Vec::new();
    let mut statuses: BTreeMap<String, u32> = BTreeMap::new();
    let mut first_error: Option<String> = None;
    let mut first_error_count = 0_u32;

    for index in 0..opts.count {
        let tick = Instant::now();
        let effective = if opts.rotate_user_agent {
            let mut per_request = opts.clone();
            per_request.user_agent =
                Some(ROTATING_USER_AGENTS[index as usize % ROTATING_USER_AGENTS.len()].into());
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
    let resolved =
        resolve(&host, port, opts.family).map_err(|e| format!("DNS resolution failed: {e}"))?;
    if resolved.is_empty() {
        return Err("DNS resolution returned no addresses".into());
    }
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
        }
        if let Some(error) = &http.certificate_error {
            println!("  TLS error: {error}");
        }
    }
}

fn print_report_csv(report: &DiagnosticReport) {
    println!("target,ok,host,port,total_elapsed_ms,addresses,connected,http_status,error");
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
                if report.rotate_user_agent {
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

fn print_dns_report(report: &DnsReport, opts: &Options) {
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
    let (sender, receiver) = mpsc::channel();
    for chunk in targets.chunks(targets.len().div_ceil(workers)) {
        let sender = sender.clone();
        let opts = opts.clone();
        let chunk = chunk.to_vec();
        thread::spawn(move || {
            for value in chunk {
                sender.send(diagnose(&value, &opts)).ok();
            }
        });
    }
    drop(sender);
    let mut ok = true;
    for result in receiver {
        match result {
            Ok(report) => {
                ok &= report.ok;
                print_report_one(&report, opts);
            }
            Err(e) => {
                ok = false;
                eprintln!("error: {e}");
            }
        }
    }
    Ok(ok)
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
            let values =
                resolve(host, 0, opts.family).map_err(|e| format!("resolve failed: {e}"))?;
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
                for value in &values {
                    println!("{} ({})", value.ip(), family(value));
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
            let port = pos
                .get(1)
                .ok_or("http-check requires a port (default is 80, or omit it entirely)")?
                .parse::<u16>()
                .map_err(|_| "port must be 1-65535")?;
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
        Some("udp-check") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("udp-check requires <host>")?;
            let port = pos
                .get(1)
                .ok_or("udp-check requires <port>")?
                .parse::<u16>()
                .map_err(|_| "port must be 1-65535")?;
            let started = Instant::now();
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
                thread::sleep(Duration::from_secs(interval));
            }
            Ok(ok)
        }
        Some(value) => Err(format!("unknown command: {value}")),
    }
}

fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
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
        assert!(ensure_loopback("rkriad585.github.io", Family::Any).is_err());
        assert!(ensure_loopback("1.1.1.1", Family::Any).is_err());
        assert!(ensure_loopback("example.com", Family::Any).is_err());
    }

    #[test]
    fn loopback_gate_accepts_loopback_only() {
        assert!(ensure_loopback("localhost", Family::Any).is_ok());
        assert!(ensure_loopback("127.0.0.1", Family::Any).is_ok());
        assert!(ensure_loopback("::1", Family::Any).is_ok());
        assert!(ensure_loopback("LOCALHOST", Family::Any).is_ok());
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
    }

    #[test]
    fn rotate_user_agent_flag_is_absorbed() {
        let (opts, pos) = options(&["--rotate-user-agent".into()]).unwrap();
        assert!(opts.rotate_user_agent);
        assert!(pos.is_empty());
    }

    #[test]
    fn rotating_browser_agents_are_valid_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for agent in ROTATING_USER_AGENTS {
            assert!(validate_user_agent(agent).is_ok());
            seen.insert(agent.to_string());
        }
        assert_eq!(seen.len(), ROTATING_USER_AGENTS.len());
    }
}
