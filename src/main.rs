use serde::Serialize;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::{Command, ExitCode};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const USER_AGENT: &str = concat!("ddos/", env!("CARGO_PKG_VERSION"));
const DEFAULT_TIMEOUT: u64 = 5;
const MAX_TIMEOUT: u64 = 120;
const MAX_RETRIES: u32 = 5;
const MAX_BATCH: usize = 100;
const MAX_CONCURRENCY: usize = 8;
const MAX_REPEAT_SECONDS: u64 = 3600;
const INSTALL_SH: &str = "https://raw.githubusercontent.com/rkriad585/ddos/main/installer.sh";
const INSTALL_PS1: &str = "https://raw.githubusercontent.com/rkriad585/ddos/main/installer.ps1";

#[derive(Clone, Copy, PartialEq)]
enum Output {
    Text,
    Json,
}
#[derive(Clone)]
struct Options {
    timeout: Duration,
    retries: u32,
    output: Output,
    verbose: bool,
    path: String,
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

fn usage() {
    println!("ddos {VERSION} — bounded network diagnostics\n\nUsage:\n  ddos resolve <host> [--output text|json]\n  ddos tcp-check <host> <port> [--timeout <seconds>] [--retry <count>] [--output text|json]\n  ddos http-check <host> [port] [--path /path] [--timeout <seconds>] [--output text|json]\n  ddos diagnose <url|host:port> [--timeout <seconds>] [--retry <count>] [--output text|json]\n  ddos batch <file|-> [--timeout <seconds>] [--retry <count>] [--output text|json]\n  ddos repeat <url|host:port> --interval <seconds> --duration <seconds> [options]\n  ddos self-update\n  ddos self-uninstall\n  ddos --version\n  ddos --help\n\nExit codes: 0 success, 1 diagnostic failure, 2 invalid usage.\nLimits: timeout 1-120s, retries 0-5, batch 100 targets, concurrency 8, repeat 1 hour.\nOnly use this tool against systems you own or are authorized to test.");
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

fn options(args: &[String]) -> Result<(Options, Vec<String>), String> {
    let mut out = Options {
        timeout: Duration::from_secs(DEFAULT_TIMEOUT),
        retries: 0,
        output: Output::Text,
        verbose: false,
        path: "/".into(),
    };
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout" => {
                out.timeout =
                    Duration::from_secs(number(args.get(i + 1), "--timeout", 1, MAX_TIMEOUT)?);
                i += 2;
            }
            "--retry" => {
                out.retries = number(args.get(i + 1), "--retry", 0, MAX_RETRIES as u64)? as u32;
                i += 2;
            }
            "--output" => {
                out.output = match args.get(i + 1).map(String::as_str) {
                    Some("text") => Output::Text,
                    Some("json") => Output::Json,
                    Some(v) => return Err(format!("unsupported output format: {v}")),
                    None => return Err("--output requires text or json".into()),
                };
                i += 2;
            }
            "--path" => {
                let path = args.get(i + 1).ok_or("--path requires a URL path")?;
                if !path.starts_with('/') || path.contains(['\r', '\n']) || path.len() > 2048 {
                    return Err(
                        "path must start with '/', contain no newlines, and be at most 2048 bytes"
                            .into(),
                    );
                }
                out.path = path.clone();
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
                out.verbose = true;
                i += 1;
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
    Ok((out, positional))
}

fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    (host, port).to_socket_addrs().map(|v| v.collect())
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

fn http_probe(url: &str, opts: &Options) -> HttpResult {
    let started = Instant::now();
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(opts.timeout)
        .timeout_read(opts.timeout)
        .timeout_write(opts.timeout)
        .redirects(5)
        .user_agent(USER_AGENT)
        .build();
    match agent.head(url).call() {
        Ok(response) => HttpResult {
            url: url.into(),
            status: Some(response.status()),
            status_text: Some(response.status_text().into()),
            elapsed_ms: started.elapsed().as_millis(),
            error: None,
        },
        Err(error) => HttpResult {
            url: url.into(),
            status: None,
            status_text: None,
            elapsed_ms: started.elapsed().as_millis(),
            error: Some(error.to_string()),
        },
    }
}

fn diagnose(value: &str, opts: &Options) -> Result<DiagnosticReport, String> {
    let started = Instant::now();
    let (host, port, url) = target(value)?;
    let resolved = resolve(&host, port).map_err(|e| format!("DNS resolution failed: {e}"))?;
    if resolved.is_empty() {
        return Err("DNS resolution returned no addresses".into());
    }
    let results = addresses(&resolved, opts);
    let connected = results.iter().any(|v| v.connected);
    let http = url.as_deref().map(|v| http_probe(v, opts));
    let http_ok = http
        .as_ref()
        .is_none_or(|v| v.status.is_some_and(|s| s < 500));
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
                print_report(&report, opts);
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
            let values = resolve(host, 0).map_err(|e| format!("resolve failed: {e}"))?;
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
            } else {
                for value in values {
                    println!("{} ({})", value.ip(), family(&value));
                }
            }
            Ok(true)
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
            print_report(&report, &opts);
            Ok(report.ok)
        }
        Some("http-check") => {
            let (opts, pos) = options(&args[1..])?;
            let host = pos.first().ok_or("http-check requires <host>")?;
            let port = pos.get(1).and_then(|v| v.parse().ok()).unwrap_or(80);
            let report = diagnose(&format!("http://{host}:{port}{}", opts.path), &opts)?;
            print_report(&report, &opts);
            Ok(report.ok)
        }
        Some("diagnose") => {
            let (opts, pos) = options(&args[1..])?;
            let value = pos.first().ok_or("diagnose requires <url|host:port>")?;
            let report = diagnose(value, &opts)?;
            print_report(&report, &opts);
            Ok(report.ok)
        }
        Some("batch") => {
            let (opts, pos) = options(&args[1..])?;
            batch(pos.first().ok_or("batch requires <file|->")?, &opts)
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
                print_report(&report, &opts);
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
        let result = batch(
            path.to_str().unwrap(),
            &Options {
                timeout: Duration::from_secs(1),
                retries: 0,
                output: Output::Json,
                verbose: false,
                path: "/".into(),
            },
        );
        fs::remove_file(path).unwrap();
        assert!(result.is_err());
    }
}
