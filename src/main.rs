use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_TIMEOUT: u64 = 5;

fn usage() {
    println!("ddos {VERSION} — bounded network diagnostics\n\nUsage:\n  ddos resolve <host>\n  ddos tcp-check <host> <port> [--timeout <seconds>]\n  ddos http-check <host> [port] [--path <path>] [--timeout <seconds>]\n  ddos --version\n  ddos --help\n\nThese commands perform one DNS lookup or one connection/request. They never flood, spoof, randomize targets, or create concurrent traffic.");
}

fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    (host, port)
        .to_socket_addrs()
        .map(|addresses| addresses.collect())
}

fn parse_timeout(args: &[String]) -> Result<Duration, String> {
    let mut timeout = DEFAULT_TIMEOUT;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--timeout" {
            i += 1;
            let value = args.get(i).ok_or("--timeout requires seconds")?;
            timeout = value
                .parse::<u64>()
                .map_err(|_| "timeout must be an integer")?;
            if timeout == 0 || timeout > 120 {
                return Err("timeout must be between 1 and 120 seconds".into());
            }
        } else {
            return Err(format!("unknown option: {}", args[i]));
        }
        i += 1;
    }
    Ok(Duration::from_secs(timeout))
}

fn tcp_check(host: &str, port: u16, timeout: Duration) -> io::Result<()> {
    let addresses = resolve(host, port)?;
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no addresses resolved",
        ));
    }
    for address in addresses {
        let started = Instant::now();
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                println!("open  {address}  ({:.0?})", started.elapsed());
                drop(stream);
                return Ok(());
            }
            Err(error) => eprintln!("closed/unreachable  {address}: {error}"),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "all resolved addresses failed",
    ))
}

fn http_check(host: &str, port: u16, path: &str, timeout: Duration) -> io::Result<()> {
    let addresses = resolve(host, port)?;
    let address = addresses
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses resolved"))?;
    let mut stream = TcpStream::connect_timeout(address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request = format!("HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: ddos/{VERSION}\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = [0_u8; 256];
    let size = stream.read(&mut response)?;
    let response = String::from_utf8_lossy(&response[..size]);
    let line = response.lines().next().unwrap_or("no response");
    println!("{address}  {line}");
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None | Some("--help") | Some("-h") => {
            usage();
            Ok(())
        }
        Some("--version") | Some("-V") => {
            println!("ddos {VERSION}");
            Ok(())
        }
        Some("resolve") => {
            let host = args.get(1).ok_or("resolve requires <host>")?;
            let addresses = resolve(host, 0).map_err(|e| format!("resolve failed: {e}"))?;
            for address in addresses {
                println!("{}", address.ip());
            }
            Ok(())
        }
        Some("tcp-check") => {
            let host = args.get(1).ok_or("tcp-check requires <host>")?;
            let port = args
                .get(2)
                .ok_or("tcp-check requires <port>")?
                .parse::<u16>()
                .map_err(|_| "port must be 1-65535")?;
            let timeout = parse_timeout(&args[3..])?;
            tcp_check(host, port, timeout).map_err(|e| e.to_string())
        }
        Some("http-check") => {
            let host = args.get(1).ok_or("http-check requires <host>")?;
            let has_port = args.get(2).is_some_and(|arg| !arg.starts_with('-'));
            let port = if has_port {
                args[2].parse::<u16>().map_err(|_| "port must be 1-65535")?
            } else {
                80
            };
            let option_start = if has_port { 3 } else { 2 };
            let mut path = "/";
            let mut timeout = Duration::from_secs(DEFAULT_TIMEOUT);
            let mut i = option_start;
            while i < args.len() {
                match args[i].as_str() {
                    "--path" => {
                        let value = args.get(i + 1).ok_or("--path requires a URL path")?;
                        if !value.starts_with('/')
                            || value.contains(['\r', '\n'])
                            || value.len() > 2048
                        {
                            return Err("path must start with '/', contain no newlines, and be at most 2048 bytes".into());
                        }
                        path = value;
                        i += 2;
                    }
                    "--timeout" => {
                        let value = args.get(i + 1).ok_or("--timeout requires seconds")?;
                        let seconds = value
                            .parse::<u64>()
                            .map_err(|_| "timeout must be an integer")?;
                        if seconds == 0 || seconds > 120 {
                            return Err("timeout must be between 1 and 120 seconds".into());
                        }
                        timeout = Duration::from_secs(seconds);
                        i += 2;
                    }
                    option => return Err(format!("unknown option: {option}")),
                }
            }
            http_check(host, port, path, timeout).map_err(|e| e.to_string())
        }
        Some(command) => Err(format!("unknown command: {command}")),
    }
}

fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}\nTry 'ddos --help' for usage.");
            ExitCode::from(2)
        }
    }
}
