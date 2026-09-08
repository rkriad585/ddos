# DDoS Attacking Tool 

---
![DDoS](logo-on-light.svg)

---

## Overview

This Python-based DDoS (Distributed Denial of Service) attacking tool is designed for Termux users to perform stress tests on networks or websites. The tool allows users to launch multiple types of attacks like TCP, UDP, HTTP, and HTTPS floods, with additional features like random port selection, custom payloads, logging, and domain resolution.

### **Disclaimer**
This tool is intended solely for educational purposes and ethical testing of servers that you own or have permission to test. Unauthorized use of this tool for malicious purposes is illegal and unethical, and could lead to legal consequences.

## Features

- **Attack Types**: Support for TCP, UDP, HTTP, and HTTPS attacks.
- **Randomized Ports**: Randomize port selection to evade basic protection.
- **Rate Limiting (Timeout Control)**: Control the speed and timing of the attacks.
- **Custom Payloads**: Sophisticated HTTP headers for targeted HTTP/HTTPS attacks.
- **Logging**: All attack results are logged for later analysis.
- **Domain to IP Resolution**: Automatically resolves domains into IP addresses.
- **Interactive Menu**: User-friendly interactive command-line interface for easy use.

## Requirements

### Termux Environment

- **Python 3**: This tool is built in Python 3.
- **Required Libraries**:
  - `rich` for interactive console display and progress bars.

Install the necessary components with the following commands:

```bash
pkg install python
pip install rich
```

## How to Use the Tool

### 1. **Cloning the Repository**
You can download the tool by cloning this repository:

```bash
git clone https://github.com/rkstudio585/ddos-tool
cd ddos-tool
```

### 2. **Running the Script**
Execute the script using Python:

```bash
python ddos_pro_tool.py
```

### 3. **Interactive Menu**
Once you run the script, an interactive menu will guide you through setting up your attack:

#### Example of an HTTP Flood Attack:

```plantext
Enter target domain or IP: example.com
Enter target Port (e.g., 80 for HTTP, 443 for HTTPS): 80
Choose attack type (tcp, udp, http, https): http
Enter number of threads: 500
Enter request timeout (seconds): 2
Enable random port targeting? (y/n): n
```

In this case:
- The tool will resolve `example.com` to its IP address.
- It will launch 500 simultaneous HTTP requests to port 80, with a timeout of 2 seconds for each request.

### 4. **Logging**
Logs are saved to a file `attack_log.txt` in the current directory. You can review these logs to see which attacks succeeded or failed.

### Example Log Entry:
```plantext
2024-10-06 10:32:45 - HTTP request sent to 93.184.216.34:80
2024-10-06 10:32:45 - HTTP request sent to 93.184.216.34:80
2024-10-06 10:32:46 - TCP Attack on 93.184.216.34:80 successful
```

### 5. **Tool Output with Progress Bars**

As attacks are launched, the tool will show you progress for each type of attack:

```plantext
Launching HTTP attack on example.com...
[#######............................] 100/500 attacks completed
```

This progress bar dynamically updates to show the number of attacks completed out of the total.

## Key Functionalities

### Attack Types

- **TCP Flood**: Sends a flood of TCP SYN packets to the target. This is aimed at overwhelming the server’s ability to respond to requests, causing service disruptions.
- **UDP Flood**: A flood of UDP packets is sent to random ports on the target server.
- **HTTP Flood**: Sends a flood of HTTP requests with randomized headers (including user agents and IPs) to overwhelm the web server.
- **HTTPS Flood**: Same as HTTP Flood but works over SSL/TLS for encrypted communication.

### Customization

1. **Random IP Spoofing**: The tool spoofs IP addresses in HTTP/HTTPS requests using `X-Forwarded-For` headers to make it appear as if the traffic is coming from multiple sources.
2. **Timeout Control**: You can specify the timeout duration for connections, helping you simulate slow or fast attacks.
3. **Threading**: This tool supports multi-threading to allow the execution of hundreds of requests simultaneously.

## Example Usages

### TCP Flood Attack

```plantext
Enter target domain or IP: 192.168.1.1
Enter target Port (e.g., 80 for HTTP, 443 for HTTPS): 22
Choose attack type (tcp, udp, http, https): tcp
Enter number of threads: 200
Enter request timeout (seconds): 3
Enable random port targeting? (y/n): n
```

- Sends 200 TCP SYN packets to port 22 (commonly used for SSH) with a timeout of 3 seconds between retries.

### UDP Flood Attack

```plantext
Enter target domain or IP: 203.0.113.0
Enter target Port (e.g., 80 for HTTP, 443 for HTTPS): 53
Choose attack type (tcp, udp, http, https): udp
Enter number of threads: 500
Enter request timeout (seconds): 1
Enable random port targeting? (y/n): y
```

- Launches a UDP flood on a random port targeting the DNS server on port 53.
- Randomizes port selection with each request for better evasion.

### HTTP Flood Attack

```plantext
Enter target domain or IP: example.com
Enter target Port (e.g., 80 for HTTP, 443 for HTTPS): 80
Choose attack type (tcp, udp, http, https): http
Enter number of threads: 100
Enter request timeout (seconds): 5
Enable random port targeting? (y/n): n
```

- Launches an HTTP flood on the web server, using randomized user agents and fake IP addresses to appear as if requests are coming from multiple users.

### HTTPS Flood Attack

```plantext
Enter target domain or IP: example.com
Enter target Port (e.g., 443 for HTTPS): 443
Choose attack type (tcp, udp, http, https): https
Enter number of threads: 300
Enter request timeout (seconds): 10
Enable random port targeting? (y/n): n
```

- This attack encrypts HTTP requests over SSL/TLS, flooding the server with HTTPS requests.
  
## Best Practices for Ethical Use

- **Test on your own servers** or servers where you have permission from the owners.
- **Monitor network performance**: Ensure you're not overloading your network or causing unwanted disruptions.
- **Log your attacks**: Review logs regularly to check whether the attacks are succeeding and monitor response times from the target.

## Conclusion

This DDoS Attacking Tool provides a powerful yet easy-to-use framework for testing the resilience of servers under high traffic loads. It is meant for ethical use only—always ensure you have permission to run stress tests on the target.

---
