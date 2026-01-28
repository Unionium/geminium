# Geminium

A lightweight Gemini protocol server with Python script execution capabilities.

## Features

- **Full Gemini Protocol Compliance**: TLS encryption, proper status codes, and MIME types
- **Python Script Execution**: Run `.py` files directly as CGI-like scripts
- **Static File Serving**: Serve `.gemini` files
- **Simple Configuration**: Certificates and files in local directory
- **English/Russian**: Multilingual codebase with English as primary

## Requirements

- C compiler (GCC recommended)
- OpenSSL development libraries
- Python 3.x
- OpenSSL for certificate generation

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/unionium/geminium.git
cd geminium
```

### 2. Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install gcc libssl-dev python3
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc openssl-devel python3
```

**macOS:**
```bash
brew install openssl python3
```

### 3. Generate SSL Certificates

Gemini protocol requires TLS encryption. Generate self-signed certificates:

```bash
# Generate private key and certificate
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

# Set appropriate permissions
chmod 600 server.key
chmod 644 server.crt
```

### 4. Compile the Server

```bash
gcc -o geminium geminium.c -lssl -lcrypto
```

## Usage

### 1. Create Content Files

Create an `index.gemini` file in the same directory:

```gemini
# Welcome to My Gemini Capsule

This is my personal Gemini capsule, served by Geminium.

=> /hello.py Dynamic content example
=> https://github.com/Unionium/geminium/ About this server and source code

Enjoy your stay!
```

### 2. Create Python Scripts

Create a Python script that outputs Gemini text:

```python
#!/usr/bin/env python3
# hello.py

print("# Hello from Python!")
print()
print("Current date and time:")
import datetime
print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
print()
print("This page was generated dynamically by Python.")
```

### 3. Run the Server

```bash
./geminium
```

The server will start on port 1965.

### 4. Connect with a Gemini Client

Use a Gemini browser to connect:

```bash
# With Amfora
amfora gemini://localhost:1965/

# With Lagrange
lagrange gemini://localhost:1965/

# With AV-98
python3 av98.py gemini://localhost:1965/
```

## Directory Structure

```
./
├── geminium.c          # Server source code
├── geminium           # Compiled binary (after compilation)
├── index.gemini      # Default home page
└── README.md         # This file
```

## File Types

### Static Files (`.gemini`)
Plain text files in Gemini format. Automatically get "Powered by Geminium" footer unless already present.

### Python Scripts (`.py`)
Executable scripts that generate Gemini content on-the-fly. Must output valid Gemini text to stdout.

## Status Codes

- `20` - Success
- `42` - CGI Error (script execution failed)
- `51` - Not Found

## Security Considerations

⚠️ **Warning**: This server executes Python scripts with the same privileges as the server process.

1. **Run as non-root user**:
   ```bash
   useradd -r -s /bin/false geminium
   chown -R geminium:geminium /path/to/geminium
   sudo -u geminium ./geminium
   ```

2. **Isolate scripts directory** (recommended):
   ```bash
   mkdir scripts
   chmod 755 scripts
   # Move all .py files to scripts directory
   ```

3. **Use firewall rules**:
   ```bash
   sudo ufw allow 1965/tcp
   ```

## Development

### Testing Scripts

Test Python scripts directly:
```bash
python3 hello.py
```

## Example Configuration

### systemd Service (Linux)

Create `/etc/systemd/system/geminium.service`:

```ini
[Unit]
Description=Geminium Gemini Server
After=network.target

[Service]
Type=simple
User=geminium
WorkingDirectory=/var/geminium
ExecStart=/var/geminium/geminium
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable geminium
sudo systemctl start geminium
```

## Troubleshooting

### "Certificate not found" error
Ensure `server.crt` and `server.key` are in the same directory as the binary.

### "Permission denied" for scripts
Make Python scripts executable:
```bash
chmod +x *.py
```

### Connection refused
Check if another service is using port 1965:
```bash
sudo netstat -tlnp | grep :1965
```

### SSL handshake errors
Regenerate certificates with proper hostname:
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Please ensure code follows the existing style and includes appropriate comments.

## License

GNU General Public License v3.0 - See [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the simplicity of the Gemini protocol
- Built with OpenSSL for secure communications
- Thanks to all Gemini protocol contributors

---

**Powered by Geminium** – Bringing dynamic content to the small web.

*Gemini: The small internet protocol that's simple, lightweight, and human-centric.*
