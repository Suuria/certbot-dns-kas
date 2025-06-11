# THIS IS A PROJECT CREATED WITH AI

# Certbot DNS KAS Plugin

A Certbot DNS authenticator plugin for All-inkl KAS Server.

## Installation

```bash
pip install certbot-dns-kas
```

Or install from source:

```bash
git clone https://github.com/yourusername/certbot-dns-kas.git
cd certbot-dns-kas
pip install .
```

## Usage

### 1. Create credentials file

Create a file with your KAS credentials (e.g., `kas.ini`):

```ini
# KAS API credentials
dns_kas_login = your_login_name
dns_kas_authtype = plain
dns_kas_authdata = your_password
```

**Important:** Make sure to secure this file:
```bash
chmod 600 kas.ini
```

### 2. Request certificate

Use the plugin with Certbot:

```bash
certbot certonly \
  --authenticator dns-kas \
  --dns-kas-credentials /path/to/kas.ini \
  --dns-kas-propagation-seconds 60 \
  -d example.com \
  -d *.example.com
```

## Configuration Options

- `--dns-kas-credentials`: Path to KAS credentials file (required)
- `--dns-kas-propagation-seconds`: DNS propagation timeout (default: 60)

## Credentials File Format

The credentials file should contain:

```ini
dns_kas_login = your_kas_login
dns_kas_authtype = plain  # or other auth type supported by KAS
dns_kas_authdata = your_kas_password
```

## Supported Authentication Types

- `plain`: Plain text password (default)
- Other types supported by the KAS API

## Requirements

- Python 3.6+
- Certbot 1.0.0+
- requests 2.20.0+

## Limitations

- Rate limited to prevent API abuse (5 second delay between requests)
- Requires valid KAS account with API access

## Troubleshooting

### Common Issues

1. **Authentication Failed**: Check your credentials in the credentials file
2. **Domain Not Found**: Ensure the domain is managed by your KAS account
3. **API Timeout**: The KAS API may be slow; increase propagation seconds

### Debug Mode

Run with verbose logging:

```bash
certbot --verbose certonly \
  --authenticator dns-kas \
  --dns-kas-credentials /path/to/kas.ini \
  -d example.com
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License

## Credits

Based on the original shell script `dns_kas.sh` from the acme.sh project.
