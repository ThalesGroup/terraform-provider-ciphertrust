# Security Policy

## Good practices to follow

**Never commit credentials to source control.** Do not put a CipherTrust username, password, API
token, or CA private key in a `.tf` file, the `~/.ciphertrust/config` file, or anywhere else that
gets checked in. Use environment variables (`CIPHERTRUST_USERNAME`, `CIPHERTRUST_PASSWORD`, etc.),
Terraform variables marked `sensitive = true`, or a secrets manager instead. See
[README: Provider configuration](README.md#provider-configuration) for the supported ways to supply
credentials.

## Supported versions

This provider does not currently maintain multiple parallel release lines. Only the most recent
state of the [`1.0.1` branch](https://github.com/ThalesGroup/terraform-provider-ciphertrust/tree/1.0.1)
receives security fixes. Upgrade to the latest release before reporting a suspected vulnerability,
in case it has already been fixed.

## Reporting a vulnerability

Do not open a public GitHub issue for a suspected security vulnerability. Instead, email
**security@opensource.thalesgroup.com** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce it, including provider version, Terraform version, and relevant configuration
- Any proof-of-concept code or logs, with credentials and other sensitive values redacted

You should receive an acknowledgement of your report. We will work with you to understand and
validate the issue before any details are made public.

## Disclosure policy

We ask that you give us a reasonable opportunity to investigate and release a fix before any public
disclosure of the vulnerability or its details.

## Security-related configuration

A few provider settings directly affect the security posture of a deployment:

- **TLS verification** is enabled by default (`no_ssl_verify = false`), with a minimum negotiated
  TLS version of 1.2. Set `no_ssl_verify = true` only for local development or testing; it disables
  certificate chain and hostname validation and exposes connections to man-in-the-middle attacks.
  For a private PKI or internally-issued certificate, supply `ca_cert` instead. See
  [README: TLS verification](README.md#tls-verification).
- **`~/.ciphertrust/config`** may hold credentials in plain text. The provider refuses to read this
  file if it is a symbolic link or if it is readable, writable, or executable by group or other —
  restrict it with `chmod 600 ~/.ciphertrust/config`.
- **Provider logs** (`log_file`, default `ctp.log`) are written with mode `0600`, since `debug`
  level records API request detail.

## Known security gaps

There are no known unresolved security gaps at this time. If you find one, please report it as
described above rather than opening a public issue.
