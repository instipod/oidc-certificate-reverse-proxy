## oidc-certificate-reverse-proxy

A reverse proxy written in Go.  It uses OIDC authentication on the frontend to identify users.  It generates dynamic client certificates (using a provided or generated CA) to the upstream server.

This can be used to shoehorn in SSO authentication to applications that don't support SSO but do support client certificate authentication.

### Configuration
An example JSON configuration file is provided in `example_config.json`.  Copy this file to `config.json` to get started.

By default, the generated client certificate is presented to the upstream server via mutual TLS. Set `upstream.cert_mode` to `"header"` to instead present it as an HTTP header (e.g. `SSL_CLIENT_CERT`), the way a reverse proxy such as nginx or Apache would when terminating client-cert TLS itself. The certificate is sent as a URL-encoded PEM blob, matching the convention used by nginx's `$ssl_client_escaped_cert`. The header name can be customized with `upstream.cert_header_name` (defaults to `SSL_CLIENT_CERT`).