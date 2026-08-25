## oidc-certificate-reverse-proxy

A reverse proxy written in Go.  It uses OIDC authentication on the frontend to identify users.  It generates dynamic client certificates (using a provided or generated CA) to the upstream server.

This can be used to shoehorn in SSO authentication to applications that don't support SSO but do support client certificate authentication.

### Configuration
An example JSON configuration file is provided in `example_config.json`.  Copy this file to `config.json` to get started.

By default, the generated client certificate is presented to the upstream server via mutual TLS. Set `upstream.cert_mode` to `"header"` to instead present it as an HTTP header (e.g. `SSL_CLIENT_CERT`), the way a reverse proxy would when terminating client-cert TLS itself. The certificate is sent as a PEM blob with every newline replaced by a single space, matching the format WildFly/Undertow's `SSLHeaderHandler` expects (e.g. EJBCA's proxy-header port, such as 8082). The header name can be customized with `upstream.cert_header_name` (defaults to `SSL_CLIENT_CERT`).