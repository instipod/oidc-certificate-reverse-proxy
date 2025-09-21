## oidc-certificate-reverse-proxy

A reverse proxy written in Go.  It uses OIDC authentication on the frontend to identify users.  It generates dynamic client certificates (using a provided or generated CA) to the upstream server.

This can be used to shoehorn in SSO authentication to applications that don't support SSO but do support client certificate authentication.

### Configuration
An example JSON configuration file is provided in `example_config.json`.  Copy this file to `config.json` to get started.