# Security

## Supported version

Use **0.1.1 or later**. Version 0.1.0 checked DNS before using a client that could independently resolve the hostname, leaving a DNS rebinding/resolver mismatch gap. The 0.1.1 transport replaces that path with direct connections to a validated IP address and validates every redirect independently.

## Security boundaries

- Reject non-public, malformed, mixed public/private, empty, and unexpected-family DNS results before creating a connection.
- Pin the chosen address as the HTTPS client's literal destination. There is no hostname lookup during connection establishment, no automatic fallback to another address, and no reuse of pooled connections.
- Retain the requested hostname for TLS SNI, the HTTP Host header, and `tls.checkServerIdentity`; require a trusted certificate and TLS 1.2 or newer.
- Do not use global fetch, global agents, proxy environment settings, or caller-supplied headers/options to make target requests. Production callers cannot disable these controls through a URL or CLI option.
- Reapply the policy for every redirect; reject HTTP downgrades, credentials, IP literals, internal hostnames, custom ports, and protocol upgrades.
- Bound deadlines, response headers, redirects, and inspected HTML. The direct transport requests identity encoding and rejects unexpected compression.

The package remains dependency-free. Test dependency-injection hooks accept executable functions only from trusted code; never pass executable code or transport configuration from an HTTP request. An attacker with code execution in the Node process is outside this boundary.

## Deployment responsibilities

The CLI has no HTTP server. Turning it into a public service also requires authorization, rate limits, destination policy and suitable network isolation. Publicly routable addresses can serve sensitive applications, and routing/firewall changes can make addresses behave differently from their nominal scope. This fix does not claim to protect against a compromised Node runtime, DNS resolver software exploit, arbitrary routing configuration, or unsafe changes to the transport.

## Reporting

For security issues, use GitHub's private vulnerability reporting when enabled, or contact the repository owner through an existing private channel. Do not post credentials, private infrastructure details, or working exploitation details in a public issue. No report channel is represented as enabled unless GitHub actually offers it.
