# Changelog

## 0.1.1 - 2026-10-30

Security fix: replaced DNS-preflight-plus-fetch with a direct HTTPS transport that pins each connection to a validated public IP address. TLS verification still checks the original hostname. Every redirect is revalidated, mixed/non-public DNS answers are rejected, and environment proxy/global-agent state is bypassed. Expanded special-address rejection and added connection, certificate, deadline, header-limit and redirect regression tests using real loopback TLS fixtures. Removed the old warning about an unfixed connection gap and documented the implemented controls and deployment boundaries.

The command and JSON result format are unchanged. This version uses the system DNS resolver and direct HTTPS instead of Cloudflare DNS-over-HTTPS. Unexpected compression now produces an inconclusive result rather than being parsed as HTML.
