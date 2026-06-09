# Changelog

## [0.1.0] — 2026-06-08

Initial release. Requires `gravitee-resource-icap` 0.1.0.

### Features

* Gravitee APIM 4.x reactive policy plugin (`id=icap-content-scan`, `proxy=REQUEST,RESPONSE`)
* Synchronous and asynchronous ICAP content scanning
* Automatic phase discovery: Request flow → `REQMOD`, Response flow → `RESPMOD`
* OPTIONS-based skip when the ICAP server does not advertise the required method
* Scan modes: `AUTO` (preview-then-continue), `QUICK`, `FULL`
* Block, detect-only, and fail-open/fail-closed behaviour for threats and ICAP errors
* Optional ICAP content modification (sanitized body and header updates)
* Webhooks in both sync and async modes (`webhookEnabled`, `webhookOn`, configurable delivery)
* Optional custom webhook payload template (Gravitee Expression Language)
* Async threat side effects: `LOG`, `METRIC`, `CONTEXT_ATTRIBUTE`
* Debug logging under `io.gravitee.policy.icap`
* Policy Studio schema with Basic and Advanced configuration sections
