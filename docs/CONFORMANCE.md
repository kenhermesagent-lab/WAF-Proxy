# Protocol conformance

This table is the published status of the HTTP behaviours the pipeline is
expected to handle. Each supported row names the test that proves it. A row
marked unsupported is a deliberate limit, not an untested claim.

| Behaviour | Status | Where |
| --- | --- | --- |
| `Content-Length` with `Transfer-Encoding` | Rejected with `400` | `TestRejectsAmbiguousFraming` |
| Duplicate `Content-Length` | Rejected with `400` | `TestRejectsAmbiguousFraming` |
| Absolute-form request target (`GET http://…`) | Rejected with `400` | `TestRejectsAmbiguousFraming` |
| Invalid header names | Rejected with `400` | `TestRejectsAmbiguousFraming` |
| `OPTIONS *` | Rejected with `400` | `TestRejectsAmbiguousFraming` |
| `TRACE`, `TRACK`, `CONNECT` | Rejected with `400` | `TestRejectsAmbiguousFraming` |
| Non-WebSocket `Upgrade` | Rejected with `400` | `TestRejectsAmbiguousFraming` |
| WebSocket upgrade | Forwarded and relayed | `TestWebSocketUpgradeReachesTheClient` |
| Encoded dot segments and `#` in the path | Screened before decoys, forwarded verbatim | `TestHashInPathSurvivesForwarding`, `TestDotSegmentsAreScreenedBeforeDecoys` |
| Dot segments that escape the root | Resolved before inspection and forwarding | `TestDotSegmentsAreScreenedBeforeDecoys` |
| `HEAD` | Forwarded as `HEAD`; `net/http` suppresses the body | Not covered by a test |
| `Range` requests | Forwarded unchanged; never served from the response cache | `TestRangeRequestBypassesTheCache` |
| `Expect: 100-continue` | Forwarded; `net/http` relays the interim response | Not covered by a test |
| `Vary` other than `Accept-Encoding` | Response not cached | `TestCacheSkipsResponsesThatVaryOnMoreThanEncoding` |
| `Set-Cookie` or `Cache-Control: private` | Response not cached | `TestCacheSkipsResponsesThatVaryOnMoreThanEncoding` |
| Request trailers | Not inspected; passed to the upstream as received | Unsupported as a WAF input |
| Response trailers and gRPC trailers | Not inspected | Unsupported |
| HTTP pipelining | Not supported by `net/http` | Unsupported |
| HTTP/3 | Supported when `WAFPROXY_HTTP3=1`: the same pipeline over QUIC on the WAN port, 0-RTT refused, advertised over TLS to HTTP/1.1 and HTTP/2 only | `TestHTTP3ServesTheSamePipeline` (GET, HEAD, POST), `TestHTTP3BlockedByTheSamePolicy`, `TestHTTP3ServesACacheHit`, `TestHTTP3RefusesZeroRTTAndBoundsStreams` |
| `Transfer-Encoding: chunked` requests | Decoded and buffered before inspection (up to the body ceiling) | Pipeline body limit tests |
| Responses larger than the profile ceiling | Cut and logged as `response-cap` | Response-cap tests |

## Retry and error semantics

| Case | Status | Where |
| --- | --- | --- |
| Upstream timeout | `504` | `TestUpstreamErrorStatusSeparatesTimeouts` |
| Other upstream failure | `502` | `TestUpstreamErrorStatusSeparatesTimeouts` |
| Idempotent request, no bytes read | Retried within `retries` | `TestRetryGetsIdempotentRequest` |
| Non-idempotent request | Never retried | `TestRetrySkipsNonIdempotentRequest` |
| Saturated site / client | `503` / `429` | `TestSiteCapRefusesBeyondLimit`, `TestClientCapIsPerClientAndCleansUp` |
