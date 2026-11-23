//! Controller CORS middleware (issue #974).
//!
//! Mirrors the wire behaviour of the configured `cors.New` middleware
//! upstream links on the controller router, which `tower-http::CorsLayer`
//! cannot reproduce: the echo'd `Origin`, the single requested method
//! uppercased, canonical requested headers, `Access-Control-Max-Age:
//! 300`, three separate `vary` adds, a denied preflight answered `200`
//! with only the `vary` trio, and `HEAD` never in the allow-methods set.
//!
//! The `external-controller-cors:` map's *presence* does not select
//! middleware: under a configured secret an absent map serves this same
//! configured path on `["*"]`/`true` defaults. Upstream's permissive
//! `AllowAll` shape fires only under an explicit `secret: ""`
//! (probe-verified), and meow mounts no CORS layer without a secret at
//! all (deliberate divergence — the origin guard already 403s
//! cross-origin requests), so AllowAll has no meow counterpart.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, header::HeaderValue, Method, Request, Response, StatusCode},
    middleware::Next,
};

use crate::routes::AppState;

/// The configured-path method set — upstream's `AllowedMethods`. `HEAD`
/// is deliberately absent: a preflight asking for it is denied and an
/// actual `HEAD` gets no `Access-Control-Allow-Origin` either
/// (weird-but-real, probe-verified); `OPTIONS` is the library's own
/// special case.
const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// The configured-path request-header allowlist — upstream's
/// `AllowedHeaders`: `Content-Type`, `Authorization` and `Origin`,
/// case-insensitive. A preflight asking for anything else is denied in
/// full, not trimmed (issue #974).
const ALLOWED_HEADERS: &[&str] = &["content-type", "authorization", "origin"];

/// `Access-Control-Max-Age` on a configured-path preflight.
const MAX_AGE: &str = "300";

const AC_REQUEST_PRIVATE_NETWORK: &str = "access-control-request-private-network";
const AC_ALLOW_PRIVATE_NETWORK: &str = "access-control-allow-private-network";
const VARY_ORIGIN: HeaderValue = HeaderValue::from_static("origin");
const VARY_ACRM: HeaderValue = HeaderValue::from_static("access-control-request-method");
const VARY_ACRH: HeaderValue = HeaderValue::from_static("access-control-request-headers");
const STAR: HeaderValue = HeaderValue::from_static("*");

/// `true` when the request is a CORS preflight: `OPTIONS` carrying both
/// an `Origin` and a non-empty `Access-Control-Request-Method` (chi's
/// guard — anything else falls through to the router, where a bare
/// `OPTIONS` reaches handlers and answers 405).
fn is_preflight(req: &Request<Body>) -> bool {
    req.method() == Method::OPTIONS
        && req.headers().contains_key(header::ORIGIN)
        && req
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|m| !m.trim().is_empty())
}

/// Case-insensitive origin allow-check for the configured path: `*` or an
/// empty allow-list matches everything; entries containing a `*` glob on
/// the first `*` (prefix + suffix, case-insensitive); the rest compare
/// exactly, case-insensitively.
fn origin_allowed(allow_origins: &[String], origin: &str) -> bool {
    if allow_all(allow_origins) {
        return true;
    }
    let origin = origin.to_ascii_lowercase();
    allow_origins.iter().any(|p| {
        let p = p.to_ascii_lowercase();
        if let Some(star) = p.find('*') {
            let (pre, suf) = (&p[..star], &p[star + 1..]);
            origin.len() >= pre.len() + suf.len()
                && origin.starts_with(pre)
                && origin.ends_with(suf)
        } else {
            p == origin
        }
    })
}

/// Whether the allow-list means "allow every origin" — a `*` entry or an
/// explicitly empty list; allow-all replies the literal `*` instead of
/// echoing the request `Origin`.
fn allow_all(allow_origins: &[String]) -> bool {
    allow_origins.is_empty() || allow_origins.iter().any(|o| o == "*")
}

/// Go's `http.CanonicalHeaderKey`: uppercase the first letter and any
/// letter after `-`, lowercase the rest (`authorization` →
/// `Authorization`). The configured path echoes requested headers in this
/// form, in request order.
fn canonical_header_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper = true;
    for c in s.trim().chars() {
        if upper && c.is_ascii_lowercase() {
            out.extend(c.to_uppercase());
        } else if !upper && c.is_ascii_uppercase() {
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
        upper = c == '-';
    }
    out
}

/// The configured `cors.New` middleware — verbatim wire mirror of the
/// upstream shape (issue #974). Mounted outside Bearer auth (so
/// preflights answer) only when a secret is configured — the no-secret
/// controller deliberately emits no CORS grants behind its
/// Host/Origin/Fetch-Site guard. Every transport — plain TCP, TLS, the
/// Unix socket and the Windows named pipe — serves the same router.
pub async fn handle(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let cors = &state.cors;
    if !is_preflight(&req) {
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        // Upstream's `handleActualRequest` gates the grant on the same
        // allowlists as a preflight — origin *and* method — so a HEAD
        // from an allowed origin still earns no ACAO (issue #974).
        let method_allowed = ALLOWED_METHODS.contains(&req.method().as_str());
        let mut resp = next.run(req).await;
        let h = resp.headers_mut();
        if let Some(origin) = origin {
            if method_allowed && origin_allowed(&cors.allow_origins, &origin) {
                h.insert(
                    header::ACCESS_CONTROL_ALLOW_ORIGIN,
                    if allow_all(&cors.allow_origins) {
                        STAR
                    } else {
                        HeaderValue::from_str(&origin).unwrap_or(STAR)
                    },
                );
            }
        }
        h.append(header::VARY, VARY_ORIGIN);
        return resp;
    }

    // Preflight — always 200 with the `vary` trio; the CORS headers ride
    // only when origin, method and every requested header pass.
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    {
        let h = resp.headers_mut();
        h.append(header::VARY, VARY_ORIGIN);
        h.append(header::VARY, VARY_ACRM);
        h.append(header::VARY, VARY_ACRH);
    }

    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !origin_allowed(&cors.allow_origins, origin) {
        return resp;
    }
    let req_method = req
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_ascii_uppercase();
    if !ALLOWED_METHODS.contains(&req_method.as_str()) {
        return resp;
    }
    // Requested headers must be a case-insensitive subset of
    // `AllowedHeaders` — one unsupported name denies the whole grant;
    // allowed names echo canonicalized, in request order.
    let req_headers = req
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let requested: Vec<&str> = req_headers
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    if !requested
        .iter()
        .all(|name| ALLOWED_HEADERS.contains(&name.to_ascii_lowercase().as_str()))
    {
        return resp;
    }
    let canonical: Vec<String> = requested
        .iter()
        .map(|name| canonical_header_key(name))
        .collect();

    let h = resp.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        if allow_all(&cors.allow_origins) {
            STAR
        } else {
            HeaderValue::from_str(origin).unwrap_or(STAR)
        },
    );
    if let Ok(v) = HeaderValue::from_str(&req_method) {
        h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, v);
    }
    if !canonical.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&canonical.join(", ")) {
            h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v);
        }
    }
    h.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static(MAX_AGE),
    );
    // Private-Network-Access: only when the operator opted in *and* the
    // request asked for it with the literal string `true`.
    if cors.allow_private_network
        && req
            .headers()
            .get(AC_REQUEST_PRIVATE_NETWORK)
            .is_some_and(|v| v == "true")
    {
        h.insert(AC_ALLOW_PRIVATE_NETWORK, HeaderValue::from_static("true"));
    }
    resp
}
