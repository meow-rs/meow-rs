//! Controller CORS middleware (issue #974).
//!
//! Mirrors the wire behaviour of the linked metacubex/chi CORS package
//! upstream uses on the controller router, which `tower-http::CorsLayer`
//! cannot reproduce: two distinct response shapes keyed on whether an
//! `external-controller-cors:` map was *present* in the config at all.
//!
//! - **Absent map** → the permissive `AllowAll` shape: literal `*` for
//!   allow-methods/-headers/-origin on a 200 preflight and a single
//!   combined `vary` header.
//! - **Present map** (even `{}`) → the configured `cors.New` shape: the
//!   echo'd `Origin`, the single requested method uppercased, canonical
//!   requested headers, `Access-Control-Max-Age: 300`, three separate
//!   `vary` adds, a denied preflight answered `200` with only the `vary`
//!   trio, and `HEAD` never in the allow-methods set.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, header::HeaderValue, Method, Request, Response, StatusCode},
    middleware::Next,
};

use crate::routes::AppState;

/// The configured-path method set — upstream's `AllowedMethods`. `HEAD`
/// is deliberately absent: a preflight asking for it is denied
/// (weird-but-real, probe-verified); `OPTIONS` is the library's own
/// special case.
const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// `Access-Control-Max-Age` on a configured-path preflight.
const MAX_AGE: &str = "300";

const AC_REQUEST_PRIVATE_NETWORK: &str = "access-control-request-private-network";
const AC_ALLOW_PRIVATE_NETWORK: &str = "access-control-allow-private-network";
const VARY_ORIGIN: HeaderValue = HeaderValue::from_static("origin");
const VARY_ACRM: HeaderValue = HeaderValue::from_static("access-control-request-method");
const VARY_ACRH: HeaderValue = HeaderValue::from_static("access-control-request-headers");
const VARY_COMBINED: HeaderValue = HeaderValue::from_static(
    "origin, access-control-request-method, access-control-request-headers",
);
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

/// The permissive `AllowAll` middleware — verbatim wire mirror of the
/// absent-map upstream shape (issue #974).
async fn handle_permissive(req: Request<Body>, next: Next) -> Response<Body> {
    if is_preflight(&req) {
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::OK;
        let h = resp.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, STAR);
        h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, STAR);
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, STAR);
        h.insert(header::VARY, VARY_COMBINED);
        return resp;
    }
    let had_origin = req.headers().contains_key(header::ORIGIN);
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if had_origin {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, STAR);
    }
    h.append(header::VARY, VARY_ORIGIN);
    resp
}

/// The configured `cors.New` middleware — verbatim wire mirror of the
/// present-map upstream shape (issue #974).
async fn handle_configured(state: &AppState, req: Request<Body>, next: Next) -> Response<Body> {
    let cors = &state.cors;
    if !is_preflight(&req) {
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut resp = next.run(req).await;
        let h = resp.headers_mut();
        if let Some(origin) = origin {
            if origin_allowed(&cors.allow_origins, &origin) {
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
    // The configured path's `AllowedHeaders` is `["*"]` upstream — every
    // requested header passes and is echoed canonicalized, in request order.
    let req_headers = req
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let canonical: Vec<String> = req_headers
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(canonical_header_key)
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

/// Dispatch on the startup snapshot — the two middlewares never mix their
/// header sets (issue #974). Mounted outside Bearer auth (so preflights
/// answer) only when a secret is configured — the no-secret controller
/// deliberately emits no CORS grants behind its Host/Origin/Fetch-Site
/// guard. Every transport — plain TCP, TLS, the Unix socket and the
/// Windows named pipe — serves the same router.
pub async fn handle(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    if state.cors.configured {
        handle_configured(&state, req, next).await
    } else {
        handle_permissive(req, next).await
    }
}
