//! `GET /traffic/ledger` and `DELETE /traffic/ledger` (meow extension, no
//! mihomo equivalent): the per-day traffic by host, app, policy and
//! interface kept by [`meow_common::traffic_ledger`].

use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use meow_common::traffic_ledger::{self, GroupBy, Report};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct LedgerParams {
    from: Option<String>,
    to: Option<String>,
    by: Option<String>,
    host: Option<String>,
    app: Option<String>,
    policy: Option<String>,
    interface: Option<String>,
}

#[derive(Serialize)]
struct LedgerResponse {
    /// `traffic-ledger.enable`. Off, or built without the `traffic-ledger`
    /// feature, nothing is recorded and `rows` is empty.
    enabled: bool,
    #[serde(flatten)]
    report: Report,
}

fn bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "message": message })),
    )
        .into_response()
}

/// `GET /traffic/ledger?from=&to=&by=&host=&app=&policy=&interface=`: the
/// traffic of the local days `from` to `to` (`YYYY-MM-DD`, both included,
/// today by default), grouped `by` `host` (the default), `app`, `policy`
/// or `interface`, largest first. `host`, `app`, `policy` and `interface`
/// keep the rows matching them, to drill into one group.
pub(crate) async fn get_ledger(Query(params): Query<LedgerParams>) -> Response {
    let today = traffic_ledger::today();
    let day = |date: Option<&str>| match date {
        None => Ok(today),
        Some(date) => traffic_ledger::day_of_date(date)
            .ok_or_else(|| format!("invalid date {date:?}: expected YYYY-MM-DD")),
    };
    let (from, to) = match (day(params.from.as_deref()), day(params.to.as_deref())) {
        (Ok(from), Ok(to)) => (from, to),
        (Err(message), _) | (_, Err(message)) => return bad_request(&message),
    };
    if from > to {
        return bad_request(&format!(
            "from {} is after to {}",
            traffic_ledger::date_of_day(from),
            traffic_ledger::date_of_day(to)
        ));
    }
    let by = match params.by.as_deref().map(str::parse::<GroupBy>).transpose() {
        Ok(by) => by.unwrap_or_default(),
        Err(message) => return bad_request(&message),
    };
    let query = traffic_ledger::Query {
        from,
        to,
        by,
        host: params.host,
        app: params.app,
        policy: params.policy,
        interface: params.interface,
    };
    // A query writes out what the tunnel counted first, then reads the
    // database.
    let blocking = query.clone();
    match tokio::task::spawn_blocking(move || traffic_ledger::query(&blocking)).await {
        Ok(Some(Ok(report))) => Json(LedgerResponse {
            enabled: true,
            report,
        })
        .into_response(),
        Ok(None) => Json(LedgerResponse {
            enabled: false,
            report: Report {
                from: traffic_ledger::date_of_day(query.from),
                to: traffic_ledger::date_of_day(query.to),
                by: query.by,
                ..Report::default()
            },
        })
        .into_response(),
        Ok(Some(Err(e))) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "message": format!("traffic ledger query failed: {e}") })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "message": format!("traffic ledger query failed: {e}") })),
        )
            .into_response(),
    }
}

/// `DELETE /traffic/ledger`: delete everything the ledger holds, on disk
/// too while `traffic-ledger.enable` is off.
pub(crate) async fn clear_ledger() -> Response {
    let failed = |e: &dyn std::fmt::Display| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "message": format!("traffic ledger clear failed: {e}") })),
        )
            .into_response()
    };
    match tokio::task::spawn_blocking(traffic_ledger::clear).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => failed(&e),
        Err(e) => failed(&e),
    }
}
