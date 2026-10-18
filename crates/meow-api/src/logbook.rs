//! `GET /logbook` and `DELETE /logbook` (meow extension, no mihomo
//! equivalent): the persistent record of notable engine events kept by
//! [`meow_common::logbook`].

use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use meow_common::logbook::{self, Level, Page};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct LogbookParams {
    limit: Option<usize>,
    before: Option<u64>,
    since: Option<u64>,
    level: Option<String>,
    kind: Option<String>,
    subject: Option<String>,
}

#[derive(Serialize)]
struct LogbookResponse {
    /// `logbook.enable`. Off, nothing is recorded and `entries` is empty.
    enabled: bool,
    #[serde(flatten)]
    page: Page,
}

/// `GET /logbook?limit=&before=&since=&level=&kind=&subject=`: entries,
/// newest first. `level` is the lowest level returned, `kind` a kind or its
/// area (`config` matches `config.reload`). Page back with `before=<id>` of
/// the last entry while `more` is true; poll with `since=<rev>` of the last
/// page for the entries written after it, folded repeats included.
pub(crate) async fn get_logbook(Query(params): Query<LogbookParams>) -> Response {
    let level = match params.level.as_deref().map(str::parse::<Level>).transpose() {
        Ok(level) => level,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": message })),
            )
                .into_response();
        }
    };
    let Some(book) = logbook::current() else {
        return Json(LogbookResponse {
            enabled: false,
            page: Page::default(),
        })
        .into_response();
    };
    let query = logbook::Query {
        limit: params.limit,
        before: params.before,
        since: params.since,
        level,
        kind: params.kind,
        subject: params.subject,
    };
    // Paging back past the entries kept in memory reads the files.
    match tokio::task::spawn_blocking(move || book.query(&query)).await {
        Ok(page) => Json(LogbookResponse {
            enabled: true,
            page,
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "message": format!("logbook query failed: {e}") })),
        )
            .into_response(),
    }
}

/// `DELETE /logbook`: delete every entry. One `logbook.cleared` entry
/// remains; entries with a lower `id` are gone.
pub(crate) async fn clear_logbook() -> StatusCode {
    if let Some(book) = logbook::current() {
        let _ = tokio::task::spawn_blocking(move || book.clear()).await;
    }
    StatusCode::NO_CONTENT
}
