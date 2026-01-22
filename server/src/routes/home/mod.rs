use axum::http::StatusCode;

pub async fn home() -> StatusCode {
    StatusCode::OK
}
