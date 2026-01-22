use axum::{
    Router,
    body::Body,
    extract::Request,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use circuits::{Circuit, passport::PassportRelation};
use http_body_util::BodyExt;
use server::ctx::{CTX, Ctx};
use server::{routes, storage};
use std::{
    env,
    fmt::Display,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

fn read_env_var_with_default<T>(var_name: &str, default: T) -> T
where
    T: FromStr,
    T::Err: Display,
{
    match env::var(var_name) {
        Ok(value) => value.parse().unwrap_or_else(|e| {
            eprintln!("Error parsing {}: {}", var_name, e);
            std::process::exit(1);
        }),
        Err(env::VarError::NotPresent) => default,
        Err(env::VarError::NotUnicode(s)) => {
            eprintln!("Error reading {} (invalid UTF-8): {:?}", var_name, s);
            std::process::exit(1);
        }
    }
}

async fn log_request_body(request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();

    // Collect the body bytes
    let bytes = body
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();

    // Log the body preview
    let body_str = String::from_utf8_lossy(&bytes);
    let preview = if body_str.len() > 200 {
        format!(
            "{}...{}",
            &body_str[..100],
            &body_str[body_str.len() - 100..]
        )
    } else {
        body_str.to_string()
    };

    tracing::info!(
        method = %parts.method,
        uri = %parts.uri,
        body_preview = %preview,
        "request body"
    );

    // Reconstruct the request with the body
    let request = Request::from_parts(parts, Body::from(bytes));

    next.run(request).await
}

#[tokio::main]
async fn main() {
    let port: u16 = read_env_var_with_default("PORT", 3000);

    if let Err(e) = tracing_subscriber::fmt::try_init() {
        eprintln!("Error initializing tracing: {}", e);
        std::process::exit(1);
    }

    tracing::info!("Initializing context...");

    let instant = std::time::Instant::now();
    let relation = PassportRelation;
    let srs = circuits::filecoin::load_srs(PassportRelation::K);
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let elapsed = instant.elapsed();

    if let Err(_) = CTX.set(Ctx { relation, srs, vk }) {
        eprintln!("Failed to set CTX");
        std::process::exit(1);
    }

    tracing::info!("Done! (took {:.2}s)", elapsed.as_secs_f64());

    storage::init(&"12345678");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(routes::home))
        .route("/verify-proof", post(routes::verify_proof))
        .layer(middleware::from_fn(log_request_body))
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Error binding to address: {}", e);
            std::process::exit(1);
        }
    };

    tracing::info!("Server listening on port {}", port);

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Error serving application: {}", e);
        std::process::exit(1);
    }
}
