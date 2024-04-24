use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{routing::get, Router};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServerState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on Port {:?}", path, port);
    let state = HttpServerState { path };

    // axum router
    let router = Router::new()
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServerState>>,
    Path(path): Path<String>,
) -> (StatusCode, String) {
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading {:?}", p);

    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            format!("File {} is Not Found", p.display()),
        )
    } else {
        match tokio::fs::read_to_string(p).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                (StatusCode::OK, content)
            }
            Err(e) => {
                warn!("Error reading file {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Error reading file {:?}", e),
                )
            }
        }
    }
}
