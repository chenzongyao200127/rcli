use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{routing::get, Router};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServerState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on Port {:?}", path, port);
    let state = HttpServerState { path: path.clone() };
    let dir_service = ServeDir::new(path);
    // axum router
    let router = Router::new()
        .route("/*path", get(file_handler))
        .nest_service("/tower", dir_service)
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
        // TODO: test p is a dictionary
        // if it is a dictionary, list all files/sub-dictionaries
        // as <li><a href="/path/to/file">file name</a></li>
        // <html><body><ul>...</ul></body></html>
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServerState {
            path: PathBuf::from("."),
        });
        let path = Path("Cargo.toml".to_string());
        let (status, content) = file_handler(State(state), path).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!content.is_empty());
        assert!(content.trim().starts_with("[package]"));
    }
}
