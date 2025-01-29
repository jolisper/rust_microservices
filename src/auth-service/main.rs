mod auth;
mod service;
mod sessions;
mod users;

use std::env;

use service::{AuthenticationServer, AuthenticationService, AuthenticationServiceConfig, Server};

const AUTH_SERVICE_PERSISTENCE_TYPE: &str = "AUTH_SERVICE_PERSISTENCE_TYPE";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::]:50051".parse()?;

    let service = build_auth_service();

    Server::builder()
        .add_service(AuthenticationServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

fn build_auth_service() -> AuthenticationService {
    if let Ok(string_config) = env::var(AUTH_SERVICE_PERSISTENCE_TYPE) {
        if let Ok(config) = string_config.parse::<AuthenticationServiceConfig>() {
            return AuthenticationService::new_with_config(config);
        }
    }
    AuthenticationService::default()
}
