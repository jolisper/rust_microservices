mod auth;
mod service;
mod sessions;
mod users;

use service::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::]:50051".parse()?;

    let service =
        AuthenticationService::new_with_config(service::AuthenticationServiceConfig::InMemory);

    Server::builder()
        .add_service(AuthenticationServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
