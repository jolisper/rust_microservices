use std::env;

mod authentication {
    tonic::include_proto!("authentication");
}

use authentication::{
    authentication_client::AuthenticationClient, SignInRequest, SignInResponse, SignOutRequest,
    SignOutResponse, SignUpRequest, SignUpResponse,
};
use tonic::transport::Channel;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_hostname = env::var("AUTH_HOSTNAME").unwrap_or("[::0]".to_owned());

    let mut client =
        AuthenticationClient::connect(format!("http://{}:50051", auth_hostname)).await?;

    loop {
        let username = Uuid::new_v4().to_string();
        let password = Uuid::new_v4().to_string();

        // SignUp
        let response = sign_up(&mut client, &username, &password).await?;
        println!("SignUp Status Code: {}", response.status_code);

        // SignIn
        let response = sign_in(&mut client, &username, &password).await?;
        println!("SignIn Status Code: {}", response.status_code);

        // SignOut
        let session_token = response.session_token;
        let response = sign_out(&mut client, &session_token).await?;

        println!("SignOut Status Code: {}", response.status_code);

        // Wait
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
}

async fn sign_up(
    client: &mut AuthenticationClient<Channel>,
    username: &str,
    password: &str,
) -> Result<SignUpResponse, Box<dyn std::error::Error>> {
    // SignUp
    let request = tonic::Request::new(SignUpRequest {
        username: username.to_owned(),
        password: password.to_owned(),
    });

    Ok(client.sign_up(request).await?.into_inner())
}

async fn sign_in(
    client: &mut AuthenticationClient<Channel>,
    username: &str,
    password: &str,
) -> Result<SignInResponse, Box<dyn std::error::Error>> {
    // SignUp
    let request = tonic::Request::new(SignInRequest {
        username: username.to_owned(),
        password: password.to_owned(),
    });

    Ok(client.sign_in(request).await?.into_inner())
}

async fn sign_out(
    client: &mut AuthenticationClient<Channel>,
    session_token: &str,
) -> Result<SignOutResponse, Box<dyn std::error::Error>> {
    // SignUp
    let request = tonic::Request::new(SignOutRequest {
        session_token: session_token.to_owned(),
    });

    Ok(client.sign_out(request).await?.into_inner())
}
