use std::str::FromStr;
use std::sync::Mutex;

use crate::{auth::Authenticator, sessions::SessionsTranstient, users::UsersTransient};

// Re-exporting
pub use authentication::authentication_server::AuthenticationServer;
pub use tonic::transport::Server;

pub mod authentication {
    tonic::include_proto!("authentication");
}

use authentication::{
    SignInRequest, SignInResponse, SignOutRequest, SignOutResponse, SignUpRequest, SignUpResponse,
    StatusCode,
};

use tonic::{Request, Response, Status};

use crate::service::authentication::authentication_server::Authentication;

pub enum AuthenticationServiceConfig {
    InMemory,
}

impl Default for AuthenticationServiceConfig {
    fn default() -> Self {
        Self::InMemory
    }
}

impl FromStr for AuthenticationServiceConfig {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "InMemory" => Ok(AuthenticationServiceConfig::InMemory),
            _ => Err(()),
        }
    }
}

pub struct AuthenticationService {
    authenticator: Mutex<Authenticator>,
}

impl AuthenticationService {
    fn new(authenticator: Authenticator) -> Self {
        Self {
            authenticator: Mutex::new(authenticator),
        }
    }

    pub fn new_with_config(config: AuthenticationServiceConfig) -> Self {
        match config {
            AuthenticationServiceConfig::InMemory => Self::new(Authenticator::new(
                UsersTransient::new(),
                SessionsTranstient::new(),
            )),
        }
    }
}

impl Default for AuthenticationService {
    fn default() -> Self {
        Self::new_with_config(AuthenticationServiceConfig::default())
    }
}

#[tonic::async_trait]
impl Authentication for AuthenticationService {
    async fn sign_up(
        &self,
        request: Request<SignUpRequest>,
    ) -> Result<Response<SignUpResponse>, Status> {
        let req = request.into_inner();

        let auth_response = self
            .authenticator
            .lock()
            .unwrap()
            .sign_up(&req.username, &req.password);

        let reply = match auth_response {
            Ok(_) => SignUpResponse {
                status_code: StatusCode::Success.into(),
            },
            Err(_) => SignUpResponse {
                status_code: StatusCode::Failure.into(),
            },
        };

        Ok(Response::new(reply))
    }

    async fn sign_in(
        &self,
        request: Request<SignInRequest>,
    ) -> Result<Response<SignInResponse>, Status> {
        let req = request.into_inner();

        let auth_response = self
            .authenticator
            .lock()
            .unwrap()
            .sign_in(&req.username, &req.password);

        let reply = match auth_response {
            Ok((session_token, user_id)) => SignInResponse {
                status_code: StatusCode::Success.into(),
                session_token,
                user_id,
            },
            Err(_) => SignInResponse {
                status_code: StatusCode::Failure.into(),
                session_token: "".to_string(),
                user_id: "".to_string(),
            },
        };

        Ok(Response::new(reply))
    }

    async fn sign_out(
        &self,
        request: Request<SignOutRequest>,
    ) -> Result<Response<SignOutResponse>, Status> {
        let req = request.into_inner();

        let auth_response = self
            .authenticator
            .lock()
            .unwrap()
            .sign_out(&req.session_token);

        let reply = match auth_response {
            Ok(_) => SignOutResponse {
                status_code: StatusCode::Success.into(),
            },
            Err(_) => SignOutResponse {
                status_code: StatusCode::Failure.into(),
            },
        };

        Ok(Response::new(reply))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sign_up_should_succeed() {
        let service = AuthenticationService::new_with_config(AuthenticationServiceConfig::InMemory);

        let request = tonic::Request::new(SignUpRequest {
            username: "username".to_string(),
            password: "password".to_string(),
        });

        let response = service.sign_up(request).await.unwrap();

        assert_eq!(
            response.into_inner().status_code,
            StatusCode::Success.into()
        );
    }

    #[tokio::test]
    async fn sign_up_shoudl_fail_if_username_exists() {
        let service = AuthenticationService::new_with_config(AuthenticationServiceConfig::InMemory);

        let username = "username";
        let password = "password";

        let request = tonic::Request::new(SignUpRequest {
            username: username.to_string(),
            password: password.to_string(),
        });

        service.sign_up(request).await.unwrap();

        let request = tonic::Request::new(SignUpRequest {
            username: username.to_string(),
            password: password.to_string(),
        });

        let response = service.sign_up(request).await.unwrap();

        assert_eq!(
            response.into_inner().status_code,
            StatusCode::Failure.into()
        );
    }

    #[tokio::test]
    async fn sign_in_should_succeed() {
        let service = AuthenticationService::new_with_config(AuthenticationServiceConfig::InMemory);

        let username = "username";
        let password = "password";

        let request = tonic::Request::new(SignUpRequest {
            username: username.to_string(),
            password: password.to_string(),
        });

        service.sign_up(request).await.unwrap();

        let request = tonic::Request::new(SignInRequest {
            username: username.to_string(),
            password: password.to_string(),
        });

        let response = service.sign_in(request).await.unwrap();

        assert_eq!(
            response.into_inner().status_code,
            StatusCode::Success.into()
        );
    }

    #[tokio::test]
    async fn sign_in_should_fail_if_user_does_not_exist() {
        let service = AuthenticationService::new_with_config(AuthenticationServiceConfig::InMemory);

        let username = "username";
        let password = "password";

        let request = tonic::Request::new(SignInRequest {
            username: username.to_string(),
            password: password.to_string(),
        });

        let response = service.sign_in(request).await.unwrap();

        assert_eq!(
            response.into_inner().status_code,
            StatusCode::Failure.into()
        );
    }

    #[tokio::test]
    async fn sign_out_should_succeed() {
        let service = AuthenticationService::new_with_config(AuthenticationServiceConfig::InMemory);

        let username = "username";
        let password = "password";

        let request = tonic::Request::new(SignUpRequest {
            username: username.to_string(),
            password: password.to_string(),
        });

        service.sign_up(request).await.unwrap();

        let request = tonic::Request::new(SignInRequest {
            username: username.to_string(),
            password: password.to_string(),
        });

        let response = service.sign_in(request).await.unwrap().into_inner();

        let request = tonic::Request::new(SignOutRequest {
            session_token: response.session_token.to_string(),
        });

        let response = service.sign_out(request).await.unwrap();

        assert_eq!(
            response.into_inner().status_code,
            StatusCode::Success.into()
        );
    }

    #[tokio::test]
    async fn sign_out_should_fail_if_session_does_not_exist() {
        let service = AuthenticationService::new_with_config(AuthenticationServiceConfig::InMemory);

        let request = tonic::Request::new(SignOutRequest {
            session_token: "session_token".to_string(),
        });

        let response = service.sign_out(request).await.unwrap();

        assert_eq!(
            response.into_inner().status_code,
            StatusCode::Failure.into()
        );
    }
}
