use std::sync::Mutex;

use crate::auth::Authenticator;

pub mod authentication {
    tonic::include_proto!("authentication");
}

use authentication::{
    SignInRequest, SignInResponse, SignOutRequest, SignOutResponse, SignUpRequest, SignUpResponse,
    StatusCode,
};

use tonic::{Request, Response, Status};

use crate::service::authentication::authentication_server::Authentication;

pub struct AuthenticationService {
    authenticator: Mutex<Authenticator>,
}

impl AuthenticationService {
    fn new(authenticator: Authenticator) -> Self {
        Self {
            authenticator: Mutex::new(authenticator),
        }
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

    use crate::sessions::SessionsTranstient;
    use crate::users::UsersTransient;

    #[tokio::test]
    async fn sign_up_should_succeed() {
        let authenticator = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());
        let service = AuthenticationService::new(authenticator);

        let request = tonic::Request::new(SignUpRequest {
            username: "username".to_string(),
            password: "password".to_string(),
        });

        let response = service.sign_up(request).await.unwrap();

        assert_eq!(response.into_inner().status_code, StatusCode::Success.into());
    }

    #[tokio::test]
    async fn sign_up_shoudl_fail_if_username_exists() {
        let mut authenticator = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());
        authenticator
            .sign_up("username", "password")
            .expect("A user should be signed up");

        let service = AuthenticationService::new(authenticator);

        let request = tonic::Request::new(SignUpRequest {
            username: "username".to_string(),
            password: "password".to_string(),
        });

        let response = service.sign_up(request).await.unwrap();

        assert_eq!(response.into_inner().status_code, StatusCode::Failure.into());
    }

    #[tokio::test]
    async fn sign_in_should_succeed() {
        let mut authenticator = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());
        authenticator
            .sign_up("username", "password")
            .expect("A user should be signed up");

        let service = AuthenticationService::new(authenticator);

        let request = tonic::Request::new(SignInRequest {
            username: "username".to_string(),
            password: "password".to_string(),
        });

        let response = service.sign_in(request).await.unwrap();

        assert_eq!(response.into_inner().status_code, StatusCode::Success.into());
    }

    #[tokio::test]
    async fn sign_in_should_fail_if_user_does_not_exist() {
        let authenticator = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());

        let service = AuthenticationService::new(authenticator);

        let request = tonic::Request::new(SignInRequest {
            username: "username".to_string(),
            password: "password".to_string(),
        });

        let response = service.sign_in(request).await.unwrap();

        assert_eq!(response.into_inner().status_code, StatusCode::Failure.into());
    }

    #[tokio::test]
    async fn sign_out_should_succeed() {
        let mut authenticator = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());
        authenticator
            .sign_up("username", "password")
            .expect("A user should be signed up");
        let (session_token, _) = authenticator
            .sign_in("username", "password")
            .expect("A user should be signed in");

        let service = AuthenticationService::new(authenticator);

        let request = tonic::Request::new(SignOutRequest {
            session_token: session_token.to_string(),
        });

        let response = service.sign_out(request).await.unwrap();

        assert_eq!(response.into_inner().status_code, StatusCode::Success.into());
    }

    #[tokio::test]
    async fn sign_out_should_fail_if_session_does_not_exist() {
        let authenticator = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());

        let service = AuthenticationService::new(authenticator);

        let request = tonic::Request::new(SignOutRequest {
            session_token: "session_token".to_string(),
        });

        let response = service.sign_out(request).await.unwrap();

        assert_eq!(response.into_inner().status_code, StatusCode::Failure.into());
    }
}
