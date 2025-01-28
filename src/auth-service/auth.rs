use crate::{sessions::Sessions, users::Users};

pub trait Bound: Send + Sync + 'static {}

impl<T: Send + Sync + 'static> Bound for T {}

pub struct Authenticator {
    users: Box<dyn Users + Send + Sync>,
    sessions: Box<dyn Sessions + Send + Sync>,
}

impl Authenticator {
    pub fn new(users: impl Users + Bound, sessions: impl Sessions + Bound) -> Self {
        Self {
            users: Box::new(users),
            sessions: Box::new(sessions),
        }
    }

    pub fn sign_up(&mut self, username: &str, password: &str) -> Result<(), String> {
        self.users.create_user(username, password)?;
        Ok(())
    }

    pub fn sign_out(&mut self, session_token: &str) -> Result<(), String> {
        self.sessions.delete_session(session_token)?;
        Ok(())
    }

    pub fn sign_in(&mut self, username: &str, password: &str) -> Result<(String, String), String> {
        let user_id = self
            .users
            .find_user_id(username, password)
            .ok_or("User not found")?;
        let session = self.sessions.create_session(&user_id)?;
        Ok((session, user_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sessions::SessionsTranstient, users::UsersTransient};

    #[test]
    fn sign_up_should_succeed_if_user_does_not_exist() {
        let mut auth = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());

        let response = auth.sign_up("username", "password");

        assert!(response.is_ok());
    }

    #[test]
    fn sign_up_should_fail_if_username_exists() {
        let mut auth = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());

        auth.sign_up("username", "password")
            .expect("A user should be signed up");

        let response = auth.sign_up("username", "password");

        assert!(response.is_err());
    }

    #[test]
    fn sign_in_should_succeed_if_user_exists() {
        let mut auth = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());

        auth.sign_up("username", "password")
            .expect("A user should be signed up");

        let response = auth.sign_in("username", "password");

        assert!(response.is_ok());
    }

    #[test]
    fn sign_in_should_fail_if_user_does_not_exist() {
        let mut auth = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());

        let response = auth.sign_in("username", "password");

        assert!(response.is_err());
    }

    #[test]
    fn sign_out_should_succeed_if_session_exists() {
        let mut auth = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());

        auth.sign_up("username", "password")
            .expect("A user should be signed up");

        let (session, _) = auth
            .sign_in("username", "password")
            .expect("A session should be created");

        let response = auth.sign_out(&session);

        assert!(response.is_ok());
    }

    #[test]
    fn sign_out_should_fail_if_session_does_not_exist() {
        let mut auth = Authenticator::new(UsersTransient::new(), SessionsTranstient::new());

        let response = auth.sign_out("does-not-exist");

        assert!(response.is_err());
    }
}
