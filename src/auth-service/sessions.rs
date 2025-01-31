use std::collections::HashMap;

pub trait Sessions {
    fn create_session(&mut self, user_id: &str) -> Result<String, String>;

    fn delete_session(&mut self, user_id: &str) -> Result<(), String>;
}

pub struct SessionsTranstient {
    uuid_to_session: HashMap<String, String>,
}

impl SessionsTranstient {
    pub fn new() -> Self {
        Self {
            uuid_to_session: HashMap::new(),
        }
    }
}

impl Sessions for SessionsTranstient {
    fn create_session(&mut self, user_id: &str) -> Result<String, String> {
        let session = uuid::Uuid::new_v4().to_string();
        self.uuid_to_session.insert(session.clone(), user_id.into());

        Ok(session)
    }

    fn delete_session(&mut self, session_token: &str) -> Result<(), String> {
        self.uuid_to_session
            .remove(session_token)
            .ok_or("Session not found")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_session() {
        let mut sessions = SessionsTranstient::new();
        assert_eq!(sessions.uuid_to_session.len(), 0);

        let session = sessions.create_session("1234").unwrap();

        assert_eq!(sessions.uuid_to_session.len(), 1);
        assert_eq!(sessions.uuid_to_session.get(&session).unwrap(), "1234");
    }

    #[test]
    fn should_delete_session() {
        let mut sessions = SessionsTranstient::new();
        assert_eq!(sessions.uuid_to_session.len(), 0);

        let session = sessions.create_session("1234").unwrap();
        sessions.delete_session(&session).unwrap();

        assert_eq!(sessions.uuid_to_session.len(), 0);
    }

    #[test]
    fn should_fail_to_delete_session_if_does_not_exist() {
        let mut sessions = SessionsTranstient::new();
        assert_eq!(sessions.uuid_to_session.len(), 0);

        assert!(sessions.delete_session("1235").is_err());
    }
}
