use std::collections::HashMap;

pub trait Sessions {
    fn create_session<T>(&mut self, user_id: T) -> Result<String, String>
    where
        T: Into<String>;

    fn delete_session<T>(&mut self, user_id: T) -> Result<(), String>
    where
        T: Into<String>;
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
    fn create_session<T>(&mut self, user_id: T) -> Result<String, String>
    where
        T: Into<String>,
    {
        let session = uuid::Uuid::new_v4().to_string();
        self.uuid_to_session.insert(user_id.into(), session.clone());

        Ok(session)
    }

    fn delete_session<T>(&mut self, user_id: T) -> Result<(), String>
    where
        T: Into<String>,
    {
        self.uuid_to_session.remove(&user_id.into());
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
        assert_eq!(sessions.uuid_to_session.get("1234").unwrap(), &session);
    }

    #[test]
    fn should_delete_session() {
        let mut sessions = SessionsTranstient::new();
        assert_eq!(sessions.uuid_to_session.len(), 0);

        sessions.create_session("1234").unwrap();
        sessions.delete_session("1234").unwrap();

        assert_eq!(sessions.uuid_to_session.len(), 0);
    }
}
