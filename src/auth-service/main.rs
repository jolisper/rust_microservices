use pbkdf2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};

#[derive(Debug)]
pub struct User {
    username: String,
    password: String,
    uuid: String,
}

impl User {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

#[derive(Debug, Default)]
pub struct UsersTransient {
    users: Vec<User>,
}

impl UsersTransient {
    pub fn new() -> UsersTransient {
        UsersTransient { users: Vec::new() }
    }

    pub fn create_user<T: Into<String>>(
        &mut self,
        username: T,
        password: T,
    ) -> Result<&User, String> {
        let username = username.into();

        if self.find_user_by_username(&username).is_some() {
            return Err("Username already exists".into());
        }

        let hashed_password = Self::hash_password(password)?;

        let user = User {
            username: username.into(),
            password: hashed_password,
            uuid: uuid::Uuid::new_v4().to_string(),
        };

        self.users.push(user);
        Ok(self.users.last().unwrap())
    }

    pub fn find_user_id<T>(&self, username: T, password: T) -> Option<String>
    where
        T: Into<String>,
    {
        let username = username.into();
        let password = password.into();

        let user = self.find_user_by_username(&username)?;

        if Self::verify_password(password, user).is_ok() {
            return Some(user.uuid.clone());
        };
        None
    }

    fn find_user_by_username(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|user| user.username == username)
    }

    fn hash_password<T: Into<String>>(password: T) -> Result<String, String> {
        let salt = SaltString::generate(&mut OsRng);
        let hashed_password = Pbkdf2
            .hash_password(password.into().as_bytes(), &salt)
            .map_err(|e| format!("Failed to hash password: {}", e))?
            .to_string();
        Ok(hashed_password)
    }

    fn verify_password(password: String, user: &User) -> Result<(), String> {
        let parsed_hash =
            PasswordHash::new(&user.password()).map_err(|_| format!("Error hashing password"))?;

        return Pbkdf2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|e| e.to_string());
    }

    fn delete_user<T>(&mut self, username: T) -> Result<(), String>
    where
        T: Into<String>,
    {
        let username = username.into();

        let index = self
            .users
            .iter()
            .position(|user| user.username() == &username)
            .ok_or_else(|| "User not found")?;

        self.users.remove(index);

        Ok(())
    }
}

fn main() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_user() {
        let mut users = UsersTransient::new();

        let user = users.create_user("username", "password");

        assert!(user.is_ok());
    }

    #[test]
    fn should_find_user_id_by_username_password() {
        let mut users = UsersTransient::new();

        let username = "username";
        let password = "password";

        users
            .create_user(username, password)
            .expect("A user should be created");

        assert!(users.find_user_id(username, password).is_some());
    }

    #[test]
    fn different_users_should_have_different_ids() {
        let mut users = UsersTransient::new();

        users
            .create_user("John", "1234")
            .expect("A user should be created");
        users
            .create_user("Paul", "4321")
            .expect("A user should be created");

        assert_ne!(
            users.find_user_id("John", "1234").unwrap(),
            users.find_user_id("Paul", "4321").unwrap(),
        );
    }

    #[test]
    fn should_cannot_create_two_users_with_same_username() {
        let mut users = UsersTransient::new();

        users
            .create_user("John", "1234")
            .expect("A user should be created");

        let error = users.create_user("John", "1234").unwrap_err();

        assert_eq!(error, "Username already exists");
    }

    #[test]
    fn should_fail_to_retreive_user_id_with_incorrect_password() {
        let mut users = UsersTransient::new();

        let username = "username";
        let password = "password";

        users
            .create_user(username, password)
            .expect("A user should be created");

        assert!(users.find_user_id(username, "wrong").is_none());
    }

    #[test]
    fn should_delete_user() {
        let mut users = UsersTransient::new();

        let username = "username";
        let password = "password";

        users
            .create_user(username, password)
            .expect("A user should be created");

        users
            .delete_user(username)
            .expect("A user should be deleted");

        assert!(users.find_user_id(username, password).is_none());
    }

    #[test]
    fn should_fail_to_delete_non_existing_user() {
        let mut users = UsersTransient::new();

        assert!(users.delete_user("username").is_err());
    }
}
