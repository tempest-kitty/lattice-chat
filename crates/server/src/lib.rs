#[derive(Debug, PartialEq, Eq)]
pub struct Account {
    pub email: String,
    pub username: String,
    password_verifier: PasswordVerifier,
}

#[derive(Debug, PartialEq, Eq)]
enum PasswordVerifier {
    DeferredToAuthenticationMilestone,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignupError {
    InvalidEmail,
    InvalidUsername,
    InvalidPassword,
}

impl Account {
    pub fn signup(email: &str, username: &str, password: &str) -> Result<Self, SignupError> {
        let email = email.trim();
        let username = username.trim();

        if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
            return Err(SignupError::InvalidEmail);
        }
        if username.len() < 3 || username.len() > 32 {
            return Err(SignupError::InvalidUsername);
        }
        if password.chars().count() < 12 {
            return Err(SignupError::InvalidPassword);
        }

        Ok(Self {
            email: email.to_owned(),
            username: username.to_owned(),
            password_verifier: PasswordVerifier::DeferredToAuthenticationMilestone,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signup_accepts_valid_account_details() {
        let account = Account::signup(
            "person@example.com",
            "tempest",
            "a sufficiently long password",
        )
        .expect("valid signup should succeed");

        assert_eq!(account.email, "person@example.com");
        assert_eq!(account.username, "tempest");
    }

    #[test]
    fn signup_rejects_invalid_email() {
        let result = Account::signup("not-an-email", "tempest", "a sufficiently long password");
        assert_eq!(result, Err(SignupError::InvalidEmail));
    }

    #[test]
    fn signup_rejects_short_password_without_storing_it() {
        let result = Account::signup("person@example.com", "tempest", "short");
        assert_eq!(result, Err(SignupError::InvalidPassword));
    }
}
