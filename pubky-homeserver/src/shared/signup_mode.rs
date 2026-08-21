use serde::{Deserialize, Serialize};

/// The mode of signup.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupMode {
    /// Everybody can signup.
    Open,
    /// Only users with a valid token can signup.
    #[default]
    TokenRequired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Serialize, Deserialize)]
    struct TestToml {
        #[serde(default)]
        signup_mode: SignupMode,
    }

    #[test]
    fn test_signup_mode_serde() {
        let test_toml = TestToml::default();
        assert_eq!(test_toml.signup_mode, SignupMode::TokenRequired);

        let test_toml_str = toml::to_string(&test_toml).unwrap();
        assert_eq!(test_toml_str, "signup_mode = \"token_required\"\n");

        let test_toml_2: TestToml = toml::from_str(&test_toml_str).unwrap();
        assert_eq!(test_toml_2.signup_mode, SignupMode::TokenRequired);

        let test_toml_3: TestToml = toml::from_str("\n").unwrap();
        assert_eq!(test_toml_3.signup_mode, SignupMode::TokenRequired);
    }
}
