use regex::Regex;
use std::sync::OnceLock;

fn jwt_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$").unwrap())
}

fn api_key_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"^[a-z0-9_]+$").unwrap())
}

pub fn is_jwt_format(s: &str) -> bool {
    jwt_regex().is_match(s)
}

pub fn is_api_key_format(s: &str) -> bool {
    api_key_regex().is_match(s)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_jwt_format() {
        let tests = [
            // Valid JWT format
            (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                true,
            ),
            // Missing a part
            ("header.payload", false),
            // Invalid characters
            ("header.payload.with=illegal&chars", false),
            // Empty string
            ("", false),
            // Extra segments
            ("a.b.c.d", false),
        ];

        for (input, expected) in tests {
            assert_eq!(
                is_jwt_format(input),
                expected,
                "is_jwt_format({:?}) should be {}",
                input,
                expected
            );
        }
    }

    #[test]
    fn test_is_api_key_format() {
        let tests = [
            // Valid API key format
            ("abc123_underscore", true),
            // Uppercase letters
            ("ABC123", false),
            // Invalid characters
            ("key-with-dash", false),
            // Spaces
            ("key with space", false),
            // Empty string
            ("", false),
        ];

        for (input, expected) in tests {
            assert_eq!(
                is_api_key_format(input),
                expected,
                "is_api_key_format({:?}) should be {}",
                input,
                expected
            );
        }
    }
}
