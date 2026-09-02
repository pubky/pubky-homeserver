//!
//! Code from unmerge PR <https://github.com/jdrouet/serde-toml-merge/pull/39>
//! We can't publish crates with a git dependency, so we copy the code here.
//!

use std::fmt;
use toml::map::Map;
use toml::Value;

#[derive(Debug, PartialEq)]
pub struct Error {
    pub path: String,
    pub expected: &'static str,
    pub existing: &'static str,
}

impl Error {
    pub fn new(path: String, expected: &'static str, existing: &'static str) -> Self {
        Self {
            path,
            expected,
            existing,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "Incompatible types at path \"{}\", expected \"{}\" received \"{}\".",
            self.path, self.expected, self.existing
        )
    }
}

/// Configuration for merging behavior
#[derive(Debug, Clone, Copy, Default)]
pub struct Merger {
    /// Whether to replace arrays completely or extend them (by default) for backward compatibility
    pub replace_arrays: bool,
}

impl Merger {
    /// Create a new Merger with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether arrays should be replaced or extended
    pub fn with_replace_arrays(mut self, replace_arrays: bool) -> Self {
        self.replace_arrays = replace_arrays;
        self
    }

    pub fn merge(&self, value: Value, other: Value) -> Result<Value, Error> {
        self.merge_inner(value, other, "$")
    }

    fn merge_inner(&self, value: Value, other: Value, path: &str) -> Result<Value, Error> {
        match (value, other) {
            (Value::String(_), Value::String(inner)) => Ok(Value::String(inner)),
            (Value::Integer(_), Value::Integer(inner)) => Ok(Value::Integer(inner)),
            (Value::Float(_), Value::Float(inner)) => Ok(Value::Float(inner)),
            (Value::Boolean(_), Value::Boolean(inner)) => Ok(Value::Boolean(inner)),
            (Value::Datetime(_), Value::Datetime(inner)) => Ok(Value::Datetime(inner)),
            (Value::Array(_), Value::Array(inner)) if self.replace_arrays => {
                Ok(Value::Array(inner))
            }
            (Value::Array(mut existing), Value::Array(inner)) if !self.replace_arrays => {
                existing.extend(inner);
                Ok(Value::Array(existing))
            }
            (Value::Table(mut existing), Value::Table(inner)) => {
                self.merge_into_table_inner(&mut existing, inner, path)?;
                Ok(Value::Table(existing))
            }
            (v, o) => Err(Error::new(path.to_owned(), v.type_str(), o.type_str())),
        }
    }

    fn merge_into_table_inner(
        &self,
        value: &mut Map<String, Value>,
        other: Map<String, Value>,
        path: &str,
    ) -> Result<(), Error> {
        for (name, inner) in other {
            if let Some(existing) = value.remove(&name) {
                let inner_path = format!("{path}.{name}");
                value.insert(name, self.merge_inner(existing, inner, &inner_path)?);
            } else {
                value.insert(name, inner);
            }
        }
        Ok(())
    }
}

pub fn merge_with_options(
    value: Value,
    other: Value,
    replace_arrays: bool,
) -> Result<Value, Error> {
    let merger = Merger::new().with_replace_arrays(replace_arrays);
    merger.merge(value, other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use toml::Value;

    macro_rules! should_match {
        // 4-argument form with replace_arrays flag
        ($first:expr, $second:expr, $result:expr, $replace_arrays:expr) => {{
            let first = toml::from_str::<Value>($first).unwrap();
            let second = toml::from_str::<Value>($second).unwrap();
            let result = toml::from_str::<Value>($result).unwrap();
            assert_eq!(
                merge_with_options(first, second, ($replace_arrays)).unwrap(),
                result
            );
        }};
        // 3-argument fallback: default replace_arrays = false
        ($first:expr, $second:expr, $result:expr) => {
            should_match!($first, $second, $result, false)
        };
    }
    #[test]
    fn with_basic() {
        should_match!(
            r#"
        string = "foo"
        integer = 42
        float = 42.24
        boolean = true
        keep_me = true
        "#,
            r#"
        string = "bar"
        integer = 43
        float = 24.42
        boolean = false
        missing = true
        "#,
            r#"
        string = "bar"
        integer = 43
        float = 24.42
        boolean = false
        keep_me = true
        missing = true
        "#
        );
    }

    #[test]
    fn with_array_merged() {
        should_match!(
            r#"foo = ["a", "b"]"#,
            r#"foo = ["c", "d"]"#,
            r#"foo = ["a", "b", "c", "d"]"#
        );
    }

    #[test]
    fn with_array_replaced() {
        should_match!(
            r#"foo = ["a", "b"]"#,
            r#"foo = ["c", "d"]"#,
            r#"foo = ["c", "d"]"#,
            true
        );
        should_match!(r#"foo = ["a", "b"]"#, r#"foo = []"#, r#"foo = []"#, true);
    }

    #[test]
    fn with_table() {
        should_match!(
            r#"
            [foo]
            bar = "baz"
        "#,
            r#"
            [foo]
            hello = "world"
        "#,
            r#"
            [foo]
            bar = "baz"
            hello = "world"
        "#
        );
    }
}
