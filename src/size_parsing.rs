use crate::error::{AppError, Result};
use regex::Regex;
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub struct HumanSize(pub u64);

impl FromStr for HumanSize {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self> {
        let re = Regex::new(r"^(?P<num>\d+)(?P<suffix>[KMGTP]?B)?$").unwrap();
        let s = s.trim().to_uppercase();

        // Handle plain numbers (bytes)
        if let Ok(num) = s.parse::<u64>() {
            return Ok(HumanSize(num));
        }

        let captures = re.captures(&s).ok_or_else(|| AppError::InvalidSizeFormat {
            input: s.to_string(),
        })?;

        let num: u64 = captures["num"].parse().map_err(|_| AppError::InvalidSizeFormat {
            input: s.to_string(),
        })?;

        let multiplier = match captures.name("suffix").map(|m| m.as_str()) {
            Some("B") => 1,
            Some("KB") => 1024,
            Some("MB") => 1024 * 1024,
            Some("GB") => 1024 * 1024 * 1024,
            Some("TB") => 1024 * 1024 * 1024 * 1024,
            Some("PB") => 1024 * 1024 * 1024 * 1024 * 1024,
            None => 1,
            _ => return Err(AppError::InvalidSizeFormat {
                input: s.to_string(),
            }),
        };

        num.checked_mul(multiplier)
            .map(HumanSize)
            .ok_or_else(|| AppError::InvalidSizeFormat {
                input: s.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_parsing() {
        assert_eq!("1024".parse::<HumanSize>().unwrap().0, 1024);
        assert_eq!("1024B".parse::<HumanSize>().unwrap().0, 1024);
        assert_eq!("1KB".parse::<HumanSize>().unwrap().0, 1024);
        assert_eq!("1kb".parse::<HumanSize>().unwrap().0, 1024);
        assert_eq!("1MB".parse::<HumanSize>().unwrap().0, 1024 * 1024);
        assert_eq!("1GB".parse::<HumanSize>().unwrap().0, 1024 * 1024 * 1024);
        assert_eq!("1TB".parse::<HumanSize>().unwrap().0, 1024 * 1024 * 1024 * 1024);
        assert!("invalid".parse::<HumanSize>().is_err());
        assert!("1XB".parse::<HumanSize>().is_err());
    }
}
