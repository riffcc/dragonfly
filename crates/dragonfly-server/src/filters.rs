/* TODO: Refactor filters for MiniJinja
pub fn length<T>(collection: &[T]) -> Result<usize> {
    Ok(collection.len())
}

pub fn string<T: std::fmt::Display>(value: T) -> Result<String> {
    Ok(format!("{}", value))
}

pub fn join_vec(vec: &[String], separator: &str) -> Result<String> {
    Ok(vec.join(separator))
}

// Helper to safely unwrap Option<String> values in templates
pub fn unwrap_or<'a>(opt: &'a Option<String>, default: &'a str) -> Result<&'a str> {
    match opt {
        Some(s) => Ok(s.as_str()),
        None => Ok(default),
    }
}

// Format DateTime<Utc> without subsecond precision
pub fn format_datetime(dt: &DateTime<Utc>) -> Result<String> {
    Ok(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}
*/
