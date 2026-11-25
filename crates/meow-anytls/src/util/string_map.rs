use std::collections::HashMap;

/// StringMap is a simple key-value map for protocol settings
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringMap(HashMap<String, String>);

impl StringMap {
    /// Create a new empty StringMap
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Create a new StringMap with the specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    /// Insert a key-value pair into the map
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }

    /// Get a value by key
    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    /// Check if the map contains a key
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Get the number of key-value pairs in the map
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert to bytes in format: "key=value\nkey2=value2\n..."
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut lines = Vec::new();
        for (key, value) in &self.0 {
            lines.push(format!("{}={}", key, value));
        }
        lines.join("\n").into_bytes()
    }

    /// Parse from bytes in format: "key=value\nkey2=value2\n..."
    ///
    /// Upstream `StringMapFromBytes` parity: split each line on the
    /// FIRST `=` and take both halves verbatim — no trimming. A peer's
    /// `padding-md5` fingerprint or `v` version must compare exactly as
    /// it arrived; surrounding whitespace is part of the value and
    /// simply fails the downstream parse, matching upstream.
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut map = HashMap::new();
        let text = String::from_utf8_lossy(data);

        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                map.insert(key.to_string(), value.to_string());
            }
        }

        Self(map)
    }

    /// Convert to Vec of (key, value) pairs
    pub fn into_vec(self) -> Vec<(String, String)> {
        self.0.into_iter().collect()
    }
}

impl std::ops::Deref for StringMap {
    type Target = HashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for StringMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<HashMap<String, String>> for StringMap {
    fn from(map: HashMap<String, String>) -> Self {
        Self(map)
    }
}

impl From<StringMap> for HashMap<String, String> {
    fn from(val: StringMap) -> Self {
        val.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_map_basic() {
        let mut map = StringMap::new();
        map.insert("key1", "value1");
        map.insert("key2", "value2");

        assert_eq!(map.get("key1"), Some(&"value1".to_string()));
        assert_eq!(map.get("key2"), Some(&"value2".to_string()));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_string_map_serialization() {
        let mut map = StringMap::new();
        map.insert("v", "2");
        map.insert("client", "anytls-rs/0.1.0");

        let bytes = map.to_bytes();
        let restored = StringMap::from_bytes(&bytes);

        assert_eq!(restored.get("v"), Some(&"2".to_string()));
        assert_eq!(restored.get("client"), Some(&"anytls-rs/0.1.0".to_string()));
    }
}
