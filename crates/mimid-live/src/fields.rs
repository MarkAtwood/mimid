//! Reading and writing the members of a message map.

use crate::DecodeError;
use crate::cbor::Value;

/// Map members not named by the CDDL, kept as read so they round-trip
/// unchanged (AGENTS.md "Unknown extensions and fields round-trip").
pub type Extra = Vec<(Value, Value)>;

/// The members of a map still to be read.
pub(crate) struct Fields(Vec<(Value, Value)>);

impl Fields {
    pub(crate) fn of(value: Value) -> Result<Self, DecodeError> {
        match value {
            Value::Map(entries) => Ok(Self(entries)),
            _ => Err(DecodeError::NotAMap),
        }
    }

    fn take(&mut self, key: &'static str) -> Option<Value> {
        let at = self
            .0
            .iter()
            .position(|(k, _)| matches!(k, Value::Text(t) if t == key))?;
        Some(self.0.remove(at).1)
    }

    fn need(&mut self, key: &'static str) -> Result<Value, DecodeError> {
        self.take(key).ok_or(DecodeError::MissingMember(key))
    }

    pub(crate) fn uint(&mut self, key: &'static str) -> Result<u64, DecodeError> {
        as_uint(key, self.need(key)?)
    }

    pub(crate) fn opt_uint(&mut self, key: &'static str) -> Result<Option<u64>, DecodeError> {
        self.take(key).map(|v| as_uint(key, v)).transpose()
    }

    pub(crate) fn text(&mut self, key: &'static str) -> Result<String, DecodeError> {
        as_text(key, self.need(key)?)
    }

    pub(crate) fn opt_text(&mut self, key: &'static str) -> Result<Option<String>, DecodeError> {
        self.take(key).map(|v| as_text(key, v)).transpose()
    }

    /// A member that is text or `null`.
    pub(crate) fn text_or_null(
        &mut self,
        key: &'static str,
    ) -> Result<Option<String>, DecodeError> {
        match self.need(key)? {
            Value::Null => Ok(None),
            v => as_text(key, v).map(Some),
        }
    }

    /// An optional member that may also be `null`: absent is `None`,
    /// `null` is `Some(None)`.
    pub(crate) fn opt_text_or_null(
        &mut self,
        key: &'static str,
    ) -> Result<Option<Option<String>>, DecodeError> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::Null) => Ok(Some(None)),
            Some(v) => as_text(key, v).map(|t| Some(Some(t))),
        }
    }

    pub(crate) fn bytes(&mut self, key: &'static str) -> Result<Vec<u8>, DecodeError> {
        as_bytes(key, self.need(key)?)
    }

    pub(crate) fn opt_bytes(&mut self, key: &'static str) -> Result<Option<Vec<u8>>, DecodeError> {
        self.take(key).map(|v| as_bytes(key, v)).transpose()
    }

    pub(crate) fn bool(&mut self, key: &'static str) -> Result<bool, DecodeError> {
        as_bool(key, self.need(key)?)
    }

    pub(crate) fn opt_bool(&mut self, key: &'static str) -> Result<Option<bool>, DecodeError> {
        self.take(key).map(|v| as_bool(key, v)).transpose()
    }

    pub(crate) fn array(&mut self, key: &'static str) -> Result<Vec<Value>, DecodeError> {
        match self.need(key)? {
            Value::Array(items) => Ok(items),
            _ => Err(DecodeError::WrongType(key)),
        }
    }

    pub(crate) fn opt_array(
        &mut self,
        key: &'static str,
    ) -> Result<Option<Vec<Value>>, DecodeError> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::Array(items)) => Ok(Some(items)),
            Some(_) => Err(DecodeError::WrongType(key)),
        }
    }

    /// A member of any type, if present.
    pub(crate) fn opt_value(&mut self, key: &'static str) -> Option<Value> {
        self.take(key)
    }

    /// A member of any type.
    pub(crate) fn take_value(&mut self, key: &'static str) -> Result<Value, DecodeError> {
        self.need(key)
    }

    /// Takes the unread members, leaving none.
    pub(crate) fn take_rest(&mut self) -> Extra {
        std::mem::take(&mut self.0)
    }

    /// What is left: the members the CDDL does not name.
    pub(crate) fn rest(self) -> Extra {
        self.0
    }
}

pub(crate) fn as_uint(key: &'static str, v: Value) -> Result<u64, DecodeError> {
    match v {
        Value::Uint(n) => Ok(n),
        _ => Err(DecodeError::WrongType(key)),
    }
}

pub(crate) fn as_text(key: &'static str, v: Value) -> Result<String, DecodeError> {
    match v {
        Value::Text(t) => Ok(t),
        _ => Err(DecodeError::WrongType(key)),
    }
}

pub(crate) fn as_bytes(key: &'static str, v: Value) -> Result<Vec<u8>, DecodeError> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(DecodeError::WrongType(key)),
    }
}

fn as_bool(key: &'static str, v: Value) -> Result<bool, DecodeError> {
    match v {
        Value::Bool(b) => Ok(b),
        _ => Err(DecodeError::WrongType(key)),
    }
}

/// The members of a map being written.
#[derive(Default)]
pub(crate) struct Writer(Vec<(Value, Value)>);

impl Writer {
    pub(crate) fn put(&mut self, key: &str, value: Value) -> &mut Self {
        self.0.push((Value::Text(key.to_owned()), value));
        self
    }

    pub(crate) fn uint(&mut self, key: &str, n: u64) -> &mut Self {
        self.put(key, Value::Uint(n))
    }

    pub(crate) fn text(&mut self, key: &str, t: &str) -> &mut Self {
        self.put(key, Value::Text(t.to_owned()))
    }

    pub(crate) fn bytes(&mut self, key: &str, b: &[u8]) -> &mut Self {
        self.put(key, Value::Bytes(b.to_vec()))
    }

    pub(crate) fn bool(&mut self, key: &str, b: bool) -> &mut Self {
        self.put(key, Value::Bool(b))
    }

    pub(crate) fn text_or_null(&mut self, key: &str, t: Option<&str>) -> &mut Self {
        self.put(key, t.map_or(Value::Null, |t| Value::Text(t.to_owned())))
    }

    pub(crate) fn opt_uint(&mut self, key: &str, n: Option<u64>) -> &mut Self {
        if let Some(n) = n {
            self.uint(key, n);
        }
        self
    }

    pub(crate) fn opt_text(&mut self, key: &str, t: Option<&str>) -> &mut Self {
        if let Some(t) = t {
            self.text(key, t);
        }
        self
    }

    pub(crate) fn opt_bytes(&mut self, key: &str, b: Option<&[u8]>) -> &mut Self {
        if let Some(b) = b {
            self.bytes(key, b);
        }
        self
    }

    pub(crate) fn opt_bool(&mut self, key: &str, b: Option<bool>) -> &mut Self {
        if let Some(b) = b {
            self.bool(key, b);
        }
        self
    }

    pub(crate) fn finish(&mut self, extra: &Extra) -> Value {
        let mut entries = std::mem::take(&mut self.0);
        entries.extend(extra.iter().cloned());
        Value::Map(entries)
    }
}
