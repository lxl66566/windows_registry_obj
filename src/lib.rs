use std::{borrow::Cow, ops::Deref};

pub use windows_registry::{
    CLASSES_ROOT, CURRENT_CONFIG, CURRENT_USER, LOCAL_MACHINE, Transaction, USERS,
};
pub use windows_result::HRESULT;

/// Crate result type with contextual [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// The cause of a registry operation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// A Windows API call failed.
    Win32(windows_result::Error),
    /// The target is a registry root key, which cannot be removed or renamed.
    RootKey,
    /// The value type is not representable by `RegValueData`; holds the raw type code.
    UnsupportedType(u32),
    /// Parsing failed because the base key segment is unknown; holds the offending segment.
    UnknownBaseKey(String),
}

/// A registry error carrying optional key path and value name context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Error {
    kind: ErrorKind,
    path: Option<String>,
    value: Option<String>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            path: None,
            value: None,
        }
    }

    /// Attaches the full key path of the failed operation.
    pub(crate) fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Attaches the value name of the failed operation.
    pub(crate) fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// The cause of the failure.
    #[must_use]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// The full key path involved, when known.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// The value name involved, when known.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.kind, f)?;
        if let Some(path) = &self.path {
            write!(f, " (key '{path}')")?;
        }
        if let Some(value) = &self.value {
            write!(f, " (value '{value}')")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Win32(err) => std::fmt::Display::fmt(err, f),
            Self::RootKey => write!(f, "a registry root key cannot be removed or renamed"),
            Self::UnsupportedType(ty) => write!(f, "registry value type {ty} is not supported"),
            Self::UnknownBaseKey(segment) => write!(f, "unknown base key '{segment}'"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Win32(err) => Some(err),
            _ => None,
        }
    }
}

impl From<windows_result::Error> for Error {
    fn from(err: windows_result::Error) -> Self {
        Self::new(ErrorKind::Win32(err))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseKey {
    ClassesRoot,
    CurrentConfig,
    CurrentUser,
    LocalMachine,
    Users,
}

impl From<&BaseKey> for &'static windows_registry::Key {
    fn from(base: &BaseKey) -> Self {
        match base {
            BaseKey::ClassesRoot => CLASSES_ROOT,
            BaseKey::CurrentConfig => CURRENT_CONFIG,
            BaseKey::CurrentUser => CURRENT_USER,
            BaseKey::LocalMachine => LOCAL_MACHINE,
            BaseKey::Users => USERS,
        }
    }
}

impl std::fmt::Display for BaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseKey::ClassesRoot => write!(f, "HKEY_CLASSES_ROOT"),
            BaseKey::CurrentConfig => write!(f, "HKEY_CURRENT_CONFIG"),
            BaseKey::CurrentUser => write!(f, "HKEY_CURRENT_USER"),
            BaseKey::LocalMachine => write!(f, "HKEY_LOCAL_MACHINE"),
            BaseKey::Users => write!(f, "HKEY_USERS"),
        }
    }
}

impl Deref for BaseKey {
    type Target = windows_registry::Key;

    fn deref(&self) -> &Self::Target {
        self.into()
    }
}

impl BaseKey {
    pub fn reg<'a>(&self, path: impl Into<Cow<'a, str>>) -> Registry<'a> {
        Registry::new(*self, path)
    }
}

/// Represents the data type of a registry value
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValueData<'a> {
    String(Cow<'a, str>),
    ExpandableString(Cow<'a, str>),
    DWord(u32),
    QWord(u64),
    Binary(Cow<'a, [u8]>),
    MultiString(Vec<Cow<'a, str>>),
}

impl<'a> From<&'a str> for RegValueData<'a> {
    fn from(s: &'a str) -> Self {
        RegValueData::String(Cow::Borrowed(s))
    }
}

impl<'a> From<&'a String> for RegValueData<'a> {
    fn from(s: &'a String) -> Self {
        RegValueData::String(Cow::Borrowed(s))
    }
}

impl From<String> for RegValueData<'_> {
    fn from(s: String) -> Self {
        RegValueData::String(Cow::Owned(s))
    }
}

impl From<u32> for RegValueData<'_> {
    fn from(value: u32) -> Self {
        RegValueData::DWord(value)
    }
}

impl From<u64> for RegValueData<'_> {
    fn from(value: u64) -> Self {
        RegValueData::QWord(value)
    }
}

impl From<Vec<u8>> for RegValueData<'_> {
    fn from(value: Vec<u8>) -> Self {
        RegValueData::Binary(Cow::Owned(value))
    }
}

impl<'a> From<&'a [u8]> for RegValueData<'a> {
    fn from(value: &'a [u8]) -> Self {
        RegValueData::Binary(Cow::Borrowed(value))
    }
}

impl From<&'_ RegValueData<'_>> for windows_registry::Type {
    fn from(val: &'_ RegValueData<'_>) -> Self {
        match val {
            RegValueData::String(_) => windows_registry::Type::String,
            RegValueData::ExpandableString(_) => windows_registry::Type::ExpandString,
            RegValueData::DWord(_) => windows_registry::Type::U32,
            RegValueData::QWord(_) => windows_registry::Type::U64,
            RegValueData::Binary(_) => windows_registry::Type::Bytes,
            RegValueData::MultiString(_) => windows_registry::Type::MultiString,
        }
    }
}

pub type RegValueDataOwned = RegValueData<'static>;

impl RegValueData<'_> {
    #[must_use]
    pub fn into_owned(self) -> RegValueDataOwned {
        match self {
            RegValueData::String(s) => RegValueData::String(Cow::Owned(s.into_owned())),
            RegValueData::ExpandableString(s) => {
                RegValueData::ExpandableString(Cow::Owned(s.into_owned()))
            },
            RegValueData::Binary(b) => RegValueData::Binary(Cow::Owned(b.into_owned())),
            RegValueData::MultiString(s) => RegValueData::MultiString(
                s.into_iter()
                    .map(|cow| Cow::Owned(cow.into_owned()))
                    .collect(),
            ),
            RegValueData::DWord(i) => RegValueData::DWord(i),
            RegValueData::QWord(i) => RegValueData::QWord(i),
        }
    }
}

impl TryFrom<windows_registry::Value> for RegValueDataOwned {
    type Error = Error;

    /// Converts a `windows_registry::Value` into a `RegValueData`.
    fn try_from(value: windows_registry::Value) -> std::result::Result<Self, Self::Error> {
        let ret = match value.ty() {
            windows_registry::Type::U32 => RegValueData::DWord(value.try_into()?),
            windows_registry::Type::U64 => RegValueData::QWord(value.try_into()?),
            windows_registry::Type::String => RegValueData::String(Cow::Owned(value.try_into()?)),
            windows_registry::Type::ExpandString => {
                RegValueData::ExpandableString(Cow::Owned(value.try_into()?))
            },
            windows_registry::Type::Bytes => RegValueData::Binary(Cow::Owned(value.to_vec())),
            windows_registry::Type::MultiString => {
                let v: Vec<String> = value.try_into()?;
                RegValueData::MultiString(v.into_iter().map(Cow::Owned).collect())
            },
            windows_registry::Type::Other(ty) => {
                return Err(Error::new(ErrorKind::UnsupportedType(ty)));
            },
        };
        Ok(ret)
    }
}
/// A structure that represents a registry value, including its name and data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegValue<'a> {
    pub name: Cow<'a, str>,
    pub data: RegValueData<'a>,
}

impl<'a, K, V> From<(K, V)> for RegValue<'a>
where
    K: Into<Cow<'a, str>>,
    V: Into<RegValueData<'a>>,
{
    fn from(value: (K, V)) -> Self {
        let (name, data) = value;
        Self {
            name: name.into(),
            data: data.into(),
        }
    }
}

/// Writes `data` as `name` into `key`, attaching the value name on failure.
fn write_value(key: &windows_registry::Key, name: &str, data: &RegValueData<'_>) -> Result<()> {
    let result = match data {
        RegValueData::String(s) => key.set_string(name, s.as_ref()),
        RegValueData::ExpandableString(s) => key.set_expand_string(name, s.as_ref()),
        RegValueData::DWord(value) => key.set_u32(name, *value),
        RegValueData::QWord(value) => key.set_u64(name, *value),
        RegValueData::Binary(value) => {
            key.set_bytes(name, windows_registry::Type::Bytes, value.as_ref())
        },
        RegValueData::MultiString(value) => key.set_multi_string(
            name,
            value
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .as_slice(),
        ),
    };
    result.map_err(|e| Error::from(e).with_value(name))
}

impl RegValue<'_> {
    pub fn set_self_value(&self, key: &windows_registry::Key) -> Result<()> {
        write_value(key, self.name.as_ref(), &self.data)
    }

    pub fn get(key: &windows_registry::Key, name: impl AsRef<str>) -> Result<RegValueDataOwned> {
        let name = name.as_ref();
        let value = key
            .get_value(name)
            .map_err(|e| Error::from(e).with_value(name))?;
        RegValueDataOwned::try_from(value).map_err(|e| e.with_value(name))
    }

    pub fn remove_self(&self, key: &windows_registry::Key) -> Result<()> {
        key.remove_value(self.name.as_ref())
            .map_err(|e| Error::from(e).with_value(self.name.as_ref()))
    }
}

/// A structure that represents a registry key, including its path and values
#[derive(Debug, Clone)]
pub struct Registry<'a> {
    pub base: BaseKey,
    pub key_path: Cow<'a, str>,
    pub values: Vec<RegValue<'a>>,
}

impl<'a> Registry<'a> {
    pub fn new(base: BaseKey, key_path: impl Into<Cow<'a, str>>) -> Self {
        Self {
            base,
            key_path: key_path.into(),
            values: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_value(mut self, value: impl Into<RegValue<'a>>) -> Self {
        self.values.push(value.into());
        self
    }

    #[must_use]
    pub fn with_values(
        mut self,
        values: impl IntoIterator<Item = impl Into<RegValue<'a>>>,
    ) -> Self {
        self.values.extend(values.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn full_path(&self) -> String {
        let mut path = self.base.to_string();
        if self.key_path.as_ref() != "" {
            path.push('\\');
            path.push_str(self.key_path.as_ref());
        }
        path
    }

    fn parent_with_self_name(&'a self) -> (Self, &'a str) {
        let key_path = self.key_path.trim_end_matches('\\').rsplit_once('\\');
        if let Some((parent, key)) = key_path {
            (Self::new(self.base, parent), key)
        } else {
            (Self::new(self.base, ""), self.key_path.as_ref())
        }
    }

    #[must_use]
    pub fn parent(&'a self) -> Self {
        self.parent_with_self_name().0
    }

    /// Opens the key for reading; fails when it does not exist.
    pub fn open_read(&'a self) -> Result<windows_registry::Key> {
        self.base
            .options()
            .read()
            .open(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    /// Opens the key for reading and writing; fails when it does not exist.
    pub fn open_write(&'a self) -> Result<windows_registry::Key> {
        self.base
            .options()
            .read()
            .write()
            .open(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    /// Opens the key for reading and writing, creating it when missing.
    pub fn open_or_create(&'a self) -> Result<windows_registry::Key> {
        self.base
            .options()
            .read()
            .write()
            .create()
            .open(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    /// Opens the key for reading and writing inside `tx`, creating it when missing.
    pub fn open_or_create_with_tx(&'a self, tx: &Transaction) -> Result<windows_registry::Key> {
        self.base
            .options()
            .read()
            .write()
            .create()
            .transaction(tx)
            .open(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    pub fn set(&self) -> Result<()> {
        let tx = Transaction::new()?;
        let key = self.open_or_create_with_tx(&tx)?;
        for value in &self.values {
            value
                .set_self_value(&key)
                .map_err(|e| e.with_path(self.full_path()))?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_single_value(&self, value: &RegValue<'_>) -> Result<()> {
        let key = self
            .base
            .create(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))?;
        value
            .set_self_value(&key)
            .map_err(|e| e.with_path(self.full_path()))
    }

    pub fn remove_registry(&self) -> Result<()> {
        let (parent, self_name) = self.parent_with_self_name();
        let key = parent.open_or_create()?;
        key.remove_tree(self_name)
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    pub fn remove_single_value(&self, name: impl AsRef<str>) -> Result<()> {
        let key = self.open_or_create()?;
        key.remove_value(name.as_ref())
            .map_err(|e| Error::from(e).with_value(name.as_ref()))
    }

    pub fn remove_values(&self) -> Result<()> {
        let tx = Transaction::new()?;
        let key = self.open_or_create_with_tx(&tx)?;
        for value in &self.values {
            value
                .remove_self(&key)
                .map_err(|e| e.with_path(self.full_path()))?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_value(&self, name: impl AsRef<str>) -> Result<RegValueDataOwned> {
        let key = self
            .base
            .options()
            .read()
            .open(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))?;
        RegValue::get(&key, name).map_err(|e| e.with_path(self.full_path()))
    }

    pub fn get_values(
        &self,
        names: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Vec<RegValueDataOwned>> {
        let key = self
            .base
            .options()
            .read()
            .open(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))?;
        let mut values = vec![];
        for name in names {
            let value = RegValue::get(&key, name).map_err(|e| e.with_path(self.full_path()))?;
            values.push(value);
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ops() -> Result<()> {
        let key1 = "test1".to_string();
        let val1 = 60u32;
        let regs = [
            Registry::new(BaseKey::CurrentUser, "Software\\windows_registry_obj\\test")
                .with_value(("", "default_value"))
                .with_value((&key1, val1))
                .with_values([("test2", "test2_value"), ("test3", "test3_value")]),
        ];
        for reg in &regs {
            reg.set()?;
        }

        let value = regs[0].get_value("")?;
        assert_eq!(value, RegValueData::String(Cow::Borrowed("default_value")));
        let value = regs[0].get_values([key1.as_str(), "test2", "test3"])?;
        assert_eq!(value, vec![
            RegValueData::DWord(val1),
            RegValueData::String(Cow::Owned("test2_value".to_string())),
            RegValueData::String(Cow::Owned("test3_value".to_string()))
        ]);

        regs[0].remove_single_value("test3")?;
        assert!(regs[0].get_value("test2").is_ok());
        assert!(regs[0].get_value("test3").is_err());

        for reg in &regs {
            reg.remove_registry()?;
        }
        assert!(regs[0].get_value("").is_err());
        assert!(regs[0].get_value(&key1).is_err());
        assert!(regs[0].get_values(["test2", "test3"]).is_err());
        Ok(())
    }

    #[test]
    fn test_full_path() {
        assert_eq!(
            BaseKey::CurrentUser
                .reg("Software\\windows_registry_obj")
                .full_path(),
            "HKEY_CURRENT_USER\\Software\\windows_registry_obj"
        );
        assert_eq!(
            BaseKey::CurrentUser.reg("").full_path(),
            "HKEY_CURRENT_USER"
        );
    }

    #[test]
    fn test_error_context() {
        let reg = BaseKey::CurrentUser.reg("Software\\windows_registry_obj\\error_ctx");

        // Missing key: the open failure carries the path, no value name yet.
        let err = reg.get_value("x").unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::Win32(_)));
        assert_eq!(
            err.path(),
            Some("HKEY_CURRENT_USER\\Software\\windows_registry_obj\\error_ctx")
        );
        assert_eq!(err.value(), None);

        // Existing key, missing value: both path and value name are attached.
        reg.set().unwrap();
        let err = reg.get_value("x").unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::Win32(_)));
        assert_eq!(err.path(), Some(reg.full_path().as_str()));
        assert_eq!(err.value(), Some("x"));

        // REG_NONE is not representable, so reading it yields UnsupportedType.
        reg.open_or_create()
            .unwrap()
            .set_bytes("none", windows_registry::Type::Other(0), &[1, 2])
            .unwrap();
        let err = reg.get_value("none").unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::UnsupportedType(0)));
        assert_eq!(err.value(), Some("none"));

        reg.remove_registry().unwrap();
    }
}
