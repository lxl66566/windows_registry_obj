use std::borrow::Cow;

pub use windows_registry::{
    CLASSES_ROOT, CURRENT_CONFIG, CURRENT_USER, Key, LOCAL_MACHINE, Transaction, Type, USERS, Value,
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

impl BaseKey {
    /// The underlying predefined root [`Key`] handle.
    #[must_use]
    pub const fn as_key(&self) -> &'static Key {
        match self {
            BaseKey::ClassesRoot => CLASSES_ROOT,
            BaseKey::CurrentConfig => CURRENT_CONFIG,
            BaseKey::CurrentUser => CURRENT_USER,
            BaseKey::LocalMachine => LOCAL_MACHINE,
            BaseKey::Users => USERS,
        }
    }

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

impl From<&'_ RegValueData<'_>> for Type {
    fn from(val: &'_ RegValueData<'_>) -> Self {
        match val {
            RegValueData::String(_) => Type::String,
            RegValueData::ExpandableString(_) => Type::ExpandString,
            RegValueData::DWord(_) => Type::U32,
            RegValueData::QWord(_) => Type::U64,
            RegValueData::Binary(_) => Type::Bytes,
            RegValueData::MultiString(_) => Type::MultiString,
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

impl TryFrom<Value> for RegValueDataOwned {
    type Error = Error;

    /// Converts a `Value` into a `RegValueData`.
    fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
        let ret = match value.ty() {
            Type::U32 => RegValueData::DWord(value.try_into()?),
            Type::U64 => RegValueData::QWord(value.try_into()?),
            Type::String => RegValueData::String(Cow::Owned(value.try_into()?)),
            Type::ExpandString => RegValueData::ExpandableString(Cow::Owned(value.try_into()?)),
            Type::Bytes => RegValueData::Binary(Cow::Owned(value.to_vec())),
            Type::MultiString => {
                let v: Vec<String> = value.try_into()?;
                RegValueData::MultiString(v.into_iter().map(Cow::Owned).collect())
            },
            Type::Other(ty) => {
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
fn write_value(key: &Key, name: &str, data: &RegValueData<'_>) -> Result<()> {
    let result = match data {
        RegValueData::String(s) => key.set_string(name, s.as_ref()),
        RegValueData::ExpandableString(s) => key.set_expand_string(name, s.as_ref()),
        RegValueData::DWord(value) => key.set_u32(name, *value),
        RegValueData::QWord(value) => key.set_u64(name, *value),
        RegValueData::Binary(value) => key.set_bytes(name, Type::Bytes, value.as_ref()),
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

/// Reads `name` from `key`, attaching the value name on failure.
fn read_value(key: &Key, name: &str) -> Result<RegValueDataOwned> {
    let value = key
        .get_value(name)
        .map_err(|e| Error::from(e).with_value(name))?;
    RegValueDataOwned::try_from(value).map_err(|e| e.with_value(name))
}

impl RegValue<'_> {
    pub fn set_self_value(&self, key: &Key) -> Result<()> {
        write_value(key, self.name.as_ref(), &self.data)
    }

    pub fn remove_self(&self, key: &Key) -> Result<()> {
        key.remove_value(self.name.as_ref())
            .map_err(|e| Error::from(e).with_value(self.name.as_ref()))
    }
}

/// A registry key addressed by a base key and a relative path, carrying the
/// values to write. An empty path addresses the base root itself.
///
/// A value named `""` addresses the key's default value.
#[derive(Debug, Clone)]
pub struct Registry<'a> {
    base: BaseKey,
    key_path: Cow<'a, str>,
    values: Vec<RegValue<'a>>,
    volatile: bool,
}

/// A [`RegValue`] without borrowed data.
pub type RegValueOwned = RegValue<'static>;

impl<'a> Registry<'a> {
    pub fn new(base: BaseKey, key_path: impl Into<Cow<'a, str>>) -> Self {
        Self {
            base,
            key_path: key_path.into(),
            values: Vec::new(),
            volatile: false,
        }
    }

    /// The base key the path is relative to.
    #[must_use]
    pub fn base(&self) -> BaseKey {
        self.base
    }

    /// The key path relative to the base key; empty for the base root itself.
    #[must_use]
    pub fn key_path(&self) -> &str {
        self.key_path.as_ref()
    }

    /// The values declared through the builder.
    #[must_use]
    pub fn declared_values(&self) -> &[RegValue<'a>] {
        &self.values
    }

    /// Marks the key so that creation does not persist across reboots.
    #[must_use]
    pub fn volatile(mut self) -> Self {
        self.volatile = true;
        self
    }

    /// Whether the key is created as volatile.
    #[must_use]
    pub fn is_volatile(&self) -> bool {
        self.volatile
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

    /// Splits the path into the parent key and own name; `None` when this is a root key.
    fn split_parent(&'a self) -> Option<(Self, &'a str)> {
        let path = self.key_path.trim_end_matches('\\');
        if path.is_empty() {
            return None;
        }
        let (parent, name) = match path.rsplit_once('\\') {
            Some((parent, name)) => (Self::new(self.base, parent), name),
            // a direct child of the base root
            None => (Self::new(self.base, ""), path),
        };
        Some((parent, name))
    }

    /// Like [`Registry::split_parent`], but rejects root keys: they cannot be
    /// removed or renamed.
    fn require_subkey(&'a self) -> Result<(Self, &'a str)> {
        self.split_parent()
            .ok_or_else(|| Error::new(ErrorKind::RootKey))
    }

    /// The parent key; a root key is its own parent.
    #[must_use]
    pub fn parent(&'a self) -> Self {
        self.split_parent()
            .map_or_else(|| self.clone(), |(parent, _)| parent)
    }

    /// Whether the key exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.open_read().is_ok()
    }

    /// Names of the subkeys under this key.
    pub fn subkeys(&self) -> Result<Vec<String>> {
        let key = self.open_read()?;
        key.keys()
            .map_err(|e| Error::from(e).with_path(self.full_path()))
            .map(Iterator::collect)
    }

    /// All values currently stored under this key.
    pub fn values(&self) -> Result<Vec<RegValueOwned>> {
        let key = self.open_read()?;
        let entries = key
            .values()
            .map_err(|e| Error::from(e).with_path(self.full_path()))?;
        let mut values = Vec::with_capacity(entries.size_hint().0);
        for (name, value) in entries {
            let data = RegValueDataOwned::try_from(value)
                .map_err(|e| e.with_value(name.as_str()).with_path(self.full_path()))?;
            values.push(RegValueOwned {
                name: Cow::Owned(name),
                data,
            });
        }
        Ok(values)
    }

    /// The registry type of an existing value.
    pub fn get_type(&self, name: impl AsRef<str>) -> Result<Type> {
        let key = self.open_read()?;
        key.get_type(name.as_ref()).map_err(|e| {
            Error::from(e)
                .with_value(name.as_ref())
                .with_path(self.full_path())
        })
    }

    /// Renames this key within its parent; a registry root key cannot be renamed.
    pub fn rename(&self, new_name: impl AsRef<str>) -> Result<()> {
        let (parent, self_name) = self.require_subkey()?;
        let key = parent.open_write()?;
        key.rename(self_name, new_name.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    /// Opens the key for reading; fails when it does not exist.
    pub fn open_read(&'a self) -> Result<Key> {
        self.base
            .as_key()
            .options()
            .read()
            .open(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    /// Opens the key for reading and writing; fails when it does not exist.
    pub fn open_write(&'a self) -> Result<Key> {
        self.base
            .as_key()
            .options()
            .read()
            .write()
            .open(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    /// Opens the key for reading and writing, creating it when missing. Created
    /// keys are volatile when the registry is marked [`Registry::volatile`].
    pub fn open_or_create(&'a self) -> Result<Key> {
        self.open_created(None)
    }

    /// Opens the key for reading and writing inside `tx`, creating it when missing.
    pub fn open_or_create_with_tx(&'a self, tx: &Transaction) -> Result<Key> {
        self.open_created(Some(tx))
    }

    /// Opens the key for reading and writing inside `tx`; fails when it does not exist.
    fn open_write_with_tx(&'a self, tx: &Transaction) -> Result<Key> {
        self.base
            .as_key()
            .options()
            .read()
            .write()
            .transaction(tx)
            .open(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    /// Opens the key for reading and writing, creating it when missing.
    fn open_created(&'a self, tx: Option<&Transaction>) -> Result<Key> {
        let root = self.base.as_key();
        let mut builder = root.options();
        let options = builder.read().write().create();
        if self.volatile {
            options.volatile();
        }
        if let Some(tx) = tx {
            options.transaction(tx);
        }
        options
            .open(self.key_path.as_ref())
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    /// Writes all declared values inside one transaction; creates the key when missing.
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

    /// Writes a single value inside its own transaction, matching [`Registry::set`].
    pub fn set_single_value(&self, value: &RegValue<'_>) -> Result<()> {
        let tx = Transaction::new()?;
        let key = self.open_or_create_with_tx(&tx)?;
        value
            .set_self_value(&key)
            .map_err(|e| e.with_path(self.full_path()))?;
        tx.commit()?;
        Ok(())
    }

    /// Removes the whole key and its subtree; a registry root key cannot be removed.
    pub fn remove_registry(&self) -> Result<()> {
        let (parent, self_name) = self.require_subkey()?;
        let key = parent.open_write()?;
        key.remove_tree(self_name)
            .map_err(|e| Error::from(e).with_path(self.full_path()))
    }

    pub fn remove_single_value(&self, name: impl AsRef<str>) -> Result<()> {
        let key = self.open_write()?;
        key.remove_value(name.as_ref())
            .map_err(|e| Error::from(e).with_value(name.as_ref()))
    }

    pub fn remove_values(&self) -> Result<()> {
        let tx = Transaction::new()?;
        let key = self.open_write_with_tx(&tx)?;
        for value in &self.values {
            value
                .remove_self(&key)
                .map_err(|e| e.with_path(self.full_path()))?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_value(&self, name: impl AsRef<str>) -> Result<RegValueDataOwned> {
        let key = self.open_read()?;
        read_value(&key, name.as_ref()).map_err(|e| e.with_path(self.full_path()))
    }

    pub fn get_values(
        &self,
        names: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Vec<RegValueDataOwned>> {
        let key = self.open_read()?;
        let mut values = vec![];
        for name in names {
            let value =
                read_value(&key, name.as_ref()).map_err(|e| e.with_path(self.full_path()))?;
            values.push(value);
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Serializes tests: concurrent transacted creation of the same intermediate
    /// key conflicts because uncommitted keys are invisible to other transactions.
    static LOCK: Mutex<()> = Mutex::new(());

    /// Removes the wrapped registry key on drop so failing tests do not leak state.
    struct Guard(Registry<'static>);

    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.remove_registry();
        }
    }

    fn guard(path: &'static str) -> Guard {
        Guard(BaseKey::CurrentUser.reg(path))
    }

    #[test]
    fn test_basic_ops() -> Result<()> {
        let _lock = LOCK.lock().unwrap();
        let key1 = "test1".to_string();
        let val1 = 60u32;
        let reg = Registry::new(BaseKey::CurrentUser, "Software\\windows_registry_obj\\test")
            .with_value(("", "default_value"))
            .with_value((&key1, val1))
            .with_values([("test2", "test2_value"), ("test3", "test3_value")]);
        let cleanup = guard("Software\\windows_registry_obj\\test");

        reg.set()?;

        let value = reg.get_value("")?;
        assert_eq!(value, RegValueData::String(Cow::Borrowed("default_value")));
        let value = reg.get_values([key1.as_str(), "test2", "test3"])?;
        assert_eq!(value, vec![
            RegValueData::DWord(val1),
            RegValueData::String(Cow::Owned("test2_value".to_string())),
            RegValueData::String(Cow::Owned("test3_value".to_string()))
        ]);

        reg.remove_single_value("test3")?;
        assert!(reg.get_value("test2").is_ok());
        assert!(reg.get_value("test3").is_err());

        drop(cleanup);
        assert!(reg.get_value("").is_err());
        assert!(reg.get_value(&key1).is_err());
        assert!(reg.get_values(["test2", "test3"]).is_err());
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
        let _lock = LOCK.lock().unwrap();
        let reg = BaseKey::CurrentUser.reg("Software\\windows_registry_obj\\error_ctx");
        let _cleanup = guard("Software\\windows_registry_obj\\error_ctx");

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
            .set_bytes("none", Type::Other(0), &[1, 2])
            .unwrap();
        let err = reg.get_value("none").unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::UnsupportedType(0)));
        assert_eq!(err.value(), Some("none"));
    }

    #[test]
    fn test_remove_root_rejected() {
        let err = BaseKey::CurrentUser.reg("").remove_registry().unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::RootKey));
        // A path of bare backslashes is still the root.
        let err = BaseKey::CurrentUser
            .reg("\\")
            .remove_registry()
            .unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::RootKey));
    }

    #[test]
    fn test_remove_missing_creates_nothing() {
        let _lock = LOCK.lock().unwrap();
        let parent = "Software\\windows_registry_obj\\missing_parent";

        // Removing a key whose parent is missing must not materialize the parent chain.
        assert!(
            BaseKey::CurrentUser
                .reg("Software\\windows_registry_obj\\missing_parent\\child")
                .remove_registry()
                .is_err()
        );
        assert!(BaseKey::CurrentUser.reg(parent).open_read().is_err());

        // Removing values of a missing key must not create it either.
        let reg = BaseKey::CurrentUser
            .reg("Software\\windows_registry_obj\\missing_key")
            .with_value(("a", 1u32));
        assert!(reg.remove_values().is_err());
        assert!(reg.remove_single_value("a").is_err());
        assert!(reg.open_read().is_err());
    }

    #[test]
    fn test_set_single_value() {
        let _lock = LOCK.lock().unwrap();
        let reg = BaseKey::CurrentUser.reg("Software\\windows_registry_obj\\single_value");
        let _cleanup = guard("Software\\windows_registry_obj\\single_value");

        reg.set_single_value(&("answer", 42u32).into()).unwrap();
        assert_eq!(reg.get_value("answer").unwrap(), RegValueData::DWord(42));
    }

    #[test]
    fn test_inspection() {
        let _lock = LOCK.lock().unwrap();
        let reg = BaseKey::CurrentUser.reg("Software\\windows_registry_obj\\inspect");
        let _cleanup = guard("Software\\windows_registry_obj\\inspect");

        assert!(!reg.exists());
        let reg = reg.with_value(("str", "a")).with_value(("num", 1u64));
        reg.set().unwrap();
        assert!(reg.exists());

        assert_eq!(reg.get_type("str").unwrap(), Type::String);
        assert_eq!(reg.get_type("num").unwrap(), Type::U64);

        let mut values = reg.values().unwrap();
        values.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(values[0], RegValue::from(("num", 1u64)));
        assert_eq!(values[1].name, "str");
        assert_eq!(values[1].data, RegValueData::String(Cow::Borrowed("a")));

        reg.open_or_create().unwrap().create("child").unwrap();
        assert_eq!(reg.subkeys().unwrap(), vec!["child".to_string()]);
    }

    #[test]
    fn test_rename() {
        let _lock = LOCK.lock().unwrap();
        let reg = BaseKey::CurrentUser.reg("Software\\windows_registry_obj\\rename_src");
        let _cleanup = guard("Software\\windows_registry_obj\\rename_src");
        reg.set().unwrap();

        let err = BaseKey::CurrentUser.reg("").rename("x").unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::RootKey));

        reg.rename("renamed").unwrap();
        assert!(!reg.exists());
        let renamed = BaseKey::CurrentUser.reg("Software\\windows_registry_obj\\renamed");
        assert!(renamed.exists());
        renamed.remove_registry().unwrap();
    }

    #[test]
    fn test_volatile() {
        let _lock = LOCK.lock().unwrap();
        let reg = BaseKey::CurrentUser
            .reg("Software\\windows_registry_obj\\volatile")
            .volatile();
        let _cleanup = guard("Software\\windows_registry_obj\\volatile");
        assert!(reg.is_volatile());

        let reg = reg.with_value(("x", 1u32));
        reg.set().unwrap();
        assert_eq!(reg.get_value("x").unwrap(), RegValueData::DWord(1));
    }
}
