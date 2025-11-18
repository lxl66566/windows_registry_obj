use std::{borrow::Cow, ops::Deref};
pub use windows_registry::{
    CLASSES_ROOT, CURRENT_CONFIG, CURRENT_USER, LOCAL_MACHINE, Result, Transaction, USERS,
};

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
    pub fn into_owned(self) -> RegValueDataOwned {
        match self {
            RegValueData::String(s) => RegValueData::String(Cow::Owned(s.into_owned())),
            RegValueData::ExpandableString(s) => {
                RegValueData::ExpandableString(Cow::Owned(s.into_owned()))
            }
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

impl From<windows_registry::Value> for RegValueDataOwned {
    /// Converts a `windows_registry::Value` into a `RegValueData`.
    fn from(value: windows_registry::Value) -> Self {
        match value.ty() {
            windows_registry::Type::U32 => RegValueData::DWord(value.try_into().unwrap()),
            windows_registry::Type::U64 => RegValueData::QWord(value.try_into().unwrap()),
            windows_registry::Type::String => {
                RegValueData::String(Cow::Owned(value.try_into().unwrap()))
            }
            windows_registry::Type::ExpandString => {
                RegValueData::ExpandableString(Cow::Owned(value.try_into().unwrap()))
            }
            windows_registry::Type::Bytes => RegValueData::Binary(Cow::Owned(value.to_vec())),
            windows_registry::Type::MultiString => {
                let v: Vec<String> = value.try_into().unwrap();
                RegValueData::MultiString(v.into_iter().map(Cow::Owned).collect())
            }
            _ => unimplemented!(),
        }
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

impl<'a> RegValue<'a> {
    pub fn set_self_value(&self, key: &windows_registry::Key) -> Result<()> {
        match self.data {
            RegValueData::String(ref s) => key.set_string(self.name.as_ref(), s.as_ref()),
            RegValueData::ExpandableString(ref s) => {
                key.set_expand_string(self.name.as_ref(), s.as_ref())
            }
            RegValueData::DWord(value) => key.set_u32(self.name.as_ref(), value),
            RegValueData::QWord(value) => key.set_u64(self.name.as_ref(), value),
            RegValueData::Binary(ref value) => key.set_bytes(
                self.name.as_ref(),
                windows_registry::Type::Bytes,
                value.as_ref(),
            ),
            RegValueData::MultiString(ref value) => key.set_multi_string(
                self.name.as_ref(),
                value
                    .iter()
                    .map(|x| x.as_ref())
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        }
    }

    pub fn get(key: &windows_registry::Key, name: impl AsRef<str>) -> Result<RegValueDataOwned> {
        Ok(RegValueData::from(key.get_value(name)?))
    }

    pub fn remove_self(&self, key: &windows_registry::Key) -> Result<()> {
        key.remove_value(self.name.as_ref())
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

    pub fn with_value(mut self, value: impl Into<RegValue<'a>>) -> Self {
        self.values.push(value.into());
        self
    }

    pub fn with_values(
        mut self,
        values: impl IntoIterator<Item = impl Into<RegValue<'a>>>,
    ) -> Self {
        self.values.extend(values.into_iter().map(|x| x.into()));
        self
    }

    pub fn full_path(&self) -> String {
        let mut path = self.base.to_string();
        if self.key_path.as_ref() != "" {
            path.push('\\');
            path.push_str(self.key_path.as_ref());
        }
        path
    }

    fn parent_with_self_name(&'a self) -> (Self, &'a str) {
        let key_path = self.key_path.rsplit_once('\\');
        if let Some((parent, key)) = key_path {
            (Self::new(self.base, parent), key)
        } else {
            (Self::new(self.base, ""), self.key_path.as_ref())
        }
    }

    pub fn parent(&'a self) -> Self {
        self.parent_with_self_name().0
    }

    pub fn open(&'a self) -> Result<windows_registry::Key> {
        self.base
            .options()
            .read()
            .write()
            .create()
            .open(self.key_path.as_ref())
    }

    pub fn open_with_tx(&'a self, tx: &Transaction) -> Result<windows_registry::Key> {
        self.base
            .options()
            .read()
            .write()
            .create()
            .transaction(tx)
            .open(self.key_path.as_ref())
    }

    pub fn set(&self) -> Result<()> {
        let tx = Transaction::new()?;
        let key = self.open_with_tx(&tx)?;
        for value in self.values.iter() {
            value.set_self_value(&key)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_single_value(&self, value: RegValue<'a>) -> Result<()> {
        let key = self.base.create(self.key_path.as_ref())?;
        value.set_self_value(&key)
    }

    pub fn remove_registry(&self) -> Result<()> {
        let (parent, self_name) = self.parent_with_self_name();
        let key = parent.open()?;
        key.remove_tree(self_name)?;
        Ok(())
    }

    pub fn remove_single_value(&self, name: impl AsRef<str>) -> Result<()> {
        let key = self.open()?;
        key.remove_value(name)
    }

    pub fn remove_values(&self) -> Result<()> {
        let tx = Transaction::new()?;
        let key = self.open_with_tx(&tx)?;
        for value in self.values.iter() {
            value.remove_self(&key)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_value(&self, name: impl AsRef<str>) -> Result<RegValueDataOwned> {
        let key = self.base.options().read().open(self.key_path.as_ref())?;
        RegValue::get(&key, name)
    }

    pub fn get_values(
        &self,
        names: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Vec<RegValueDataOwned>> {
        let tx = Transaction::new()?;
        let key = self
            .base
            .options()
            .read()
            .transaction(&tx)
            .open(self.key_path.as_ref())?;
        let mut values = vec![];
        for name in names.into_iter() {
            values.push(RegValue::get(&key, name)?);
        }
        tx.commit()?;
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ops() -> Result<()> {
        let key1 = "test1".to_string();
        let val1 = 60;
        let regs = [
            Registry::new(BaseKey::CurrentUser, "Software\\windows_registry_obj\\test")
                .with_value(("", "default_value"))
                .with_value((&key1, val1 as u32))
                .with_values([("test2", "test2_value"), ("test3", "test3_value")]),
        ];
        for reg in regs.iter() {
            reg.set()?;
        }

        let value = regs[0].get_value("")?;
        assert_eq!(value, RegValueData::String(Cow::Borrowed("default_value")));
        let value = regs[0].get_values([key1.as_str(), "test2", "test3"])?;
        assert_eq!(
            value,
            vec![
                RegValueData::DWord(val1 as u32),
                RegValueData::String(Cow::Owned("test2_value".to_string())),
                RegValueData::String(Cow::Owned("test3_value".to_string()))
            ]
        );

        regs[0].remove_single_value("test3")?;
        assert!(regs[0].get_value("test2").is_ok());
        assert!(regs[0].get_value("test3").is_err());

        for reg in regs.iter() {
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
}
