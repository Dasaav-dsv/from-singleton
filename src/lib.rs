#![doc = include_str!("../README.md")]

use std::{
    any,
    borrow::Cow,
    ptr::{self, NonNull},
    sync::{LazyLock, OnceLock},
};

use find::{FD4SingletonMap, FD4SingletonPartialResult};
use fxhash::FxHashMap;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

pub mod find;

/// Assigns a type a name that can be used for Dantelion2 singleton reflection.
///
/// The default implementation trims the type name down to its base, but it
/// can also be overriden.
pub trait FromSingleton {
    /// Returns the name to look up the singleton by.
    #[inline]
    fn name() -> Cow<'static, str> {
        let type_name = any::type_name::<Self>();

        let end = type_name.find('<').unwrap_or(type_name.len());

        let start = type_name[..end]
            .rfind(':')
            .unwrap_or(usize::MAX)
            .wrapping_add(1);

        Cow::Borrowed(&type_name[start..end])
    }
}

/// Returns a reference to the singleton map for the process, where
/// keys are singleton names and values are pointers to the static singleton pointers.
///
/// This function is safe, but may not contain all singletons if it is called
/// before Dantelion2 reflection is initialized by the process.
pub fn map() -> &'static FxHashMap<String, NonNull<*mut u8>> {
    if let Some(map) = ALL_SINGLETON_MAP.get() {
        return map;
    }

    let derived = &*DERIVED_SINGLETON_MAP;
    let partial = &*PARTIAL_SINGLETON_MAP;

    if !partial.all_null() || !derived.all_null() {
        ALL_SINGLETON_MAP.get_or_init(|| {
            // SAFETY: if any singletons are not null initialization has surely happened
            let mut new_map = unsafe { partial.clone().finish() };

            new_map.extend(derived.iter().map(|(k, v)| (k.clone(), *v)));

            new_map
        })
    } else {
        derived
    }
}

/// Returns a pointer to a singleton instance using
/// Dantelion2 reflection. May return [`None`] if the singleton
/// was not found.
///
/// This function is safe, but it may not find all singletons if it is called
/// before Dantelion2 reflection is initialized by the process.
///
/// Ensure the return value is convertible to a reference before dereferencing it.
#[inline]
pub fn address_of<T>() -> Option<NonNull<T>>
where
    T: FromSingleton + Sized,
{
    let static_ptr = static_of::<T>()?;

    // SAFETY: pointer is valid for the read as insured by `static_of`.
    unsafe { NonNull::new(static_ptr.read()) }
}

/// Returns a pointer to the pointer to a singleton instance using
/// Dantelion2 reflection. May return [`None`] if the singleton
/// was not found.
///
/// This function is safe, but it may not find all singletons if it is called
/// before Dantelion2 reflection is initialized by the process.
///
/// Ensure the return value is convertible to a reference before dereferencing it.
#[inline]
pub fn static_of<T>() -> Option<NonNull<*mut T>>
where
    T: FromSingleton + Sized,
{
    let name = <T as FromSingleton>::name();
    map().get(&*name).cloned().map(NonNull::cast)
}

static DERIVED_SINGLETON_MAP: LazyLock<FD4SingletonMap> = LazyLock::new(|| unsafe {
    let image_base = GetModuleHandleW(ptr::null());
    assert!(!image_base.is_null(), "GetModuleHandleW failed");
    let pe = pelite::pe::PeView::module(image_base as _);
    find::derived_singletons(pe)
});

static PARTIAL_SINGLETON_MAP: LazyLock<FD4SingletonPartialResult> = LazyLock::new(|| unsafe {
    let image_base = GetModuleHandleW(ptr::null());
    assert!(!image_base.is_null(), "GetModuleHandleW failed");
    let pe = pelite::pe::PeView::module(image_base as _);
    find::fd4_singletons(pe)
});

static ALL_SINGLETON_MAP: OnceLock<FD4SingletonMap> = OnceLock::new();

#[cfg(test)]
mod tests {
    use crate::FromSingleton;

    mod fd4 {
        use std::{borrow::Cow, marker::PhantomData};

        use crate::FromSingleton;

        pub struct FD4PadManager;
        pub struct FD4HkEzDrawRigidBodyDispBufferManager<T>(PhantomData<T>);
        pub struct FD4FileManager;

        impl FromSingleton for FD4PadManager {}

        impl<T> FromSingleton for FD4HkEzDrawRigidBodyDispBufferManager<T> {}

        impl FromSingleton for FD4FileManager {
            fn name() -> Cow<'static, str> {
                Cow::Borrowed("CSFile")
            }
        }
    }

    mod cs {
        use crate::FromSingleton;

        pub struct CSFile;

        impl FromSingleton for CSFile {}
    }

    impl<T> FromSingleton for Option<T> {}

    #[test]
    fn correct_names() {
        type LongType = fd4::FD4HkEzDrawRigidBodyDispBufferManager<Option<Option<i32>>>;

        assert_eq!(fd4::FD4PadManager::name(), "FD4PadManager");

        assert_eq!(LongType::name(), "FD4HkEzDrawRigidBodyDispBufferManager");

        assert_eq!(fd4::FD4FileManager::name(), cs::CSFile::name());

        assert_eq!(Option::<Result<LongType, LongType>>::name(), "Option");
    }
}
