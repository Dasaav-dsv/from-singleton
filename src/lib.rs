#![doc = include_str!("../README.md")]

use std::{
    any,
    borrow::Cow,
    collections::HashMap,
    mem,
    num::NonZeroUsize,
    ops::Deref,
    ptr::NonNull,
    sync::{LazyLock, RwLock},
};

use windows::{core::PCWSTR, Win32::System::LibraryLoader::GetModuleHandleW};

pub mod find;

/// Assigns a type a name that can be used for Dantelion2 singleton reflection.
/// 
/// The default implementation trims the type name down to its base, but it
/// can also be overriden.
pub trait FromSingleton {
    /// Returns the name to look up the singleton by.
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

/// Returns a copy of the singleton map for the process, where
/// keys are singleton names and values are pointers to the static singleton pointers.
/// 
/// This function is safe, but may not contain all singletons if it is called
/// before Dantelion2 reflection is initialized by the process.
pub fn map() -> HashMap<Cow<'static, str>, NonNull<*mut u8>> {
    let mut new_map = derived_singletons().clone();

    if let Ok(map) = FD4_SINGLETON_MAP.read() {
        if let Some(map) = &*map {
            new_map.extend(
                map.iter()
                    .map(|(k, v)| unsafe { (k.clone(), mem::transmute(*v)) }),
            );

            return new_map;
        }
    }

    unsafe {
        let mut map = match FD4_SINGLETON_MAP.write() {
            Ok(value) => value,
            Err(value) => value.into_inner(),
        };

        let partial = partial_singletons();

        if !partial.all_null() || !new_map.iter().all(|(_, p)| p.read().is_null()) {
            let fd4_map = partial.finish();

            new_map.extend(fd4_map.iter().map(|(k, v)| (k.clone(), *v)));

            *map = Some(mem::transmute(fd4_map));
        }
    }

    new_map
}

/// Returns a pointer to a singleton instance using
/// Dantelion2 reflection. May return [`None`] if the singleton
/// was not found.
/// 
/// This function is safe, but it may not find all singletons if it is called
/// before Dantelion2 reflection is initialized by the process.
/// 
/// Ensure the return value is convertible to a reference before dereferencing it.
pub fn address_of<T: FromSingleton>() -> Option<NonNull<T>> {
    let static_ptr = static_of::<T>()?;
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
pub fn static_of<T: FromSingleton>() -> Option<NonNull<*mut T>> {
    let name = T::name();

    let derived_map = derived_singletons();

    if let Some(addr) = derived_map.get(&name) {
        return unsafe { Some(mem::transmute(*addr)) };
    }

    if let Ok(map) = FD4_SINGLETON_MAP.read() {
        if let Some(map) = &*map {
            let addr = map.get(&name)?;

            return unsafe { Some(mem::transmute(*addr)) };
        }
    }

    let mut map = match FD4_SINGLETON_MAP.write() {
        Ok(value) => value,
        Err(value) => value.into_inner(),
    };

    let partial = partial_singletons();

    unsafe {
        if !partial.all_null() || !derived_map.iter().all(|(_, p)| p.read().is_null()) {
            let new_map = partial.finish();

            let found = new_map.get(&name).cloned();

            *map = Some(mem::transmute(new_map));

            if let Some(addr) = found {
                return Some(mem::transmute(addr));
            }
        }
    }

    None
}

fn derived_singletons() -> &'static HashMap<Cow<'static, str>, NonNull<*mut u8>> {
    let map: &'static HashMap<Cow<'static, str>, NonZeroUsize> = DERIVED_SINGLETON_MAP.deref();
    unsafe { mem::transmute(map) }
}

fn partial_singletons() -> find::FD4SingletonPartialResult {
    unsafe {
        let image_base = GetModuleHandleW(PCWSTR::null()).expect("GetModuleHandleW failed");
        let pe = pelite::pe::PeView::module(image_base.0 as _);
        find::fd4_singletons(pe)
    }
}

static FD4_SINGLETON_MAP: RwLock<Option<HashMap<Cow<'static, str>, NonZeroUsize>>> =
    RwLock::new(None);

static DERIVED_SINGLETON_MAP: LazyLock<HashMap<Cow<'static, str>, NonZeroUsize>> =
    LazyLock::new(|| unsafe {
        let image_base = GetModuleHandleW(PCWSTR::null()).expect("GetModuleHandleW failed");
        let pe = pelite::pe::PeView::module(image_base.0 as _);
        mem::transmute(find::derived_singletons(pe))
    });

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
