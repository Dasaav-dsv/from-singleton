//! `FD4DerivedSingleton` and `FD4Singleton` search routines.

use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::{c_char, CStr},
    mem,
    ptr::NonNull,
    sync::LazyLock,
};

use pelite::pe::Pe;
use regex::bytes::{Captures, Match, Regex};

/// "Unfinished" `FD4Singleton` mapping without names.
/// 
/// Dantelion2 reflection data is needed to finish mapping reflection
/// primitives to the instance names, which must be initialized.
/// 
/// For that reason, [`FD4SingletonPartialResult::finish`] is unsafe.
pub struct FD4SingletonPartialResult {
    map: HashMap<*mut u8, NonNull<*mut u8>>,
    get_name: Option<unsafe extern "C" fn(*const u8) -> *const c_char>,
}

/// Build a map of all `FD4DerivedSingleton` names and addresses.
///
/// # Panics
/// If `pe` does not contain valid ".text" and ".data" sections.
pub fn derived_singletons<'a, T: Pe<'a>>(pe: T) -> HashMap<Cow<'static, str>, NonNull<*mut u8>> {
    let re = RE_DER_SINGLETON.clone();
    let subre = SUBRE_DER_SINGLETON.clone();

    if re.static_captures_len() != Some(4) || subre.static_captures_len() != Some(2) {
        unreachable!("static captures length changed");
    }

    let sections = pe.section_headers();

    let (text, text_range) = sections
        .by_name(".text")
        .and_then(|s| pe.get_section_bytes(s).ok().zip(Some(s.virtual_range())))
        .expect(".text section missing or malformed");

    let data_range = sections
        .by_name(".data")
        .map(|s| s.virtual_range())
        .expect(".data section missing or malformed");

    let mut vk_map = Vec::<(u32, u32)>::new();

    let image_base = pe.image().as_ptr() as usize;

    for [mov, addr_disp32, test, sub] in re.captures_iter(text).map(extract_captures) {
        if !verify_registers(mov.as_bytes(), test.as_bytes()) {
            continue;
        }

        let addr_bytes = <[u8; 4]>::try_from(addr_disp32.as_bytes()).unwrap();

        let addr = u32::wrapping_add(
            u32::wrapping_add(text_range.start, addr_disp32.end() as _),
            u32::from_le_bytes(addr_bytes),
        );

        let Err(index) = vk_map.binary_search_by_key(&addr, |(v, _)| *v) else {
            continue;
        };

        if !data_range.contains(&addr) {
            continue;
        }

        let Some(captures) = subre.captures(sub.as_bytes()) else {
            continue;
        };

        let [_, name_disp32] = extract_captures(captures);

        let name_bytes = <[u8; 4]>::try_from(name_disp32.as_bytes()).unwrap();

        let name = u32::wrapping_add(
            usize::wrapping_sub(name_disp32.as_bytes().as_ptr() as _, image_base) as _,
            u32::from_le_bytes(name_bytes).wrapping_add(4),
        );

        vk_map.insert(index, (addr, name));
    }

    vk_map
        .into_iter()
        .filter_map(|(v, k)| {
            let addr = NonNull::new(image_base.wrapping_add(v as _) as *mut *mut u8)?;

            if addr.is_aligned() {
                let name = usize::wrapping_add(image_base, k as _);

                // SAFETY: using valid C strings wrapped in `NonNull`.
                NonNull::new(name as _)
                    .map(|a| unsafe { (CStr::from_ptr(a.as_ptr()).to_string_lossy(), addr) })
            } else {
                None
            }
        })
        .collect()
}

/// Build a partial result of a map of all `FD4Singleton` names and addresses.
///
/// Finishing the map is unsafe, as it requires the Dantelion2 reflection data
/// to have been initialized during the startup of the process.
///
/// # Panics
/// If `pe` does not contain valid ".text" and ".data" sections.
pub fn fd4_singletons<'a, T: Pe<'a>>(pe: T) -> FD4SingletonPartialResult {
    let re = RE_FD4_SINGLETON.clone();
    let subre = SUBRE_FD4_SINGLETON.clone();

    if re.static_captures_len() != Some(6) {
        unreachable!("static captures length changed");
    }

    let sections = pe.section_headers();

    let (text, text_range) = sections
        .by_name(".text")
        .and_then(|s| pe.get_section_bytes(s).ok().zip(Some(s.virtual_range())))
        .expect(".text section missing or malformed");

    let data_range = sections
        .by_name(".data")
        .map(|s| s.virtual_range())
        .expect(".data section missing or malformed");

    let mut vk_map = Vec::<(u32, u32)>::new();

    let mut get_name: Option<unsafe extern "C" fn(*const u8) -> *const c_char> = None;

    for [mov, addr_disp32, test, reflection_disp32, fn_disp32, sub] in
        re.captures_iter(text).map(extract_captures)
    {
        if !verify_registers(mov.as_bytes(), test.as_bytes()) {
            continue;
        }

        let addr_bytes = <[u8; 4]>::try_from(addr_disp32.as_bytes()).unwrap();

        let addr = u32::wrapping_add(
            u32::wrapping_add(text_range.start, addr_disp32.end() as _),
            u32::from_le_bytes(addr_bytes),
        );

        let Err(index) = vk_map.binary_search_by_key(&addr, |(v, _)| *v) else {
            continue;
        };

        if !data_range.contains(&addr) {
            continue;
        }

        if !subre.is_match(sub.as_bytes()) {
            continue;
        };

        if get_name.is_none() {
            let fn_bytes = <[u8; 4]>::try_from(fn_disp32.as_bytes()).unwrap();

            let fn_ptr = fn_disp32
                .as_bytes()
                .as_ptr()
                .wrapping_byte_add(u32::wrapping_add(u32::from_le_bytes(fn_bytes), 4) as _);

            if !text.as_ptr_range().contains(&fn_ptr) {
                continue;
            }

            get_name = Some(unsafe { mem::transmute(fn_ptr) });
        }

        let reflection_bytes = <[u8; 4]>::try_from(reflection_disp32.as_bytes()).unwrap();

        let reflection = u32::wrapping_add(
            u32::wrapping_add(text_range.start, reflection_disp32.end() as _),
            u32::from_le_bytes(reflection_bytes),
        );

        vk_map.insert(index, (addr, reflection));
    }

    let image_base = pe.image().as_ptr() as usize;

    let map = vk_map
        .into_iter()
        .filter_map(|(v, k)| {
            let addr = NonNull::new(image_base.wrapping_add(v as _) as *mut *mut u8)?;

            if addr.is_aligned() {
                let reflection = usize::wrapping_add(image_base, k as _);

                Some((reflection as _, addr))
            } else {
                None
            }
        })
        .collect();

    FD4SingletonPartialResult { map, get_name }
}

fn extract_captures<'h, const N: usize>(c: Captures<'h>) -> [Match<'h>; N] {
    let mut iter = c.iter().flatten();
    [0; N].map(|_| iter.next().expect("too few captures"))
}

fn verify_registers(mov: &[u8], test: &[u8]) -> bool {
    let mov_rexw = mov[0] & 1;
    let test_rexw = test[0] & 1;

    let mov_reg = (mov[2] & 0b00111000) >> 3;
    let test_reg = (test[2] & 0b00111000) >> 3;

    mov_rexw == test_rexw && mov_reg == test_reg
}

impl FD4SingletonPartialResult {
    /// Finish mapping `FD4Singleton` instances by retrieving their names.
    ///
    /// # Safety
    /// The process must have finished initializing Dantelion2 reflection data.
    pub unsafe fn finish(self) -> HashMap<Cow<'static, str>, NonNull<*mut u8>> {
        // SAFETY: preconditions should be met for `self.get_name`,
        // returned names are wrapped in `NonNull` and are valid C strings.
        self.map
            .into_iter()
            .filter_map(|(r, p)| unsafe {
                let name = NonNull::new((self.get_name?)(r) as _)?;

                Some((CStr::from_ptr(name.as_ptr()).to_string_lossy(), p))
            })
            .collect()
    }

    /// Check whether all `FD4Singleton` instances are uninitialized.
    ///
    /// It is a good sign [`Self::finish`] is not safe to be called.
    pub fn all_null(&self) -> bool {
        self.map.iter().all(|(_, p)| unsafe { p.read().is_null() })
    }
}

const RE_DER_SINGLETON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?sx-u)
        [\x48-\x4f]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](.{4})
        .{0,3}?
        ([\x48-\x4f]\x85[\xc0\xc9\xd2\xdb\xe4\xed\xf6\xff])
        (?:(?:\x75.)|(?:\x0f\x85.{4}))
        (.{26}) # load args in R9, R8, RDX and RCX in arbitrary order
        \xe8.{4}",
    )
    .unwrap()
});

const RE_FD4_SINGLETON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?sx-u)
        [\x48-\x4f]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](.{4})
        .{0,3}?
        ([\x48-\x4f]\x85[\xc0\xc9\xd2\xdb\xe4\xed\xf6\xff])
        (?:(?:\x75.)|(?:\x0f\x85.{4}))
        \x48\x8d\x0d(.{4})
        \xe8(.{4})
        \x90??
        (.{22}) # load args in R9, R8, RDX and RCX in arbitrary order
        \xe8.{4}",
    )
    .unwrap()
});

const SUBRE_DER_SINGLETON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?sx-u)
        (?:\x4c\x8d\x0d(.{4}) \x4c\x8d\x05.{4} \xba.{4} \x48\x8d\x0d.{4})   # R9 R8 RDX RCX
        | (?:\x4c\x8d\x0d(.{4}) \x4c\x8d\x05.{4} \x48\x8d\x0d.{4} \xba.{4}) # R9 R8 RCX RDX
        | (?:\x4c\x8d\x0d(.{4}) \xba.{4} \x4c\x8d\x05.{4} \x48\x8d\x0d.{4}) # R9 RDX R8 RCX
        | (?:\x4c\x8d\x0d(.{4}) \xba.{4} \x48\x8d\x0d.{4} \x4c\x8d\x05.{4}) # R9 RDX RCX R8
        | (?:\x4c\x8d\x0d(.{4}) \x48\x8d\x0d.{4} \x4c\x8d\x05.{4} \xba.{4}) # R9 RCX R8 RDX
        | (?:\x4c\x8d\x0d(.{4}) \x48\x8d\x0d.{4} \xba.{4} \x4c\x8d\x05.{4}) # R9 RCX RDX R8
        | (?:\x4c\x8d\x05.{4} \x4c\x8d\x0d(.{4}) \xba.{4} \x48\x8d\x0d.{4}) # R8 R9 RDX RCX
        | (?:\x4c\x8d\x05.{4} \x4c\x8d\x0d(.{4}) \x48\x8d\x0d.{4} \xba.{4}) # R8 R9 RCX RDX
        | (?:\x4c\x8d\x05.{4} \xba.{4} \x4c\x8d\x0d(.{4}) \x48\x8d\x0d.{4}) # R8 RDX R9 RCX
        | (?:\x4c\x8d\x05.{4} \xba.{4} \x48\x8d\x0d.{4} \x4c\x8d\x0d(.{4})) # R8 RDX RCX R9
        | (?:\x4c\x8d\x05.{4} \x48\x8d\x0d.{4} \x4c\x8d\x0d(.{4}) \xba.{4}) # R8 RCX R9 RDX
        | (?:\x4c\x8d\x05.{4} \x48\x8d\x0d.{4} \xba.{4} \x4c\x8d\x0d(.{4})) # R8 RCX RDX R9
        | (?:\xba.{4} \x4c\x8d\x0d(.{4}) \x4c\x8d\x05.{4} \x48\x8d\x0d.{4}) # RDX R9 R8 RCX
        | (?:\xba.{4} \x4c\x8d\x0d(.{4}) \x48\x8d\x0d.{4} \x4c\x8d\x05.{4}) # RDX R9 RCX R8
        | (?:\xba.{4} \x4c\x8d\x05.{4} \x4c\x8d\x0d(.{4}) \x48\x8d\x0d.{4}) # RDX R8 R9 RCX
        | (?:\xba.{4} \x4c\x8d\x05.{4} \x48\x8d\x0d.{4} \x4c\x8d\x0d(.{4})) # RDX R8 RCX R9
        | (?:\xba.{4} \x48\x8d\x0d.{4} \x4c\x8d\x0d(.{4}) \x4c\x8d\x05.{4}) # RDX RCX R9 R8
        | (?:\xba.{4} \x48\x8d\x0d.{4} \x4c\x8d\x05.{4} \x4c\x8d\x0d(.{4})) # RDX RCX R8 R9
        | (?:\x48\x8d\x0d.{4} \x4c\x8d\x0d(.{4}) \x4c\x8d\x05.{4} \xba.{4}) # RCX R9 R8 RDX
        | (?:\x48\x8d\x0d.{4} \x4c\x8d\x0d(.{4}) \xba.{4} \x4c\x8d\x05.{4}) # RCX R9 RDX R8
        | (?:\x48\x8d\x0d.{4} \x4c\x8d\x05.{4} \x4c\x8d\x0d(.{4}) \xba.{4}) # RCX R8 R9 RDX
        | (?:\x48\x8d\x0d.{4} \x4c\x8d\x05.{4} \xba.{4} \x4c\x8d\x0d(.{4})) # RCX R8 RDX R9
        | (?:\x48\x8d\x0d.{4} \xba.{4} \x4c\x8d\x0d(.{4}) \x4c\x8d\x05.{4}) # RCX RDX R9 R8
        | (?:\x48\x8d\x0d.{4} \xba.{4} \x4c\x8d\x05.{4} \x4c\x8d\x0d(.{4})) # RCX RDX R8 R9",
    )
    .unwrap()
});

const SUBRE_FD4_SINGLETON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?sx-u)
        (?:\x4c\x8b\xc8 \x4c\x8d\x05.{4} \xba.{4} \x48\x8d\x0d.{4})   # R9 R8 RDX RCX
        | (?:\x4c\x8b\xc8 \x4c\x8d\x05.{4} \x48\x8d\x0d.{4} \xba.{4}) # R9 R8 RCX RDX
        | (?:\x4c\x8b\xc8 \xba.{4} \x4c\x8d\x05.{4} \x48\x8d\x0d.{4}) # R9 RDX R8 RCX
        | (?:\x4c\x8b\xc8 \xba.{4} \x48\x8d\x0d.{4} \x4c\x8d\x05.{4}) # R9 RDX RCX R8
        | (?:\x4c\x8b\xc8 \x48\x8d\x0d.{4} \x4c\x8d\x05.{4} \xba.{4}) # R9 RCX R8 RDX
        | (?:\x4c\x8b\xc8 \x48\x8d\x0d.{4} \xba.{4} \x4c\x8d\x05.{4}) # R9 RCX RDX R8
        | (?:\x4c\x8d\x05.{4} \x4c\x8b\xc8 \xba.{4} \x48\x8d\x0d.{4}) # R8 R9 RDX RCX
        | (?:\x4c\x8d\x05.{4} \x4c\x8b\xc8 \x48\x8d\x0d.{4} \xba.{4}) # R8 R9 RCX RDX
        | (?:\x4c\x8d\x05.{4} \xba.{4} \x4c\x8b\xc8 \x48\x8d\x0d.{4}) # R8 RDX R9 RCX
        | (?:\x4c\x8d\x05.{4} \xba.{4} \x48\x8d\x0d.{4} \x4c\x8b\xc8) # R8 RDX RCX R9
        | (?:\x4c\x8d\x05.{4} \x48\x8d\x0d.{4} \x4c\x8b\xc8 \xba.{4}) # R8 RCX R9 RDX
        | (?:\x4c\x8d\x05.{4} \x48\x8d\x0d.{4} \xba.{4} \x4c\x8b\xc8) # R8 RCX RDX R9
        | (?:\xba.{4} \x4c\x8b\xc8 \x4c\x8d\x05.{4} \x48\x8d\x0d.{4}) # RDX R9 R8 RCX
        | (?:\xba.{4} \x4c\x8b\xc8 \x48\x8d\x0d.{4} \x4c\x8d\x05.{4}) # RDX R9 RCX R8
        | (?:\xba.{4} \x4c\x8d\x05.{4} \x4c\x8b\xc8 \x48\x8d\x0d.{4}) # RDX R8 R9 RCX
        | (?:\xba.{4} \x4c\x8d\x05.{4} \x48\x8d\x0d.{4} \x4c\x8b\xc8) # RDX R8 RCX R9
        | (?:\xba.{4} \x48\x8d\x0d.{4} \x4c\x8b\xc8 \x4c\x8d\x05.{4}) # RDX RCX R9 R8
        | (?:\xba.{4} \x48\x8d\x0d.{4} \x4c\x8d\x05.{4} \x4c\x8b\xc8) # RDX RCX R8 R9
        | (?:\x48\x8d\x0d.{4} \x4c\x8b\xc8 \x4c\x8d\x05.{4} \xba.{4}) # RCX R9 R8 RDX
        | (?:\x48\x8d\x0d.{4} \x4c\x8b\xc8 \xba.{4} \x4c\x8d\x05.{4}) # RCX R9 RDX R8
        | (?:\x48\x8d\x0d.{4} \x4c\x8d\x05.{4} \x4c\x8b\xc8 \xba.{4}) # RCX R8 R9 RDX
        | (?:\x48\x8d\x0d.{4} \x4c\x8d\x05.{4} \xba.{4} \x4c\x8b\xc8) # RCX R8 RDX R9
        | (?:\x48\x8d\x0d.{4} \xba.{4} \x4c\x8b\xc8 \x4c\x8d\x05.{4}) # RCX RDX R9 R8
        | (?:\x48\x8d\x0d.{4} \xba.{4} \x4c\x8d\x05.{4} \x4c\x8b\xc8) # RCX RDX R8 R9",
    )
    .unwrap()
});

#[cfg(test)]
mod tests {
    use super::{RE_DER_SINGLETON, RE_FD4_SINGLETON, SUBRE_DER_SINGLETON, SUBRE_FD4_SINGLETON};

    #[test]
    fn regex_compiles() {
        let _ = RE_DER_SINGLETON.clone();
        let _ = RE_FD4_SINGLETON.clone();
        let _ = SUBRE_DER_SINGLETON.clone();
        let _ = SUBRE_FD4_SINGLETON.clone();
    }
}
