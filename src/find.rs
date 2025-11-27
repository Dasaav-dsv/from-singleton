//! `FD4DerivedSingleton` and `FD4Singleton` search routines.

use std::{
    ffi::{c_char, CStr},
    mem,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use fxhash::FxHashMap;
use pelite::pe::Pe;
use smallvec::{smallvec, SmallVec};

/// A complete `FD4Singleton` mapping with names.
///
/// Implements [`Deref`] to the underlying [`HashMap`].
#[derive(Clone, Debug)]
pub struct FD4SingletonMap(FxHashMap<String, NonNull<*mut u8>>);

/// "Unfinished" `FD4Singleton` mapping without names.
///
/// Dantelion2 reflection data is needed to finish mapping reflection
/// primitives to the instance names, which must be initialized.
///
/// For that reason, [`FD4SingletonPartialResult::finish`] is unsafe.
#[derive(Clone, Debug)]
pub struct FD4SingletonPartialResult {
    map: FxHashMap<*mut u8, NonNull<*mut u8>>,
    get_name: Option<unsafe extern "C" fn(*const u8) -> *const c_char>,
}

/// Build a map of all `FD4DerivedSingleton` names and addresses.
///
/// # Panics
/// If `pe` does not contain valid ".text" and ".data" sections.
pub fn derived_singletons<'a, T: Pe<'a>>(pe: T) -> FD4SingletonMap {
    let sections = pe.section_headers();

    let text = sections
        .by_name(".text")
        .and_then(|s| pe.get_section_bytes(s).ok())
        .expect(".text section missing or malformed");

    let data_range = sections
        .by_name(".data")
        .map(|s| s.virtual_range())
        .expect(".data section missing or malformed");

    let image_base = pe.image().as_ptr();

    let mut vk_map = Vec::<(u32, u32)>::new();

    for [addr_disp32, name_disp32] in derived_singleton_pat_iter(text) {
        let addr_bytes = <[u8; 4]>::try_from(addr_disp32).unwrap();

        let addr = unsafe {
            u32::wrapping_add(
                addr_disp32.as_ptr_range().end.offset_from(image_base) as u32,
                u32::from_le_bytes(addr_bytes),
            )
        };

        let Err(index) = vk_map.binary_search_by_key(&addr, |(v, _)| *v) else {
            continue;
        };

        if !data_range.contains(&addr) {
            continue;
        }

        let name_bytes = <[u8; 4]>::try_from(name_disp32).unwrap();

        let name = unsafe {
            u32::wrapping_add(
                name_disp32.as_ptr_range().end.offset_from(image_base) as u32,
                u32::from_le_bytes(name_bytes),
            )
        };

        vk_map.insert(index, (addr, name));
    }

    let map = vk_map
        .into_iter()
        .filter_map(|(v, k)| {
            let addr = NonNull::new(image_base.wrapping_add(v as _) as *mut *mut u8)?;

            if addr.is_aligned() {
                let name = image_base.wrapping_add(k as _);

                // SAFETY: using valid C strings wrapped in `NonNull`.
                NonNull::new(name as _).map(|a| unsafe {
                    (
                        CStr::from_ptr(a.as_ptr()).to_string_lossy().to_string(),
                        addr,
                    )
                })
            } else {
                None
            }
        })
        .collect();

    FD4SingletonMap(map)
}

/// Build a partial result of a map of all `FD4Singleton` names and addresses.
///
/// Finishing the map is unsafe, as it requires the Dantelion2 reflection data
/// to have been initialized during the startup of the process.
///
/// # Panics
/// If `pe` does not contain valid ".text" and ".data" sections.
pub fn fd4_singletons<'a, T: Pe<'a>>(pe: T) -> FD4SingletonPartialResult {
    let sections = pe.section_headers();

    let text = sections
        .by_name(".text")
        .and_then(|s| pe.get_section_bytes(s).ok())
        .expect(".text section missing or malformed");

    let data_range = sections
        .by_name(".data")
        .map(|s| s.virtual_range())
        .expect(".data section missing or malformed");

    let image_base = pe.image().as_ptr();

    let mut vk_map = Vec::<(u32, u32)>::new();

    let mut get_name: Option<unsafe extern "C" fn(*const u8) -> *const c_char> = None;

    for [addr_disp32, reflection_disp32, fn_disp32] in fd4_singleton_pat_iter(text) {
        let addr_bytes = <[u8; 4]>::try_from(addr_disp32).unwrap();

        let addr = unsafe {
            u32::wrapping_add(
                addr_disp32.as_ptr_range().end.offset_from(image_base) as u32,
                u32::from_le_bytes(addr_bytes),
            )
        };

        let Err(index) = vk_map.binary_search_by_key(&addr, |(v, _)| *v) else {
            continue;
        };

        if !data_range.contains(&addr) {
            continue;
        }

        if get_name.is_none() {
            let fn_bytes = <[u8; 4]>::try_from(fn_disp32).unwrap();

            let fn_ptr = fn_disp32
                .as_ptr_range()
                .end
                .wrapping_byte_add(u32::from_le_bytes(fn_bytes) as _);

            if !text.as_ptr_range().contains(&fn_ptr) {
                continue;
            }

            get_name = Some(unsafe { mem::transmute(fn_ptr) });
        }

        let reflection_bytes = <[u8; 4]>::try_from(reflection_disp32).unwrap();

        let reflection = unsafe {
            u32::wrapping_add(
                reflection_disp32.as_ptr_range().end.offset_from(image_base) as _,
                u32::from_le_bytes(reflection_bytes),
            )
        };

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

impl FD4SingletonMap {
    /// Check whether all `FD4Singleton` instances are uninitialized.
    ///
    /// It is a good sign [`FD4SingletonPartialResult::finish`] is not safe to be called.
    pub fn all_null(&self) -> bool {
        self.0.iter().all(|(_, p)| unsafe { p.read().is_null() })
    }
}

impl FD4SingletonPartialResult {
    /// Finish mapping `FD4Singleton` instances by retrieving their names.
    ///
    /// # Safety
    /// The process must have finished initializing Dantelion2 reflection data.
    pub unsafe fn finish(self) -> FD4SingletonMap {
        // SAFETY: preconditions should be met for `self.get_name`,
        // returned names are wrapped in `NonNull` and are valid C strings.
        FD4SingletonMap(
            self.map
                .into_iter()
                .filter_map(|(r, p)| unsafe {
                    let name = NonNull::new((self.get_name?)(r) as _)?;

                    Some((
                        CStr::from_ptr(name.as_ptr()).to_string_lossy().to_string(),
                        p,
                    ))
                })
                .collect(),
        )
    }

    /// Check whether all `FD4Singleton` instances are uninitialized.
    ///
    /// It is a good sign [`Self::finish`] is not safe to be called.
    pub fn all_null(&self) -> bool {
        self.map.iter().all(|(_, p)| unsafe { p.read().is_null() })
    }
}

impl Deref for FD4SingletonMap {
    type Target = FxHashMap<String, NonNull<*mut u8>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FD4SingletonMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub fn derived_singleton_pat_iter<'h>(
    text: &'h [u8],
) -> impl Iterator<Item = [&'h [u8]; 2]> + use<'h> {
    candidates_iter(text).filter_map(|candidate| {
        let Candidate::Derived(pos, cap2) = candidate else {
            return None;
        };

        let cap2 = text.get(cap2 as usize..cap2 as usize + 4)?;

        let pos = cond_jump(text, pos)?;

        let pos = pos.checked_sub(3)?;
        let test = text.get(pos as usize..pos as usize + 3)?;

        let test_rex = test[0];
        let test_modrm = test[2];

        let test_rexb = test_rex & 1;

        let test_mod = test_modrm & 0b11000000;

        let test_reg1 = test_modrm & 0b111;
        let test_reg2 = (test_modrm >> 3) & 0b111;

        if test_rex & REX_MASK != REX_W || test_mod != 0xc0 || test_reg1 != test_reg2 {
            return None;
        }

        for pad in 0..=3 {
            let pos = pos.checked_sub(7 + pad)?;

            let mov = text.get(pos as usize..pos as usize + 7)?;
            let cap1 = &mov[3..];

            let mov_rex = mov[0];
            let mov_modrm = mov[2];

            let mov_rexw = (mov_rex >> 2) & 1;
            let mov_mod = mov_modrm & 0b11000000;

            let mov_mem = mov_modrm & 0b111;
            let mov_reg = (mov_modrm >> 3) & 0b111;

            if mov_rex & REX_MASK == REX_W
                && mov_mod == 0
                && mov_mem == 5
                && mov_rexw == test_rexb
                && mov_reg == test_reg1
            {
                return Some([cap1, cap2]);
            }
        }

        None
    })
}

pub fn fd4_singleton_pat_iter<'h>(text: &'h [u8]) -> impl Iterator<Item = [&'h [u8]; 3]> + use<'h> {
    candidates_iter(text).filter_map(|candidate| {
        let Candidate::Fd4(pos) = candidate else {
            return None;
        };

        for pad in 0..=1 {
            let pos = pos.checked_sub(5 + pad)?;
            if text.get(pos as usize) != Some(&CALL) {
                continue;
            }
            let cap3 = text.get(pos as usize + 1..pos as usize + 5)?;

            let pos = pos.checked_sub(7)?;
            if text.get(pos as usize..pos as usize + 3) != Some(LEA_RCX) {
                continue;
            }
            let cap2 = text.get(pos as usize + 3..pos as usize + 7)?;

            let Some(pos) = cond_jump(text, pos) else {
                continue;
            };

            let pos = pos.checked_sub(3)?;
            let test = text.get(pos as usize..pos as usize + 3)?;

            let test_rex = test[0];
            let test_modrm = test[2];

            let test_rexb = test_rex & 1;

            let test_mod = test_modrm & 0b11000000;

            let test_reg1 = test_modrm & 0b111;
            let test_reg2 = (test_modrm >> 3) & 0b111;

            if test_rex & REX_MASK != REX_W || test_mod != 0xc0 || test_reg1 != test_reg2 {
                continue;
            }

            for pad in 0..=3 {
                let pos = pos.checked_sub(7 + pad)?;

                let mov = text.get(pos as usize..pos as usize + 7)?;
                let cap1 = &mov[3..];

                let mov_rex = mov[0];
                let mov_modrm = mov[2];

                let mov_rexw = (mov_rex >> 2) & 1;
                let mov_mod = mov_modrm & 0b11000000;

                let mov_mem = mov_modrm & 0b111;
                let mov_reg = (mov_modrm >> 3) & 0b111;

                if mov_rex & REX_MASK == REX_W
                    && mov_mod == 0
                    && mov_mem == 5
                    && mov_rexw == test_rexb
                    && mov_reg == test_reg1
                {
                    return Some([cap1, cap2, cap3]);
                }
            }
        }

        None
    })
}

const REX_W: u8 = 0x48;
const REX_WRXB: u8 = 0x4f;
const REX_MASK: u8 = !(REX_WRXB ^ REX_W);

fn cond_jump(text: &[u8], pos: u32) -> Option<u32> {
    let pos_short = pos.checked_sub(2)?;

    if text.get(pos_short as usize) == Some(&JNE_SHORT) {
        return Some(pos_short);
    }

    let pos = pos.checked_sub(6)?;

    (text.get(pos as usize..pos as usize + 2) == Some(JNE)).then_some(pos)
}

const JNE_SHORT: u8 = 0x75;
const JNE: &[u8; 2] = &[0x0f, 0x85];

pub enum Candidate {
    Derived(u32, u32),
    Fd4(u32),
}

pub fn candidates_iter<'h>(text: &'h [u8]) -> impl Iterator<Item = Candidate> + use<'h> {
    assert!(text.len() <= u32::MAX as usize, "text is too long!");

    memchr::memchr_iter(MOV_EDX, text).filter_map(|pos| {
        let mut instructions: SmallVec<[Instruction; 4]> =
            smallvec![Instruction::MovEdx(pos as u32)];

        while instructions.len() < 4 {
            let next_pos = instructions.last()?.next_pos();
            let check_next = text.get(next_pos as usize..next_pos as usize + 3)?;

            match check_next {
                LEA_RCX => instructions.push(Instruction::LeaRcx(next_pos)),
                LEA_R8 => instructions.push(Instruction::LeaR8(next_pos)),
                LEA_R9 => instructions.push(Instruction::LeaR9(next_pos)),
                MOV_R9 => instructions.push(Instruction::MovR9(next_pos)),
                &[CALL, ..] => break,
                _ => return None,
            }
        }

        while instructions.len() < 4 {
            let pos = instructions.first()?.pos();
            let prev_pos = pos.checked_sub(7)?;

            let check_prev = text.get(prev_pos as usize..pos as usize)?;

            match &check_prev[..3] {
                LEA_RCX => instructions.insert(0, Instruction::LeaRcx(prev_pos)),
                LEA_R8 => instructions.insert(0, Instruction::LeaR8(prev_pos)),
                LEA_R9 => instructions.insert(0, Instruction::LeaR9(prev_pos)),
                _ if &check_prev[4..] == MOV_R9 => {
                    instructions.insert(0, Instruction::MovR9(prev_pos + 4))
                }
                _ => return None,
            }
        }

        let instructions = instructions.into_inner().ok()?;

        let mask = instructions
            .iter()
            .fold(0, |mask, instruction| match instruction {
                Instruction::LeaRcx(_) => mask | 1,
                Instruction::LeaR8(_) => mask | 2,
                Instruction::LeaR9(_) => mask | 4,
                Instruction::MovR9(_) => mask | 8,
                _ => mask,
            });

        match mask {
            7 => {
                let capture = instructions
                    .iter()
                    .find_map(|instruction| match instruction {
                        Instruction::LeaR9(pos) => Some(pos + 3),
                        _ => None,
                    })?;

                Some(Candidate::Derived(instructions[0].pos(), capture))
            }
            11 => Some(Candidate::Fd4(instructions[0].pos())),
            _ => None,
        }
    })
}

const CALL: u8 = 0xe8;
const MOV_EDX: u8 = 0xba;

const LEA_RCX: &[u8] = &[0x48, 0x8d, 0x0d];
const LEA_R8: &[u8] = &[0x4c, 0x8d, 0x05];
const LEA_R9: &[u8] = &[0x4c, 0x8d, 0x0d];
const MOV_R9: &[u8] = &[0x4c, 0x8b, 0xc8];

#[derive(Clone, Copy)]
enum Instruction {
    LeaRcx(u32),
    LeaR8(u32),
    LeaR9(u32),
    MovR9(u32),
    MovEdx(u32),
}

impl Instruction {
    fn pos(self) -> u32 {
        match self {
            Self::MovEdx(pos) => pos,
            Self::LeaRcx(pos) => pos,
            Self::LeaR8(pos) => pos,
            Self::LeaR9(pos) => pos,
            Self::MovR9(pos) => pos,
        }
    }

    fn next_pos(self) -> u32 {
        match self {
            Self::MovEdx(pos) => pos + 5,
            Self::LeaRcx(pos) => pos + 7,
            Self::LeaR8(pos) => pos + 7,
            Self::LeaR9(pos) => pos + 7,
            Self::MovR9(pos) => pos + 3,
        }
    }
}

unsafe impl Send for FD4SingletonMap {}

unsafe impl Sync for FD4SingletonMap {}

unsafe impl Send for FD4SingletonPartialResult {}

unsafe impl Sync for FD4SingletonPartialResult {}
