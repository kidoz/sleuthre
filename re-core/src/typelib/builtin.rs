use crate::typelib::TypeLibrary;
use crate::types::{CompoundType, FunctionParameter, FunctionSignature, PrimitiveType, StructField, TypeRef};
use std::collections::BTreeMap;

/// Helper to build a TypeRef for `const char*`
fn const_char_ptr() -> TypeRef {
    TypeRef::Pointer(Box::new(TypeRef::Const(Box::new(TypeRef::Primitive(
        PrimitiveType::Char,
    )))))
}

/// Helper to build a TypeRef for `char*`
fn char_ptr() -> TypeRef {
    TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::Char)))
}

/// Helper to build a TypeRef for `void*`
fn void_ptr() -> TypeRef {
    TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::Void)))
}

/// Helper to build a TypeRef for `const void*`
fn const_void_ptr() -> TypeRef {
    TypeRef::Pointer(Box::new(TypeRef::Const(Box::new(TypeRef::Primitive(
        PrimitiveType::Void,
    )))))
}

fn sig(
    name: &str,
    ret: TypeRef,
    params: Vec<(&str, TypeRef)>,
    is_variadic: bool,
) -> (String, FunctionSignature) {
    (
        name.to_string(),
        FunctionSignature {
            name: name.to_string(),
            return_type: ret,
            parameters: params
                .into_iter()
                .map(|(n, t)| FunctionParameter {
                    name: n.to_string(),
                    type_ref: t,
                })
                .collect(),
            calling_convention: String::new(),
            is_variadic,
        },
    )
}

/// Built-in libc type library with common C standard library functions.
pub fn libc_library() -> TypeLibrary {
    let i32t = TypeRef::Primitive(PrimitiveType::I32);
    let u64t = TypeRef::Primitive(PrimitiveType::U64);
    let sizet = TypeRef::Primitive(PrimitiveType::USize);
    let void = TypeRef::Primitive(PrimitiveType::Void);
    let file_ptr = TypeRef::Pointer(Box::new(TypeRef::Named("FILE".to_string())));

    let mut sigs = BTreeMap::new();

    // stdio
    let entries = vec![
        sig(
            "printf",
            i32t.clone(),
            vec![("format", const_char_ptr())],
            true,
        ),
        sig(
            "fprintf",
            i32t.clone(),
            vec![("stream", file_ptr.clone()), ("format", const_char_ptr())],
            true,
        ),
        sig(
            "sprintf",
            i32t.clone(),
            vec![("str", char_ptr()), ("format", const_char_ptr())],
            true,
        ),
        sig(
            "snprintf",
            i32t.clone(),
            vec![
                ("str", char_ptr()),
                ("size", sizet.clone()),
                ("format", const_char_ptr()),
            ],
            true,
        ),
        sig(
            "scanf",
            i32t.clone(),
            vec![("format", const_char_ptr())],
            true,
        ),
        sig(
            "sscanf",
            i32t.clone(),
            vec![("str", const_char_ptr()), ("format", const_char_ptr())],
            true,
        ),
        sig("puts", i32t.clone(), vec![("s", const_char_ptr())], false),
        sig("putchar", i32t.clone(), vec![("c", i32t.clone())], false),
        sig("getchar", i32t.clone(), vec![], false),
        sig(
            "fopen",
            file_ptr.clone(),
            vec![("filename", const_char_ptr()), ("mode", const_char_ptr())],
            false,
        ),
        sig(
            "fclose",
            i32t.clone(),
            vec![("stream", file_ptr.clone())],
            false,
        ),
        sig(
            "fread",
            sizet.clone(),
            vec![
                ("ptr", void_ptr()),
                ("size", sizet.clone()),
                ("nmemb", sizet.clone()),
                ("stream", file_ptr.clone()),
            ],
            false,
        ),
        sig(
            "fwrite",
            sizet.clone(),
            vec![
                ("ptr", const_void_ptr()),
                ("size", sizet.clone()),
                ("nmemb", sizet.clone()),
                ("stream", file_ptr.clone()),
            ],
            false,
        ),
        sig(
            "fgets",
            char_ptr(),
            vec![
                ("s", char_ptr()),
                ("size", i32t.clone()),
                ("stream", file_ptr.clone()),
            ],
            false,
        ),
        sig(
            "fputs",
            i32t.clone(),
            vec![("s", const_char_ptr()), ("stream", file_ptr.clone())],
            false,
        ),
        sig(
            "fseek",
            i32t.clone(),
            vec![
                ("stream", file_ptr.clone()),
                ("offset", TypeRef::Primitive(PrimitiveType::I64)),
                ("whence", i32t.clone()),
            ],
            false,
        ),
        sig(
            "ftell",
            TypeRef::Primitive(PrimitiveType::I64),
            vec![("stream", file_ptr.clone())],
            false,
        ),
        sig(
            "fflush",
            i32t.clone(),
            vec![("stream", file_ptr.clone())],
            false,
        ),
        sig(
            "feof",
            i32t.clone(),
            vec![("stream", file_ptr.clone())],
            false,
        ),
        sig(
            "ferror",
            i32t.clone(),
            vec![("stream", file_ptr.clone())],
            false,
        ),
        sig("perror", void.clone(), vec![("s", const_char_ptr())], false),
        // stdlib
        sig("malloc", void_ptr(), vec![("size", sizet.clone())], false),
        sig(
            "calloc",
            void_ptr(),
            vec![("nmemb", sizet.clone()), ("size", sizet.clone())],
            false,
        ),
        sig(
            "realloc",
            void_ptr(),
            vec![("ptr", void_ptr()), ("size", sizet.clone())],
            false,
        ),
        sig("free", void.clone(), vec![("ptr", void_ptr())], false),
        sig("exit", void.clone(), vec![("status", i32t.clone())], false),
        sig("abort", void.clone(), vec![], false),
        sig(
            "atoi",
            i32t.clone(),
            vec![("nptr", const_char_ptr())],
            false,
        ),
        sig(
            "atol",
            TypeRef::Primitive(PrimitiveType::I64),
            vec![("nptr", const_char_ptr())],
            false,
        ),
        sig(
            "strtol",
            TypeRef::Primitive(PrimitiveType::I64),
            vec![
                ("nptr", const_char_ptr()),
                ("endptr", TypeRef::Pointer(Box::new(char_ptr()))),
                ("base", i32t.clone()),
            ],
            false,
        ),
        sig(
            "strtoul",
            u64t.clone(),
            vec![
                ("nptr", const_char_ptr()),
                ("endptr", TypeRef::Pointer(Box::new(char_ptr()))),
                ("base", i32t.clone()),
            ],
            false,
        ),
        sig("abs", i32t.clone(), vec![("j", i32t.clone())], false),
        sig("rand", i32t.clone(), vec![], false),
        sig(
            "srand",
            void.clone(),
            vec![("seed", TypeRef::Primitive(PrimitiveType::U32))],
            false,
        ),
        sig(
            "qsort",
            void.clone(),
            vec![
                ("base", void_ptr()),
                ("nmemb", sizet.clone()),
                ("size", sizet.clone()),
                (
                    "compar",
                    TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::Void))),
                ),
            ],
            false,
        ),
        sig(
            "getenv",
            char_ptr(),
            vec![("name", const_char_ptr())],
            false,
        ),
        sig(
            "system",
            i32t.clone(),
            vec![("command", const_char_ptr())],
            false,
        ),
        // string
        sig(
            "strlen",
            sizet.clone(),
            vec![("s", const_char_ptr())],
            false,
        ),
        sig(
            "strcmp",
            i32t.clone(),
            vec![("s1", const_char_ptr()), ("s2", const_char_ptr())],
            false,
        ),
        sig(
            "strncmp",
            i32t.clone(),
            vec![
                ("s1", const_char_ptr()),
                ("s2", const_char_ptr()),
                ("n", sizet.clone()),
            ],
            false,
        ),
        sig(
            "strcpy",
            char_ptr(),
            vec![("dest", char_ptr()), ("src", const_char_ptr())],
            false,
        ),
        sig(
            "strncpy",
            char_ptr(),
            vec![
                ("dest", char_ptr()),
                ("src", const_char_ptr()),
                ("n", sizet.clone()),
            ],
            false,
        ),
        sig(
            "strcat",
            char_ptr(),
            vec![("dest", char_ptr()), ("src", const_char_ptr())],
            false,
        ),
        sig(
            "strncat",
            char_ptr(),
            vec![
                ("dest", char_ptr()),
                ("src", const_char_ptr()),
                ("n", sizet.clone()),
            ],
            false,
        ),
        sig(
            "strchr",
            char_ptr(),
            vec![("s", const_char_ptr()), ("c", i32t.clone())],
            false,
        ),
        sig(
            "strrchr",
            char_ptr(),
            vec![("s", const_char_ptr()), ("c", i32t.clone())],
            false,
        ),
        sig(
            "strstr",
            char_ptr(),
            vec![("haystack", const_char_ptr()), ("needle", const_char_ptr())],
            false,
        ),
        sig("strdup", char_ptr(), vec![("s", const_char_ptr())], false),
        sig(
            "strtok",
            char_ptr(),
            vec![("str", char_ptr()), ("delim", const_char_ptr())],
            false,
        ),
        sig(
            "strerror",
            char_ptr(),
            vec![("errnum", i32t.clone())],
            false,
        ),
        // memory
        sig(
            "memcpy",
            void_ptr(),
            vec![
                ("dest", void_ptr()),
                ("src", const_void_ptr()),
                ("n", sizet.clone()),
            ],
            false,
        ),
        sig(
            "memmove",
            void_ptr(),
            vec![
                ("dest", void_ptr()),
                ("src", const_void_ptr()),
                ("n", sizet.clone()),
            ],
            false,
        ),
        sig(
            "memset",
            void_ptr(),
            vec![("s", void_ptr()), ("c", i32t.clone()), ("n", sizet.clone())],
            false,
        ),
        sig(
            "memcmp",
            i32t.clone(),
            vec![
                ("s1", const_void_ptr()),
                ("s2", const_void_ptr()),
                ("n", sizet.clone()),
            ],
            false,
        ),
        sig(
            "memchr",
            void_ptr(),
            vec![
                ("s", const_void_ptr()),
                ("c", i32t.clone()),
                ("n", sizet.clone()),
            ],
            false,
        ),
        // POSIX
        sig(
            "open",
            i32t.clone(),
            vec![("pathname", const_char_ptr()), ("flags", i32t.clone())],
            true,
        ),
        sig("close", i32t.clone(), vec![("fd", i32t.clone())], false),
        sig(
            "read",
            TypeRef::Primitive(PrimitiveType::ISize),
            vec![
                ("fd", i32t.clone()),
                ("buf", void_ptr()),
                ("count", sizet.clone()),
            ],
            false,
        ),
        sig(
            "write",
            TypeRef::Primitive(PrimitiveType::ISize),
            vec![
                ("fd", i32t.clone()),
                ("buf", const_void_ptr()),
                ("count", sizet.clone()),
            ],
            false,
        ),
        sig(
            "mmap",
            void_ptr(),
            vec![
                ("addr", void_ptr()),
                ("length", sizet.clone()),
                ("prot", i32t.clone()),
                ("flags", i32t.clone()),
                ("fd", i32t.clone()),
                ("offset", TypeRef::Primitive(PrimitiveType::I64)),
            ],
            false,
        ),
        sig(
            "munmap",
            i32t.clone(),
            vec![("addr", void_ptr()), ("length", sizet.clone())],
            false,
        ),
    ];

    for (name, s) in entries {
        sigs.insert(name, s);
    }

    TypeLibrary {
        name: "libc".to_string(),
        platform: "unix".to_string(),
        types: BTreeMap::new(),
        function_signatures: sigs,
    }
}

/// Built-in Win32 API type library with common Windows API functions.
pub fn win32_library() -> TypeLibrary {
    let i32t = TypeRef::Primitive(PrimitiveType::I32);
    let u32t = TypeRef::Primitive(PrimitiveType::U32);
    let u64t = TypeRef::Primitive(PrimitiveType::U64);
    let sizet = TypeRef::Primitive(PrimitiveType::USize);
    let void = TypeRef::Primitive(PrimitiveType::Void);
    let bool_t = TypeRef::Primitive(PrimitiveType::I32); // BOOL = int
    let handle = TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::Void))); // HANDLE = void*
    let wchar_ptr = TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::WChar)));
    let const_wchar_ptr = TypeRef::Pointer(Box::new(TypeRef::Const(Box::new(TypeRef::Primitive(
        PrimitiveType::WChar,
    )))));
    let const_char_ptr_val = const_char_ptr();
    let byte_ptr = TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::U8)));

    let mut sigs = BTreeMap::new();

    let entries = vec![
        // File operations
        sig(
            "CreateFileA",
            handle.clone(),
            vec![
                ("lpFileName", const_char_ptr_val.clone()),
                ("dwDesiredAccess", u32t.clone()),
                ("dwShareMode", u32t.clone()),
                ("lpSecurityAttributes", void_ptr()),
                ("dwCreationDisposition", u32t.clone()),
                ("dwFlagsAndAttributes", u32t.clone()),
                ("hTemplateFile", handle.clone()),
            ],
            false,
        ),
        sig(
            "CreateFileW",
            handle.clone(),
            vec![
                ("lpFileName", const_wchar_ptr.clone()),
                ("dwDesiredAccess", u32t.clone()),
                ("dwShareMode", u32t.clone()),
                ("lpSecurityAttributes", void_ptr()),
                ("dwCreationDisposition", u32t.clone()),
                ("dwFlagsAndAttributes", u32t.clone()),
                ("hTemplateFile", handle.clone()),
            ],
            false,
        ),
        sig(
            "ReadFile",
            bool_t.clone(),
            vec![
                ("hFile", handle.clone()),
                ("lpBuffer", void_ptr()),
                ("nNumberOfBytesToRead", u32t.clone()),
                (
                    "lpNumberOfBytesRead",
                    TypeRef::Pointer(Box::new(u32t.clone())),
                ),
                ("lpOverlapped", void_ptr()),
            ],
            false,
        ),
        sig(
            "WriteFile",
            bool_t.clone(),
            vec![
                ("hFile", handle.clone()),
                ("lpBuffer", const_void_ptr()),
                ("nNumberOfBytesToWrite", u32t.clone()),
                (
                    "lpNumberOfBytesWritten",
                    TypeRef::Pointer(Box::new(u32t.clone())),
                ),
                ("lpOverlapped", void_ptr()),
            ],
            false,
        ),
        sig(
            "CloseHandle",
            bool_t.clone(),
            vec![("hObject", handle.clone())],
            false,
        ),
        sig(
            "DeleteFileA",
            bool_t.clone(),
            vec![("lpFileName", const_char_ptr_val.clone())],
            false,
        ),
        sig(
            "DeleteFileW",
            bool_t.clone(),
            vec![("lpFileName", const_wchar_ptr.clone())],
            false,
        ),
        // Memory
        sig(
            "VirtualAlloc",
            void_ptr(),
            vec![
                ("lpAddress", void_ptr()),
                ("dwSize", sizet.clone()),
                ("flAllocationType", u32t.clone()),
                ("flProtect", u32t.clone()),
            ],
            false,
        ),
        sig(
            "VirtualFree",
            bool_t.clone(),
            vec![
                ("lpAddress", void_ptr()),
                ("dwSize", sizet.clone()),
                ("dwFreeType", u32t.clone()),
            ],
            false,
        ),
        sig(
            "VirtualProtect",
            bool_t.clone(),
            vec![
                ("lpAddress", void_ptr()),
                ("dwSize", sizet.clone()),
                ("flNewProtect", u32t.clone()),
                ("lpflOldProtect", TypeRef::Pointer(Box::new(u32t.clone()))),
            ],
            false,
        ),
        sig(
            "HeapAlloc",
            void_ptr(),
            vec![
                ("hHeap", handle.clone()),
                ("dwFlags", u32t.clone()),
                ("dwBytes", sizet.clone()),
            ],
            false,
        ),
        sig(
            "HeapFree",
            bool_t.clone(),
            vec![
                ("hHeap", handle.clone()),
                ("dwFlags", u32t.clone()),
                ("lpMem", void_ptr()),
            ],
            false,
        ),
        sig("GetProcessHeap", handle.clone(), vec![], false),
        // DLL / Module
        sig(
            "LoadLibraryA",
            handle.clone(),
            vec![("lpLibFileName", const_char_ptr_val.clone())],
            false,
        ),
        sig(
            "LoadLibraryW",
            handle.clone(),
            vec![("lpLibFileName", const_wchar_ptr.clone())],
            false,
        ),
        sig(
            "LoadLibraryExA",
            handle.clone(),
            vec![
                ("lpLibFileName", const_char_ptr_val.clone()),
                ("hFile", handle.clone()),
                ("dwFlags", u32t.clone()),
            ],
            false,
        ),
        sig(
            "FreeLibrary",
            bool_t.clone(),
            vec![("hLibModule", handle.clone())],
            false,
        ),
        sig(
            "GetProcAddress",
            void_ptr(),
            vec![
                ("hModule", handle.clone()),
                ("lpProcName", const_char_ptr_val.clone()),
            ],
            false,
        ),
        sig(
            "GetModuleHandleA",
            handle.clone(),
            vec![("lpModuleName", const_char_ptr_val.clone())],
            false,
        ),
        sig(
            "GetModuleHandleW",
            handle.clone(),
            vec![("lpModuleName", const_wchar_ptr.clone())],
            false,
        ),
        // Process / Thread
        sig("GetCurrentProcess", handle.clone(), vec![], false),
        sig("GetCurrentThread", handle.clone(), vec![], false),
        sig("GetCurrentProcessId", u32t.clone(), vec![], false),
        sig("GetCurrentThreadId", u32t.clone(), vec![], false),
        sig(
            "ExitProcess",
            void.clone(),
            vec![("uExitCode", u32t.clone())],
            false,
        ),
        sig(
            "TerminateProcess",
            bool_t.clone(),
            vec![("hProcess", handle.clone()), ("uExitCode", u32t.clone())],
            false,
        ),
        sig(
            "CreateThread",
            handle.clone(),
            vec![
                ("lpThreadAttributes", void_ptr()),
                ("dwStackSize", sizet.clone()),
                ("lpStartAddress", void_ptr()),
                ("lpParameter", void_ptr()),
                ("dwCreationFlags", u32t.clone()),
                ("lpThreadId", TypeRef::Pointer(Box::new(u32t.clone()))),
            ],
            false,
        ),
        sig(
            "WaitForSingleObject",
            u32t.clone(),
            vec![
                ("hHandle", handle.clone()),
                ("dwMilliseconds", u32t.clone()),
            ],
            false,
        ),
        sig(
            "Sleep",
            void.clone(),
            vec![("dwMilliseconds", u32t.clone())],
            false,
        ),
        // Error handling
        sig("GetLastError", u32t.clone(), vec![], false),
        sig(
            "SetLastError",
            void.clone(),
            vec![("dwErrCode", u32t.clone())],
            false,
        ),
        // String
        sig(
            "lstrlenA",
            i32t.clone(),
            vec![("lpString", const_char_ptr_val.clone())],
            false,
        ),
        sig(
            "lstrlenW",
            i32t.clone(),
            vec![("lpString", const_wchar_ptr.clone())],
            false,
        ),
        sig(
            "lstrcpyA",
            char_ptr(),
            vec![
                ("lpString1", char_ptr()),
                ("lpString2", const_char_ptr_val.clone()),
            ],
            false,
        ),
        sig(
            "lstrcpyW",
            wchar_ptr.clone(),
            vec![
                ("lpString1", wchar_ptr.clone()),
                ("lpString2", const_wchar_ptr.clone()),
            ],
            false,
        ),
        sig(
            "MultiByteToWideChar",
            i32t.clone(),
            vec![
                ("CodePage", u32t.clone()),
                ("dwFlags", u32t.clone()),
                ("lpMultiByteStr", const_char_ptr_val.clone()),
                ("cbMultiByte", i32t.clone()),
            ],
            false,
        ),
        // Registry
        sig(
            "RegOpenKeyExA",
            i32t.clone(),
            vec![
                ("hKey", handle.clone()),
                ("lpSubKey", const_char_ptr_val.clone()),
                ("ulOptions", u32t.clone()),
                ("samDesired", u32t.clone()),
                ("phkResult", TypeRef::Pointer(Box::new(handle.clone()))),
            ],
            false,
        ),
        sig(
            "RegCloseKey",
            i32t.clone(),
            vec![("hKey", handle.clone())],
            false,
        ),
        sig(
            "RegQueryValueExA",
            i32t.clone(),
            vec![
                ("hKey", handle.clone()),
                ("lpValueName", const_char_ptr_val.clone()),
                ("lpReserved", TypeRef::Pointer(Box::new(u32t.clone()))),
                ("lpType", TypeRef::Pointer(Box::new(u32t.clone()))),
                ("lpData", byte_ptr.clone()),
                ("lpcbData", TypeRef::Pointer(Box::new(u32t.clone()))),
            ],
            false,
        ),
        // Misc
        sig("GetTickCount", u32t.clone(), vec![], false),
        sig("GetTickCount64", u64t.clone(), vec![], false),
        sig(
            "QueryPerformanceCounter",
            bool_t.clone(),
            vec![(
                "lpPerformanceCount",
                TypeRef::Pointer(Box::new(TypeRef::Primitive(PrimitiveType::I64))),
            )],
            false,
        ),
        sig(
            "OutputDebugStringA",
            void.clone(),
            vec![("lpOutputString", const_char_ptr_val.clone())],
            false,
        ),
        sig(
            "OutputDebugStringW",
            void,
            vec![("lpOutputString", const_wchar_ptr.clone())],
            false,
        ),
        sig("IsDebuggerPresent", bool_t.clone(), vec![], false),
        sig(
            "MessageBoxA",
            i32t.clone(),
            vec![
                ("hWnd", handle.clone()),
                ("lpText", const_char_ptr_val.clone()),
                ("lpCaption", const_char_ptr_val.clone()),
                ("uType", u32t.clone()),
            ],
            false,
        ),
        sig(
            "MessageBoxW",
            i32t.clone(),
            vec![
                ("hWnd", handle.clone()),
                ("lpText", const_wchar_ptr.clone()),
                ("lpCaption", const_wchar_ptr),
                ("uType", u32t.clone()),
            ],
            false,
        ),
    ];

    for (name, s) in entries {
        sigs.insert(name, s);
    }

    let mut types = BTreeMap::new();

    types.insert(
        "POINT".to_string(),
        CompoundType::Struct {
            name: "POINT".to_string(),
            fields: vec![
                StructField { name: "x".to_string(), type_ref: i32t.clone(), offset: 0, bit_offset: None, bit_size: None },
                StructField { name: "y".to_string(), type_ref: i32t.clone(), offset: 4, bit_offset: None, bit_size: None },
            ],
            size: 8,
        },
    );

    types.insert(
        "RECT".to_string(),
        CompoundType::Struct {
            name: "RECT".to_string(),
            fields: vec![
                StructField { name: "left".to_string(), type_ref: i32t.clone(), offset: 0, bit_offset: None, bit_size: None },
                StructField { name: "top".to_string(), type_ref: i32t.clone(), offset: 4, bit_offset: None, bit_size: None },
                StructField { name: "right".to_string(), type_ref: i32t.clone(), offset: 8, bit_offset: None, bit_size: None },
                StructField { name: "bottom".to_string(), type_ref: i32t.clone(), offset: 12, bit_offset: None, bit_size: None },
            ],
            size: 16,
        },
    );

    types.insert(
        "MSG".to_string(),
        CompoundType::Struct {
            name: "MSG".to_string(),
            fields: vec![
                StructField { name: "hwnd".to_string(), type_ref: handle.clone(), offset: 0, bit_offset: None, bit_size: None },
                StructField { name: "message".to_string(), type_ref: u32t.clone(), offset: 4, bit_offset: None, bit_size: None },
                StructField { name: "wParam".to_string(), type_ref: sizet.clone(), offset: 8, bit_offset: None, bit_size: None },
                StructField { name: "lParam".to_string(), type_ref: sizet.clone(), offset: 12, bit_offset: None, bit_size: None },
                StructField { name: "time".to_string(), type_ref: u32t.clone(), offset: 16, bit_offset: None, bit_size: None },
                StructField { name: "pt".to_string(), type_ref: TypeRef::Named("POINT".to_string()), offset: 20, bit_offset: None, bit_size: None },
            ],
            size: 28,
        },
    );

    types.insert(
        "IDirectDrawSurface7Vtbl".to_string(),
        CompoundType::Struct {
            name: "IDirectDrawSurface7Vtbl".to_string(),
            fields: vec![
                StructField {
                    name: "QueryInterface".to_string(),
                    type_ref: TypeRef::FunctionPointer {
                        return_type: Box::new(i32t.clone()),
                        params: vec![
                            TypeRef::Pointer(Box::new(TypeRef::Named("IDirectDrawSurface7".to_string()))),
                            void_ptr(),
                            TypeRef::Pointer(Box::new(void_ptr())),
                        ],
                        is_variadic: false,
                    },
                    offset: 0,
                    bit_offset: None,
                    bit_size: None,
                },
                StructField {
                    name: "AddRef".to_string(),
                    type_ref: TypeRef::FunctionPointer {
                        return_type: Box::new(u32t.clone()),
                        params: vec![TypeRef::Pointer(Box::new(TypeRef::Named("IDirectDrawSurface7".to_string())))],
                        is_variadic: false,
                    },
                    offset: 4,
                    bit_offset: None,
                    bit_size: None,
                },
                StructField {
                    name: "Release".to_string(),
                    type_ref: TypeRef::FunctionPointer {
                        return_type: Box::new(u32t.clone()),
                        params: vec![TypeRef::Pointer(Box::new(TypeRef::Named("IDirectDrawSurface7".to_string())))],
                        is_variadic: false,
                    },
                    offset: 8,
                    bit_offset: None,
                    bit_size: None,
                },
            ],
            size: 12,
        },
    );

    types.insert(
        "IDirectDrawSurface7".to_string(),
        CompoundType::Struct {
            name: "IDirectDrawSurface7".to_string(),
            fields: vec![
                StructField {
                    name: "lpVtbl".to_string(),
                    type_ref: TypeRef::Pointer(Box::new(TypeRef::Named("IDirectDrawSurface7Vtbl".to_string()))),
                    offset: 0,
                    bit_offset: None,
                    bit_size: None,
                }
            ],
            size: 4,
        },
    );

    TypeLibrary {
        name: "win32".to_string(),
        platform: "windows".to_string(),
        types,
        function_signatures: sigs,
    }
}
