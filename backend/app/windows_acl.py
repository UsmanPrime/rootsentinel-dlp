"""Read-only Windows DACL validation; never changes system/user ACLs."""
import ctypes
from ctypes import wintypes

from .errors import DomainError


def require_private_acl(path):
    """Allow access only to current user, SYSTEM and local administrators.

    Parent replacement by those trusted principals is outside the threat model.
    Reject unknown ACE formats rather than interpreting them permissively.
    """
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetAce.argtypes = [pointer, wintypes.DWORD, ctypes.POINTER(pointer)]
    advapi.GetAce.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(pointer)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer

    def sid_string(sid):
        string = pointer()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(string)):
            raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
        try:
            return ctypes.wstring_at(string)
        finally:
            kernel.LocalFree(string)

    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
        user_sid = sid_string(pointer.from_buffer(buffer).value)
    finally:
        kernel.CloseHandle(token)
    dacl, descriptor, owner = pointer(), pointer(), pointer()
    if advapi.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)):
        raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
    try:
        if not dacl.value:
            raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
        if not owner.value or sid_string(owner.value) not in {user_sid, "S-1-5-18", "S-1-5-32-544"}:
            raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
        # ACL header: revision(1), padding(1), size(2), ACE count(2), padding(2).
        count = ctypes.c_ushort.from_address(dacl.value + 4).value
        for index in range(count):
            ace = pointer()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
            kind = ctypes.c_ubyte.from_address(ace.value).value
            if kind == 1:  # deny ACE grants nothing
                continue
            if kind != 0:
                raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
            sid = sid_string(ace.value + 8)
            if sid not in {user_sid, "S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-4"}:
                raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
    finally:
        kernel.LocalFree(descriptor)
