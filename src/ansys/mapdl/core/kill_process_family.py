import subprocess
import psutil
import sys
import os
import time
import ctypes
import ctypes.util
import warnings

def setup_restrictions():
    libseccomp = ctypes.CDLL(ctypes.util.find_library('seccomp'), use_errno=True)
    if not libseccomp:
        warnings.warn("libseccomp not found: Failed to protect watchdog.")
        return
        
    scmp_filter_ctx = ctypes.POINTER(None)

    SCMP_ACT_ALLOW = 0x7fff0000
    SCMP_ACT_ERRNO = lambda x : (0x00050000 | ((x) & 0x0000ffff))
    EPERM = 1
    SCMP_CMP_EQ = 4

    arch = os.uname()[4]
    if(arch == 'x86_64'):
        NR_kill = 62
        NR_tkill = 200
        NR_tgkill = 234
    else:
        warnings.warn("unsupported architecture: Failed to protect watchdog.")
        return

    libseccomp.seccomp_init.restype = scmp_filter_ctx
    libseccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    ctx = libseccomp.seccomp_init(SCMP_ACT_ALLOW)

    class struct_scmp_arg_cmp(ctypes.Structure):
        _pack_ = 1 # source:False
        _fields_ = [
            ('arg', ctypes.c_uint32),
            ('op', ctypes.c_uint32),
            ('datum_a', ctypes.c_uint64),
            ('datum_b', ctypes.c_uint64),
        ]

    libseccomp.seccomp_rule_add.restype = ctypes.c_int32
    libseccomp.seccomp_rule_add.argtypes = [scmp_filter_ctx, ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32, struct_scmp_arg_cmp]
    rule = struct_scmp_arg_cmp(0, SCMP_CMP_EQ, os.getpid(), 0)
    libseccomp.seccomp_rule_add(ctx, SCMP_ACT_ERRNO(1), NR_kill, 1, rule)
    libseccomp.seccomp_rule_add.argtypes = [scmp_filter_ctx, ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32]
    libseccomp.seccomp_rule_add(ctx, SCMP_ACT_ERRNO(1), NR_tkill, 0)
    libseccomp.seccomp_rule_add(ctx, SCMP_ACT_ERRNO(1), NR_tgkill, 0)
    
    libseccomp.seccomp_load.restype = ctypes.c_int32
    libseccomp.seccomp_load.argtypes = [scmp_filter_ctx]
    libseccomp.seccomp_load(ctx)

term = open("/dev/tty","w")
sys.stdout = term
sys.stderr = term

# this may produce a warning, so we move to after the stdout/stderr reassignment
setup_restrictions()

sys.argv.pop(0)
r = subprocess.Popen(sys.argv)
while r.poll() is None:
    if os.getppid() == 1:
        for proc in psutil.Process().children(recursive = True):
            proc.kill()
    time.sleep(0.1)
