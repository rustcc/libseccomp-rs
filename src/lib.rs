/// Replacing the SCMP_SYS() macro in C by using an enum
/// # Examples
/// ```
/// let sccp = Seccomp::init(SCMP_ACT::ALLOW);
///         let cmptr = SCMP_ARG_CMP{
///             arg:0,
///             op: SCMP_COMPARE::EQ,
///             oprand1:1000,
///             oprand2:10,
///         };
///         assert!(sccp.add_rule(SCMP_ACT::KILL, SCMP_SYS::setuid as i32, 1, cmptr) == Ok(0));
/// ```
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum SCMP_SYS {
    read = 0,
    write = 1,
    open = 2,
    close = 3,
    stat = 4,
    fstat = 5,
    lstat = 6,
    poll = 7,
    lseek = 8,
    mmap = 9,
    mprotect = 10,
    munmap = 11,
    brk = 12,
    rt_sigaction = 13,
    rt_sigprocmask = 14,
    rt_sigreturn = 15,
    ioctl = 16,
    pread64 = 17,
    pwrite64 = 18,
    readv = 19,
    writev = 20,
    access = 21,
    pipe = 22,
    select = 23,
    sched_yield = 24,
    mremap = 25,
    msync = 26,
    mincore = 27,
    madvise = 28,
    shmget = 29,
    shmat = 30,
    shmctl = 31,
    dup = 32,
    dup2 = 33,
    pause = 34,
    nanosleep = 35,
    getitimer = 36,
    alarm = 37,
    setitimer = 38,
    getpid = 39,
    sendfile = 40,
    socket = 41,
    connect = 42,
    accept = 43,
    sendto = 44,
    recvfrom = 45,
    sendmsg = 46,
    recvmsg = 47,
    shutdown = 48,
    bind = 49,
    listen = 50,
    getsockname = 51,
    getpeername = 52,
    socketpair = 53,
    setsockopt = 54,
    getsockopt = 55,
    clone = 56,
    fork = 57,
    vfork = 58,
    execve = 59,
    exit = 60,
    wait4 = 61,
    kill = 62,
    uname = 63,
    semget = 64,
    semop = 65,
    semctl = 66,
    shmdt = 67,
    msgget = 68,
    msgsnd = 69,
    msgrcv = 70,
    msgctl = 71,
    fcntl = 72,
    flock = 73,
    fsync = 74,
    fdatasync = 75,
    truncate = 76,
    ftruncate = 77,
    getdents = 78,
    getcwd = 79,
    chdir = 80,
    fchdir = 81,
    rename = 82,
    mkdir = 83,
    rmdir = 84,
    creat = 85,
    link = 86,
    unlink = 87,
    symlink = 88,
    readlink = 89,
    chmod = 90,
    fchmod = 91,
    chown = 92,
    fchown = 93,
    lchown = 94,
    umask = 95,
    gettimeofday = 96,
    getrlimit = 97,
    getrusage = 98,
    sysinfo = 99,
    times = 100,
    ptrace = 101,
    getuid = 102,
    syslog = 103,
    getgid = 104,
    setuid = 105,
    setgid = 106,
    geteuid = 107,
    getegid = 108,
    setpgid = 109,
    getppid = 110,
    getpgrp = 111,
    setsid = 112,
    setreuid = 113,
    setregid = 114,
    getgroups = 115,
    setgroups = 116,
    setresuid = 117,
    getresuid = 118,
    setresgid = 119,
    getresgid = 120,
    getpgid = 121,
    setfsuid = 122,
    setfsgid = 123,
    getsid = 124,
    capget = 125,
    capset = 126,
    rt_sigpending = 127,
    rt_sigtimedwait = 128,
    rt_sigqueueinfo = 129,
    rt_sigsuspend = 130,
    sigaltstack = 131,
    utime = 132,
    mknod = 133,
    uselib = 134,
    personality = 135,
    ustat = 136,
    statfs = 137,
    fstatfs = 138,
    sysfs = 139,
    getpriority = 140,
    setpriority = 141,
    sched_setparam = 142,
    sched_getparam = 143,
    sched_setscheduler = 144,
    sched_getscheduler = 145,
    sched_get_priority_max = 146,
    sched_get_priority_min = 147,
    sched_rr_get_interval = 148,
    mlock = 149,
    munlock = 150,
    mlockall = 151,
    munlockall = 152,
    vhangup = 153,
    modify_ldt = 154,
    pivot_root = 155,
    _sysctl = 156,
    prctl = 157,
    arch_prctl = 158,
    adjtimex = 159,
    setrlimit = 160,
    chroot = 161,
    sync = 162,
    acct = 163,
    settimeofday = 164,
    mount = 165,
    umount2 = 166,
    swapon = 167,
    swapoff = 168,
    reboot = 169,
    sethostname = 170,
    setdomainname = 171,
    iopl = 172,
    ioperm = 173,
    create_module = 174,
    init_module = 175,
    delete_module = 176,
    get_kernel_syms = 177,
    query_module = 178,
    quotactl = 179,
    nfsservctl = 180,
    getpmsg = 181,
    putpmsg = 182,
    afs_syscall = 183,
    tuxcall = 184,
    security = 185,
    gettid = 186,
    readahead = 187,
    setxattr = 188,
    lsetxattr = 189,
    fsetxattr = 190,
    getxattr = 191,
    lgetxattr = 192,
    fgetxattr = 193,
    listxattr = 194,
    llistxattr = 195,
    flistxattr = 196,
    removexattr = 197,
    lremovexattr = 198,
    fremovexattr = 199,
    tkill = 200,
    time = 201,
    futex = 202,
    sched_setaffinity = 203,
    sched_getaffinity = 204,
    set_thread_area = 205,
    io_setup = 206,
    io_destroy = 207,
    io_getevents = 208,
    io_submit = 209,
    io_cancel = 210,
    get_thread_area = 211,
    lookup_dcookie = 212,
    epoll_create = 213,
    epoll_ctl_old = 214,
    epoll_wait_old = 215,
    remap_file_pages = 216,
    getdents64 = 217,
    set_tid_address = 218,
    restart_syscall = 219,
    semtimedop = 220,
    fadvise64 = 221,
    timer_create = 222,
    timer_settime = 223,
    timer_gettime = 224,
    timer_getoverrun = 225,
    timer_delete = 226,
    clock_settime = 227,
    clock_gettime = 228,
    clock_getres = 229,
    clock_nanosleep = 230,
    exit_group = 231,
    epoll_wait = 232,
    epoll_ctl = 233,
    tgkill = 234,
    utimes = 235,
    vserver = 236,
    mbind = 237,
    set_mempolicy = 238,
    get_mempolicy = 239,
    mq_open = 240,
    mq_unlink = 241,
    mq_timedsend = 242,
    mq_timedreceive = 243,
    mq_notify = 244,
    mq_getsetattr = 245,
    kexec_load = 246,
    waitid = 247,
    add_key = 248,
    request_key = 249,
    keyctl = 250,
    ioprio_set = 251,
    ioprio_get = 252,
    inotify_init = 253,
    inotify_add_watch = 254,
    inotify_rm_watch = 255,
    migrate_pages = 256,
    openat = 257,
    mkdirat = 258,
    mknodat = 259,
    fchownat = 260,
    futimesat = 261,
    newfstatat = 262,
    unlinkat = 263,
    renameat = 264,
    linkat = 265,
    symlinkat = 266,
    readlinkat = 267,
    fchmodat = 268,
    faccessat = 269,
    pselect6 = 270,
    ppoll = 271,
    unshare = 272,
    set_robust_list = 273,
    get_robust_list = 274,
    splice = 275,
    tee = 276,
    sync_file_range = 277,
    vmsplice = 278,
    move_pages = 279,
    utimensat = 280,
    epoll_pwait = 281,
    signalfd = 282,
    timerfd_create = 283,
    eventfd = 284,
    fallocate = 285,
    timerfd_settime = 286,
    timerfd_gettime = 287,
    accept4 = 288,
    signalfd4 = 289,
    eventfd2 = 290,
    epoll_create1 = 291,
    dup3 = 292,
    pipe2 = 293,
    inotify_init1 = 294,
    preadv = 295,
    pwritev = 296,
    rt_tgsigqueueinfo = 297,
    perf_event_open = 298,
    recvmmsg = 299,
    fanotify_init = 300,
    fanotify_mark = 301,
    prlimit64 = 302,
    name_to_handle_at = 303,
    open_by_handle_at = 304,
    clock_adjtime = 305,
    syncfs = 306,
    sendmmsg = 307,
    setns = 308,
    getcpu = 309,
    process_vm_readv = 310,
    process_vm_writev = 311,
    kcmp = 312,
    finit_module = 313,
    sched_setattr = 314,
    sched_getattr = 315,
    renameat2 = 316,
    seccomp = 317,
    getrandom = 318,
    memfd_create = 319,
    kexec_file_load = 320,
    bpf = 321,
    execveat = 322,
    userfaultfd = 323,
    membarrier = 324,
    mlock2 = 325,
    copy_file_range = 326,
    preadv2 = 327,
    pwritev2 = 328,
}

// break is keyword so i used _break
#[cfg(all(target_os = "linux", target_arch = "x86"))]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum SCMP_SYS {
    restart_syscall = 0,
    exit = 1,
    fork = 2,
    read = 3,
    write = 4,
    open = 5,
    close = 6,
    waitpid = 7,
    creat = 8,
    link = 9,
    unlink = 10,
    execve = 11,
    chdir = 12,
    time = 13,
    mknod = 14,
    chmod = 15,
    lchown = 16,
    _break = 17,
    oldstat = 18,
    lseek = 19,
    getpid = 20,
    mount = 21,
    umount = 22,
    setuid = 23,
    getuid = 24,
    stime = 25,
    ptrace = 26,
    alarm = 27,
    oldfstat = 28,
    pause = 29,
    utime = 30,
    stty = 31,
    gtty = 32,
    access = 33,
    nice = 34,
    ftime = 35,
    sync = 36,
    kill = 37,
    rename = 38,
    mkdir = 39,
    rmdir = 40,
    dup = 41,
    pipe = 42,
    times = 43,
    prof = 44,
    brk = 45,
    setgid = 46,
    getgid = 47,
    signal = 48,
    geteuid = 49,
    getegid = 50,
    acct = 51,
    umount2 = 52,
    lock = 53,
    ioctl = 54,
    fcntl = 55,
    mpx = 56,
    setpgid = 57,
    ulimit = 58,
    oldolduname = 59,
    umask = 60,
    chroot = 61,
    ustat = 62,
    dup2 = 63,
    getppid = 64,
    getpgrp = 65,
    setsid = 66,
    sigaction = 67,
    sgetmask = 68,
    ssetmask = 69,
    setreuid = 70,
    setregid = 71,
    sigsuspend = 72,
    sigpending = 73,
    sethostname = 74,
    setrlimit = 75,
    getrlimit = 76,
    getrusage = 77,
    gettimeofday = 78,
    settimeofday = 79,
    getgroups = 80,
    setgroups = 81,
    select = 82,
    symlink = 83,
    oldlstat = 84,
    readlink = 85,
    uselib = 86,
    swapon = 87,
    reboot = 88,
    readdir = 89,
    mmap = 90,
    munmap = 91,
    truncate = 92,
    ftruncate = 93,
    fchmod = 94,
    fchown = 95,
    getpriority = 96,
    setpriority = 97,
    profil = 98,
    statfs = 99,
    fstatfs = 100,
    ioperm = 101,
    socketcall = 102,
    syslog = 103,
    setitimer = 104,
    getitimer = 105,
    stat = 106,
    lstat = 107,
    fstat = 108,
    olduname = 109,
    iopl = 110,
    vhangup = 111,
    idle = 112,
    vm86old = 113,
    wait4 = 114,
    swapoff = 115,
    sysinfo = 116,
    ipc = 117,
    fsync = 118,
    sigreturn = 119,
    clone = 120,
    setdomainname = 121,
    uname = 122,
    modify_ldt = 123,
    adjtimex = 124,
    mprotect = 125,
    sigprocmask = 126,
    create_module = 127,
    init_module = 128,
    delete_module = 129,
    get_kernel_syms = 130,
    quotactl = 131,
    getpgid = 132,
    fchdir = 133,
    bdflush = 134,
    sysfs = 135,
    personality = 136,
    afs_syscall = 137,
    setfsuid = 138,
    setfsgid = 139,
    _llseek = 140,
    getdents = 141,
    _newselect = 142,
    flock = 143,
    msync = 144,
    readv = 145,
    writev = 146,
    getsid = 147,
    fdatasync = 148,
    _sysctl = 149,
    mlock = 150,
    munlock = 151,
    mlockall = 152,
    munlockall = 153,
    sched_setparam = 154,
    sched_getparam = 155,
    sched_setscheduler = 156,
    sched_getscheduler = 157,
    sched_yield = 158,
    sched_get_priority_max = 159,
    sched_get_priority_min = 160,
    sched_rr_get_interval = 161,
    nanosleep = 162,
    mremap = 163,
    setresuid = 164,
    getresuid = 165,
    vm86 = 166,
    query_module = 167,
    poll = 168,
    nfsservctl = 169,
    setresgid = 170,
    getresgid = 171,
    prctl = 172,
    rt_sigreturn = 173,
    rt_sigaction = 174,
    rt_sigprocmask = 175,
    rt_sigpending = 176,
    rt_sigtimedwait = 177,
    rt_sigqueueinfo = 178,
    rt_sigsuspend = 179,
    pread64 = 180,
    pwrite64 = 181,
    chown = 182,
    getcwd = 183,
    capget = 184,
    capset = 185,
    sigaltstack = 186,
    sendfile = 187,
    getpmsg = 188,
    putpmsg = 189,
    vfork = 190,
    ugetrlimit = 191,
    mmap2 = 192,
    truncate64 = 193,
    ftruncate64 = 194,
    stat64 = 195,
    lstat64 = 196,
    fstat64 = 197,
    lchown32 = 198,
    getuid32 = 199,
    getgid32 = 200,
    geteuid32 = 201,
    getegid32 = 202,
    setreuid32 = 203,
    setregid32 = 204,
    getgroups32 = 205,
    setgroups32 = 206,
    fchown32 = 207,
    setresuid32 = 208,
    getresuid32 = 209,
    setresgid32 = 210,
    getresgid32 = 211,
    chown32 = 212,
    setuid32 = 213,
    setgid32 = 214,
    setfsuid32 = 215,
    setfsgid32 = 216,
    pivot_root = 217,
    mincore = 218,
    madvise = 219,
    getdents64 = 220,
    fcntl64 = 221,
    gettid = 224,
    readahead = 225,
    setxattr = 226,
    lsetxattr = 227,
    fsetxattr = 228,
    getxattr = 229,
    lgetxattr = 230,
    fgetxattr = 231,
    listxattr = 232,
    llistxattr = 233,
    flistxattr = 234,
    removexattr = 235,
    lremovexattr = 236,
    fremovexattr = 237,
    tkill = 238,
    sendfile64 = 239,
    futex = 240,
    sched_setaffinity = 241,
    sched_getaffinity = 242,
    set_thread_area = 243,
    get_thread_area = 244,
    io_setup = 245,
    io_destroy = 246,
    io_getevents = 247,
    io_submit = 248,
    io_cancel = 249,
    fadvise64 = 250,
    exit_group = 252,
    lookup_dcookie = 253,
    epoll_create = 254,
    epoll_ctl = 255,
    epoll_wait = 256,
    remap_file_pages = 257,
    set_tid_address = 258,
    timer_create = 259,
    timer_settime = 260,
    timer_gettime = 261,
    timer_getoverrun = 262,
    timer_delete = 263,
    clock_settime = 264,
    clock_gettime = 265,
    clock_getres = 266,
    clock_nanosleep = 267,
    statfs64 = 268,
    fstatfs64 = 269,
    tgkill = 270,
    utimes = 271,
    fadvise64_64 = 272,
    vserver = 273,
    mbind = 274,
    get_mempolicy = 275,
    set_mempolicy = 276,
    mq_open = 277,
    mq_unlink = 278,
    mq_timedsend = 279,
    mq_timedreceive = 280,
    mq_notify = 281,
    mq_getsetattr = 282,
    kexec_load = 283,
    waitid = 284,
    add_key = 286,
    request_key = 287,
    keyctl = 288,
    ioprio_set = 289,
    ioprio_get = 290,
    inotify_init = 291,
    inotify_add_watch = 292,
    inotify_rm_watch = 293,
    migrate_pages = 294,
    openat = 295,
    mkdirat = 296,
    mknodat = 297,
    fchownat = 298,
    futimesat = 299,
    fstatat64 = 300,
    unlinkat = 301,
    renameat = 302,
    linkat = 303,
    symlinkat = 304,
    readlinkat = 305,
    fchmodat = 306,
    faccessat = 307,
    pselect6 = 308,
    ppoll = 309,
    unshare = 310,
    set_robust_list = 311,
    get_robust_list = 312,
    splice = 313,
    sync_file_range = 314,
    tee = 315,
    vmsplice = 316,
    move_pages = 317,
    getcpu = 318,
    epoll_pwait = 319,
    utimensat = 320,
    signalfd = 321,
    timerfd_create = 322,
    eventfd = 323,
    fallocate = 324,
    timerfd_settime = 325,
    timerfd_gettime = 326,
    signalfd4 = 327,
    eventfd2 = 328,
    epoll_create1 = 329,
    dup3 = 330,
    pipe2 = 331,
    inotify_init1 = 332,
    preadv = 333,
    pwritev = 334,
    rt_tgsigqueueinfo = 335,
    perf_event_open = 336,
    recvmmsg = 337,
    fanotify_init = 338,
    fanotify_mark = 339,
    prlimit64 = 340,
    name_to_handle_at = 341,
    open_by_handle_at = 342,
    clock_adjtime = 343,
    syncfs = 344,
    sendmmsg = 345,
    setns = 346,
    process_vm_readv = 347,
    process_vm_writev = 348,
    kcmp = 349,
    finit_module = 350,
    sched_setattr = 351,
    sched_getattr = 352,
    renameat2 = 353,
    seccomp = 354,
    getrandom = 355,
    memfd_create = 356,
    bpf = 357,
    execveat = 358,
    socket = 359,
    socketpair = 360,
    bind = 361,
    connect = 362,
    listen = 363,
    accept4 = 364,
    getsockopt = 365,
    setsockopt = 366,
    getsockname = 367,
    getpeername = 368,
    sendto = 369,
    sendmsg = 370,
    recvfrom = 371,
    recvmsg = 372,
    shutdown = 373,
    userfaultfd = 374,
    membarrier = 375,
    mlock2 = 376,
    copy_file_range = 377,
    preadv2 = 378,
    pwritev2 = 379,
}

// TODO: support aarch64 arm .. well is not unsupported you can also manually use i32

/// SCMP_ARCH in C
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum SCMP_ARCH {
    NATIVE = 0x0,
    X86 = 0x40000003,
    X86_64 = 0xc000003e,
    X32 = 0x4000003e,
    ARM = 0x40000028,
    AARCH64 = 0xc00000b7,
    MIPS = 0x8,
    MIPS64 = 0x80000008,
    MIPS64N32 = 0xa0000008,
    MIPSEL = 0x40000008,
    MIPSEL64 = 0xc0000008,
    MIPSEL64N32 = 0xe0000008,
    PPC = 0x14,
    PPC64 = 0x80000015,
    PPC64LE = 0xc0000015,
    S390 = 0x16,
    S390X = 0x80000016,
}

/// SCMP_ACT_* in C
#[allow(non_snake_case)]
#[allow(dead_code)]
pub mod SCMP_ACT {
    pub const KILL: libc::c_uint = 0x00000000;
    pub const TRAP: libc::c_uint = 0x00030000;
    pub const ALLOW: libc::c_uint = 0x7fff0000;
    pub const LOG: libc::c_uint = 0x7ffc0000;
    pub const NOTIFY: libc::c_uint = 0x7fc00000;
    pub fn ERRNO(x: libc::c_uint) -> libc::c_uint {
        0x00050000 | ((x) & 0x0000ffff)
    }
    pub fn TRACE(x: libc::c_uint) -> libc::c_uint {
        0x7ff00000 | ((x) & 0x0000ffff)
    }
}

/// SCMP_FILTER_ATTR in C
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum SCMP_FILTER_ATTR {
    MIN,
    ACT_DEFAULT,
    /** default filter action */
    ACT_BADARCH,
    /** bad architecture action */
    CTL_NNP,
    /** set NO_NEW_PRIVS on filter load */
    MAX,
}


/// SCMP_CMP operators
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum SCMP_COMPARE {
    MIN = 0,
    NE = 1,
    /** not equal */
    LT = 2,
    /** less than */
    LE = 3,
    /** less than or equal */
    EQ = 4,
    /** equal */
    GE = 5,
    /** greater than or equal */
    GT = 6,
    /** greater than */
    MASKED_EQ = 7,
    /** masked equality */
    MAX,
}

// you know using void* right...
#[allow(non_camel_case_types)]
pub type SCMP_FILTER_CTX = libc::c_void;

/// A struct, replace SCMP_CMP
#[derive(Debug)]
#[repr(C)]
pub struct SCMP_ARG_CMP {
    pub arg: libc::c_uint,
    /** argument number, starting at 0 */
    pub op: SCMP_COMPARE,
    /** the comparison op, e.g. SCMP_CMP_* */
    pub oprand1: u64,
    pub oprand2: u64,
}

#[link(name = "seccomp")]
extern "C" {
    /**
     * Initialize the filter state
     *
     * @param def_action the default filter action
     *
     * This function initializes the internal seccomp filter state and should
     * be called before any other functions in this library to ensure the filter
     * state is initialized.  Returns a filter context on success, NULL on failure.
     *
     */
    fn seccomp_init(def_action: libc::c_uint) -> *mut SCMP_FILTER_CTX;
    /**
     * Reset the filter state
     *
     * @param ctx the filter context
     * @param def_action the default filter action
     *
     * This function resets the given seccomp filter state and ensures the
     * filter state is reinitialized.  This function does not reset any seccomp
     * filters already loaded into the kernel.  Returns zero on success, negative
     * values on failure.
     *
     */
    fn seccomp_reset(ctx: *mut SCMP_FILTER_CTX, def_action: libc::c_uint) -> libc::c_int;
    /**
     * Destroys the filter state and releases any resources
     *
     * @param ctx the filter context
     *
     * This functions destroys the given seccomp filter state and releases any
     * resources, including memory, associated with the filter state.  This
     * function does not reset any seccomp filters already loaded into the kernel.
     * The filter context can no longer be used after calling this function.
     *
     */
    fn seccomp_release(ctx: *mut SCMP_FILTER_CTX);
    /**
     * Adds an architecture to the filter
     * @param ctx the filter context
     * @param arch_token the architecture token, e.g. SCMP_ARCH_*
     *
     * This function adds a new architecture to the given seccomp filter context.
     * Any new rules added after this function successfully returns will be added
     * to this architecture but existing rules will not be added to this
     * architecture.  If the architecture token is SCMP_ARCH_NATIVE then the native
     * architecture will be assumed.  Returns zero on success, negative values on
     * failure.
     *
     */
    fn seccomp_arch_add(ctx: *mut SCMP_FILTER_CTX, arch_token: libc::c_uint) -> libc::c_int;
    /**
     * Removes an architecture from the filter
     * @param ctx the filter context
     * @param arch_token the architecture token, e.g. SCMP_ARCH_*
     *
     * This function removes an architecture from the given seccomp filter context.
     * If the architecture token is SCMP_ARCH_NATIVE then the native architecture
     * will be assumed.  Returns zero on success, negative values on failure.
     *
     */
    fn seccomp_arch_remove(ctx: *mut SCMP_FILTER_CTX, arch_token: libc::c_uint) -> libc::c_int;
    /**
     * Loads the filter into the kernel
     *
     * @param ctx the filter context
     *
     * This function loads the given seccomp filter context into the kernel.  If
     * the filter was loaded correctly, the kernel will be enforcing the filter
     * when this function returns.  Returns zero on success, negative values on
     * error.
     *
     */
    fn seccomp_load(ctx: *const SCMP_FILTER_CTX) -> libc::c_int;
    /**
     * Get the value of a filter attribute
     *
     * @param ctx the filter context
     * @param attr the filter attribute name
     * @param value the filter attribute value
     *
     * This function fetches the value of the given attribute name and returns it
     * via @value.  Returns zero on success, negative values on failure.
     *
     */
    fn seccomp_attr_get(
        ctx: *const SCMP_FILTER_CTX,
        attr: SCMP_FILTER_ATTR,
        value: *mut libc::c_uint,
    ) -> libc::c_int;
    /**
     * Set the value of a filter attribute
     *
     * @param ctx the filter context
     * @param attr the filter attribute name
     * @param value the filter attribute value
     *
     * This function sets the value of the given attribute.  Returns zero on
     * success, negative values on failure.
     *
     */
    fn seccomp_attr_set(
        ctx: *mut SCMP_FILTER_CTX,
        attr: SCMP_FILTER_ATTR,
        value: libc::c_uint,
    ) -> libc::c_int;
    /**
     * Resolve a syscall name to a number
     * @param name the syscall name
     *
     * Resolve the given syscall name to the syscall number.  Returns the syscall
     * number on success, including negative pseudo syscall numbers (e.g. __PNR_*);
     * returns __NR_SCMP_ERROR on failure.
     *
     */
    fn seccomp_syscall_resolve_name(name: *const libc::c_char) -> libc::c_int;
    /**
     * Set the priority of a given syscall
     *
     * @param ctx the filter context
     * @param syscall the syscall number
     * @param priority priority value, higher value == higher priority
     *
     * This function sets the priority of the given syscall; this value is used
     * when generating the seccomp filter code such that higher priority syscalls
     * will incur less filter code overhead than the lower priority syscalls in the
     * filter.  Returns zero on success, negative values on failure.
     *
     */
    fn seccomp_syscall_priority(
        ctx: *mut SCMP_FILTER_CTX,
        syscall: libc::c_int,
        priority: u8,
    ) -> libc::c_int;
    /**
     * Add a new rule to the filter
     *
     * @param ctx the filter context
     * @param action the filter action
     * @param syscall the syscall number
     * @param arg_cnt the number of argument filters in the argument filter chain
     * @param ... SCMP_ARG_CMP structs (use of SCMP_ARG_CMP() recommended)
     *
     * This function adds a series of new argument/value checks to the seccomp
     * filter for the given syscall; multiple argument/value checks can be
     * specified and they will be chained together (AND'd together) in the filter.
     * If the specified rule needs to be adjusted due to architecture specifics it
     * will be adjusted without notification.  Returns zero on success, negative
     * values on failure.
     *
     */
    fn seccomp_rule_add(
        ctx: *mut SCMP_FILTER_CTX,
        action: libc::c_uint,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        ...
    ) -> libc::c_int;
    /**
     * Add a new rule to the filter
     *
     * @param ctx the filter context
     * @param action the filter action
     * @param syscall the syscall number
     * @param arg_cnt the number of elements in the arg_array parameter
     * @param arg_array array of SCMP_ARG_CMP structs
     *
     * This function adds a series of new argument/value checks to the seccomp
     * filter for the given syscall; multiple argument/value checks can be
     * specified and they will be chained together (AND'd together) in the filter.
     * If the specified rule needs to be adjusted due to architecture specifics it
     * will be adjusted without notification.  Returns zero on success, negative
     * values on failure.
     *
     */
    fn seccomp_rule_add_array(
        ctx: *mut SCMP_FILTER_CTX,
        action: libc::c_uint,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        arg_array: *const SCMP_ARG_CMP,
    ) -> libc::c_int;
    /**
     * Add a new rule to the filter
     *
     * @param ctx the filter context
     * @param action the filter action
     * @param syscall the syscall number
     * @param arg_cnt the number of argument filters in the argument filter chain
     * @param ... SCMP_ARG_CMP structs (use of SCMP_ARG_CMP() recommended)
     *
     * This function adds a series of new argument/value checks to the seccomp
     * filter for the given syscall; multiple argument/value checks can be
     * specified and they will be chained together (AND'd together) in the filter.
     * If the specified rule can not be represented on the architecture the
     * function will fail.  Returns zero on success, negative values on failure.
     *
     */
    fn seccomp_rule_add_exact(
        ctx: *mut SCMP_FILTER_CTX,
        action: libc::c_uint,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        ...
    ) -> libc::c_int;
    /**
     * Add a new rule to the filter
     *
     * @param ctx the filter context
     * @param action the filter action
     * @param syscall the syscall number
     * @param arg_cnt  the number of elements in the arg_array parameter
     * @param arg_array array of SCMP_ARG_CMP structs
     *
     * This function adds a series of new argument/value checks to the seccomp
     * filter for the given syscall; multiple argument/value checks can be
     * specified and they will be chained together (AND'd together) in the filter.
     * If the specified rule can not be represented on the architecture the
     * function will fail.  Returns zero on success, negative values on failure.
     *
     */
    fn seccomp_rule_add_exact_array(
        ctx: *mut SCMP_FILTER_CTX,
        action: libc::c_uint,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        arg_array: *const SCMP_ARG_CMP,
    ) -> libc::c_int;
    /**
     * Generate seccomp Pseudo Filter Code (PFC) and export it to a file
     *
     * @param ctx the filter context
     * @param fd the destination fd
     *
     * This function generates seccomp Pseudo Filter Code (PFC) and writes it to
     * the given fd.  Returns zero on success, negative values on failure.
     *
     */
    fn seccomp_export_pfc(ctx: *const SCMP_FILTER_CTX, fd: libc::c_int) -> libc::c_int;
    /**
     * Generate seccomp Berkley Packet Filter (BPF) code and export it to a file
     *
     * @param ctx the filter context
     * @param fd the destination fd
     *
     * This function generates seccomp Berkley Packer Filter (BPF) code and writes
     * it to the given fd.  Returns zero on success, negative values on failure.
     *
     */
    fn seccomp_export_bpf(ctx: *const SCMP_FILTER_CTX, fd: libc::c_int) -> libc::c_int;
}

pub struct Seccomp{
    ctx : *mut SCMP_FILTER_CTX,
}

impl Seccomp {
    /// initialize the seccomp and set the context into the struct
    pub fn init(act: libc::c_uint) -> Self {
        Seccomp{
            ctx:unsafe { seccomp_init(act) }
        }
    }
    /// load seccomp to kernel
    pub fn load(self) -> Result<libc::c_int, String> {
        match unsafe { seccomp_load(self.ctx) } {
            0 => Ok(0),
            x => Err(format!("LOAD SECCOMP FAILED WITH CODE {}", x)),
        }
    }
    /// add an architecture
    pub fn add_arch(
        &self,
        arch_token: libc::c_uint,
    ) -> Result<libc::c_int, String> {
        match unsafe { seccomp_arch_add(self.ctx, arch_token) } {
            0 => Ok(0),
            x => Err(format!("ADD SECCOMP ARCH FAILED WITH CODE {}", x)),
        }
    }
    /// remove an architecture
    pub fn remove_arch(
        &self,
        arch_token: libc::c_uint,
    ) -> Result<libc::c_int, String> {
        match unsafe { seccomp_arch_remove(self.ctx, arch_token) } {
            0 => Ok(0),
            x => Err(format!("REMOVE SECCOMP ARCH FAILED WITH CODE {}", x)),
        }
    }

    pub fn get_attr(
        ctx: *const SCMP_FILTER_CTX,
        attr: SCMP_FILTER_ATTR,
        value: *mut libc::c_uint,
    ) -> Result<*mut libc::c_uint, String> {
        match unsafe { seccomp_attr_get(ctx, attr, value) } {
            0 => Ok(value),
            x => Err(format!("GET SECCOMP ATTR FAILED WITH CODE {}", x)),
        }
    }

    pub fn set_attr(
        &self,
        attr: SCMP_FILTER_ATTR,
        value: libc::c_uint,
    ) -> Result<libc::c_int, String> {
        match unsafe { seccomp_attr_set(self.ctx, attr, value) } {
            0 => Ok(0),
            x => Err(format!("SET SECCOMP ATTR FAILED WITH CODE {}", x)),
        }
    }

    pub fn add_exact_rule(
        &self,
        action: libc::c_uint,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        arg: SCMP_ARG_CMP,
    ) -> Result<libc::c_int, String> {
        match unsafe { seccomp_rule_add_exact(self.ctx, action, syscall, arg_cnt, arg) } {
            0 => Ok(0),
            x => Err(format!("LOAD SECCOMP EXACT RULE FAILED WITH CODE {}", x)),
        }
    }
    pub fn add_exact_rules(
        &self,
        action: libc::c_uint,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        arg_array: Vec<SCMP_ARG_CMP>,
    ) -> Result<libc::c_int, String> {
        match unsafe {
            seccomp_rule_add_exact_array(self.ctx, action, syscall, arg_cnt, arg_array.as_ptr())
        } {
            0 => Ok(0),
            x => Err(format!("LOAD SECCOMP EXACT RULES FAILED WITH CODE {}", x)),
        }
    }
    /// adding rule to seccomp before the seccomp loaded to kernel
    pub fn add_rule(
        &self,
        action: libc::c_uint,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        arg: SCMP_ARG_CMP,
    ) -> Result<libc::c_int, String> {
        match unsafe { seccomp_rule_add(self.ctx, action, syscall, arg_cnt, arg) } {
            0 => Ok(0),
            x => Err(format!("LOAD SECCOMP RULE FAILED WITH CODE {}", x)),
        }
    }
    /// adding rules(vector) to seccomp before the seccomp loaded to kernel
    pub fn add_rules(
        &self,
        action: libc::c_uint,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        arg_array: Vec<SCMP_ARG_CMP>,
    ) -> Result<libc::c_int, String> {
        match unsafe { seccomp_rule_add_array(self.ctx, action, syscall, arg_cnt, arg_array.as_ptr()) } {
            0 => Ok(0),
            x => Err(format!("LOAD SECCOMP RULES FAILED WITH CODE {}", x)),
        }
    }

    pub fn export_bpf(ctx: *const SCMP_FILTER_CTX, fd: libc::c_int) -> Result<libc::c_int, String> {
        match unsafe { seccomp_export_bpf(ctx, fd) } {
            0 => Ok(0),
            x => Err(format!("EXPORT SECCOMP BPF FAILED WITH CODE {}", x)),
        }
    }

    pub fn export_pfc(ctx: *const SCMP_FILTER_CTX, fd: libc::c_int) -> Result<libc::c_int, String> {
        match unsafe { seccomp_export_pfc(ctx, fd) } {
            0 => Ok(0),
            x => Err(format!("EXPORT SECCOMP PFC FAILED WITH CODE {}", x)),
        }
    }
    /// if you are using arm/aarch64 you could use this instead of SCMP_SYS
    pub fn resolve_syscall_name(name: &str) -> i32 {
        unsafe { seccomp_syscall_resolve_name(name.as_ptr() as *const i8) }
    }
    pub fn syscall_priority(
        &self,
        syscall: libc::c_int,
        priority: u8,
    ) -> Result<libc::c_int, String> {
        match unsafe { seccomp_syscall_priority(self.ctx, syscall, priority) } {
            0 => Ok(0),
            x => Err(format!(
                "LOAD SECCOMP SYSCALL PRIORITY FAILED WITH CODE {}",
                x
            )),
        }
    }
    /// reset the seccomp
    pub fn reset(
        &self,
        def_action: libc::c_uint,
    ) -> Result<libc::c_int, String> {
        match unsafe { seccomp_reset(self.ctx, def_action) } {
            0 => Ok(0),
            x => Err(format!("SECCOMP RESET FAILED WITH CODE {}", x)),
        }
    }
    /// release the seccomp from kernel
    pub fn release(ctx: *mut SCMP_FILTER_CTX) {
        unsafe { seccomp_release(ctx) }
    }
}


#[cfg(test)]
mod test{
    use super::*;
    #[test]
    fn test(){
        let sccp = Seccomp::init(SCMP_ACT::ALLOW);
        let cmptr = SCMP_ARG_CMP{
            arg:0,
            op: SCMP_COMPARE::EQ,
            oprand1:1000,
            oprand2:10,
        };
        assert!(sccp.add_rule(SCMP_ACT::KILL, SCMP_SYS::setuid as i32, 1, cmptr) == Ok(0),"well ... if you seccomp is installed successfully it will return OK(0)");
        assert!(sccp.load() == Ok(0),"this will fail in wsl");
        println!("now if you use libc::secuid(1000) == 0 it will panic!")
    }
}