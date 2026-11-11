//! The seccomp profile of a box process, as a rule table.
//!
//! [`BOX`] is the one profile. [`compile`] turns a profile into a classic BPF
//! program and [`install`] loads it; the container launch and the entry into
//! a running box both install the same compiled program.
//!
//! A rule names syscalls, conditions on their arguments and an action. For
//! each syscall the first rule whose conditions hold decides, and a syscall
//! no rule decides gets the profile's default. Two checks come before any
//! rule and are part of every compiled profile: a caller on an ABI that is
//! neither the native one nor its 32-bit compat ABI is killed, and so is an
//! x32 caller on x86_64, because their syscall numbers mean something else.

use std::collections::BTreeMap;

/// What the kernel does with a matched syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Run the syscall.
    Allow,
    /// Fail the syscall with this errno.
    Errno(i32),
    /// Kill the calling process with `SIGSYS`.
    KillProcess,
}

impl Action {
    fn ret(self) -> u32 {
        match self {
            Self::Allow => libc::SECCOMP_RET_ALLOW,
            Self::Errno(errno) => libc::SECCOMP_RET_ERRNO | (errno as u32 & 0xffff),
            Self::KillProcess => libc::SECCOMP_RET_KILL_PROCESS,
        }
    }
}

/// A syscall by its number on each ABI this build answers to. `None` where
/// the ABI has no such syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Syscall {
    /// The name, for error messages.
    pub name: &'static str,
    /// The number on the native ABI.
    pub native: Option<u32>,
    /// The number on the 32-bit compat ABI.
    pub compat: Option<u32>,
}

/// A comparison against the low 32 bits of a syscall argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    /// Equal to the value.
    Eq(u32),
    /// Equal to one of the values.
    In(&'static [u32]),
}

/// A condition on one argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cond {
    /// The argument's index, 0 to 5.
    pub arg: u8,
    /// The comparison its low 32 bits must satisfy.
    pub cmp: Cmp,
}

/// One row of a profile: these syscalls, when every condition holds, get
/// this action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// The syscalls the rule is about.
    pub syscalls: &'static [Syscall],
    /// The conditions, all of which must hold. Empty matches every call.
    pub when: &'static [Cond],
    /// What a matching call gets.
    pub action: Action,
}

/// A rule table and the action for everything no rule decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// The rules, first match wins.
    pub rules: &'static [Rule],
    /// The action for a syscall no rule matched.
    pub default: Action,
}

#[cfg(target_arch = "x86_64")]
mod arch {
    pub(super) const NATIVE: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
    pub(super) const COMPAT: u32 = 0x4000_0003; // AUDIT_ARCH_I386
    /// Set in the syscall number of an x32 call.
    pub(super) const X32_BIT: Option<u32> = Some(0x4000_0000);
    pub(super) const COMPAT_SOCKET: u32 = 359;
    pub(super) const COMPAT_SOCKETPAIR: u32 = 360;
}

#[cfg(target_arch = "aarch64")]
mod arch {
    pub(super) const NATIVE: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64
    pub(super) const COMPAT: u32 = 0x4000_0028; // AUDIT_ARCH_ARM
    pub(super) const X32_BIT: Option<u32> = None;
    pub(super) const COMPAT_SOCKET: u32 = 281;
    pub(super) const COMPAT_SOCKETPAIR: u32 = 288;
}

/// `socket(2)`.
pub const SOCKET: Syscall = Syscall {
    name: "socket",
    native: Some(libc::SYS_socket as u32),
    compat: Some(arch::COMPAT_SOCKET),
};

/// `socketpair(2)`.
pub const SOCKETPAIR: Syscall = Syscall {
    name: "socketpair",
    native: Some(libc::SYS_socketpair as u32),
    compat: Some(arch::COMPAT_SOCKETPAIR),
};

/// `io_uring_setup(2)`, which has one number on every ABI.
pub const IO_URING_SETUP: Syscall = Syscall {
    name: "io_uring_setup",
    native: Some(libc::SYS_io_uring_setup as u32),
    compat: Some(425),
};

/// `socketcall(2)`, the 32-bit multiplexer for the socket calls. Its
/// arguments sit behind a pointer a filter cannot read.
pub const SOCKETCALL: Syscall = Syscall {
    name: "socketcall",
    native: None,
    compat: Some(102),
};

/// The `socketcall(2)` sub-calls that create sockets: `SYS_SOCKET` and
/// `SYS_SOCKETPAIR`.
const SOCKETCALL_CREATES: &[u32] = &[1, 8];

/// The address families a box may open sockets in. Each is confined by the
/// box's network namespace or by its cgroup's network policy. `AF_VSOCK` is
/// confined by neither and reaches the VM host, so it is not here.
const FAMILIES: &[u32] = &[
    libc::AF_UNIX as u32,
    libc::AF_INET as u32,
    libc::AF_INET6 as u32,
];

/// The profile every box process runs under.
///
/// - `io_uring_setup` fails with `ENOSYS`: a ring creates sockets without
///   `socket(2)`.
/// - `socket` and `socketpair` admit unix, inet, inet6, and netlink with the
///   `NETLINK_ROUTE` protocol. Another netlink protocol fails with
///   `EPROTONOSUPPORT`, the kernel's own answer for a protocol it lacks, and
///   another family with `EAFNOSUPPORT`.
/// - A 32-bit program's `socketcall` fails with `ENOSYS` for the two
///   sub-calls that create sockets, so its libc falls back to the direct
///   syscalls the rules above judge.
pub static BOX: Profile = Profile {
    rules: &[
        Rule {
            syscalls: &[IO_URING_SETUP],
            when: &[],
            action: Action::Errno(libc::ENOSYS),
        },
        Rule {
            syscalls: &[SOCKETCALL],
            when: &[Cond {
                arg: 0,
                cmp: Cmp::In(SOCKETCALL_CREATES),
            }],
            action: Action::Errno(libc::ENOSYS),
        },
        Rule {
            syscalls: &[SOCKET, SOCKETPAIR],
            when: &[
                Cond {
                    arg: 0,
                    cmp: Cmp::Eq(libc::AF_NETLINK as u32),
                },
                Cond {
                    arg: 2,
                    cmp: Cmp::Eq(libc::NETLINK_ROUTE as u32),
                },
            ],
            action: Action::Allow,
        },
        Rule {
            syscalls: &[SOCKET, SOCKETPAIR],
            when: &[Cond {
                arg: 0,
                cmp: Cmp::Eq(libc::AF_NETLINK as u32),
            }],
            action: Action::Errno(libc::EPROTONOSUPPORT),
        },
        Rule {
            syscalls: &[SOCKET, SOCKETPAIR],
            when: &[Cond {
                arg: 0,
                cmp: Cmp::In(FAMILIES),
            }],
            action: Action::Allow,
        },
        Rule {
            syscalls: &[SOCKET, SOCKETPAIR],
            when: &[],
            action: Action::Errno(libc::EAFNOSUPPORT),
        },
    ],
    default: Action::Allow,
};

/// A compiled profile.
#[derive(Debug, Clone)]
pub struct Program(Vec<libc::sock_filter>);

impl Program {
    /// The instructions.
    #[must_use]
    pub fn instructions(&self) -> &[libc::sock_filter] {
        &self.0
    }
}

/// Why a profile does not compile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// A condition names an argument a syscall does not have.
    #[error("{syscall}: a syscall has arguments 0 to 5, not {arg}")]
    NoSuchArgument {
        /// The syscall the rule is about.
        syscall: &'static str,
        /// The index the condition named.
        arg: u8,
    },
    /// The rules of one syscall are longer than a branch can skip.
    #[error(
        "{syscall}: its rules need a branch over {distance} instructions, and 255 is the limit"
    )]
    BranchTooFar {
        /// The syscall whose rules are too long.
        syscall: &'static str,
        /// The distance the branch would have to cover.
        distance: usize,
    },
    /// The program is longer than the kernel loads.
    #[error("the program has {0} instructions, and the kernel loads at most 4096")]
    TooLong(usize),
}

/// The largest program the kernel loads (`BPF_MAXINSNS`).
const MAX_INSTRUCTIONS: usize = 4096;

/// Offsets into `struct seccomp_data`.
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;

/// The offset of the low 32 bits of argument `arg`. Both supported
/// architectures are little-endian, so the low word comes first.
fn offset_arg(arg: u8) -> u32 {
    16 + 8 * u32::from(arg)
}

fn load(offset: u32) -> libc::sock_filter {
    stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, offset)
}

fn ret(action: Action) -> libc::sock_filter {
    stmt(libc::BPF_RET | libc::BPF_K, action.ret())
}

fn stmt(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | code | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    }
}

/// Which ABI a section of the program judges.
#[derive(Clone, Copy)]
enum Abi {
    Native,
    Compat,
}

impl Syscall {
    fn number(&self, abi: Abi) -> Option<u32> {
        match abi {
            Abi::Native => self.native,
            Abi::Compat => self.compat,
        }
    }
}

/// The instructions that judge one rule, ending in its action. A call the
/// rule does not match skips to the instruction after them.
fn rule_block(syscall: &'static str, rule: &Rule) -> Result<Vec<libc::sock_filter>, CompileError> {
    // Built back to front, so each branch knows how far the end is.
    let mut block = vec![ret(rule.action)];
    for cond in rule.when.iter().rev() {
        if cond.arg > 5 {
            return Err(CompileError::NoSuchArgument {
                syscall,
                arg: cond.arg,
            });
        }
        let values: &[u32] = match &cond.cmp {
            Cmp::Eq(value) => std::slice::from_ref(value),
            Cmp::In(values) => values,
        };
        let rest = block.len();
        let mut compares = Vec::with_capacity(values.len() + 1);
        compares.push(load(offset_arg(cond.arg)));
        for (i, value) in values.iter().enumerate() {
            let last = i + 1 == values.len();
            // A hit skips the remaining compares. A miss on the last one
            // skips the rest of the rule.
            let hit = values.len() - 1 - i;
            let miss = if last { rest } else { 0 };
            let far = hit.max(miss);
            let branch = |distance: usize| {
                u8::try_from(distance).map_err(|_| CompileError::BranchTooFar {
                    syscall,
                    distance: far,
                })
            };
            compares.push(jump(libc::BPF_JEQ, *value, branch(hit)?, branch(miss)?));
        }
        // A condition with no value matches nothing.
        if values.is_empty() {
            let skip = u32::try_from(rest).unwrap_or(u32::MAX);
            compares.push(stmt(libc::BPF_JMP | libc::BPF_JA, skip));
        }
        compares.append(&mut block);
        block = compares;
    }
    Ok(block)
}

/// The syscall number -1, which names no syscall.
const NO_SYSCALL: u32 = u32::MAX;

/// The section that judges every syscall of one ABI: a dispatch on the
/// syscall number, then the rules of each syscall in table order.
fn abi_section(profile: &Profile, abi: Abi) -> Result<Vec<libc::sock_filter>, CompileError> {
    // The rules of each syscall number, in table order.
    let mut by_number: BTreeMap<u32, (&'static str, Vec<&Rule>)> = BTreeMap::new();
    for rule in profile.rules {
        for syscall in rule.syscalls {
            if let Some(number) = syscall.number(abi) {
                by_number
                    .entry(number)
                    .or_insert_with(|| (syscall.name, Vec::new()))
                    .1
                    .push(rule);
            }
        }
    }
    let mut blocks = Vec::new();
    for (number, (name, rules)) in &by_number {
        let mut block = Vec::new();
        for rule in rules {
            block.append(&mut rule_block(name, rule)?);
        }
        block.push(ret(profile.default));
        blocks.push((*number, block));
    }

    let mut section = vec![load(OFFSET_NR)];
    if let (Abi::Native, Some(bit)) = (abi, arch::X32_BIT) {
        // A tracer cancels a syscall by setting its number to -1, and the
        // filter runs after the tracer. The kernel answers -1 with `ENOSYS`.
        section.push(jump(libc::BPF_JEQ, NO_SYSCALL, 0, 1));
        section.push(ret(Action::Allow));
        section.push(jump(libc::BPF_JGE, bit, 0, 1));
        section.push(ret(Action::KillProcess));
    }
    // One compare and one long jump per syscall, then the default. The long
    // jump has a 32-bit offset, so a profile can grow past what a
    // conditional branch reaches.
    let dispatch = 2 * blocks.len() + 1;
    let mut before = 0;
    for (i, (number, block)) in blocks.iter().enumerate() {
        section.push(jump(libc::BPF_JEQ, *number, 0, 1));
        let to_block = dispatch - (2 * i + 2) + before;
        section.push(stmt(
            libc::BPF_JMP | libc::BPF_JA,
            u32::try_from(to_block).unwrap_or(u32::MAX),
        ));
        before += block.len();
    }
    section.push(ret(profile.default));
    for (_, mut block) in blocks {
        section.append(&mut block);
    }
    Ok(section)
}

/// Compiles `profile` into a program for this build's architecture.
///
/// # Errors
///
/// A [`CompileError`] when the profile cannot be expressed.
pub fn compile(profile: &Profile) -> Result<Program, CompileError> {
    let native = abi_section(profile, Abi::Native)?;
    let mut compat = abi_section(profile, Abi::Compat)?;
    let to_compat = u32::try_from(native.len() + 1).unwrap_or(u32::MAX);
    let mut program = vec![
        load(OFFSET_ARCH),
        // Native: skip the compat compare, its long jump and the kill.
        jump(libc::BPF_JEQ, arch::NATIVE, 3, 0),
        jump(libc::BPF_JEQ, arch::COMPAT, 0, 1),
        stmt(libc::BPF_JMP | libc::BPF_JA, to_compat),
        ret(Action::KillProcess),
    ];
    program.extend(native);
    program.append(&mut compat);
    if program.len() > MAX_INSTRUCTIONS {
        return Err(CompileError::TooLong(program.len()));
    }
    Ok(Program(program))
}

/// The compiled [`BOX`] profile. The first call compiles it, so a caller
/// that installs it after a fork takes the reference before the fork.
///
/// # Panics
///
/// If [`BOX`] does not compile, which the tests rule out.
#[must_use]
pub fn box_program() -> &'static Program {
    static PROGRAM: std::sync::OnceLock<Program> = std::sync::OnceLock::new();
    PROGRAM.get_or_init(|| compile(&BOX).expect("the box profile compiles"))
}

/// Loads `program` into the calling thread, after setting `no_new_privs`,
/// which an unprivileged caller needs for the load. It makes only the
/// `prctl` and `seccomp` syscalls, so it is safe between a fork and an exec.
///
/// # Errors
///
/// The errno of the failing syscall.
pub fn install(program: &Program) -> std::io::Result<()> {
    // SAFETY: `prctl` with constant arguments reads no memory of ours.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let prog = libc::sock_fprog {
        len: program.0.len() as u16,
        filter: program.0.as_ptr().cast_mut(),
    };
    // SAFETY: `prog` points at the program's instructions, which outlive the
    // call, and the kernel copies them.
    let loaded = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &raw const prog,
        )
    };
    if loaded == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One synthetic `struct seccomp_data`.
    #[derive(Clone, Copy)]
    struct Call {
        arch: u32,
        nr: u32,
        args: [u32; 6],
    }

    /// Runs a program over one call and returns the action value it ends
    /// with. It knows the opcodes [`compile`] emits and no others.
    fn evaluate(program: &Program, call: Call) -> u32 {
        let (mut pc, mut acc) = (0usize, 0u32);
        loop {
            let insn = program.0[pc];
            pc += 1;
            let code = u32::from(insn.code);
            if code == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS {
                acc = match insn.k {
                    OFFSET_NR => call.nr,
                    OFFSET_ARCH => call.arch,
                    k if k >= 16 && (k - 16) % 8 == 0 && k < 64 => {
                        call.args[((k - 16) / 8) as usize]
                    }
                    other => panic!("load of seccomp_data offset {other}"),
                };
            } else if code == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K {
                pc += usize::from(if acc == insn.k { insn.jt } else { insn.jf });
            } else if code == libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K {
                pc += usize::from(if acc >= insn.k { insn.jt } else { insn.jf });
            } else if code == libc::BPF_JMP | libc::BPF_JA {
                pc += insn.k as usize;
            } else if code == libc::BPF_RET | libc::BPF_K {
                return insn.k;
            } else {
                panic!("opcode {code:#x} at {}", pc - 1);
            }
        }
    }

    fn call(arch: u32, nr: u32, arg0: u32, arg2: u32) -> Call {
        Call {
            arch,
            nr,
            args: [arg0, 0, arg2, 0, 0, 0],
        }
    }

    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;
    fn errno(errno: i32) -> u32 {
        libc::SECCOMP_RET_ERRNO | errno as u32
    }

    /// Every row of the box profile, both outcomes, on both ABIs, read off
    /// the compiled program.
    #[test]
    fn the_compiled_box_profile_decides_each_row_on_both_abis() {
        let program = box_program();
        let unix = libc::AF_UNIX as u32;
        let inet = libc::AF_INET as u32;
        let inet6 = libc::AF_INET6 as u32;
        let netlink = libc::AF_NETLINK as u32;
        let packet = libc::AF_PACKET as u32;
        let vsock = libc::AF_VSOCK as u32;
        let route = libc::NETLINK_ROUTE as u32;
        let audit = libc::NETLINK_AUDIT as u32;
        for (arch, abi) in [(arch::NATIVE, Abi::Native), (arch::COMPAT, Abi::Compat)] {
            for creator in [SOCKET, SOCKETPAIR] {
                let nr = creator.number(abi).unwrap();
                for family in [unix, inet, inet6] {
                    assert_eq!(evaluate(program, call(arch, nr, family, 0)), ALLOW);
                    // The protocol is judged only for netlink.
                    assert_eq!(evaluate(program, call(arch, nr, family, 7)), ALLOW);
                }
                assert_eq!(evaluate(program, call(arch, nr, netlink, route)), ALLOW);
                assert_eq!(
                    evaluate(program, call(arch, nr, netlink, audit)),
                    errno(libc::EPROTONOSUPPORT)
                );
                for family in [packet, vsock, 0, 45] {
                    assert_eq!(
                        evaluate(program, call(arch, nr, family, 0)),
                        errno(libc::EAFNOSUPPORT)
                    );
                }
            }
            let ring = IO_URING_SETUP.number(abi).unwrap();
            assert_eq!(
                evaluate(program, call(arch, ring, 0, 0)),
                errno(libc::ENOSYS)
            );
            // A syscall no rule names.
            assert_eq!(evaluate(program, call(arch, 1, vsock, 0)), ALLOW);
        }
        // socketcall is judged on the compat ABI only: 102 is another
        // syscall on the native one.
        let multiplexer = SOCKETCALL.compat.unwrap();
        for creates in [1, 8] {
            assert_eq!(
                evaluate(program, call(arch::COMPAT, multiplexer, creates, 0)),
                errno(libc::ENOSYS)
            );
        }
        for other in [2, 3, 6, 9, 17] {
            assert_eq!(
                evaluate(program, call(arch::COMPAT, multiplexer, other, 0)),
                ALLOW
            );
        }
        assert_eq!(
            evaluate(program, call(arch::NATIVE, multiplexer, 1, 0)),
            ALLOW
        );
    }

    #[test]
    fn a_foreign_architecture_is_killed() {
        let program = box_program();
        // AUDIT_ARCH_RISCV64 and AUDIT_ARCH_PPC64LE, neither native nor compat here.
        for foreign in [0xc000_00f3u32, 0xc000_0015] {
            assert_eq!(evaluate(program, call(foreign, 1, 0, 0)), KILL);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn an_x32_call_is_killed() {
        let program = box_program();
        for nr in [0x4000_0000u32, 0x4000_0000 | 41, u32::MAX - 1] {
            assert_eq!(evaluate(program, call(arch::NATIVE, nr, 1, 0)), KILL);
        }
        // The compat ABI has no x32 numbers; a large number there is an
        // unknown syscall the kernel refuses by itself.
        assert_eq!(
            evaluate(program, call(arch::COMPAT, 0x4000_0000, 1, 0)),
            ALLOW
        );
    }

    /// The number a tracer sets to cancel a syscall is allowed on both
    /// ABIs, and is no x32 call.
    #[test]
    fn the_syscall_number_minus_one_is_allowed() {
        let program = box_program();
        for arch in [arch::NATIVE, arch::COMPAT] {
            assert_eq!(evaluate(program, call(arch, u32::MAX, 1, 0)), ALLOW);
        }
    }

    #[test]
    fn the_first_matching_rule_decides() {
        static WRITE: Syscall = Syscall {
            name: "write",
            native: Some(libc::SYS_write as u32),
            compat: Some(4),
        };
        static PROFILE: Profile = Profile {
            rules: &[
                Rule {
                    syscalls: &[WRITE],
                    when: &[Cond {
                        arg: 0,
                        cmp: Cmp::Eq(7),
                    }],
                    action: Action::Errno(libc::EPERM),
                },
                Rule {
                    syscalls: &[WRITE],
                    when: &[Cond {
                        arg: 0,
                        cmp: Cmp::In(&[7, 8]),
                    }],
                    action: Action::Errno(libc::EBADF),
                },
                Rule {
                    syscalls: &[WRITE],
                    when: &[Cond {
                        arg: 5,
                        cmp: Cmp::In(&[]),
                    }],
                    action: Action::KillProcess,
                },
            ],
            default: Action::Errno(libc::ENOSYS),
        };
        let program = compile(&PROFILE).unwrap();
        let write = libc::SYS_write as u32;
        let on = |fd| evaluate(&program, call(arch::NATIVE, write, fd, 0));
        assert_eq!(on(7), errno(libc::EPERM));
        assert_eq!(on(8), errno(libc::EBADF));
        assert_eq!(on(9), errno(libc::ENOSYS));
        assert_eq!(
            evaluate(&program, call(arch::NATIVE, write + 1, 7, 0)),
            errno(libc::ENOSYS)
        );
    }

    #[test]
    fn a_profile_that_cannot_be_expressed_does_not_compile() {
        static READ: Syscall = Syscall {
            name: "read",
            native: Some(libc::SYS_read as u32),
            compat: Some(3),
        };
        static BAD_ARG: Profile = Profile {
            rules: &[Rule {
                syscalls: &[READ],
                when: &[Cond {
                    arg: 6,
                    cmp: Cmp::Eq(0),
                }],
                action: Action::Allow,
            }],
            default: Action::Allow,
        };
        assert_eq!(
            compile(&BAD_ARG).unwrap_err(),
            CompileError::NoSuchArgument {
                syscall: "read",
                arg: 6
            }
        );
        static MANY: [u32; 300] = [1; 300];
        static TOO_FAR: Profile = Profile {
            rules: &[Rule {
                syscalls: &[READ],
                when: &[Cond {
                    arg: 0,
                    cmp: Cmp::In(&MANY),
                }],
                action: Action::Allow,
            }],
            default: Action::Allow,
        };
        assert!(matches!(
            compile(&TOO_FAR),
            Err(CompileError::BranchTooFar {
                syscall: "read",
                ..
            })
        ));
    }

    /// Forks, installs the box program in the child, runs `probe` there and
    /// returns what it reported. The child makes only async-signal-safe
    /// calls. `Err` carries the child's wait status when it did not report.
    fn under_the_box_profile<const N: usize>(probe: fn() -> [u8; N]) -> Result<[u8; N], i32> {
        let program = box_program();
        let mut fds = [0; 2];
        // SAFETY: `pipe` fills the two descriptors.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the child calls only async-signal-safe functions.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: plain syscalls on this child's own descriptors.
            unsafe {
                libc::close(fds[0]);
                if install(program).is_err() {
                    libc::_exit(127);
                }
                let report = probe();
                libc::write(fds[1], report.as_ptr().cast(), N);
                libc::_exit(0);
            }
        }
        let mut report = [0u8; N];
        // SAFETY: the parent owns both ends and the child's pid.
        let status = unsafe {
            libc::close(fds[1]);
            let mut filled = 0;
            while filled < N {
                let n = libc::read(fds[0], report[filled..].as_mut_ptr().cast(), N - filled);
                if n <= 0 {
                    break;
                }
                filled += n as usize;
            }
            libc::close(fds[0]);
            let mut status = 0;
            libc::waitpid(pid, &raw mut status, 0);
            status
        };
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            Ok(report)
        } else {
            Err(status)
        }
    }

    /// 0 when the call returned a descriptor (closed again), its errno
    /// otherwise.
    fn outcome(fd: libc::c_long) -> u8 {
        if fd >= 0 {
            // SAFETY: closes the descriptor the call just returned.
            unsafe { libc::close(fd as i32) };
            0
        } else {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(255) as u8
        }
    }

    fn socket(family: i32, ty: i32, protocol: i32) -> u8 {
        // SAFETY: `socket` reads only its arguments.
        outcome(libc::c_long::from(unsafe {
            libc::socket(family, ty, protocol)
        }))
    }

    fn socketpair(family: i32) -> u8 {
        let mut pair = [-1; 2];
        // SAFETY: `socketpair` fills the two descriptors.
        let made = unsafe { libc::socketpair(family, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
        if made == 0 {
            // SAFETY: closes the pair just made.
            unsafe {
                libc::close(pair[0]);
                libc::close(pair[1]);
            }
            0
        } else {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(255) as u8
        }
    }

    /// Real syscalls in a child under the installed box profile: each rule,
    /// both outcomes.
    #[test]
    fn the_kernel_enforces_each_row_of_the_box_profile() {
        let report = under_the_box_profile(|| {
            [
                socket(libc::AF_UNIX, libc::SOCK_STREAM, 0),
                socket(libc::AF_INET, libc::SOCK_STREAM, 0),
                socket(libc::AF_INET6, libc::SOCK_DGRAM, 0),
                socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE),
                socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_AUDIT),
                socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW,
                    libc::NETLINK_KOBJECT_UEVENT,
                ),
                socket(libc::AF_PACKET, libc::SOCK_DGRAM, 0),
                socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0),
                socketpair(libc::AF_UNIX),
                socketpair(libc::AF_VSOCK),
                // SAFETY: `io_uring_setup` with no parameters fails before it
                // reads any.
                outcome(unsafe {
                    libc::syscall(libc::SYS_io_uring_setup, 4, std::ptr::null::<u8>())
                }),
                // A syscall no rule names still runs.
                // SAFETY: `getpid` takes no arguments.
                u8::from(unsafe { libc::getpid() } <= 0),
            ]
        })
        .expect("the probe ran under the profile");
        let proto = libc::EPROTONOSUPPORT as u8;
        let family = libc::EAFNOSUPPORT as u8;
        let nosys = libc::ENOSYS as u8;
        assert_eq!(
            report,
            [
                0, 0, 0, 0, proto, proto, family, family, 0, family, nosys, 0
            ],
            "unix, inet, inet6, netlink route, netlink audit, netlink uevent, packet, vsock, \
             socketpair unix, socketpair vsock, io_uring_setup, getpid"
        );
    }

    /// An x32 syscall under the installed profile ends the process with
    /// `SIGSYS`.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_kernel_kills_an_x32_caller() {
        let status = under_the_box_profile(|| {
            // SAFETY: the x32 `getpid`; the filter kills before it runs.
            unsafe { libc::syscall(0x4000_0000 | libc::SYS_getpid) };
            [0u8; 1]
        })
        .expect_err("the x32 call must not return");
        assert!(
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS,
            "wait status {status:#x}"
        );
    }

    /// A call of syscall -1 under the installed profile returns `ENOSYS`,
    /// as it does for a tracer that cancelled a syscall.
    #[test]
    fn the_kernel_answers_syscall_minus_one_with_enosys() {
        let report = under_the_box_profile(|| {
            // SAFETY: -1 names no syscall, so the kernel runs nothing.
            [outcome(unsafe { libc::syscall(-1) })]
        })
        .expect("the call returns under the profile");
        assert_eq!(report, [libc::ENOSYS as u8]);
    }

    /// The 32-bit helper: each socket syscall through the i386 ABI, one
    /// `name=errno` line per call, 0 for success.
    #[cfg(target_arch = "x86_64")]
    const COMPAT_HELPER: &str = r#"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
static void say(const char *name, long r) {
    if (r >= 0) { close((int)r); printf("%s=0\n", name); } else printf("%s=%d\n", name, errno);
}
int main(void) {
    long sv[2];
    unsigned long a[3];
    say("socket_unix", syscall(359, 1, 1, 0));
    say("socket_inet", syscall(359, 2, 1, 0));
    say("socket_inet6", syscall(359, 10, 2, 0));
    say("socket_netlink_route", syscall(359, 16, 3, 0));
    say("socket_netlink_audit", syscall(359, 16, 3, 9));
    say("socket_packet", syscall(359, 17, 2, 0));
    say("socket_vsock", syscall(359, 40, 1, 0));
    errno = 0;
    printf("socketpair_unix=%d\n", syscall(360, 1, 1, 0, sv) == 0 ? 0 : errno);
    printf("socketpair_vsock=%d\n", syscall(360, 40, 1, 0, sv) == 0 ? 0 : errno);
    a[0] = 1; a[1] = 1; a[2] = 0;
    say("socketcall_socket", syscall(102, 1, a));
    printf("socketcall_socketpair=%d\n", syscall(102, 8, a) == 0 ? 0 : errno);
    a[0] = (unsigned long)-1; a[1] = 0; a[2] = 0;
    printf("socketcall_getsockname=%d\n", syscall(102, 6, a) == 0 ? 0 : errno);
    say("io_uring_setup", syscall(425, 4, 0));
    return 0;
}
"#;

    /// A 32-bit program under the installed profile gets the same family
    /// rules through its direct syscalls, and `ENOSYS` from the two
    /// `socketcall` sub-calls that create sockets.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_kernel_enforces_the_box_profile_on_the_compat_abi() {
        use std::os::unix::process::CommandExt as _;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("compat.c");
        let helper = dir.path().join("compat");
        std::fs::write(&source, COMPAT_HELPER).unwrap();
        let built = std::process::Command::new("gcc")
            .args(["-m32", "-static", "-o"])
            .arg(&helper)
            .arg(&source)
            .output();
        if !built.as_ref().is_ok_and(|out| out.status.success()) {
            eprintln!(
                "skipping the compat ABI proof: this host cannot build a static 32-bit program \
                 (gcc -m32 -static, from gcc-multilib): {built:?}"
            );
            return;
        }
        let program = box_program();
        let mut command = std::process::Command::new(&helper);
        // SAFETY: the hook makes only the `prctl` and `seccomp` syscalls.
        unsafe {
            command.pre_exec(move || install(program));
        }
        let output = command.output().unwrap();
        if !output.status.success() && output.stdout.is_empty() {
            eprintln!(
                "skipping the compat ABI proof: this kernel does not run 32-bit programs: {:?}",
                output.status
            );
            return;
        }
        let lines: BTreeMap<String, i32> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once('=')?;
                Some((name.to_string(), value.parse().ok()?))
            })
            .collect();
        let expected: BTreeMap<String, i32> = [
            ("socket_unix", 0),
            ("socket_inet", 0),
            ("socket_inet6", 0),
            ("socket_netlink_route", 0),
            ("socket_netlink_audit", libc::EPROTONOSUPPORT),
            ("socket_packet", libc::EAFNOSUPPORT),
            ("socket_vsock", libc::EAFNOSUPPORT),
            ("socketpair_unix", 0),
            ("socketpair_vsock", libc::EAFNOSUPPORT),
            ("socketcall_socket", libc::ENOSYS),
            ("socketcall_socketpair", libc::ENOSYS),
            // A sub-call that creates nothing reaches the kernel.
            ("socketcall_getsockname", libc::EBADF),
            ("io_uring_setup", libc::ENOSYS),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect();
        assert_eq!(lines, expected);
    }
}
