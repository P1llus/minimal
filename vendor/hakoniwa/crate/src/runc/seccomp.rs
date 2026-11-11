use libseccomp::{
    ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
};

use super::{error::*, sys};
use crate::{Container, Runctl};

pub(crate) fn load(container: &Container) -> Result<()> {
    let nnp = !container.runctl.contains(&Runctl::AllowNewPrivs);
    match &container.seccomp_filter {
        Some(filter) => load_imp(filter, nnp),
        None => match nnp {
            true => sys::set_no_new_privs(),
            _ => Ok(()),
        },
    }
}

fn load_imp(filter: &crate::seccomp::Filter, nnp: bool) -> Result<()> {
    // Create a new filter context.
    let default_scmp_action = translate_action(filter.default_action);
    let mut ctx = ScmpFilterContext::new(default_scmp_action)?;
    ctx.set_ctl_nnp(nnp)?;

    // Add architectures.
    for arch in &filter.architectures {
        let scmp_arch = translate_arch(*arch);
        ctx.add_arch(scmp_arch)?;
    }

    // Add rules.
    for rule in &filter.rules {
        let (action, sysname, argcmps) = (rule.action, &rule.sysname, &rule.argcmps);

        // If the action is the same as the default action, the rule is
        // redundant, skip it.
        let scmp_action = translate_action(action);
        if scmp_action == default_scmp_action {
            continue;
        }

        // If the syscall is not supported by the kernel, skip it.
        let scmp_syscall = match ScmpSyscall::from_name(sysname) {
            Ok(syscall) => syscall,
            Err(_) => continue,
        };

        // Adds a single rule for an unconditional action on a syscall.
        if argcmps.is_empty() {
            ctx.add_rule(scmp_action, scmp_syscall)?;
            continue;
        }

        // Adds a single rule for a conditional action on a syscall.
        let scmp_argcmps = translate_argcmps(argcmps);
        ctx.add_rule_conditional(scmp_action, scmp_syscall, &scmp_argcmps)?;
    }

    // Load the filter.
    Ok(ctx.load()?)
}

fn translate_action(action: crate::seccomp::Action) -> ScmpAction {
    match action {
        crate::seccomp::Action::Allow => ScmpAction::Allow,
        crate::seccomp::Action::Errno(v) => ScmpAction::Errno(v),
        crate::seccomp::Action::KillProcess => ScmpAction::KillProcess,
        crate::seccomp::Action::KillThread => ScmpAction::KillThread,
        crate::seccomp::Action::Log => ScmpAction::Log,
        crate::seccomp::Action::Notify => ScmpAction::Notify,
        crate::seccomp::Action::Trace(v) => ScmpAction::Trace(v),
        crate::seccomp::Action::Trap => ScmpAction::Trap,
    }
}

fn translate_arch(arch: crate::seccomp::Arch) -> ScmpArch {
    match arch {
        crate::seccomp::Arch::Native => ScmpArch::Native,
        crate::seccomp::Arch::X86 => ScmpArch::X86,
        crate::seccomp::Arch::X8664 => ScmpArch::X8664,
        crate::seccomp::Arch::X32 => ScmpArch::X32,
        crate::seccomp::Arch::Arm => ScmpArch::Arm,
        crate::seccomp::Arch::Aarch64 => ScmpArch::Aarch64,
        crate::seccomp::Arch::Loongarch64 => ScmpArch::Loongarch64,
        crate::seccomp::Arch::M68k => ScmpArch::M68k,
        crate::seccomp::Arch::Mips => ScmpArch::Mips,
        crate::seccomp::Arch::Mips64 => ScmpArch::Mips64,
        crate::seccomp::Arch::Mips64n32 => ScmpArch::Mips64N32,
        crate::seccomp::Arch::Mipsel => ScmpArch::Mipsel,
        crate::seccomp::Arch::Mipsel64 => ScmpArch::Mipsel64,
        crate::seccomp::Arch::Mipsel64n32 => ScmpArch::Mipsel64N32,
        crate::seccomp::Arch::Ppc => ScmpArch::Ppc,
        crate::seccomp::Arch::Ppc64 => ScmpArch::Ppc64,
        crate::seccomp::Arch::Ppc64le => ScmpArch::Ppc64Le,
        crate::seccomp::Arch::S390 => ScmpArch::S390,
        crate::seccomp::Arch::S390x => ScmpArch::S390X,
        crate::seccomp::Arch::Parisc => ScmpArch::Parisc,
        crate::seccomp::Arch::Parisc64 => ScmpArch::Parisc64,
        crate::seccomp::Arch::Riscv64 => ScmpArch::Riscv64,
        crate::seccomp::Arch::Sheb => ScmpArch::Sheb,
        crate::seccomp::Arch::Sh => ScmpArch::Sh,
    }
}

fn translate_argcmps(argcmps: &[crate::seccomp::ArgCmp]) -> Vec<ScmpArgCompare> {
    argcmps
        .iter()
        .map(|cmp| {
            let mut datum = cmp.datum_a;
            let op = match cmp.op {
                crate::seccomp::ArgCmpOp::Ne => ScmpCompareOp::NotEqual,
                crate::seccomp::ArgCmpOp::Lt => ScmpCompareOp::Less,
                crate::seccomp::ArgCmpOp::Le => ScmpCompareOp::LessOrEqual,
                crate::seccomp::ArgCmpOp::Eq => ScmpCompareOp::Equal,
                crate::seccomp::ArgCmpOp::Gt => ScmpCompareOp::Greater,
                crate::seccomp::ArgCmpOp::Ge => ScmpCompareOp::GreaterEqual,
                crate::seccomp::ArgCmpOp::MaskedEq => {
                    datum = cmp.datum_b;
                    ScmpCompareOp::MaskedEqual(cmp.datum_a)
                }
            };
            ScmpArgCompare::new(cmp.arg, op, datum)
        })
        .collect()
}
