//! `min finalize-install`: the one privileged step for every host need.
//! The user-namespace profile, names, the network policy engine and KVM
//! group membership are each probed on this host and carried in one script
//! only while they are missing.

use serde::Serialize;

use super::*;

/// What a finished host is told, with exit 0.
pub(crate) const FINISHED: &str =
    "Every part of the install is finished on this machine; there is nothing to run.";

/// The last line of a completed run that added no group membership.
pub(crate) const PICKED_UP: &str = "Running boxes pick this up on their next start.";

/// The last line of a completed run that installed the policy loader: a
/// daemon asks the loader once, when it starts.
pub(crate) const NEEDS_DAEMON_RESTART: &str = "A running daemon gets the network policy engine \
     at its next start. Its boxes end when it stops.";

/// The last line of a completed run that added the operator to the `kvm`
/// group: a membership is read at login, so no running process has it yet.
pub(crate) const NEEDS_LOGIN: &str = "KVM group membership starts at your next login: log out \
     and back in, or restart the daemon from a new login.";

/// The file route a caller without a terminal is pointed at.
pub(crate) const SCRIPT_POINTER: &str =
    "f=$(mktemp) && min finalize-install --show --script > \"$f\" && sudo sh \"$f\"";

/// The same route for `--undo`: the removal script, never the install's.
pub(crate) const UNDO_SCRIPT_POINTER: &str =
    "f=$(mktemp) && min finalize-install --undo --show --script > \"$f\" && sudo sh \"$f\"";

/// The heading the items no script can fix are listed under.
pub(crate) const CANNOT_HEADING: &str = "can't do on this machine:";

/// What a waiting item is listed as.
pub(crate) const WAITING: &str = "waiting on a daemon";

/// The `--show --json` document's schema.
pub(crate) const SCHEMA: &str = "min/v1/finalize-install";

/// The names item's cause when no daemon reports the DNS service's port
/// to point the resolver at.
const NO_PORT: &str = "no daemon is reachable to report the port its DNS service listens on";

/// How long the names item waits on the daemons for a port before it
/// reports itself waiting: one bounded read, so a probe from the installer
/// (`--show --script` in a shell with no timeout of its own) never hangs
/// on a daemon that accepts and does not answer.
const DAEMON_READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// The KVM item's id, read by the run to pick its closing line.
pub(crate) const KVM_ID: &str = "kvm-group";

/// The network policy engine item's id, read by the host line.
pub(crate) const POLICY_ENGINE_ID: &str = "policy-engine";

/// One item's state on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ItemState {
    /// Installed and holding: nothing to run.
    Done,
    /// Wanted: the script carries this item's step.
    Missing,
    /// Installed by another version: the script carries this item's step,
    /// and what the item gives is refused until it runs.
    OutOfDate,
    /// A host fact no script changes blocks it; `cause` says which.
    Cannot,
    /// Wanted, but not renderable until a daemon reports what the step
    /// needs; `cause` says what is awaited. Never blocks the other items.
    Waiting,
}

/// One part of the install, as `--show` lists it and the script carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Item {
    /// The stable id a caller matches on.
    pub id: &'static str,
    /// The plain-language name of what the item gives the operator.
    pub label: &'static str,
    pub state: ItemState,
    /// What the operator loses today, while the item is missing.
    pub today: Option<String>,
    /// `today` as separate lines, when it is a list: the summary sets one
    /// under the other, and the JSON keeps `today`'s single line.
    #[serde(skip)]
    today_list: Vec<String>,
    /// What the step changes, when it runs.
    pub step: Option<String>,
    /// Why no script can fix it, when none can.
    pub cause: Option<String>,
    /// The step's block in the script, while the item is missing.
    #[serde(skip)]
    script: Option<String>,
}

impl Item {
    fn done(id: &'static str, label: &'static str) -> Self {
        Item {
            id,
            label,
            state: ItemState::Done,
            today: None,
            today_list: Vec::new(),
            step: None,
            cause: None,
            script: None,
        }
    }

    fn missing(
        id: &'static str,
        label: &'static str,
        today: String,
        step: String,
        script: String,
    ) -> Self {
        Item {
            id,
            label,
            state: ItemState::Missing,
            today: Some(today),
            today_list: Vec::new(),
            step: Some(step),
            cause: None,
            script: Some(script),
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    fn out_of_date(
        id: &'static str,
        label: &'static str,
        today: String,
        step: String,
        script: String,
    ) -> Self {
        Item {
            state: ItemState::OutOfDate,
            ..Item::missing(id, label, today, step, script)
        }
    }

    fn cannot(id: &'static str, label: &'static str, cause: String) -> Self {
        Item {
            id,
            label,
            state: ItemState::Cannot,
            today: None,
            today_list: Vec::new(),
            step: None,
            cause: Some(cause),
            script: None,
        }
    }

    fn waiting(id: &'static str, label: &'static str, cause: String) -> Self {
        Item {
            id,
            label,
            state: ItemState::Waiting,
            today: None,
            today_list: Vec::new(),
            step: None,
            cause: Some(cause),
            script: None,
        }
    }
}

/// The `--show --json` document.
#[derive(Serialize)]
struct Report<'a> {
    schema: &'static str,
    finished: bool,
    items: &'a [Item],
}

/// Every item this host has, probed: the one source the summary, the
/// JSON and the script render from, so what `--show` names is what a run
/// installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub items: Vec<Item>,
}

impl Plan {
    /// Whether every item is done.
    pub(crate) fn finished(&self) -> bool {
        self.items.iter().all(|item| item.state == ItemState::Done)
    }

    /// The items the script carries a step for.
    fn missing(&self) -> impl Iterator<Item = &Item> {
        self.items
            .iter()
            .filter(|item| matches!(item.state, ItemState::Missing | ItemState::OutOfDate))
    }

    fn cannot(&self) -> impl Iterator<Item = &Item> {
        self.items
            .iter()
            .filter(|item| item.state == ItemState::Cannot)
    }

    /// The exit status `--show --json` and a run that runs nothing end
    /// with: 0 once every item is done, 1 while any is missing, out of
    /// date, waiting or blocked. None of those is a finished host.
    pub(crate) fn exit_code(&self) -> i32 {
        i32::from(!self.finished())
    }

    /// Whether the script adds the operator to the `kvm` group, which
    /// decides the closing line: a membership is read at login.
    pub(crate) fn adds_kvm_group(&self) -> bool {
        self.missing().any(|item| item.id == KVM_ID)
    }

    /// Whether the script installs an item other than the `kvm` group:
    /// one a running box picks up at its next start.
    pub(crate) fn installs_other_items(&self) -> bool {
        self.missing()
            .any(|item| item.id != KVM_ID && item.id != POLICY_ENGINE_ID)
    }

    /// Whether the script installs or renews the policy loader, which a
    /// running daemon only uses after a restart.
    pub(crate) fn installs_policy_engine(&self) -> bool {
        self.missing().any(|item| item.id == POLICY_ENGINE_ID)
    }

    /// The one script a run executes and `--show --script` prints: one
    /// header over the missing items' blocks, in order. `None` while no
    /// item is missing — a finished host, or one whose every open item no
    /// script can fix.
    pub(crate) fn script(&self) -> Option<String> {
        let missing: Vec<&Item> = self.missing().collect();
        if missing.is_empty() {
            return None;
        }
        let labels: Vec<&str> = missing.iter().map(|item| item.label).collect();
        let what = format!(
            "Finish the Minimal install on this host: {}",
            labels.join(", ")
        );
        let mut script = crate::resolver::script_header(&what, crate::resolver::FINALIZE_SHOWN_BY);
        for item in missing {
            script.push('\n');
            script.push_str(item.script.as_deref().unwrap_or_default());
        }
        Some(script)
    }

    /// The summary: a ✓/✗ line per item, what a missing one costs today
    /// and what the step changes, and the items no script can fix under
    /// their own heading. [`FINISHED`] alone on a finished host.
    pub(crate) fn summary(&self) -> String {
        if self.finished() {
            return format!("{FINISHED}\n");
        }
        let mut out = String::from("install status on this machine:\n");
        for item in self
            .items
            .iter()
            .filter(|item| item.state != ItemState::Cannot)
        {
            match item.state {
                ItemState::Done => out.push_str(&format!("  ✓ {}\n", item.label)),
                ItemState::Waiting => out.push_str(&format!(
                    "  ✗ {} — {WAITING} ({})\n",
                    item.label,
                    item.cause.as_deref().unwrap_or_default()
                )),
                _ => {
                    out.push_str(&format!("  ✗ {}\n", item.label));
                    match (&item.today, item.today_list.as_slice()) {
                        (Some(today), []) => out.push_str(&format!("      today: {today}\n")),
                        (Some(_), list) => {
                            out.push_str(&format!(
                                "      today: {} thing{} to fix:\n",
                                list.len(),
                                if list.len() == 1 { "" } else { "s" }
                            ));
                            for line in list {
                                out.push_str(&format!("        - {line}\n"));
                            }
                        }
                        (None, _) => {}
                    }
                    if let Some(step) = &item.step {
                        out.push_str(&format!("      this step: {step}\n"));
                    }
                }
            }
        }
        let cannot: Vec<&Item> = self.cannot().collect();
        if !cannot.is_empty() {
            out.push_str(CANNOT_HEADING);
            out.push('\n');
            for item in cannot {
                out.push_str(&format!(
                    "  ✗ {} — {}\n",
                    item.label,
                    item.cause.as_deref().unwrap_or_default()
                ));
            }
        }
        out
    }

    /// The `--show --json` document.
    pub(crate) fn json(&self) -> String {
        serde_json_lenient::to_string(&Report {
            schema: SCHEMA,
            finished: self.finished(),
            items: &self.items,
        })
        .expect("the report serializes: strings and bools only")
    }
}

/// How a run elevates, decided from whether a terminal can answer a
/// prompt: with one, `sudo sh <file>`; without one, `sudo -n sh <file>`,
/// and only when `sudo -n` can run quietly — otherwise the run is refused
/// with the file route, so no caller hangs on a prompt nothing answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunDecision {
    /// Run the script with these arguments ahead of the file's path.
    Run(Vec<&'static str>),
    /// Run nothing: print `message` and exit with `exit`.
    Refuse { message: String, exit: i32 },
}

/// [`RunDecision`] for a run with (`stdin_is_tty`) or without a terminal;
/// `sudo_runs_quietly` is whether `sudo -n true` succeeded, consulted only
/// without one. `pointer` is the file route the refusal names: the
/// install's or `--undo`'s, whichever the caller runs.
pub(crate) fn run_decision(
    stdin_is_tty: bool,
    sudo_runs_quietly: bool,
    pointer: &str,
) -> RunDecision {
    if stdin_is_tty {
        RunDecision::Run(vec!["sudo", "sh"])
    } else if sudo_runs_quietly {
        RunDecision::Run(vec!["sudo", "-n", "sh"])
    } else {
        RunDecision::Refuse {
            message: format!(
                "sudo needs a password and no terminal is attached to ask on; run the \
                 step yourself: {pointer}"
            ),
            exit: 1,
        }
    }
}

/// `min finalize-install`: probe every part of the install this host
/// needs, name what is missing, and run the one script that installs it
/// with `sudo sh <file>` as the only prompt. `--show` prints the summary
/// and runs nothing; `--show --script` adds the script on stdout; `--show
/// --json` prints the report and exits non-zero while anything is
/// missing; `--undo` removes everything the step installed.
pub async fn cmd_finalize_install(
    global: &GlobalArgs,
    args: FinalizeInstallArgs,
) -> Result<(), anyhow::Error> {
    if let Some(message) = undo_flags_refusal(&args) {
        use clap::CommandFactory as _;
        Cli::command()
            .error(clap::error::ErrorKind::MissingRequiredArgument, message)
            .exit();
    }
    if args.undo {
        return cmd_finalize_install_undo(args.show);
    }
    let plan = plan_for_this_host(global).await;
    if args.json {
        println!("{}", plan.json());
        if plan.exit_code() != 0 {
            exit(plan.exit_code());
        }
        return Ok(());
    }
    if args.show {
        if args.script {
            eprint!("{}", plan.summary());
            if let Some(script) = plan.script() {
                print!("{script}");
            }
        } else {
            print!("{}", plan.summary());
        }
        return Ok(());
    }
    print!("{}", plan.summary());
    let Some(script) = plan.script() else {
        // Nothing a script can do here: a finished host (exit 0), or one
        // whose every open item is blocked or waiting (exit 1).
        if plan.exit_code() != 0 {
            exit(plan.exit_code());
        }
        return Ok(());
    };
    // The installed service runs as one operator; replacing another user's
    // is not this user's call (spec 18's open question on several users).
    if let Some(refusal) = crate::resolver::other_operator_refusal_on_this_host() {
        eprintln!("min finalize-install: {refusal}");
        exit(1);
    }
    run_as_root(&script, SCRIPT_POINTER)?;
    print!(
        "{}",
        closing_lines(
            plan.installs_other_items(),
            plan.installs_policy_engine(),
            plan.adds_kvm_group(),
        )
    );
    Ok(())
}

/// The lines a completed run ends with: [`PICKED_UP`] when the script
/// installed items other than the `kvm` group, [`NEEDS_LOGIN`] when it
/// added the operator to that group, both — items line first, the login
/// line last — when both apply.
pub(crate) fn closing_lines(
    installed_other_items: bool,
    installed_policy_engine: bool,
    added_kvm_group: bool,
) -> String {
    let mut out = String::new();
    if installed_other_items {
        out.push_str(PICKED_UP);
        out.push('\n');
    }
    if installed_policy_engine {
        out.push_str(NEEDS_DAEMON_RESTART);
        out.push('\n');
    }
    if added_kvm_group {
        out.push_str(NEEDS_LOGIN);
        out.push('\n');
    }
    out
}

/// Why `--undo` refuses its flags, when it does: `--undo` runs the removal
/// or, with `--show --script`, prints it; `--show` alone has no summary to
/// show for a removal, so it is refused rather than guessed at.
pub(crate) fn undo_flags_refusal(args: &FinalizeInstallArgs) -> Option<&'static str> {
    (args.undo && args.show && !args.script)
        .then_some("--undo takes --show only with --script: `min finalize-install --undo --show --script` prints the removal script")
}

/// `min finalize-install --undo`: remove everything the step installs on
/// this host (NET-122's removal). The script reads no daemon, so it works
/// with nothing running, and every step of it tolerates what is already
/// gone, so it succeeds on a clean host. With `--show --script` it prints
/// the script and runs nothing.
fn cmd_finalize_install_undo(show: bool) -> Result<(), anyhow::Error> {
    let script = crate::resolver::undo_command();
    if show {
        print!("{script}");
        return Ok(());
    }
    run_as_root(&script, UNDO_SCRIPT_POINTER)
}

/// Exits with `code` once stdout and stderr are flushed: `std::process::exit`
/// runs no destructor, and a piped stdout is block-buffered, so the report
/// or summary printed just before it would otherwise never reach its reader
/// (`min finalize-install --show --json > report.json` on an unfinished
/// host would write an empty file).
fn exit(code: i32) -> ! {
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code)
}

/// Writes `script` to a private temp file — created exclusively, mode
/// 0600, so no other user can read or swap it.
pub(crate) fn write_private_script(script: &str) -> Result<tempfile::NamedTempFile, anyhow::Error> {
    use std::io::Write as _;
    let mut file = tempfile::Builder::new()
        .prefix("min-finalize-install-")
        .suffix(".sh")
        .tempfile()
        .context("min finalize-install: could not create a private file for the script")?;
    file.write_all(script.as_bytes())
        .and_then(|()| file.flush())
        .context("min finalize-install: could not write the script")?;
    Ok(file)
}

/// Runs a host-setup script as root: written by [`write_private_script`]
/// and run under the elevation [`run_decision`] picks, whose prompt is the
/// one privilege prompt. The file is removed once the script exits, and
/// the process exits with the script's status. The script is the one
/// `--show --script` prints, byte for byte.
fn run_as_root(script: &str, pointer: &str) -> Result<(), anyhow::Error> {
    let stdin_is_tty = std::io::stdin().is_terminal();
    let sudo_runs_quietly = !stdin_is_tty
        && std::process::Command::new("sudo")
            .args(["-n", "true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
    let argv = match run_decision(stdin_is_tty, sudo_runs_quietly, pointer) {
        RunDecision::Run(argv) => argv,
        RunDecision::Refuse {
            message,
            exit: code,
        } => {
            eprintln!("{message}");
            exit(code);
        }
    };
    let file = write_private_script(script)?;
    let status = std::process::Command::new(argv[0])
        .args(&argv[1..])
        .arg(file.path())
        .status()
        .context("min finalize-install: could not start sudo to run the script")?;
    // Removed before the exit below, which runs no destructor.
    file.close()
        .context("min finalize-install: could not remove the script")?;
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// Every item this host has, probed.
async fn plan_for_this_host(global: &GlobalArgs) -> Plan {
    plan_over(
        other_items_for_this_host(global),
        names_item_on_this_host(global).await,
    )
}

/// The plan in the order the summary lists it: the user-namespace profile,
/// the names item, then the rest.
fn plan_over(mut items: Vec<Item>, names: Item) -> Plan {
    let at = items
        .iter()
        .take_while(|item| item.id == "userns-profile")
        .count();
    items.insert(at, names);
    Plan { items }
}

/// Every item of this host's plan other than names, under the one per-host
/// scoping both readers share: the user-namespace profile unless the
/// configured provider is the Linux VM provider, then the `kvm` group
/// membership for that provider or the network policy engine for the
/// native one. [`plan_for_this_host`] slots the names item in among them
/// and the host line ([`host_install_for_this_host`]) reads them whole, so
/// the two read the same items by construction. Every item is Linux-only,
/// so a macOS host reads none.
fn other_items_for_this_host(global: &GlobalArgs) -> Vec<Item> {
    #[cfg(target_os = "linux")]
    {
        if global.use_minvmd() {
            vec![linux::kvm_item_on_this_host()]
        } else {
            linux::userns_item_on_this_host()
                .into_iter()
                .chain([linux::policy_engine_item_on_this_host()])
                .collect()
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = global;
        Vec::new()
    }
}

/// The install facts the host line reads beyond the surface verdict: the
/// state of the items [`other_items_for_this_host`] scopes for this host,
/// probed from this host alone. No daemon is read: the names item is the
/// surface verdict the line already holds. Every item is Linux-only, so a
/// macOS host reads the default.
pub(crate) fn host_install_for_this_host(global: &GlobalArgs) -> crate::resolver::HostInstall {
    let items = other_items_for_this_host(global);
    crate::resolver::HostInstall {
        other_items_unfinished: items.iter().any(|item| item.state != ItemState::Done),
        policy_loader_out_of_date: items
            .iter()
            .any(|item| item.id == POLICY_ENGINE_ID && item.state == ItemState::OutOfDate),
    }
}

/// The names item's id and label.
const NAMES_ID: &str = "names";
const NAMES_LABEL: &str =
    "DNS names for boxes (<box>.min.internal) in every program on this machine";

/// The names item from its verdict: done, missing with the facts the
/// advisory names and the step that installs them, or blocked by the
/// note's cause.
pub(crate) fn names_item(verdict: crate::resolver::NamesVerdict, port: u16) -> Item {
    use crate::resolver::NamesVerdict;
    match verdict {
        NamesVerdict::Done => Item::done(NAMES_ID, NAMES_LABEL),
        NamesVerdict::Blocked { note } => Item::cannot(
            NAMES_ID,
            NAMES_LABEL,
            note.trim_start_matches("note: ")
                .trim_end_matches('.')
                .to_string(),
        ),
        NamesVerdict::Missing { facts, install } => {
            let zone = crate::resolver::ZONE;
            // The range clause closes the macOS list, so the service
            // clause joins with a comma there and with "and" on Linux,
            // where it is the last one.
            let step = if cfg!(target_os = "macos") {
                format!(
                    "sends *.{zone} lookups to Minimal's DNS service on \
                     127.0.0.1:{port}{}, and reserves the box IPs ({}) on this \
                     machine's loopback at every boot",
                    if install.is_some() {
                        ", installs that service"
                    } else {
                        ""
                    },
                    crate::resolver::range_text()
                )
            } else {
                // The boot unit is part of the step: without it the
                // setting is gone after the next restart.
                format!(
                    "configures this machine's DNS (systemd-resolved) to send \
                     *.{zone} lookups to Minimal's DNS service on \
                     127.0.0.1:{port} at every boot{}",
                    if install.is_some() {
                        " and installs that service"
                    } else {
                        ""
                    }
                )
            };
            // The JSON's `today` is the facts on one line; the list, its
            // count and its indentation are the summary's alone.
            Item {
                today_list: facts.clone(),
                ..Item::missing(
                    NAMES_ID,
                    NAMES_LABEL,
                    facts.join("; "),
                    step,
                    crate::resolver::names_steps(port, install.as_ref()),
                )
            }
        }
    }
}

/// The names item on this host: its verdict over this host's reads and
/// the answerer port `min ls` reads — each listed VM's own state from its
/// VM host daemon's control socket (NET-138), else the daemon's listing.
/// It never starts a daemon: with none reachable, or none that reports a
/// port, there is no port to point a script at, and the item says so. The
/// daemon reads are one bounded attempt ([`DAEMON_READ_DEADLINE`]): a
/// daemon that does not answer in time is one that is not reachable.
async fn names_item_on_this_host(global: &GlobalArgs) -> Item {
    let read = tokio::time::timeout(DAEMON_READ_DEADLINE, answerer_port_from_daemons(global)).await;
    let (answerer, held_no_channel) = match read {
        Ok(found) => found,
        Err(_) => {
            return Item::waiting(
                NAMES_ID,
                NAMES_LABEL,
                format!(
                    "no daemon answered within {}s",
                    DAEMON_READ_DEADLINE.as_secs()
                ),
            );
        }
    };
    let Some((port, bound)) = answerer else {
        // No port to point a script at yet: the item waits on a daemon,
        // and never blocks the items the script can carry without one.
        let cause = match held_no_channel {
            Some(port) => crate::resolver::port_held_no_channel_warning(port),
            None => NO_PORT.to_string(),
        };
        return Item::waiting(NAMES_ID, NAMES_LABEL, cause);
    };
    let (detection, answerer_step) = crate::cmd::session::advisory_host_reads(global).await;
    // The range read the live-surface verdict makes, so the item names the
    // same missing facts the surface line reports.
    let range_present =
        crate::resolver::live_name_surface_with_range_at(&detection, Some(port), bound)
            .await
            .and_then(|verdict| verdict.range_present);
    let (hook, blocker, range_step) = &detection;
    let verdict = crate::resolver::names_verdict_at(
        hook,
        port,
        false,
        range_present,
        range_step,
        &answerer_step,
        blocker.as_deref(),
    );
    names_item(verdict, port)
}

/// The answerer port the daemons report (with whether it is bound), and
/// the port a listing holds with no channel behind it, over every VM's
/// listing (`min ls`'s read).
async fn answerer_port_from_daemons(global: &GlobalArgs) -> (Option<(u16, bool)>, Option<u16>) {
    let listings = ls_listings_best_effort(global).await;
    let mut answerer = None;
    let mut held_no_channel = None;
    for listing in &listings {
        let (port, bound, held) =
            match crate::cmd::session::vm_host_answerer_status_at(listing.control_sock.clone())
                .await
            {
                Some(status) => {
                    let read = crate::resolver::host_answerer_read(status).await;
                    (read.port, read.answerer_bound, read.held_no_channel)
                }
                None => (
                    listing.resp.zone_answerer_port,
                    listing.resp.answerer_bound,
                    false,
                ),
            };
        match port {
            // A port no channel reaches is no daemon's answerer: say that
            // fact instead of a script, unless another listing reports a
            // port that answers.
            Some(port) if held => held_no_channel = held_no_channel.or(Some(port)),
            Some(port) => {
                answerer = Some((port, bound));
                break;
            }
            None => {}
        }
    }
    (answerer, held_no_channel)
}

/// The Linux-only items: the user-namespace profile, the network policy
/// engine and KVM group membership. Each is pure over pre-read facts, so its
/// table is unit-tested on every platform the suite runs on.
#[cfg(any(test, target_os = "linux"))]
pub(crate) mod linux {
    use super::*;
    use crate::resolver::{
        ANSWERER_PROGRAM_DIR, APPARMOR_DIR, APPARMOR_PROFILE_RECORD, EARLIER_INSTALL_CGROUP,
        EARLIER_INSTALL_FILES, KVM_GROUP_RECORD, POLICY_LOADER_SYSTEMD_UNIT,
        POLICY_LOADER_UNIT_SERVICE_PATH, POLICY_LOADER_UNIT_SOCKET_PATH,
    };
    use paths::POLICY_LOADER_PROGRAM;

    pub(crate) const USERNS_ID: &str = "userns-profile";
    const USERNS_LABEL: &str = "the private sandbox every box runs in";
    const POLICY_ENGINE_LABEL: &str = "network policy engine";
    const KVM_LABEL: &str = "KVM access for the Linux VM provider";

    /// The profile the step installs, the very file the checkout ships.
    const APPARMOR_PROFILE: &str = include_str!("../../../../packaging/apparmor/minimald");
    /// Its tunable: the binary paths the profile attaches to.
    const APPARMOR_TUNABLE: &str = include_str!("../../../../packaging/apparmor/tunables/minimald");
    const PROFILE_HEREDOC: &str = "MINIMAL_APPARMOR_PROFILE_EOF";
    const TUNABLE_HEREDOC: &str = "MINIMAL_APPARMOR_TUNABLE_EOF";

    /// The install locations the stock tunable already attaches the
    /// profile to; a `minimald` elsewhere needs its path appended. The
    /// tunable's `@{HOME}/.local/bin/minimald` reaches only the homes
    /// AppArmor's `<tunables/home>` expands `@{HOME}` to: `/root/` and
    /// `@{HOMEDIRS}/*/`, `/home/` by default. A home elsewhere (`/srv/home`,
    /// an NFS mount) is not covered, so its daemon counts as any other path.
    fn daemon_in_stock_path(daemon: &str, home: Option<&str>) -> bool {
        daemon == "/usr/bin/minimald"
            || daemon == "/usr/local/bin/minimald"
            || home.is_some_and(|home| {
                let home = home.trim_end_matches('/');
                stock_home(home) && daemon == format!("{home}/.local/bin/minimald")
            })
    }

    /// Whether `home` is one `@{HOME}` expands to on a stock host.
    fn stock_home(home: &str) -> bool {
        let home = home.trim_end_matches('/');
        home == "/root"
            || home
                .strip_prefix("/home/")
                .is_some_and(|user| !user.is_empty() && !user.contains('/'))
    }

    /// The facts the user-namespace item decides on.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub(crate) struct UsernsFacts {
        /// `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`, when readable.
        pub apparmor_restrict: Option<String>,
        /// `/proc/sys/user/max_user_namespaces`, when readable.
        pub max_user_namespaces: Option<String>,
        /// Whether `/etc/apparmor.d/minimald` exists.
        pub profile_installed: bool,
        /// Whether the installed tunables name `daemon`.
        pub tunables_name_daemon: bool,
        /// Whether `apparmor_parser` is on this host.
        pub parser_present: bool,
        /// The `minimald` this host runs, absolute, when it is found beside
        /// this `min`.
        pub daemon: Option<String>,
        /// This user's home (`$HOME`), which decides whether the stock
        /// tunable's `@{HOME}` entry reaches a daemon under it.
        pub home: Option<String>,
    }

    /// The user-namespace item over `facts`: `None` on a host whose kernel
    /// does not restrict unprivileged user namespaces (nothing to install),
    /// done when the profile is loaded and attaches this host's daemon,
    /// and blocked where user namespaces are off altogether or no parser
    /// can load a profile.
    pub(crate) fn userns_item_over(facts: &UsernsFacts) -> Option<Item> {
        let max = facts
            .max_user_namespaces
            .as_deref()
            .and_then(|s| s.trim().parse::<u64>().ok());
        if max.is_none_or(|n| n == 0) {
            return Some(Item::cannot(
                USERNS_ID,
                USERNS_LABEL,
                "user namespaces are disabled on this machine (user.max_user_namespaces \
                 is 0 or missing), and no profile can turn them on"
                    .to_string(),
            ));
        }
        let restricted = facts
            .apparmor_restrict
            .as_deref()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .is_some_and(|v| v != 0);
        if !restricted {
            return None;
        }
        let daemon = facts.daemon.as_deref();
        let home = facts.home.as_deref();
        let attached =
            daemon.is_none_or(|d| daemon_in_stock_path(d, home) || facts.tunables_name_daemon);
        if facts.profile_installed && attached {
            return Some(Item::done(USERNS_ID, USERNS_LABEL));
        }
        if !facts.parser_present {
            return Some(Item::cannot(
                USERNS_ID,
                USERNS_LABEL,
                "this machine restricts unprivileged user namespaces but has no \
                 apparmor_parser to load the profile that allows them for minimald"
                    .to_string(),
            ));
        }
        let extra = daemon.filter(|d| !daemon_in_stock_path(d, home));
        // The path is written into an AppArmor tunable, whose values are
        // whitespace-separated and `#`-commented, and into a single-quoted
        // shell word: a path those cannot carry is a fact no script fixes.
        if extra.is_some_and(|d| d.contains(['\'', '#']) || d.contains(char::is_whitespace)) {
            return Some(Item::cannot(
                USERNS_ID,
                USERNS_LABEL,
                format!(
                    "minimald's path ({}) holds a quote, a hash or whitespace, which an \
                     AppArmor tunable cannot name; install it under a plain path",
                    extra.unwrap_or_default()
                ),
            ));
        }
        Some(Item::missing(
            USERNS_ID,
            USERNS_LABEL,
            "no box can start on this machine: it restricts unprivileged user \
             namespaces (Ubuntu 24.04+), and minimald has no profile that allows them"
                .to_string(),
            "installs an AppArmor profile that allows user namespaces for minimald \
             alone and confines nothing"
                .to_string(),
            userns_steps(extra),
        ))
    }

    /// The step's block: the tunable and the profile written from the bytes
    /// this script carries, the daemon's path appended where the stock
    /// tunable does not name it, and the profile loaded.
    fn userns_steps(extra_daemon_path: Option<&str>) -> String {
        let mut script = format!(
            "# The user-namespace profile: lets minimald create the user namespace every\n\
             # box runs in, for minimald alone, and confines nothing.\n\
             mkdir -p {APPARMOR_DIR}/tunables\n\
             cat > {APPARMOR_DIR}/tunables/minimald <<\\{TUNABLE_HEREDOC}\n\
             {APPARMOR_TUNABLE}\
             {TUNABLE_HEREDOC}\n\
             cat > {APPARMOR_DIR}/minimald <<\\{PROFILE_HEREDOC}\n\
             {APPARMOR_PROFILE}\
             {PROFILE_HEREDOC}\n\
             chmod 0644 {APPARMOR_DIR}/tunables/minimald {APPARMOR_DIR}/minimald\n"
        );
        if let Some(path) = extra_daemon_path {
            script.push_str(&format!(
                "# Attach the profile to this host's minimald too. This replaces the local\n\
                 # attachment set (what install-apparmor-profile.sh --path wrote, if anything).\n\
                 mkdir -p {APPARMOR_DIR}/tunables/minimald.d\n\
                 printf '@{{minimald_bin}} += %s\\n' '{path}' > \
                 {APPARMOR_DIR}/tunables/minimald.d/local\n"
            ));
        }
        script.push_str(&format!(
            "apparmor_parser --replace {APPARMOR_DIR}/minimald\n\
             # The record marks the profile as this step's, so --undo removes it; one\n\
             # installed another way is left alone.\n\
             mkdir -p /var/lib/minimal\n\
             : > {APPARMOR_PROFILE_RECORD}\n"
        ));
        script
    }

    /// The `minimald` beside this `min`, when there is one.
    fn daemon_beside_min() -> Option<String> {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("minimald")))
            .filter(|path| path.is_file())
            .and_then(|path| path.to_str().map(str::to_owned))
    }

    /// [`userns_item_over`] this host's reads.
    pub(crate) fn userns_item_on_this_host() -> Option<Item> {
        let daemon = daemon_beside_min();
        let tunables_name_daemon = daemon.as_deref().is_some_and(|d| {
            [
                format!("{APPARMOR_DIR}/tunables/minimald"),
                format!("{APPARMOR_DIR}/tunables/minimald.d/local"),
            ]
            .iter()
            .any(|file| std::fs::read_to_string(file).is_ok_and(|text| text.contains(d)))
        });
        let parser_present = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
            .iter()
            .map(|dir| std::path::Path::new(dir).join("apparmor_parser"))
            .chain(
                std::env::var_os("PATH")
                    .map(|path| {
                        std::env::split_paths(&path)
                            .map(|dir| dir.join("apparmor_parser"))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            )
            .any(|candidate| candidate.is_file());
        userns_item_over(&UsernsFacts {
            apparmor_restrict: std::fs::read_to_string(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            )
            .ok(),
            max_user_namespaces: std::fs::read_to_string("/proc/sys/user/max_user_namespaces").ok(),
            profile_installed: std::path::Path::new(&format!("{APPARMOR_DIR}/minimald")).is_file(),
            tunables_name_daemon,
            parser_present,
            daemon,
            home: std::env::var("HOME").ok(),
        })
    }

    /// The oldest kernel the policy engine's programs load on.
    const POLICY_ENGINE_KERNEL: (u32, u32) = (5, 19);

    /// How long a `minimald` gets to print its loader identity. A binary
    /// from a version without that mode may do anything with the arguments,
    /// and this runs at every session start.
    const IDENTITY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

    /// The delimiter both unit files are written under. It is quoted in the
    /// script, so nothing in a unit expands.
    const UNIT_HEREDOC: &str = "MINIMAL_UNIT_EOF";

    /// The installed loader copy as `lstat` reads it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct LoaderCopy {
        /// A regular file, not a symlink or a directory.
        pub(crate) regular_file: bool,
        pub(crate) uid: u32,
        /// The permission bits: `st_mode & 0o7777`.
        pub(crate) mode: u32,
    }

    /// The facts the network policy engine item decides on.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct PolicyEngineFacts {
        /// The account the loader's socket is installed for.
        pub(crate) operator: String,
        /// `/run/systemd/system` is a directory: systemd is PID 1.
        pub(crate) systemd: bool,
        /// `/sys/fs/cgroup/cgroup.controllers` exists: cgroup v2 is mounted
        /// there.
        pub(crate) cgroup_v2: bool,
        /// The kernel release, as `uname -r` prints it.
        pub(crate) kernel_release: String,
        /// The `minimald` beside this `min`, absolute, when there is one.
        pub(crate) daemon: Option<String>,
        /// The loader identity that `minimald` prints.
        pub(crate) daemon_identity: Option<String>,
        /// The copy at [`POLICY_LOADER_PROGRAM`], when anything is there.
        pub(crate) copy: Option<LoaderCopy>,
        /// The loader identity the copy prints.
        pub(crate) copy_identity: Option<String>,
        /// The installed socket unit's text, when the file reads.
        pub(crate) socket_unit: Option<String>,
        /// The installed service unit's text, when the file reads.
        pub(crate) service_unit: Option<String>,
        /// `systemctl is-active` says the socket unit is active.
        pub(crate) socket_active: bool,
        /// What an earlier version installed and is still there.
        pub(crate) earlier_pieces: Vec<String>,
    }

    /// The major and minor version a kernel release starts with.
    pub(crate) fn kernel_version(release: &str) -> Option<(u32, u32)> {
        let number = |part: &str| {
            let digits = part
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(part.len());
            part[..digits].parse::<u32>().ok()
        };
        let mut parts = release.trim().split('.');
        Some((number(parts.next()?)?, number(parts.next()?)?))
    }

    /// The identity in what `minimald __policy-loader --identity` printed:
    /// one line, `abi=<decimal> object=<64 hex digits> loader=<64 hex
    /// digits>`: the layouts, the programs, and the loader's own code.
    /// Anything else is a binary without that mode, or a loader from
    /// before the line had all three.
    pub(crate) fn identity_line(stdout: &str) -> Option<&str> {
        let line = stdout.strip_suffix('\n').unwrap_or(stdout);
        let (abi, rest) = line.strip_prefix("abi=")?.split_once(" object=")?;
        let (object, loader) = rest.split_once(" loader=")?;
        let hash = |text: &str| text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit());
        let well_formed = !abi.is_empty()
            && abi.bytes().all(|b| b.is_ascii_digit())
            && hash(object)
            && hash(loader);
        well_formed.then_some(line)
    }

    /// The network policy engine item over `facts`. Blocked where the host
    /// cannot run the loader or the script cannot name what it installs.
    /// Done when the root-owned copy is this host's minimald, both units
    /// are the ones this version writes for the operator, the socket
    /// listens, and nothing of an earlier version is left. Out of date when
    /// an installed loader is another version's. Missing otherwise.
    pub(crate) fn policy_engine_item_over(facts: &PolicyEngineFacts) -> Item {
        let cannot = |cause: String| Item::cannot(POLICY_ENGINE_ID, POLICY_ENGINE_LABEL, cause);
        if !facts.systemd {
            return cannot(
                "systemd is not this machine's init system, and the network policy loader \
                 is a systemd socket unit"
                    .to_string(),
            );
        }
        if !facts.cgroup_v2 {
            return cannot(
                "no cgroup2 filesystem is mounted at /sys/fs/cgroup, which the network \
                 policy engine attaches to"
                    .to_string(),
            );
        }
        if kernel_version(&facts.kernel_release).is_some_and(|v| v < POLICY_ENGINE_KERNEL) {
            return cannot(format!(
                "this machine's kernel ({}) is older than {}.{}, which the network policy \
                 engine needs",
                facts.kernel_release.trim(),
                POLICY_ENGINE_KERNEL.0,
                POLICY_ENGINE_KERNEL.1,
            ));
        }
        let Some(daemon) = facts.daemon.as_deref() else {
            return cannot(
                "no minimald is installed beside this min, so there is no network policy \
                 loader to install"
                    .to_string(),
            );
        };
        // The path goes into the root script inside double quotes.
        if daemon.contains(['\'', '"', '$', '`', '\\', '\n', '\r', '\0']) {
            return cannot(format!(
                "minimald's path ({daemon}) holds a quote, a `$`, a backtick, a backslash or \
                 a line break, which the install script cannot quote; install it under a \
                 plain path"
            ));
        }
        let operator = facts.operator.as_str();
        if operator.is_empty() {
            return cannot(
                "could not read this process's user name, so there is no account to \
                 install the network policy loader for"
                    .to_string(),
            );
        }
        // The name goes into a unit file, where systemd expands `%`.
        if !operator
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            return cannot(format!(
                "this process's user name ({operator:?}) carries a character outside \
                 [A-Za-z0-9._-], which a systemd unit cannot name"
            ));
        }
        // Installing this minimald would leave a loader that never matches.
        let Some(daemon_identity) = facts.daemon_identity.as_deref() else {
            return cannot(format!(
                "the minimald beside this min ({daemon}) does not report a network policy \
                 loader, so it is from another version than this min; install both from \
                 one release"
            ));
        };

        let copy_trusted = facts
            .copy
            .is_some_and(|copy| copy.regular_file && copy.uid == 0 && copy.mode & 0o022 == 0);
        let copy_current = facts.copy_identity.as_deref() == Some(daemon_identity);
        let units_current = facts.socket_unit.as_deref()
            == Some(crate::resolver::policy_loader_socket_unit(operator).as_str())
            && facts.service_unit.as_deref()
                == Some(crate::resolver::policy_loader_service_unit().as_str());
        if copy_trusted
            && copy_current
            && units_current
            && facts.socket_active
            && facts.earlier_pieces.is_empty()
        {
            return Item::done(POLICY_ENGINE_ID, POLICY_ENGINE_LABEL);
        }

        let step = format!(
            "installs a root-owned copy of minimald at {POLICY_LOADER_PROGRAM} and the \
             systemd units that run it as the network policy loader for {operator}'s \
             daemon{}",
            if facts.earlier_pieces.is_empty() {
                ""
            } else {
                ", and removes what an earlier version installed"
            }
        );
        let script = policy_engine_steps(operator, daemon);
        if facts.copy.is_some()
            && facts.socket_unit.is_some()
            && facts.service_unit.is_some()
            && !copy_current
        {
            return Item::out_of_date(
                POLICY_ENGINE_ID,
                POLICY_ENGINE_LABEL,
                "the installed network policy loader is from another version of Minimal, \
                 so boxes with a network policy are refused until `min finalize-install` \
                 runs"
                    .to_string(),
                step,
                script,
            );
        }
        const REFUSED: &str = "boxes with a network policy are refused";
        let today = if facts.copy.is_none() {
            format!("{REFUSED}: the network policy loader is not installed")
        } else if !copy_trusted {
            format!(
                "{REFUSED}: the loader at {POLICY_LOADER_PROGRAM} is not a root-owned file \
                 that only root can write"
            )
        } else if !units_current {
            format!(
                "{REFUSED}: the loader's systemd units are missing, or are not the ones \
                 this version installs for {operator}"
            )
        } else if !facts.socket_active {
            format!(
                "{REFUSED}: the loader's socket ({POLICY_LOADER_SYSTEMD_UNIT}.socket) is not active"
            )
        } else {
            format!(
                "what an earlier version installed for network enforcement is still on \
                 this machine: {}",
                facts.earlier_pieces.join(", ")
            )
        };
        Item::missing(POLICY_ENGINE_ID, POLICY_ENGINE_LABEL, today, step, script)
    }

    /// The step's block: the copy of `daemon` put in place by a rename, so
    /// a loader that is running keeps its file; both units; the socket
    /// enabled and restarted, so a changed unit takes effect; then the
    /// removal of what an earlier version installed.
    fn policy_engine_steps(operator: &str, daemon: &str) -> String {
        format!(
            "# policy-engine\n\
             install -d -m 0755 -o root -g root {ANSWERER_PROGRAM_DIR}\n\
             install -m 0755 -o root -g root \"{daemon}\" {POLICY_LOADER_PROGRAM}.new\n\
             mv -f {POLICY_LOADER_PROGRAM}.new {POLICY_LOADER_PROGRAM}\n\
             cat > {POLICY_LOADER_UNIT_SOCKET_PATH} <<'{UNIT_HEREDOC}'\n\
             {socket}\
             {UNIT_HEREDOC}\n\
             cat > {POLICY_LOADER_UNIT_SERVICE_PATH} <<'{UNIT_HEREDOC}'\n\
             {service}\
             {UNIT_HEREDOC}\n\
             chmod 0644 {POLICY_LOADER_UNIT_SOCKET_PATH} {POLICY_LOADER_UNIT_SERVICE_PATH}\n\
             systemctl daemon-reload\n\
             systemctl enable --now {POLICY_LOADER_SYSTEMD_UNIT}.socket\n\
             systemctl restart {POLICY_LOADER_SYSTEMD_UNIT}.socket\n\
             \n\
             {earlier}",
            socket = crate::resolver::policy_loader_socket_unit(operator),
            service = crate::resolver::policy_loader_service_unit(),
            earlier = crate::resolver::earlier_install_removal(""),
        )
    }

    /// What `program __policy-loader --identity` prints, when it is an
    /// identity. The mode needs no privilege.
    fn loader_identity(program: &str) -> Option<String> {
        use std::io::Read as _;
        let mut child = std::process::Command::new(program)
            .args(["__policy-loader", "--identity"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let deadline = std::time::Instant::now() + IDENTITY_DEADLINE;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        };
        if !status.success() {
            return None;
        }
        // The line is far shorter than a pipe's buffer, so the child never
        // blocked on it.
        let mut stdout = String::new();
        child.stdout.take()?.read_to_string(&mut stdout).ok()?;
        identity_line(&stdout).map(str::to_owned)
    }

    /// [`policy_engine_item_over`] this host's reads.
    pub(crate) fn policy_engine_item_on_this_host() -> Item {
        use std::os::unix::fs::MetadataExt as _;
        let daemon = daemon_beside_min();
        let copy = std::fs::symlink_metadata(POLICY_LOADER_PROGRAM)
            .ok()
            .map(|meta| LoaderCopy {
                regular_file: meta.file_type().is_file(),
                uid: meta.uid(),
                mode: meta.mode() & 0o7777,
            });
        let socket_unit = std::fs::read_to_string(POLICY_LOADER_UNIT_SOCKET_PATH).ok();
        // A path this account may not look at reads as absent: it cannot
        // tell, and the removal lines run with every install anyway.
        let earlier_pieces = EARLIER_INSTALL_FILES
            .iter()
            .filter(|path| std::fs::symlink_metadata(path).is_ok())
            .chain(
                std::path::Path::new(EARLIER_INSTALL_CGROUP)
                    .is_dir()
                    .then_some(&EARLIER_INSTALL_CGROUP),
            )
            .map(|path| (*path).to_string())
            .collect();
        policy_engine_item_over(&PolicyEngineFacts {
            operator: crate::resolver::operator_name(),
            systemd: std::path::Path::new("/run/systemd/system").is_dir(),
            cgroup_v2: std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            kernel_release: std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap_or_default(),
            daemon_identity: daemon.as_deref().and_then(loader_identity),
            copy_identity: copy
                .filter(|copy| copy.regular_file)
                .and_then(|_| loader_identity(POLICY_LOADER_PROGRAM)),
            socket_active: socket_unit.is_some()
                && std::process::Command::new("systemctl")
                    .args([
                        "is-active",
                        "--quiet",
                        &format!("{POLICY_LOADER_SYSTEMD_UNIT}.socket"),
                    ])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok_and(|status| status.success()),
            daemon,
            copy,
            socket_unit,
            service_unit: std::fs::read_to_string(POLICY_LOADER_UNIT_SERVICE_PATH).ok(),
            earlier_pieces,
        })
    }

    /// The KVM item over the result of opening `/dev/kvm` for reading:
    /// done when it opens; missing — the step adds `operator` to the `kvm`
    /// group — on `EACCES`, unless `already_member` says the group database
    /// lists the operator already, when only a new login is missing and
    /// the step has nothing to add (and nothing to record for `--undo` to
    /// take back); blocked when the device is not there, or on any other
    /// error, named.
    pub(crate) fn kvm_item_over(
        open: Result<(), std::io::Error>,
        operator: &str,
        already_member: bool,
    ) -> Item {
        match open {
            Ok(()) => Item::done(KVM_ID, KVM_LABEL),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                if operator.is_empty() {
                    return Item::cannot(
                        KVM_ID,
                        KVM_LABEL,
                        "could not read this process's user name, so there is no account \
                         to add to the kvm group"
                            .to_string(),
                    );
                }
                if already_member {
                    return Item::cannot(
                        KVM_ID,
                        KVM_LABEL,
                        format!(
                            "{operator} is in the kvm group already, but this login predates \
                             it; log out and back in (or restart the daemon from a new login) \
                             and /dev/kvm opens"
                        ),
                    );
                }
                if operator.contains(['\'', '\n', ' ']) {
                    return Item::cannot(
                        KVM_ID,
                        KVM_LABEL,
                        format!(
                            "this process's user name ({operator:?}) holds a quote, a space or \
                             a newline, which the script cannot quote; add the account to the \
                             kvm group by hand"
                        ),
                    );
                }
                Item::missing(
                    KVM_ID,
                    KVM_LABEL,
                    format!(
                        "VM boots fail with /dev/kvm: permission denied, because {operator} is \
                         not in the kvm group"
                    ),
                    format!(
                        "adds {operator} to the kvm group (it takes effect at your next login)"
                    ),
                    format!(
                        "# KVM access: the Linux VM provider drives KVM, which the kvm group may\n\
                         # open. The record names who was added, one per line, so --undo takes\n\
                         # back only those, and one user's run never drops another's name.\n\
                         usermod -aG kvm '{operator}'\n\
                         mkdir -p /var/lib/minimal\n\
                         grep -qxF '{operator}' {KVM_GROUP_RECORD} 2>/dev/null || \
                         printf '%s\\n' '{operator}' >> {KVM_GROUP_RECORD}\n"
                    ),
                )
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Item::cannot(
                KVM_ID,
                KVM_LABEL,
                "/dev/kvm is not there: the KVM module is not loaded, or this machine has no \
                 hardware virtualization"
                    .to_string(),
            ),
            Err(err) => Item::cannot(KVM_ID, KVM_LABEL, format!("opening /dev/kvm: {err}")),
        }
    }

    /// Whether `group` (the `/etc/group` text) lists `operator` as a member
    /// of `kvm`: a membership the running login does not carry yet.
    pub(crate) fn in_kvm_group(group: &str, operator: &str) -> bool {
        !operator.is_empty()
            && group.lines().any(|line| {
                let mut fields = line.split(':');
                fields.next() == Some("kvm")
                    && fields
                        .nth(2)
                        .is_some_and(|members| members.split(',').any(|m| m == operator))
            })
    }

    /// [`kvm_item_over`] this host's reads.
    pub(crate) fn kvm_item_on_this_host() -> Item {
        let open = std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/kvm")
            .map(|_| ());
        let operator = crate::resolver::operator_name();
        let group = std::fs::read_to_string("/etc/group").unwrap_or_default();
        kvm_item_over(open, &operator, in_kvm_group(&group, &operator))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(id: &'static str) -> Item {
        Item::done(id, "a done item")
    }

    fn missing(id: &'static str, block: &str) -> Item {
        Item::missing(
            id,
            "a missing item",
            "what it costs today".to_string(),
            "what the step changes".to_string(),
            format!("# The step: {block}.\necho {block}\n"),
        )
    }

    fn cannot(id: &'static str, cause: &str) -> Item {
        Item::cannot(id, "an unfixable item", cause.to_string())
    }

    /// NET-122: a finished host is told so, exactly, with no script to run
    /// and exit 0 — the common case after the first run, so a success.
    #[test]
    fn finalize_install_finished_host_runs_nothing_and_exits_zero() {
        let plan = Plan {
            items: vec![done("names"), done("userns-profile")],
        };
        assert!(plan.finished());
        assert_eq!(plan.summary(), format!("{FINISHED}\n"));
        assert_eq!(plan.script(), None);
        assert_eq!(plan.exit_code(), 0);
        assert!(plan.json().contains("\"finished\":true"), "{}", plan.json());
    }

    /// NET-122: an item no script can fix is listed under its own heading
    /// with its cause, and the script still carries every item a script
    /// can fix — the run is never refused whole on the unfixable one.
    #[test]
    fn finalize_install_lists_unfixable_facts_and_runs_the_rest() {
        let plan = Plan {
            items: vec![
                missing("names", "names"),
                cannot("policy-engine", "no cgroup2 filesystem is mounted"),
            ],
        };
        let summary = plan.summary();
        assert!(summary.contains(CANNOT_HEADING), "{summary}");
        assert!(
            summary.contains("✗ an unfixable item — no cgroup2 filesystem is mounted"),
            "{summary}"
        );
        let script = plan.script().expect("the fixable item still runs");
        assert!(script.contains("echo names"), "{script}");
        assert!(!script.contains("cgroup2"), "{script}");
        assert_eq!(plan.exit_code(), 1);
    }

    /// NET-122: when every missing item is one no script can fix, the run
    /// lists them under their heading, runs nothing, and exits non-zero —
    /// never the finished sentence, since a blocked host is not finished.
    #[test]
    fn finalize_install_all_blocked_runs_nothing_and_exits_non_zero() {
        let blocked = Plan {
            items: vec![cannot("userns-profile", "no user namespaces")],
        };
        assert_eq!(blocked.script(), None);
        assert!(!blocked.finished());
        assert_eq!(blocked.exit_code(), 1);
        let summary = blocked.summary();
        assert!(summary.contains(CANNOT_HEADING), "{summary}");
        assert!(!summary.contains(FINISHED), "{summary}");

        // Done beside a blocked item is the same host: no script, exit 1.
        let done_and_cannot = Plan {
            items: vec![
                done("names"),
                cannot("userns-profile", "no user namespaces"),
            ],
        };
        assert_eq!(done_and_cannot.script(), None);
        assert_eq!(done_and_cannot.exit_code(), 1);
        let summary = done_and_cannot.summary();
        assert!(!summary.contains(FINISHED), "{summary}");
        assert!(summary.contains(CANNOT_HEADING), "{summary}");
    }

    /// NET-122: with no daemon, the names item is listed as waiting on one,
    /// with its cause, under the summary — not under the unfixable heading
    /// — and the items that need no daemon still run; a waiting item never
    /// finishes the host.
    #[test]
    fn finalize_install_without_daemon_runs_the_items_that_need_none() {
        let plan = Plan {
            items: vec![
                missing("userns-profile", "userns"),
                Item::waiting("names", "box names", "no daemon is reachable".to_string()),
            ],
        };
        let summary = plan.summary();
        assert!(
            summary.contains("  ✗ box names — waiting on a daemon (no daemon is reachable)\n"),
            "{summary}"
        );
        assert!(!summary.contains(CANNOT_HEADING), "{summary}");
        assert!(!summary.contains(FINISHED), "{summary}");
        let script = plan.script().expect("the userns item still runs");
        assert!(script.contains("echo userns"), "{script}");
        assert_eq!(plan.exit_code(), 1);
        let value: serde_json_lenient::Value = serde_json_lenient::from_str(&plan.json()).unwrap();
        assert_eq!(value["items"][1]["state"], "waiting");
        assert_eq!(value["finished"], false);

        // Waiting alone: nothing to run, exit 1, no finished sentence.
        let waiting = Plan {
            items: vec![Item::waiting("names", "box names", "no daemon".to_string())],
        };
        assert_eq!(waiting.script(), None);
        assert_eq!(waiting.exit_code(), 1);
        assert!(!waiting.summary().contains(FINISHED));
    }

    /// NET-122: a run that added the operator to the KVM group ends with the
    /// login note, exactly; one that installed anything else ends with the
    /// pick-up line.
    #[test]
    fn finalize_install_kvm_group_closing_line_names_a_new_login() {
        let closing = |plan: &Plan| {
            closing_lines(
                plan.installs_other_items(),
                plan.installs_policy_engine(),
                plan.adds_kvm_group(),
            )
        };
        // The kvm group alone: the login line only.
        let kvm_only = Plan {
            items: vec![done("names"), missing(KVM_ID, "kvm")],
        };
        assert!(kvm_only.adds_kvm_group() && !kvm_only.installs_other_items());
        assert_eq!(closing(&kvm_only), format!("{NEEDS_LOGIN}\n"));
        assert_eq!(
            NEEDS_LOGIN,
            "KVM group membership starts at your next login: log out and back in, or restart \
             the daemon from a new login."
        );
        // Other items alone: the pick-up line only.
        let without = Plan {
            items: vec![missing("names", "names"), done(KVM_ID)],
        };
        assert!(!without.adds_kvm_group() && without.installs_other_items());
        assert_eq!(closing(&without), format!("{PICKED_UP}\n"));
        // Both: both lines, the items line first and the login line last.
        let both = Plan {
            items: vec![missing("names", "names"), missing(KVM_ID, "kvm")],
        };
        assert!(both.adds_kvm_group() && both.installs_other_items());
        assert_eq!(closing(&both), format!("{PICKED_UP}\n{NEEDS_LOGIN}\n"));
        // The policy loader serves a daemon when it starts, so a run that
        // installed it says the daemon has to start again.
        let engine = Plan {
            items: vec![missing(POLICY_ENGINE_ID, "engine")],
        };
        assert_eq!(closing(&engine), format!("{NEEDS_DAEMON_RESTART}\n"));
    }

    /// `--undo` takes `--show` only with `--script`: `--undo --show` alone
    /// is refused as a usage error, the other combinations are not.
    #[test]
    fn finalize_install_undo_refuses_show_without_script() {
        let args = |show, script, undo| FinalizeInstallArgs {
            show,
            script,
            json: false,
            undo,
        };
        assert!(undo_flags_refusal(&args(true, false, true)).is_some());
        assert_eq!(undo_flags_refusal(&args(true, true, true)), None);
        assert_eq!(undo_flags_refusal(&args(false, false, true)), None);
        assert_eq!(undo_flags_refusal(&args(true, false, false)), None);
    }

    /// NET-122: without a terminal the run goes through `sudo -n`, and when
    /// that cannot run quietly the run is refused with the file route and
    /// exit 1 — never a prompt nothing can answer. A cached credential
    /// still runs the step.
    #[test]
    fn finalize_install_without_tty_exits_one_with_script_pointer() {
        assert_eq!(
            run_decision(true, false, SCRIPT_POINTER),
            RunDecision::Run(vec!["sudo", "sh"])
        );
        assert_eq!(
            run_decision(false, true, SCRIPT_POINTER),
            RunDecision::Run(vec!["sudo", "-n", "sh"])
        );
        let RunDecision::Refuse { message, exit } = run_decision(false, false, SCRIPT_POINTER)
        else {
            panic!("a prompt with no terminal is refused");
        };
        assert_eq!(exit, 1);
        assert!(message.ends_with(SCRIPT_POINTER), "{message}");
        assert_eq!(
            SCRIPT_POINTER,
            "f=$(mktemp) && min finalize-install --show --script > \"$f\" && sudo sh \"$f\""
        );
        // `--undo` refused the same way points at its own script, never
        // at the install's: following the pointer must remove, not install.
        let RunDecision::Refuse { message, .. } = run_decision(false, false, UNDO_SCRIPT_POINTER)
        else {
            panic!("a prompt with no terminal is refused");
        };
        assert!(message.ends_with(UNDO_SCRIPT_POINTER), "{message}");
        assert_eq!(
            UNDO_SCRIPT_POINTER,
            "f=$(mktemp) && min finalize-install --undo --show --script > \"$f\" && sudo sh \"$f\""
        );
    }

    /// NET-122: `--show` names what is missing — a ✓ or ✗ per item, what a
    /// missing one costs today and what the step changes — and nothing in
    /// it is a script, a prompt or an elevation.
    #[test]
    fn finalize_install_show_names_missing_items_without_prompt() {
        let plan = Plan {
            items: vec![done("userns-profile"), missing("names", "names")],
        };
        let summary = plan.summary();
        assert!(
            summary.starts_with("install status on this machine:\n"),
            "{summary}"
        );
        assert!(summary.contains("  ✓ a done item\n"), "{summary}");
        assert!(summary.contains("  ✗ a missing item\n"), "{summary}");
        assert!(
            summary.contains("      today: what it costs today\n"),
            "{summary}"
        );
        assert!(
            summary.contains("      this step: what the step changes\n"),
            "{summary}"
        );
        assert!(!summary.contains(CANNOT_HEADING), "{summary}");
        assert!(
            !summary.contains("#!/bin/sh") && !summary.contains("sudo") && !summary.contains('?'),
            "{summary}"
        );
    }

    /// NET-122: the JSON report carries the schema, every item's stable id
    /// and state, and the one-bit exit status — 1 while anything is not
    /// done, 0 once everything is.
    #[test]
    fn finalize_install_show_json_carries_stable_item_ids_and_exit_status() {
        let plan = Plan {
            items: vec![
                done("userns-profile"),
                missing("names", "names"),
                cannot("policy-engine", "no cgroup2 mount"),
            ],
        };
        let json = plan.json();
        let value: serde_json_lenient::Value = serde_json_lenient::from_str(&json).unwrap();
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["finished"], false);
        let items = value["items"].as_array().unwrap();
        let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["userns-profile", "names", "policy-engine"]);
        assert_eq!(items[0]["state"], "done");
        assert_eq!(items[1]["state"], "missing");
        assert_eq!(items[1]["today"], "what it costs today");
        assert_eq!(items[2]["state"], "cannot");
        assert_eq!(items[2]["cause"], "no cgroup2 mount");
        assert!(
            items[1].get("script").is_none(),
            "the script is not the report's"
        );
        assert_eq!(plan.exit_code(), 1);
        assert_eq!(
            Plan {
                items: vec![done("names")]
            }
            .exit_code(),
            0
        );
    }

    /// NET-122: a run writes the exact script `--show --script` prints to
    /// a file only the operator can read, and elevates once — `sudo sh`
    /// of that file. The closing line is the one the spec names.
    #[test]
    fn finalize_install_runs_the_script_with_one_elevation() {
        use std::os::unix::fs::PermissionsExt as _;
        let plan = Plan {
            items: vec![missing("names", "names"), missing("kvm-group", "kvm")],
        };
        let shown = plan.script().unwrap();
        let file = write_private_script(&shown).unwrap();
        assert_eq!(std::fs::read_to_string(file.path()).unwrap(), shown);
        assert_eq!(
            std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            run_decision(true, false, SCRIPT_POINTER),
            RunDecision::Run(vec!["sudo", "sh"])
        );
        assert_eq!(PICKED_UP, "Running boxes pick this up on their next start.");
    }

    /// The script is one header over the missing items' blocks, in order:
    /// its lead-in names the items, it says how it is shown and that it
    /// runs as root, and `set -eu` precedes every step.
    #[test]
    fn finalize_install_script_is_one_header_over_the_missing_items() {
        let plan = Plan {
            items: vec![
                done("userns-profile"),
                missing("names", "names"),
                missing("kvm-group", "kvm"),
            ],
        };
        let script = plan.script().unwrap();
        let lines: Vec<&str> = script.lines().collect();
        assert_eq!(lines[0], "#!/bin/sh");
        assert_eq!(
            lines[1],
            "# Finish the Minimal install on this host: a missing item, a missing item."
        );
        assert!(
            lines[2].contains("min finalize-install --show --script")
                && lines[2].contains("it must run as root: sudo sh <this file>"),
            "{script}"
        );
        assert_eq!(lines[3], "set -eu");
        let names = script.find("echo names").unwrap();
        let kvm = script.find("echo kvm").unwrap();
        assert!(names < kvm, "{script}");
        assert_eq!(script.matches("#!/bin/sh").count(), 1, "{script}");
    }

    /// The names item from its verdict: done, missing with the facts and
    /// the step's block, or blocked by the note's cause.
    #[test]
    fn names_item_follows_its_verdict() {
        use crate::resolver::NamesVerdict;
        assert_eq!(names_item(NamesVerdict::Done, 15353).state, ItemState::Done);
        let blocked = names_item(
            NamesVerdict::Blocked {
                note: "note: host lookups bypass the resolver.".to_string(),
            },
            15353,
        );
        assert_eq!(blocked.state, ItemState::Cannot);
        assert_eq!(
            blocked.cause.as_deref(),
            Some("host lookups bypass the resolver")
        );
        let missing = names_item(
            NamesVerdict::Missing {
                facts: vec!["the resolver is not configured".to_string()],
                install: None,
            },
            15353,
        );
        assert_eq!(missing.state, ItemState::Missing);
        assert_eq!(missing.id, "names");
        assert_eq!(
            missing.today.as_deref(),
            Some("the resolver is not configured")
        );
        let expected_step = if cfg!(target_os = "macos") {
            "sends *.min.internal lookups to Minimal's DNS service on 127.0.0.1:15353, and \
             reserves the box IPs (127.0.64.0/24) on this machine's loopback at every boot"
        } else {
            "configures this machine's DNS (systemd-resolved) to send *.min.internal lookups \
             to Minimal's DNS service on 127.0.0.1:15353 at every boot"
        };
        assert_eq!(missing.step.as_deref(), Some(expected_step));
        assert!(NAMES_LABEL.contains(crate::resolver::ZONE), "{NAMES_LABEL}");
        let summary = Plan {
            items: vec![missing.clone()],
        }
        .summary();
        assert!(
            summary.contains(
                "      today: 1 thing to fix:\n        - the resolver is not configured\n      \
                 this step: "
            ),
            "{summary}"
        );
        let script = missing.script.unwrap();
        assert!(script.starts_with("# The resolver: "), "{script}");
        assert!(!script.contains("#!/bin/sh"), "{script}");
    }

    /// The names item's facts are a list in the summary and one line in
    /// the JSON, which carries no layout; a carried service step joins the
    /// step text as this platform's list reads.
    #[test]
    fn names_item_lists_its_facts_in_the_summary_only() {
        use crate::resolver::{AnswererInstall, NamesVerdict};
        let item = names_item(
            NamesVerdict::Missing {
                facts: vec![
                    "the resolver is not configured".to_string(),
                    "the DNS service is not installed; this step installs it".to_string(),
                ],
                install: Some(AnswererInstall {
                    operator: "op".to_string(),
                    operator_uid: 1000,
                    channel: "/run/min/zone.sock".to_string(),
                    channel_dir: "/run/min".to_string(),
                    source: "/usr/local/bin/minzoned".to_string(),
                    sha256: "0".repeat(64),
                    bundle: Vec::new(),
                    requirement: None,
                    controls: Vec::new(),
                }),
            },
            15353,
        );
        let step = item.step.as_deref().unwrap();
        if cfg!(target_os = "macos") {
            assert!(
                step.contains(
                    "on 127.0.0.1:15353, installs that service, and reserves the box IPs"
                ),
                "{step}"
            );
        } else {
            assert!(
                step.ends_with("on 127.0.0.1:15353 at every boot and installs that service"),
                "{step}"
            );
        }
        let plan = Plan { items: vec![item] };
        let summary = plan.summary();
        assert!(
            summary.contains(
                "      today: 2 things to fix:\n        - the resolver is not configured\n        \
                 - the DNS service is not installed; this step installs it\n      this step: "
            ),
            "{summary}"
        );
        let value: serde_json_lenient::Value = serde_json_lenient::from_str(&plan.json()).unwrap();
        let names = &value["items"][0];
        assert_eq!(
            names["today"],
            "the resolver is not configured; the DNS service is not installed; this step \
             installs it"
        );
        assert!(names.get("today_list").is_none(), "{names}");
    }

    /// The user-namespace item's table: not an item where the kernel does
    /// not restrict, done when the profile is loaded and attaches the
    /// daemon, blocked without user namespaces or a parser, and otherwise
    /// a step that writes both files from the bytes it carries and loads
    /// the profile — appending the daemon's path only where the stock
    /// tunable does not name it.
    #[test]
    fn userns_item_table() {
        use linux::{UsernsFacts, userns_item_over};
        let restricted = UsernsFacts {
            apparmor_restrict: Some("1\n".to_string()),
            max_user_namespaces: Some("15000\n".to_string()),
            profile_installed: false,
            tunables_name_daemon: false,
            parser_present: true,
            daemon: Some("/usr/local/bin/minimald".to_string()),
            home: Some("/home/alice".to_string()),
        };
        assert_eq!(
            userns_item_over(&UsernsFacts {
                apparmor_restrict: Some("0\n".to_string()),
                ..restricted.clone()
            }),
            None
        );
        assert_eq!(
            userns_item_over(&UsernsFacts {
                apparmor_restrict: None,
                ..restricted.clone()
            }),
            None
        );
        let disabled = userns_item_over(&UsernsFacts {
            max_user_namespaces: Some("0\n".to_string()),
            ..restricted.clone()
        })
        .unwrap();
        assert_eq!(disabled.state, ItemState::Cannot);
        assert!(disabled.cause.unwrap().contains("max_user_namespaces"));
        let done = userns_item_over(&UsernsFacts {
            profile_installed: true,
            ..restricted.clone()
        })
        .unwrap();
        assert_eq!(done.state, ItemState::Done);
        let no_parser = userns_item_over(&UsernsFacts {
            parser_present: false,
            ..restricted.clone()
        })
        .unwrap();
        assert_eq!(no_parser.state, ItemState::Cannot);
        assert!(no_parser.cause.unwrap().contains("apparmor_parser"));

        let missing = userns_item_over(&restricted).unwrap();
        assert_eq!(missing.state, ItemState::Missing);
        assert_eq!(missing.id, "userns-profile");
        let script = missing.script.unwrap();
        for step in [
            "cat > /etc/apparmor.d/tunables/minimald <<\\MINIMAL_APPARMOR_TUNABLE_EOF\n",
            "cat > /etc/apparmor.d/minimald <<\\MINIMAL_APPARMOR_PROFILE_EOF\n",
            "profile minimald @{minimald_bin} flags=(unconfined) {\n",
            "apparmor_parser --replace /etc/apparmor.d/minimald\n",
            ": > /var/lib/minimal/finalize-install-apparmor-profile\n",
        ] {
            assert!(script.contains(step), "{step:?} in {script}");
        }
        assert!(!script.contains("minimald.d/local"), "{script}");

        // A daemon outside the stock paths: attached by the local tunable,
        // and the profile already loaded does not count until it names it.
        let dev = UsernsFacts {
            daemon: Some("/opt/minimal/bin/minimald".to_string()),
            ..restricted.clone()
        };
        let script = userns_item_over(&dev).unwrap().script.unwrap();
        assert!(
            script.contains(
                "printf '@{minimald_bin} += %s\\n' '/opt/minimal/bin/minimald' > \
                 /etc/apparmor.d/tunables/minimald.d/local\n"
            ),
            "{script}"
        );
        assert_eq!(
            userns_item_over(&UsernsFacts {
                profile_installed: true,
                ..dev.clone()
            })
            .unwrap()
            .state,
            ItemState::Missing
        );
        assert_eq!(
            userns_item_over(&UsernsFacts {
                profile_installed: true,
                tunables_name_daemon: true,
                ..dev.clone()
            })
            .unwrap()
            .state,
            ItemState::Done
        );

        // `$HOME/.local/bin/minimald` is stock only where `@{HOME}` reaches:
        // `/home/<user>` and `/root`. A home elsewhere is any other path,
        // attached through the local tunable, and the profile alone does
        // not count there.
        for (home, stock) in [
            ("/home/alice", true),
            ("/root", true),
            ("/home/alice/", true),
            ("/srv/home/alice", false),
            ("/home/alice/nested", false),
            ("/home/", false),
        ] {
            let facts = UsernsFacts {
                daemon: Some(format!(
                    "{}/.local/bin/minimald",
                    home.trim_end_matches('/')
                )),
                home: Some(home.to_string()),
                profile_installed: true,
                ..restricted.clone()
            };
            let item = userns_item_over(&facts).unwrap();
            if stock {
                assert_eq!(item.state, ItemState::Done, "{home}");
            } else {
                assert_eq!(item.state, ItemState::Missing, "{home}");
                assert!(
                    item.script.unwrap().contains("minimald.d/local"),
                    "{home}: attached through the local tunable"
                );
            }
        }
        assert_eq!(
            userns_item_over(&UsernsFacts {
                daemon: Some("/home/bob/.local/bin/minimald".to_string()),
                profile_installed: true,
                ..restricted.clone()
            })
            .unwrap()
            .state,
            ItemState::Missing,
            "another user's home is not this user's @{{HOME}}"
        );

        // A path an AppArmor tunable cannot name is a fact no script fixes,
        // never a silently dropped attachment.
        for path in [
            "/opt/my minimal/minimald",
            "/opt/min#1/minimald",
            "/opt/it's/minimald",
        ] {
            let item = userns_item_over(&UsernsFacts {
                daemon: Some(path.to_string()),
                ..dev.clone()
            })
            .unwrap();
            assert_eq!(item.state, ItemState::Cannot, "{path}");
            assert!(item.cause.as_deref().unwrap().contains(path), "{item:?}");
        }
    }

    const IDENTITY: &str = "abi=3 object=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
         loader=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    /// The same layouts and programs, other loader code: what a fix inside
    /// the loader looks like.
    const OTHER_IDENTITY: &str = "abi=3 object=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
         loader=0000ba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// A host where the policy engine is installed for alice and current.
    fn policy_engine_installed() -> linux::PolicyEngineFacts {
        linux::PolicyEngineFacts {
            operator: "alice".to_string(),
            systemd: true,
            cgroup_v2: true,
            kernel_release: "6.8.0-45-generic\n".to_string(),
            daemon: Some("/home/alice/.local/bin/minimald".to_string()),
            daemon_identity: Some(IDENTITY.to_string()),
            copy: Some(linux::LoaderCopy {
                regular_file: true,
                uid: 0,
                mode: 0o755,
            }),
            copy_identity: Some(IDENTITY.to_string()),
            socket_unit: Some(crate::resolver::policy_loader_socket_unit("alice")),
            service_unit: Some(crate::resolver::policy_loader_service_unit()),
            socket_active: true,
            earlier_pieces: Vec::new(),
        }
    }

    /// The policy engine item's table: done only when every installed
    /// piece is this version's and trusted, missing with what a user gets
    /// today for each piece that is not, out of date for a loader of
    /// another version, and blocked by each host fact no script changes.
    #[test]
    fn policy_engine_item_table() {
        use linux::{LoaderCopy, PolicyEngineFacts, policy_engine_item_over};
        let installed = policy_engine_installed();
        let done = policy_engine_item_over(&installed);
        assert_eq!(done.state, ItemState::Done);
        assert_eq!(done.id, "policy-engine");
        assert_eq!(done.label, "network policy engine");
        assert!(done.script.is_none());

        let copy = |regular_file, uid, mode| {
            Some(LoaderCopy {
                regular_file,
                uid,
                mode,
            })
        };
        let missing: [(&str, PolicyEngineFacts, &str); 10] = [
            (
                "no copy",
                PolicyEngineFacts {
                    copy: None,
                    copy_identity: None,
                    socket_unit: None,
                    service_unit: None,
                    socket_active: false,
                    ..installed.clone()
                },
                "boxes with a network policy are refused: the network policy loader is not \
                 installed",
            ),
            (
                "a copy the operator owns",
                PolicyEngineFacts {
                    copy: copy(true, 1000, 0o755),
                    ..installed.clone()
                },
                "is not a root-owned file that only root can write",
            ),
            (
                "a copy others can write",
                PolicyEngineFacts {
                    copy: copy(true, 0, 0o757),
                    ..installed.clone()
                },
                "is not a root-owned file that only root can write",
            ),
            (
                "a copy the group can write",
                PolicyEngineFacts {
                    copy: copy(true, 0, 0o775),
                    ..installed.clone()
                },
                "is not a root-owned file that only root can write",
            ),
            (
                "a symlink where the copy goes",
                PolicyEngineFacts {
                    copy: copy(false, 0, 0o777),
                    ..installed.clone()
                },
                "is not a root-owned file that only root can write",
            ),
            (
                "a socket unit for another operator",
                PolicyEngineFacts {
                    socket_unit: Some(crate::resolver::policy_loader_socket_unit("bob")),
                    ..installed.clone()
                },
                "are not the ones this version installs for alice",
            ),
            (
                "a service unit with another line",
                PolicyEngineFacts {
                    service_unit: installed
                        .service_unit
                        .as_ref()
                        .map(|unit| unit.replace("PrivateNetwork=yes\n", "")),
                    ..installed.clone()
                },
                "are not the ones this version installs for alice",
            ),
            (
                "no service unit, under a copy of another version",
                PolicyEngineFacts {
                    service_unit: None,
                    copy_identity: Some(OTHER_IDENTITY.to_string()),
                    ..installed.clone()
                },
                "the loader's systemd units are missing",
            ),
            (
                "a socket that is not active",
                PolicyEngineFacts {
                    socket_active: false,
                    ..installed.clone()
                },
                "the loader's socket (minimal-policy-loader.socket) is not active",
            ),
            (
                "a piece of an earlier version",
                PolicyEngineFacts {
                    earlier_pieces: vec!["/usr/local/lib/minimal/quic443-leaf".to_string()],
                    ..installed.clone()
                },
                "what an earlier version installed for network enforcement is still on this \
                 machine: /usr/local/lib/minimal/quic443-leaf",
            ),
        ];
        for (case, facts, today) in &missing {
            let item = policy_engine_item_over(facts);
            assert_eq!(item.state, ItemState::Missing, "{case}");
            let said = item.today.as_deref().unwrap();
            assert!(said.contains(today), "{case}: {said}");
            assert!(item.script.is_some() && item.step.is_some(), "{case}");
        }
        // Only a host that carries earlier pieces is told they go.
        let step_of = |facts: &PolicyEngineFacts| policy_engine_item_over(facts).step.unwrap();
        assert_eq!(
            step_of(&missing[0].1),
            "installs a root-owned copy of minimald at /usr/local/lib/minimal/minimald and \
             the systemd units that run it as the network policy loader for alice's daemon"
        );
        assert!(
            step_of(&missing[9].1).ends_with(", and removes what an earlier version installed")
        );

        let out_of_date = [
            (
                "a copy of another version",
                PolicyEngineFacts {
                    copy_identity: Some(OTHER_IDENTITY.to_string()),
                    ..installed.clone()
                },
            ),
            (
                "a copy that prints no identity",
                PolicyEngineFacts {
                    copy_identity: None,
                    ..installed.clone()
                },
            ),
            (
                "a copy of another version under units that differ too",
                PolicyEngineFacts {
                    copy_identity: Some(OTHER_IDENTITY.to_string()),
                    socket_unit: Some("[Socket]\n".to_string()),
                    socket_active: false,
                    ..installed.clone()
                },
            ),
        ];
        let fresh = policy_engine_item_over(&missing[0].1);
        for (case, facts) in &out_of_date {
            let item = policy_engine_item_over(facts);
            assert_eq!(item.state, ItemState::OutOfDate, "{case}");
            assert_eq!(
                item.today.as_deref(),
                Some(
                    "the installed network policy loader is from another version of Minimal, \
                     so boxes with a network policy are refused until `min finalize-install` \
                     runs"
                ),
                "{case}"
            );
            assert_eq!(
                item.script, fresh.script,
                "{case}: the step a fresh host runs"
            );
        }

        let cannot = [
            (
                PolicyEngineFacts {
                    systemd: false,
                    ..installed.clone()
                },
                "systemd is not this machine's init system",
            ),
            (
                PolicyEngineFacts {
                    cgroup_v2: false,
                    ..installed.clone()
                },
                "no cgroup2 filesystem is mounted at /sys/fs/cgroup",
            ),
            (
                PolicyEngineFacts {
                    kernel_release: "5.15.0-91-generic\n".to_string(),
                    ..installed.clone()
                },
                "this machine's kernel (5.15.0-91-generic) is older than 5.19",
            ),
            (
                PolicyEngineFacts {
                    daemon: None,
                    daemon_identity: None,
                    ..installed.clone()
                },
                "no minimald is installed beside this min",
            ),
            (
                PolicyEngineFacts {
                    daemon: Some("/opt/min$(id)/minimald".to_string()),
                    ..installed.clone()
                },
                "which the install script cannot quote",
            ),
            (
                PolicyEngineFacts {
                    operator: String::new(),
                    ..installed.clone()
                },
                "could not read this process's user name",
            ),
            (
                PolicyEngineFacts {
                    operator: "al%ice".to_string(),
                    ..installed.clone()
                },
                "which a systemd unit cannot name",
            ),
            (
                PolicyEngineFacts {
                    daemon_identity: None,
                    ..installed.clone()
                },
                "does not report a network policy loader",
            ),
        ];
        for (facts, cause) in &cannot {
            let item = policy_engine_item_over(facts);
            assert_eq!(item.state, ItemState::Cannot, "{cause}");
            let said = item.cause.as_deref().unwrap();
            assert!(said.contains(cause), "{said}");
            assert!(item.script.is_none(), "{cause}");
        }
        // 5.19 itself and anything newer is not blocked, and neither is a
        // release that does not read as a version.
        for release in ["5.19.0", "6.18.58.1-microsoft-standard-WSL2", "7.0-rc1", ""] {
            let item = policy_engine_item_over(&PolicyEngineFacts {
                kernel_release: release.to_string(),
                ..installed.clone()
            });
            assert_eq!(item.state, ItemState::Done, "{release:?}");
        }
    }

    #[test]
    fn kernel_version_reads_major_and_minor() {
        use linux::kernel_version;
        assert_eq!(kernel_version("6.8.0-45-generic\n"), Some((6, 8)));
        assert_eq!(kernel_version("5.19"), Some((5, 19)));
        assert_eq!(kernel_version("6.12-rc3"), Some((6, 12)));
        assert!(kernel_version("4.18.0") < Some((5, 19)));
        assert_eq!(kernel_version("6"), None);
        assert_eq!(kernel_version("generic"), None);
    }

    /// A loader identity is one line of the agreed shape. What a minimald
    /// without that mode prints, such as a usage error, is none.
    #[test]
    fn identity_line_takes_one_well_formed_line() {
        use linux::identity_line;
        assert_eq!(identity_line(&format!("{IDENTITY}\n")), Some(IDENTITY));
        assert_eq!(identity_line(IDENTITY), Some(IDENTITY));
        for not_one in [
            String::new(),
            "\n".to_string(),
            format!("{IDENTITY}\n{IDENTITY}\n"),
            format!("note\n{IDENTITY}\n"),
            format!("{IDENTITY} \n"),
            IDENTITY.replace("abi=3", "abi="),
            IDENTITY.replace("abi=3", "abi=0x3"),
            IDENTITY.replace("object=0", "object=g"),
            IDENTITY.replace("loader=f", "loader=g"),
            // A loader from before the line named its own code.
            IDENTITY
                .split(" loader=")
                .next()
                .unwrap_or_default()
                .to_string(),
            IDENTITY[..IDENTITY.len() - 1].to_string(),
            "error: unrecognized subcommand '__policy-loader'\n".to_string(),
        ] {
            assert_eq!(identity_line(&not_one), None, "{not_one:?}");
        }
    }

    /// The policy engine block, as a fresh host's script carries it: the
    /// copy put in place by a rename, both units written whole for the
    /// operator, the socket enabled, then what an earlier version
    /// installed taken away. The script around it parses.
    #[test]
    fn policy_engine_script_installs_the_copy_and_units_for_the_operator() {
        let item = linux::policy_engine_item_over(&linux::PolicyEngineFacts {
            copy: None,
            copy_identity: None,
            socket_unit: None,
            service_unit: None,
            socket_active: false,
            ..policy_engine_installed()
        });
        let block = item.script.clone().unwrap();
        let socket_unit = crate::resolver::policy_loader_socket_unit("alice");
        let service_unit = crate::resolver::policy_loader_service_unit();
        assert!(socket_unit.contains("SocketUser=alice\n"), "{socket_unit}");
        let earlier = crate::resolver::earlier_install_removal("");
        let expected = format!(
            "# policy-engine\n\
             install -d -m 0755 -o root -g root /usr/local/lib/minimal\n\
             install -m 0755 -o root -g root \"/home/alice/.local/bin/minimald\" \
             /usr/local/lib/minimal/minimald.new\n\
             mv -f /usr/local/lib/minimal/minimald.new /usr/local/lib/minimal/minimald\n\
             cat > /etc/systemd/system/minimal-policy-loader.socket <<'MINIMAL_UNIT_EOF'\n\
             {socket_unit}\
             MINIMAL_UNIT_EOF\n\
             cat > /etc/systemd/system/minimal-policy-loader@.service <<'MINIMAL_UNIT_EOF'\n\
             {service_unit}\
             MINIMAL_UNIT_EOF\n\
             chmod 0644 /etc/systemd/system/minimal-policy-loader.socket \
             /etc/systemd/system/minimal-policy-loader@.service\n\
             systemctl daemon-reload\n\
             systemctl enable --now minimal-policy-loader.socket\n\
             systemctl restart minimal-policy-loader.socket\n\
             \n\
             {earlier}"
        );
        assert_eq!(block, expected);
        for line in [
            "for unit in minimald-classifier.service minimald-place.socket minimald-place.path; do\n",
            "      /etc/sudoers.d/minimal-quic443-leaf /var/lib/minimal/finalize-install-classifier\n",
            "nft delete table inet minimal_class 2>/dev/null || true; fi\n",
            "if [ -d /sys/fs/cgroup/minimald.slice ]; then\n",
        ] {
            assert!(earlier.contains(line), "{line:?} in {earlier}");
        }
        // Neither unit can end its own heredoc early.
        for unit in [&socket_unit, &service_unit] {
            assert!(!unit.lines().any(|line| line == "MINIMAL_UNIT_EOF"));
        }

        let script = Plan {
            items: vec![missing("names", "names"), item],
        }
        .script()
        .unwrap();
        assert!(script.ends_with(&expected), "{script}");
        let mut sh = std::process::Command::new("/bin/sh")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("sh starts");
        {
            use std::io::Write as _;
            sh.stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
        }
        let checked = sh.wait_with_output().unwrap();
        assert!(
            checked.status.success(),
            "sh -n: {}\n{script}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }

    /// A native Linux host that is offered every item lists them in this
    /// order, whatever order they were probed in.
    #[test]
    fn finalize_install_show_json_lists_the_item_ids_in_order() {
        let plan = plan_over(
            vec![
                done(linux::USERNS_ID),
                linux::policy_engine_item_over(&policy_engine_installed()),
            ],
            done("names"),
        );
        let value: serde_json_lenient::Value = serde_json_lenient::from_str(&plan.json()).unwrap();
        let ids: Vec<&str> = value["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["userns-profile", "names", "policy-engine"]);
        assert_eq!(plan.exit_code(), 0);
        // A host that needs no user-namespace profile has names first.
        let plan = plan_over(vec![done(POLICY_ENGINE_ID)], done("names"));
        let ids: Vec<&str> = plan.items.iter().map(|item| item.id).collect();
        assert_eq!(ids, ["names", "policy-engine"]);
    }

    /// An out-of-date item is unfinished the way a missing one is: the
    /// report says `out_of_date` and exits 1, the summary says what it
    /// costs today, and the script carries its step.
    #[test]
    fn finalize_install_out_of_date_item_is_unfinished_and_carries_its_step() {
        let item = linux::policy_engine_item_over(&linux::PolicyEngineFacts {
            copy_identity: Some(OTHER_IDENTITY.to_string()),
            ..policy_engine_installed()
        });
        let plan = Plan {
            items: vec![done("names"), item],
        };
        assert!(!plan.finished());
        assert_eq!(plan.exit_code(), 1);
        let value: serde_json_lenient::Value = serde_json_lenient::from_str(&plan.json()).unwrap();
        assert_eq!(value["finished"], false);
        assert_eq!(value["items"][1]["id"], "policy-engine");
        assert_eq!(value["items"][1]["state"], "out_of_date");
        assert!(plan.json().contains("\"state\":\"out_of_date\""));
        let summary = plan.summary();
        assert!(
            summary.contains(
                "  ✗ network policy engine\n      today: the installed network policy loader \
                 is from another version of Minimal, so boxes with a network policy are \
                 refused until `min finalize-install` runs\n      this step: installs a \
                 root-owned copy of minimald"
            ),
            "{summary}"
        );
        assert!(!summary.contains(CANNOT_HEADING), "{summary}");
        let script = plan.script().expect("an out-of-date item has a step");
        assert!(
            script.contains("# Finish the Minimal install on this host: network policy engine.\n"),
            "{script}"
        );
        assert!(script.contains("\n# policy-engine\n"), "{script}");
        assert!(plan.installs_policy_engine() && !plan.adds_kvm_group());
    }

    /// The KVM item's table: done when the device opens, a group step on
    /// permission denied, blocked when the device is not there.
    #[test]
    fn kvm_item_table() {
        use linux::{in_kvm_group, kvm_item_over};
        use std::io::{Error, ErrorKind};
        let denied = || Err(Error::from(ErrorKind::PermissionDenied));
        assert_eq!(kvm_item_over(Ok(()), "alice", false).state, ItemState::Done);
        let missing = kvm_item_over(denied(), "alice", false);
        assert_eq!(missing.state, ItemState::Missing);
        assert_eq!(missing.id, "kvm-group");
        let script = missing.script.unwrap();
        assert!(script.contains("usermod -aG kvm 'alice'\n"), "{script}");
        assert!(
            script.contains(
                "grep -qxF 'alice' /var/lib/minimal/finalize-install-kvm-group 2>/dev/null || \
                 printf '%s\\n' 'alice' >> /var/lib/minimal/finalize-install-kvm-group\n"
            ),
            "the record is appended, never replaced: {script}"
        );
        assert!(missing.step.unwrap().contains("next login"));
        let absent = kvm_item_over(Err(Error::from(ErrorKind::NotFound)), "alice", false);
        assert_eq!(absent.state, ItemState::Cannot);
        assert!(absent.cause.unwrap().contains("/dev/kvm is not there"));
        let unnamed = kvm_item_over(denied(), "", false);
        assert_eq!(unnamed.state, ItemState::Cannot);
        assert!(
            unnamed
                .cause
                .unwrap()
                .contains("could not read this process's user name")
        );
        let unquotable = kvm_item_over(denied(), "al ice", false);
        assert_eq!(unquotable.state, ItemState::Cannot);
        assert!(
            unquotable
                .cause
                .unwrap()
                .contains("holds a quote, a space or a newline"),
            "a name that read but cannot be quoted is told apart from none"
        );

        // Already in the group, in a login that predates it: `/dev/kvm`
        // refuses, but there is nothing to add, so no step and no record a
        // later `--undo` would act on — a new login is what is missing.
        let relogin = kvm_item_over(denied(), "alice", true);
        assert_eq!(relogin.state, ItemState::Cannot);
        assert!(relogin.script.is_none());
        assert!(relogin.cause.unwrap().contains("log out and back in"));

        let group = "root:x:0:\nkvm:x:108:bob,alice\nalice:x:1000:\n";
        assert!(in_kvm_group(group, "alice"));
        assert!(in_kvm_group(group, "bob"));
        assert!(!in_kvm_group(group, "carol"));
        assert!(!in_kvm_group(group, "ali"));
        assert!(!in_kvm_group("kvm:x:108:\n", ""));
        assert!(!in_kvm_group("", "alice"));
    }
}
