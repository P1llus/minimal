//! `min session policy`: rendering the effective box policy as text or JSON.

use super::*;

/// The one-line note `min session activate` prints for an own-address box
/// that declares no egress: the default the box has, and the flags that
/// declare its reach.
///
/// The caller checks the daemon's opt-out first. The daemon knows whether
/// it is set, so [`activate_box`] reads it off the create reply and stays
/// silent for a box the default does not bind.
pub const DENY_ALL_DEFAULT_NOTICE: &str = "This box can reach no external address: a --network \
     own_ip box with no egress rules gets the deny-all default. To allow outbound traffic, \
     activate a new session with --allow-subnets or --allow-dns-hosts, for example \
     --allow-dns-hosts github.com.";

/// The note a box-creating command prints for a box whose egress rules
/// allow every address and list no name. Such a box looks up no name: its
/// resolver answers only names a rule admits, and a subnet rule admits
/// addresses.
pub const NO_NAME_RESOLVES_NOTICE: &str = "This box can look up no external host name, because      its egress rules allow every address but list no name, and a subnet rule grants addresses      only. Add each name the box needs with --allow-dns-hosts, or with allow_dns_hosts in      minimal.toml.";

/// [`NO_NAME_RESOLVES_NOTICE`] when the box `config` describes is such a
/// box.
#[must_use]
pub fn no_name_resolves_notice(config: &minimald_rpc::BoxConfig) -> Option<&'static str> {
    (config.network != boxes::NetworkMode::NoNet
        && boxes::egress::allows_every_address_and_no_name(config.policy.egress.as_ref()))
    .then_some(NO_NAME_RESOLVES_NOTICE)
}

/// The words `min session policy` and `min ls` both print for a box's
/// egress posture (T110), so the two surfaces cannot drift. A default is
/// marked as one. A declared deny-all is not, because the box chose it. A
/// declaration with rules of its own reads as `declared rules`, the rows
/// `min session policy` lists under it.
#[must_use]
pub fn egress_posture_words(posture: minimald_rpc::EgressPosture) -> &'static str {
    match posture {
        minimald_rpc::EgressPosture::DenyAllDefault => "deny-all (default)",
        minimald_rpc::EgressPosture::AllowAllDefault => "allow-all (default)",
        minimald_rpc::EgressPosture::DenyAll => "deny-all",
        minimald_rpc::EgressPosture::DeclaredRules => "declared rules",
        minimald_rpc::EgressPosture::NoNetwork => "no network",
    }
}

/// The EGRESS cell `min ls` prints for a box: the posture in
/// [`egress_posture_words`]' words. A posture the daemon did not report
/// prints `-`.
#[must_use]
pub fn egress_posture_cell(posture: Option<minimald_rpc::EgressPosture>) -> String {
    posture.map_or_else(
        || "-".to_string(),
        |posture| egress_posture_words(posture).to_string(),
    )
}

/// Renders a session's effective policy as its rules.
///
/// The egress block prints a declared section's dimensions, each as its
/// list or its default (`allow-all`, and `(none)` for `deny subnets` when
/// nothing is denied). A section that admits nothing prints `deny-all`. A
/// box that declared no egress prints the default its daemon resolved,
/// marked as one: `deny-all (default)` or `allow-all (default)`. The
/// ingress block prints the mappings and the dynamic stance.
///
/// A box with no network prints one line in place of both blocks. A box
/// that shares its host's address has no ingress policy, so its ingress
/// block is left out. Shared by `min session policy` and the tests that
/// pin the rendering.
pub fn format_policy(
    out: &mut impl std::io::Write,
    effective: &boxes::EffectiveBoxPolicy,
    network: boxes::NetworkMode,
    shared_port_collisions: &[minimald_rpc::SharedPortCollision],
) -> Result<(), anyhow::Error> {
    // A none box has no network, so it can carry no egress or ingress
    // declaration at all — nothing the blocks print would describe anything
    // real (the same case the TUI's detail pane replaces with this note).
    if network == boxes::NetworkMode::NoNet {
        writeln!(out, "This box has no network (--network none)")?;
        return Ok(());
    }
    writeln!(out, "egress")?;
    let posture = minimald_rpc::EgressPosture::of(&effective.egress, network);
    if posture != minimald_rpc::EgressPosture::DeclaredRules {
        // A verdict by name rather than as rows: the defaults marked as
        // defaults, and the declared deny-all section unmarked — every list
        // empty would render as blankness, which reads as nothing, the one
        // rendering this block must never print (NET-075's "never
        // nothing"). The mark is the difference between a verdict the box
        // chose and the one the rollout chose for it, and the JSON document
        // carries the same distinction as `source`. The label is the
        // posture's own words, shared with `min ls` (T110).
        writeln!(out, "  {}", egress_posture_words(posture))?;
    } else if let boxes::EffectiveEgress::Declared(egress) = &effective.egress {
        write_rules(out, "subnets", egress.allow_subnets.as_ref(), "allow-all")?;
        write_rules(
            out,
            "dns hosts",
            egress.allow_dns_hosts.as_ref(),
            "allow-all",
        )?;
        match &egress.allow_protocols {
            None => writeln!(out, "  protocols  allow-all")?,
            Some(protos) => writeln!(
                out,
                "  protocols  {}",
                protos
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )?,
        }
        write_rules(out, "deny subnets", egress.deny_subnets.as_ref(), "(none)")?;
    }
    // Ingress is an own-address surface: the switch's static forwarder is the
    // only per-session ingress minimald applies, and a host-address box
    // shares its host's namespace, so there is no per-session ingress policy
    // to show for it — "deny-all" there would claim a deny-rule exists.
    if network != boxes::NetworkMode::HostNet {
        writeln!(out, "ingress")?;
        // The dynamic row is the resolved stance, printed whether or not
        // anything was declared (NET-043): an absent setting is the deny the
        // policy module evaluates it as, and this render is where a person
        // reads which stance a box runs under — silence would read as
        // "unset" where there is no unset, only deny. The static half
        // keeps its own deny-all line: it describes the declared mappings,
        // not the dynamic stance. An absent setting carries the `(default)`
        // mark the egress row uses, so it never reads as an explicit deny.
        let dynamic_ingress = match effective
            .ingress
            .as_ref()
            .and_then(|ingress| ingress.dynamic_ingress)
        {
            Some(mode) => mode.to_string(),
            None => format!("{} (default)", boxes::DynamicIngress::Deny),
        };
        let dynamic_range = effective
            .ingress
            .as_ref()
            .and_then(|ingress| ingress.dynamic_allowed_range);
        match &effective.ingress {
            None => writeln!(out, "  deny-all")?,
            Some(ingress) => {
                if ingress.port_mappings.is_empty()
                    && ingress.dynamic_allowed_range.is_none()
                    && ingress.dynamic_ingress.is_none()
                {
                    writeln!(out, "  deny-all")?;
                }
                for mapping in &ingress.port_mappings {
                    // NET-129: a declared port another box at the same shared
                    // loopback address holds is served by that box — this
                    // box's attach yielded the forward (first-come) — so the
                    // row says whose it is rather than reading as this box's
                    // own. Every other declared row prints as before; an
                    // empty list, or one a client too old to fetch could not
                    // pass, marks nothing.
                    let held_by = shared_port_collisions
                        .iter()
                        .find(|c| c.port == mapping.external_port)
                        .map(|c| format!(" (held by {})", c.held_by));
                    match held_by {
                        Some(mark) => writeln!(
                            out,
                            "  {}  :{} → :{}{}",
                            mapping.proto, mapping.external_port, mapping.internal_port, mark
                        )?,
                        None => writeln!(
                            out,
                            "  {}  :{} → :{}",
                            mapping.proto, mapping.external_port, mapping.internal_port
                        )?,
                    }
                }
            }
        }
        if let Some((lo, hi)) = dynamic_range {
            writeln!(out, "  dynamic ports  {lo}–{hi}")?;
        }
        writeln!(out, "  dynamic ingress  {dynamic_ingress}")?;
    }
    Ok(())
}

/// The ports the box published at runtime, listed beside the declaration
/// (NET-044): one row a publish — the address its forward is bound on, and
/// the in-box port it forwards to — shaped like the declared mapping rows
/// above it, so the two read as one surface: what the box declared, and what
/// it went on to publish. A current daemon admits every runtime publish as
/// it binds it, so its rows carry no caveat. A row marked pending comes only
/// from an older daemon that did not admit runtime publishes, and says so
/// rather than reading as reachable. A row from a daemon older than the
/// `pending` field — one that could not classify the port either way —
/// says *unknown* and why, never
/// the reachable reading a missing state must not default itself into. A
/// box that published nothing prints no section: an empty header would
/// claim a distinction between "nothing published" and "nothing
/// publishable" the listing has no way to draw — the declaration above
/// already says what is permitted, and silence says the box used none of it.
///
/// Shared by `min session policy`'s printer and the tests that pin the
/// rendering, the way [`format_policy`] is.
pub fn write_live_ingress(
    out: &mut impl std::io::Write,
    live: &[minimald_rpc::LiveMapping],
) -> Result<(), anyhow::Error> {
    if live.is_empty() {
        return Ok(());
    }
    writeln!(out, "live ingress (published at runtime)")?;
    for mapping in live {
        let reachability = match mapping.pending {
            Some(true) => "  (pending; not yet reachable)",
            Some(false) => "",
            // A reply from a daemon that predates the field: the state is
            // unknown, not reachable — the row says both.
            None => "  (reachability unknown: the running daemon is older than this min)",
        };
        writeln!(
            out,
            "  {}  {} → :{}{}",
            mapping.proto, mapping.local, mapping.internal_port, reachability
        )?;
    }
    Ok(())
}

/// The warnings `min session policy` prints for the permitted listening
/// ports the daemon left unpublished because their audit record could not
/// be written (NET-046 fails closed): a listen-publish is driven by the
/// box's own listener, with no caller to answer, so this line is where the
/// failure reaches the user. One line per port; nothing when the list is
/// empty.
pub fn write_unaudited_listen_ports(
    out: &mut impl std::io::Write,
    ports: &[u16],
    audit_log: Option<&str>,
) -> Result<(), anyhow::Error> {
    let audit_log = audit_log.map_or_else(
        || "the audit log".to_string(),
        |path| format!("the audit log {path}"),
    );
    for port in ports {
        writeln!(
            out,
            "warning: port {port} is allowed but not reachable yet: Minimal could not write \
             {audit_log}. The port is published once that log can be written."
        )?;
    }
    Ok(())
}

/// The schema string of the document `min session policy -o json` writes:
/// the stamp a client checks before it reads anything else, held as a
/// constant so the renderer and the tests that pin the document cite one
/// spelling. The failure's object carries its own stamp (`min/v1/error`),
/// held beside the emitter that writes it, in `main`.
pub const POLICY_JSON_SCHEMA: &str = "min/v1/session-policy";

/// The `[network]` section a box was created with (BCLI-025), from the
/// network mode and the policy its record stores: the values the creating
/// command's override flags left after they applied (BCLI-024). These are
/// the values the create request stamped into the box's spec
/// ([`crate::spec_flags`]), so the section is written through the spec's
/// own serializer, key for key as the stored spec holds it.
///
/// It is the stored declaration, not the policy the gate enforces:
/// `min session policy` renders that one ([`format_policy`]).
///
/// # Errors
///
/// Fails when the section cannot be encoded as TOML or `out` fails.
pub fn write_stored_network(
    out: &mut impl std::io::Write,
    network: boxes::NetworkMode,
    policy: &boxes::BoxPolicy,
) -> Result<(), anyhow::Error> {
    let spec = mfile::spec::BoxSpec::for_session(
        None,
        mfile::spec::SpecFlags {
            network,
            policy: policy.clone(),
            hooks_enabled: true,
        },
    );
    let mut document =
        toml::Table::try_from(&spec).context("Cannot encode the box's network section")?;
    let section = document
        .remove("network")
        .context("The box's spec has no network section")?;
    let mut table = toml::Table::new();
    table.insert("network".to_owned(), section);
    let text = toml::to_string(&table).context("Cannot encode the box's network section")?;
    out.write_all(text.as_bytes())?;
    Ok(())
}

/// The ingress block as the document carries it: the declared policy, or
/// `deny_all` where the text rendering writes that reading — the same
/// decision its "deny-all" line makes, so the document never claims rules
/// the box never declared. Tagged by `kind` so a client branches on one
/// field, with the declared policy's own keys flattened beside it. The
/// `dynamic_ingress` key is the resolved stance in both variants (NET-043):
/// the deny an absent setting evaluates as, never a null a parser would
/// have to default itself — the document and the text rendering answer
/// "which stance does this box run under" identically.
#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PolicyIngressJson<'a> {
    /// Nothing is set, and the switch's default state is the deny: a claim
    /// about the switch, not about declared rules.
    DenyAll {
        /// The dynamic stance the box runs under, resolved — deny, the
        /// evaluation an absent setting takes (NET-043).
        dynamic_ingress: boxes::DynamicIngress,
        /// Always `default` here: a box that declared a stance is
        /// `declared`, whatever the stance.
        dynamic_ingress_source: &'static str,
    },
    /// The declared policy, carried as the wire's own shape.
    Declared(PolicyDeclaredIngressJson<'a>),
}

impl<'a> PolicyIngressJson<'a> {
    /// The document's form of the block [`format_policy`] prints: the same
    /// empty→deny-all reading, so a box that declared nothing does not read
    /// as carrying an empty declaration beside a box that denied everything
    /// on purpose.
    fn from_effective(policy: Option<&'a boxes::IngressPolicy>) -> Self {
        match policy {
            None => Self::DenyAll {
                dynamic_ingress: boxes::DynamicIngress::Deny,
                dynamic_ingress_source: "default",
            },
            Some(ingress)
                if ingress.port_mappings.is_empty()
                    && ingress.dynamic_allowed_range.is_none()
                    && ingress.dynamic_ingress.is_none() =>
            {
                Self::DenyAll {
                    dynamic_ingress: boxes::DynamicIngress::Deny,
                    dynamic_ingress_source: "default",
                }
            }
            Some(ingress) => Self::Declared(PolicyDeclaredIngressJson {
                port_mappings: &ingress.port_mappings,
                dynamic_allowed_range: ingress.dynamic_allowed_range,
                dynamic_ingress: ingress
                    .dynamic_ingress
                    .unwrap_or(boxes::DynamicIngress::Deny),
                dynamic_ingress_source: if ingress.dynamic_ingress.is_some() {
                    "declared"
                } else {
                    "default"
                },
            }),
        }
    }
}

/// The declared policy as the document carries it: the wire's own keys,
/// with `dynamic_ingress` resolved to the stance the box runs under rather
/// than the raw `None` the record stores.
#[derive(serde::Serialize)]
struct PolicyDeclaredIngressJson<'a> {
    port_mappings: &'a [boxes::PortMapping],
    dynamic_allowed_range: Option<(u16, u16)>,
    dynamic_ingress: boxes::DynamicIngress,
    /// `declared` when the box set a stance, `default` when the resolved
    /// deny is the absent setting's — the text rendering's `(default)` mark,
    /// as a field, the way the egress block's `source` carries it.
    dynamic_ingress_source: &'static str,
}

/// The egress block as the document carries it: the posture the gate
/// enforces, by the name the text rendering prints (`deny-all`,
/// `allow-all`), and which of the two ways it came about — `default`, the
/// rollout's resolution of a section the box never declared (NET-074), or
/// `declared`, the box's own section (NET-075) — so a consumer reading the
/// document never recomputes the default rule to tell a declared deny-all
/// from the default's identical verdict: the mark the text rendering puts
/// on the row, as a field. A declaration that admits something has no
/// single name, so its rows ride under `rules` with
/// `effective: "rules"` — the same lists the text rendering prints as its
/// dimension rows.
#[derive(serde::Serialize)]
struct PolicyEgressJson<'a> {
    /// The posture's name: `deny-all` or `allow-all` when the verdict has
    /// one, `rules` when the declaration's own rows say it.
    effective: &'static str,
    /// `default` for the rollout's resolution of an absent section,
    /// `declared` for the box's own.
    source: &'static str,
    /// The declared section, carried exactly when the box declared one —
    /// the shape the strict record holds, empty lists and all, so a
    /// declared deny-all is reconstructable from the document alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    rules: Option<&'a boxes::EgressPolicy>,
}

impl<'a> PolicyEgressJson<'a> {
    /// The document's form of the block [`format_policy`] prints: the same
    /// named verdicts, the same declaration-versus-default distinction the
    /// `(default)` mark carries, so the text and the document say one
    /// thing about a box's egress.
    fn from_effective(egress: &'a boxes::EffectiveEgress) -> Self {
        match egress {
            boxes::EffectiveEgress::DenyAll => Self {
                effective: "deny-all",
                source: "default",
                rules: None,
            },
            boxes::EffectiveEgress::AllowAll => Self {
                effective: "allow-all",
                source: "default",
                rules: None,
            },
            // The declared deny-all section keeps its name — the four
            // present-and-empty lists it would print as blankness — and its
            // `rules` ride beside the name the way every declaration's do.
            boxes::EffectiveEgress::Declared(section) => Self {
                effective: if section.admits_nothing() {
                    "deny-all"
                } else {
                    "rules"
                },
                source: "declared",
                rules: Some(section),
            },
        }
    }
}

/// One `min/v1/session-policy` document: the effective policy's parts, each
/// named as a parser reads them. The blocks the text rendering prints carry
/// over as keys, and the ones it suppresses are left out entirely rather
/// than nulled, so a key's absence is itself the claim (a host-address box
/// shares its host's namespace and has no per-session ingress; a none box
/// has no policy at all) — [`format_policy`]'s shape decisions restated for
/// a machine.
///
/// The live mappings ride as the wire's own rows, `pending` included, since
/// carrying that state is half of what the mode is for: a published port
/// the daemon has not admitted yet must not read as reachable to
/// something parsing this.
#[derive(serde::Serialize)]
struct PolicyJson<'a> {
    schema: &'static str,
    network: boxes::NetworkMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress: Option<PolicyEgressJson<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ingress: Option<PolicyIngressJson<'a>>,
    /// The box's credentialed upstream as it declared it, carried only
    /// when it declared one.
    #[serde(skip_serializing_if = "Option::is_none")]
    credentialed_upstream: Option<&'a boxes::CredentialedUpstream>,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_ingress: Option<LiveIngressJson>,
    /// The permitted listening ports the daemon left unpublished because
    /// their audit record could not be written (NET-046) — the text
    /// rendering's warning lines, for a machine. Absent when there are none.
    #[serde(skip_serializing_if = "<[u16]>::is_empty")]
    unaudited_listen_ports: &'a [u16],
    /// NET-129: the declared ports this box yields because another box at
    /// the same shared loopback address holds them, as the wire's own rows
    /// (`port`, and the holding box as `held_by`) — the text rendering's
    /// "(held by …)" marks. Omitted when empty, the reading a daemon that
    /// predates the fact, or a facts fetch that failed, also leaves.
    #[serde(skip_serializing_if = "no_shared_port_collisions")]
    shared_port_collisions: &'a [minimald_rpc::SharedPortCollision],
}

/// Serde helper: leave [`PolicyJson::shared_port_collisions`] out when empty.
fn no_shared_port_collisions(rows: &&[minimald_rpc::SharedPortCollision]) -> bool {
    rows.is_empty()
}

/// The live rows as the document carries them — the two states a client
/// must be able to tell apart, because each says a different thing about
/// the box: the rows the wire served, `pending` included — an empty list
/// is a claim about the box, that it published nothing — or `null`, the
/// view the daemon could not serve, which is no claim at all: the box may
/// have published anything, so an unavailability must never read as a
/// publish count of zero. (The third state is the key's absence, which
/// [`write_policy_json`] decides from the mode: a box with no network has
/// no live-ingress surface.)
#[derive(serde::Serialize)]
#[serde(untagged)]
enum LiveIngressJson {
    /// The daemon could not serve the view — an older build without the
    /// subsystem, a session mid-teardown. The same `null` a pre-field
    /// `pending` row reads as: unknown, never empty.
    Unavailable,
    /// The rows the wire served.
    Rows(Vec<minimald_rpc::LiveMapping>),
}

/// The document renderer `min session policy -o json` goes through — the
/// JSON-side counterpart of [`format_policy`], taking the same inputs the
/// command walks for so the two renderings describe the same policy: the
/// live rows arrive as the fetch's own result, served or failed, because
/// which of the two it was is part of what the document says. Shared with
/// the tests that pin the document, the way [`format_policy`] is. Like
/// [`format_policy`], it renders for a VM host.
pub fn write_policy_json(
    out: &mut impl std::io::Write,
    effective: &boxes::EffectiveBoxPolicy,
    network: boxes::NetworkMode,
    live: Result<Vec<minimald_rpc::LiveMapping>, String>,
    shared_port_collisions: &[minimald_rpc::SharedPortCollision],
) -> Result<(), anyhow::Error> {
    write_policy_json_noting(out, effective, network, live, shared_port_collisions, &[])
}

/// [`write_policy_json`], with the permitted listening ports the daemon left
/// unpublished because their audit record could not be written (NET-046)
/// carried as `unaudited_listen_ports` — the key a machine reads the
/// fail-closed listen-publish from, the way a person reads the text
/// rendering's warning lines.
pub fn write_policy_json_noting(
    out: &mut impl std::io::Write,
    effective: &boxes::EffectiveBoxPolicy,
    network: boxes::NetworkMode,
    live: Result<Vec<minimald_rpc::LiveMapping>, String>,
    shared_port_collisions: &[minimald_rpc::SharedPortCollision],
    unaudited_listen_ports: &[u16],
) -> Result<(), anyhow::Error> {
    // A none box has no policy to describe; the text rendering's one-line
    // note is prose for a person, so the document carries the schema, the
    // mode and what the box declared for a credentialed upstream, and every
    // other key's absence says why.
    let document = if network == boxes::NetworkMode::NoNet {
        PolicyJson {
            schema: POLICY_JSON_SCHEMA,
            network,
            egress: None,
            ingress: None,
            credentialed_upstream: effective.credentialed_upstream.as_ref(),
            live_ingress: None,
            unaudited_listen_ports: &[],
            shared_port_collisions: &[],
        }
    } else {
        PolicyJson {
            schema: POLICY_JSON_SCHEMA,
            network,
            egress: Some(PolicyEgressJson::from_effective(&effective.egress)),
            // Ingress is an own-address surface — the text rendering's gate:
            // a host-address box shares its host's namespace, so a key there
            // would claim a per-session policy that does not exist.
            ingress: (network != boxes::NetworkMode::HostNet)
                .then(|| PolicyIngressJson::from_effective(effective.ingress.as_ref())),
            credentialed_upstream: effective.credentialed_upstream.as_ref(),
            // The wire's own rows, `pending` included — an empty list is a
            // claim about the box (it published nothing), which is what the
            // key is for; the modes without a surface leave it out instead.
            // A fetch that failed is neither of those, so it must not
            // collapse into the first: the box may have published anything,
            // and the run cannot warn about it in prose either (a `-o
            // json` run's stderr is the error object's alone), so the
            // document says the state itself — `null`, the unknown — and
            // the why goes nowhere.
            live_ingress: Some(match live {
                Ok(rows) => LiveIngressJson::Rows(rows),
                Err(_) => LiveIngressJson::Unavailable,
            }),
            unaudited_listen_ports,
            // Ingress's own gate: a host-address box has no per-session
            // ingress, so it yields nothing a key could claim.
            shared_port_collisions: if network == boxes::NetworkMode::HostNet {
                &[]
            } else {
                shared_port_collisions
            },
        }
    };
    let encoded =
        serde_json_lenient::to_string(&document).context("encoding the session-policy document")?;
    writeln!(out, "{encoded}").context("writing the session-policy document")?;
    Ok(())
}

/// Why a `-o json` walk failed, tagged where the kinds can be told apart —
/// the tag carries this walk's own knowledge: the `code` the failure answers
/// with (the architecture's names, so a script branches on one vocabulary
/// across every machine-output command) and the hint naming the remedy, or
/// the kind of thing that was missing.
enum PolicyJsonFailure {
    /// No daemon to ask: the autospawn, the connection, or an RPC the daemon
    /// never answered.
    DaemonUnreachable(String),
    /// The daemon answered, but nothing matches the selector.
    SessionNotFound(String),
    /// The session resolved, but its effective policy could not be read.
    PolicyUnavailable(String),
}

impl PolicyJsonFailure {
    /// The failure as the machine-mode error object carries it — the
    /// generic payload every `-o json` command fails into (see
    /// [`MachineModeFailure`]), this walk's kinds mapped onto it.
    fn machine_failure(&self) -> MachineModeFailure {
        match self {
            Self::DaemonUnreachable(message) => MachineModeFailure::new(
                "daemon_unreachable",
                message.clone(),
                "the daemon may be down or mid-restart; try again, and check \
                 that --minimal-dir and --vm name the instance you meant"
                    .to_string(),
            ),
            // The architecture's code for a missing thing, with the kind —
            // a session — in the message (from the shared resolver, which
            // already names it) and in the hint beside it.
            Self::SessionNotFound(message) => MachineModeFailure::new(
                "not_found",
                message.clone(),
                "no session by that name or id exists; `min ls` lists the \
                 sessions there are"
                    .to_string(),
            ),
            Self::PolicyUnavailable(message) => MachineModeFailure::new(
                "policy_unavailable",
                message.clone(),
                "the session resolved but its effective policy could not be \
                 read — the daemon may be mid-restart; try again"
                    .to_string(),
            ),
        }
    }
}

/// The live-ingress fetch itself: the ports the box published at runtime
/// (NET-044) — the rows that make a `min net expose` visible rather than
/// only permitted — as the wire served them, or the failure as its
/// message. Built through `SessionLookup::parse` rather than a conversion
/// so the request types stay the rpc crate's, where the wire contract
/// lives.
///
/// A view of live state, not a fact the listing stands on, so both walks
/// degrade rather than fail — and the failure comes back rather than being
/// printed here, because the two renderings degrade differently and only
/// one of them may say it in prose: the text walk warns on stderr
/// ([`fetch_live_ingress_degrading`]), while a `-o json` run's stderr is
/// the error object's alone, so its document says the view is unknown
/// instead (see [`write_policy_json`]) — an unavailability must never read
/// as a claim that the box published nothing.
async fn fetch_live_ingress(
    client: &mut client::Client,
    box_name: &str,
) -> Result<Vec<minimald_rpc::LiveMapping>, String> {
    let live_lookup = match SessionLookup::parse(box_name) {
        SessionLookup::Id(id) => minimald_rpc::GetLiveIngressRequest::Id(id),
        SessionLookup::Name(n) => minimald_rpc::GetLiveIngressRequest::Name(n),
    };
    match client
        .oneshot_rpc::<minimald_rpc::GetLiveIngress>(live_lookup)
        .await
    {
        Ok(minimald_rpc::Errorable::Ok(live)) => Ok(live),
        Ok(minimald_rpc::Errorable::Err { error }) => Err(format!(
            "could not read the ports this box published while running: {error}"
        )),
        Err(error) => Err(format!(
            "could not read the ports this box published while running: {error:#}"
        )),
    }
}

/// The text walk's degrade of [`fetch_live_ingress`]: against a daemon
/// that cannot serve the rows — an older build without the subsystem, a
/// session mid-teardown — the declaration still renders, with a warning
/// that the live rows are unavailable rather than a claim that nothing is
/// published. Prose for a person, so stderr is where it goes, and this is
/// the one rendering that may put it there.
pub(crate) async fn fetch_live_ingress_degrading(
    client: &mut client::Client,
    box_name: &str,
) -> Vec<minimald_rpc::LiveMapping> {
    fetch_live_ingress(client, box_name)
        .await
        .unwrap_or_else(|warning| {
            eprintln!("warning: {warning}");
            Vec::new()
        })
}

/// The walk behind the JSON rendering: the same three steps as the text
/// walk — resolve the record, read the effective policy, list the live
/// mappings — with each failure tagged where the kinds can be told apart,
/// since the error document's `code` is a contract. The live fetch comes
/// back as its own result rather than degraded here, because the two
/// renderings degrade differently (see [`fetch_live_ingress`]): the
/// document says the unknown itself, so nothing is printed for it on a
/// stderr the error object has alone.
async fn box_policy_json_inputs(
    global: &GlobalArgs,
    box_name: &str,
) -> Result<
    (
        boxes::Record,
        boxes::EffectiveBoxPolicy,
        Result<Vec<minimald_rpc::LiveMapping>, String>,
        Vec<u16>,
        Vec<minimald_rpc::SharedPortCollision>,
    ),
    PolicyJsonFailure,
> {
    ensure_daemon(global)
        .map_err(|error| PolicyJsonFailure::DaemonUnreachable(format!("{error:#}")))?;
    let client = connect_daemon(global)
        .await
        .map_err(|error| PolicyJsonFailure::DaemonUnreachable(format!("{error:#}")))?;

    // The record the ingress key is gated on, resolved through the same
    // lookup the text walk uses — on the VM that owns the name (NET-058) —
    // with the failure kinds told apart where they can be: an RPC the daemon
    // never answered is no daemon to ask; a lookup that answered with
    // nothing, or a box on a stopped VM, is the not-found itself.
    let example = format!("session policy {box_name} -o json");
    let (mut client, record) = resolve_box_on_any_vm(global, client, box_name, &example)
        .await
        .map_err(|error| {
            if error.downcast_ref::<BoxNotFound>().is_some()
                || error.downcast_ref::<AmbiguousIdPrefix>().is_some()
                || error.downcast_ref::<AmbiguousBoxName>().is_some()
            {
                PolicyJsonFailure::SessionNotFound(error.to_string())
            } else {
                PolicyJsonFailure::DaemonUnreachable(format!("{error:#}"))
            }
        })?;
    // By the resolved id, as the text walk does.
    let box_id = &record.id.to_string();

    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    let lookup = match SessionLookup::parse(box_id) {
        SessionLookup::Id(id) => GetEffectiveSessionPolicyRequest::Id(id),
        SessionLookup::Name(n) => GetEffectiveSessionPolicyRequest::Name(n),
    };
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(lookup)
        .await
        .map_err(|error| PolicyJsonFailure::PolicyUnavailable(format!("{error:#}")))?;

    let live = fetch_live_ingress(&mut client, box_id).await;
    // The listen publishes the audit log refused (NET-046) and the yielded
    // shared-address ports (NET-129), from the runtime facts the text walk
    // reads them from. Optional facts: a daemon that cannot answer — an older
    // build, a session mid-teardown — leaves both keys out, as a box with
    // nothing to say does.
    let facts_lookup = match SessionLookup::parse(box_id) {
        SessionLookup::Id(id) => minimald_rpc::GetSessionRuntimeFactsRequest::Id(id),
        SessionLookup::Name(n) => minimald_rpc::GetSessionRuntimeFactsRequest::Name(n),
    };
    let (unaudited_listen_ports, shared_port_collisions) = match client
        .oneshot_rpc::<minimald_rpc::GetSessionRuntimeFacts>(facts_lookup)
        .await
    {
        Ok(minimald_rpc::Errorable::Ok(facts)) => {
            (facts.unaudited_listen_ports, facts.shared_port_collisions)
        }
        Ok(minimald_rpc::Errorable::Err { .. }) | Err(_) => (Vec::new(), Vec::new()),
    };

    match resp {
        minimald_rpc::Errorable::Ok(policy) => Ok((
            record,
            policy,
            live,
            unaudited_listen_ports,
            shared_port_collisions,
        )),
        minimald_rpc::Errorable::Err { error } => {
            Err(PolicyJsonFailure::PolicyUnavailable(error.to_string()))
        }
    }
}

/// The `-o json` rendering: the walk's inputs as one `min/v1/session-policy`
/// document on stdout, or the failure's one `min/v1/error` object on stderr
/// and a non-zero exit — never a document beside a plain-text error line,
/// so a client parses exactly one thing. The walk never writes the object
/// itself: it fails into the generic [`MachineModeFailure`] payload, which
/// `main`'s machine-mode error emitter — keyed on the output mode, shared
/// by every command that takes `-o json` — writes, so the error path is
/// one mechanism rather than a per-command one.
pub(crate) async fn box_policy_as_json(
    global: &GlobalArgs,
    box_name: &str,
) -> Result<(), anyhow::Error> {
    let (record, policy, live, unaudited_listen_ports, shared_port_collisions) =
        match box_policy_json_inputs(global, box_name).await {
            Ok(inputs) => inputs,
            Err(failure) => return Err(failure.machine_failure().into()),
        };
    let mut out = std::io::stdout();
    write_policy_json_noting(
        &mut out,
        &policy,
        record.network,
        live,
        &shared_port_collisions,
        &unaudited_listen_ports,
    )
    .context(OutputWriteError)?;
    out.flush().context(OutputWriteError)?;
    Ok(())
}

/// One egress rule row: the CIDR or hostname list, or the default the policy
/// resolves to when the dimension is unset. Writes comma-separated entries
/// to `out`, using `default` for an unset list and `(none)` for an empty list.
///
/// # Errors
///
/// Propagates errors from writing the row to `out`.
fn write_rules(
    out: &mut impl std::io::Write,
    label: &str,
    rules: Option<&Vec<String>>,
    default: &str,
) -> Result<(), anyhow::Error> {
    match rules {
        None => writeln!(out, "  {label}  {default}")?,
        // A list that is present and empty grants nothing in its dimension
        // — the shape an absent destination list resolves to on a box of
        // any network mode (NET-074) — and is spelled out, never printed as
        // a blank value in the egress display.
        Some(rules) if rules.is_empty() => writeln!(out, "  {label}  (none)")?,
        Some(rules) => writeln!(out, "  {label}  {}", rules.join(", "))?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxes::{
        CredentialedUpstream, DynamicIngress, EffectiveBoxPolicy, EffectiveEgress, IngressPolicy,
        IpProto, NetworkMode, PortMapping,
    };

    #[test]
    fn format_policy_dynamic_ingress_allow_prints_row_not_deny_all() {
        let policy = EffectiveBoxPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: Some(IngressPolicy {
                port_mappings: vec![],
                dynamic_allowed_range: None,
                dynamic_ingress: Some(DynamicIngress::Allow),
            }),
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, &[]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  dynamic ingress  allow"),
            "dynamic ingress row must be printed: {rendered}"
        );
        assert!(
            !rendered.contains("  deny-all"),
            "a policy with an explicit dynamic ingress setting must not print 'deny-all': {rendered}"
        );
    }

    #[test]
    fn format_policy_dynamic_ingress_prints_beside_static_mapping() {
        let policy = EffectiveBoxPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: Some(IngressPolicy {
                port_mappings: vec![PortMapping {
                    external_port: 8080,
                    internal_port: 80,
                    proto: IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
                dynamic_ingress: Some(DynamicIngress::Ask),
            }),
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, &[]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  tcp  :8080 → :80"),
            "static mapping must still render: {rendered}"
        );
        assert!(
            rendered.contains("  dynamic ingress  ask"),
            "dynamic ingress row must render alongside mapping: {rendered}"
        );
    }

    #[test]
    fn format_policy_egress_rows_default_when_unset() {
        // A declared-but-empty section: the strict shape the daemon handed
        // down before NET-074, which still arrives as `Declared` when the
        // session or the box opted out of the default — and so keeps
        // printing the per-dimension defaults, not `deny-all`.
        let policy = EffectiveBoxPolicy {
            egress: EffectiveEgress::Declared(boxes::EgressPolicy::default()),
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, &[]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains("egress\n"), "{rendered}");
        assert!(rendered.contains("  allow-all\n"), "{rendered}");
        assert!(rendered.contains("ingress\n"), "{rendered}");
        assert!(rendered.contains("  deny-all\n"), "{rendered}");
    }

    /// A declared deny-all section renders by name (NET-075): every allow
    /// list present and empty is the verdict `deny-all`, and the rows it
    /// would print otherwise are four blanks — a rendering that reads as
    /// nothing, the one this block must never produce. The name is the
    /// requirement's literal token, and it is bare: the `(default)` mark is
    /// the one distinction between a verdict the box declared and the same
    /// verdict the rollout resolved an absent section to, so the declared
    /// row carries none and the default's carries it — asserted here as
    /// the difference between the two renders, in the text and in the JSON
    /// document, whose `source` field carries the same distinction for a
    /// machine.
    #[test]
    fn policy_shows_declared_deny_all() {
        let declared = EffectiveBoxPolicy {
            egress: EffectiveEgress::Declared(boxes::EgressPolicy::deny_all()),
            ingress: None,
            credentialed_upstream: None,
        };

        // Own-address: the name, and no dimension rows — never blankness.
        let mut out = Vec::new();
        format_policy(&mut out, &declared, NetworkMode::OwnIp, &[]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("egress\n  deny-all\n"),
            "a declared deny-all box must show the deny-all name: {rendered}"
        );
        for row in ["  subnets", "  dns hosts", "  protocols", "  deny subnets"] {
            assert!(
                !rendered.contains(row),
                "the deny-all verdict must not render as dimension rows: {rendered}"
            );
        }
        assert!(
            !rendered.contains("deny-all (default)"),
            "a declared deny-all is a declaration, never a default, so its \
             row carries no mark: {rendered}"
        );

        // The same verdict the in-force default resolves an absent section
        // to, and the two rows differ by the mark alone: the declared row is
        // what the box chose, the marked row what the rollout chose for a
        // box that declared nothing (NET-075's "marked as a default and not
        // as a declaration" is the mark's own half of the pair).
        let defaulted = EffectiveBoxPolicy {
            egress: EffectiveEgress::DenyAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &defaulted, NetworkMode::OwnIp, &[]).unwrap();
        let default_rendered = String::from_utf8(out).unwrap();
        assert!(
            default_rendered.contains("egress\n  deny-all (default)\n"),
            "a box the rollout resolved to deny-all shows the name, marked \
             as the default: {default_rendered}"
        );
        assert_ne!(
            rendered, default_rendered,
            "the declared and the default renders must differ — the mark is \
             the difference between them"
        );

        // The JSON document carries the same distinction (NET-075): the
        // verdict's name in `effective`, its origin in `source`, so a
        // consumer never recomputes the default rule to tell a declared
        // deny-all from the default's identical verdict. The declared
        // section rides with its name, empty lists and all, the shape the
        // strict record holds; the default's carries no `rules`, because
        // the box declared nothing to carry.
        let egress_of = |policy: &EffectiveBoxPolicy| {
            let mut out = Vec::new();
            write_policy_json(&mut out, policy, NetworkMode::OwnIp, Ok(Vec::new()), &[]).unwrap();
            serde_json_lenient::from_slice::<serde_json_lenient::Value>(&out).unwrap()["egress"]
                .clone()
        };
        let declared_json = egress_of(&declared);
        assert_eq!(
            declared_json["effective"], "deny-all",
            "the document names the declared verdict by the same token: {declared_json}"
        );
        assert_eq!(
            declared_json["source"], "declared",
            "a declared verdict says where it came from: {declared_json}"
        );
        assert_eq!(
            declared_json["rules"]["allow_subnets"],
            serde_json_lenient::Value::Array(Vec::new()),
            "the declared section rides with its name, present-and-empty \
             lists and all: {declared_json}"
        );
        let default_json = egress_of(&defaulted);
        assert_eq!(
            default_json["effective"], "deny-all",
            "the default's verdict is the same name: {default_json}"
        );
        assert_eq!(
            default_json["source"], "default",
            "the rollout's resolution says so, so no consumer recomputes it: {default_json}"
        );
        assert!(
            default_json.get("rules").is_none(),
            "a box that declared nothing carries no section to carry: {default_json}"
        );
        assert_ne!(
            declared_json, default_json,
            "a declared deny-all and the default's never read the same in \
             the document"
        );

        // A section that allows something is not deny-all and keeps its
        // rows: one allowed subnet makes the verdict "10.0.0.0/8 and
        // nothing else", not deny-all, so it must not collapse to the name.
        let not_deny_all = EffectiveBoxPolicy {
            egress: EffectiveEgress::Declared(boxes::EgressPolicy {
                allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                allow_dns_hosts: Some(vec![]),
                allow_protocols: Some(vec![]),
                deny_subnets: None,
            }),
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &not_deny_all, NetworkMode::OwnIp, &[]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  subnets  10.0.0.0/8"),
            "a section that allows a subnet keeps its rows: {rendered}"
        );
        assert!(
            !rendered.contains("egress\n  deny-all\n"),
            "an allow-listed section is not deny-all and must not read as it: {rendered}"
        );
        // And in the document it is the one shape that carries rows rather
        // than a name: the verdict is the lists, spelled as the text
        // rendering spells them.
        let not_deny_all_json = egress_of(&not_deny_all);
        assert_eq!(
            not_deny_all_json["effective"], "rules",
            "a declaration that admits something has no name; its rows are \
             the verdict: {not_deny_all_json}"
        );
        assert_eq!(
            not_deny_all_json["rules"]["allow_subnets"][0], "10.0.0.0/8",
            "the named subnet rides the declared section: {not_deny_all_json}"
        );

        // A names-only declaration on an own-address box resolves its
        // absent `allow_subnets` to present and empty (NET-074): the row is
        // spelled out as `(none)`, never printed blank, and the section is
        // not deny-all, since its names grant reach.
        let names_only = EffectiveBoxPolicy {
            egress: EffectiveEgress::Declared(boxes::EgressPolicy {
                allow_subnets: Some(vec![]),
                allow_dns_hosts: Some(vec!["github.com".to_string()]),
                allow_protocols: None,
                deny_subnets: None,
            }),
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &names_only, NetworkMode::OwnIp, &[]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  subnets  (none)\n")
                && rendered.contains("  dns hosts  github.com\n"),
            "a resolved-empty list is spelled out beside the names: {rendered}"
        );
        assert!(
            !rendered.contains("egress\n  deny-all\n"),
            "a names-only section grants reach and is not deny-all: {rendered}"
        );
    }

    #[test]
    fn format_policy_prints_the_effective_default_for_a_bare_own_ip_box() {
        // NET-075: once the deny-all default is in force, a box that
        // declared no egress prints the posture the gate enforces, not the
        // absent section — by name, marked as the default it is.
        let deny_all = EffectiveBoxPolicy {
            egress: EffectiveEgress::DenyAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &deny_all, NetworkMode::OwnIp, &[]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("egress\n  deny-all (default)\n"),
            "a bare own-address box must show deny-all, marked as the \
             default: {rendered}"
        );
        assert!(
            !rendered.contains("allow-all"),
            "deny-all must not also print the allow-all default row: {rendered}"
        );
        // The opt-out keeps the shipped default, so that box still reads
        // allow-all (NET-077), under the same mark.
        let allow_all = EffectiveBoxPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &allow_all, NetworkMode::OwnIp, &[]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("egress\n  allow-all (default)\n"),
            "an opted-out bare box must show allow-all: {rendered}"
        );
    }

    /// The document says what the box declared for a credentialed
    /// upstream, as a key that is there only when it declared one. The text
    /// has no row for it: the rules the grant generates are part of the
    /// box's compiled policy.
    #[test]
    fn the_policy_document_carries_a_declared_credentialed_upstream() {
        let declared = EffectiveBoxPolicy {
            egress: EffectiveEgress::Declared(boxes::EgressPolicy::deny_all()),
            ingress: None,
            credentialed_upstream: Some(CredentialedUpstream::default()),
        };
        let plain = EffectiveBoxPolicy {
            credentialed_upstream: None,
            ..declared.clone()
        };
        let json_of = |policy: &EffectiveBoxPolicy, network| {
            let mut out = Vec::new();
            write_policy_json(&mut out, policy, network, Ok(Vec::new()), &[]).unwrap();
            serde_json_lenient::from_slice::<serde_json_lenient::Value>(&out).unwrap()
        };
        for network in [NetworkMode::OwnIp, NetworkMode::HostNet, NetworkMode::NoNet] {
            let json = json_of(&declared, network);
            assert_eq!(
                json["credentialed_upstream"],
                serde_json_lenient::json!({}),
                "{network:?}: {json}"
            );
            let json = json_of(&plain, network);
            assert!(json.get("credentialed_upstream").is_none(), "{json}");

            let mut out = Vec::new();
            format_policy(&mut out, &declared, network, &[]).unwrap();
            let rendered = String::from_utf8(out).unwrap();
            assert!(!rendered.contains("credentialed"), "{rendered}");
        }
    }

    /// NET-044: the ports a box published at runtime are listed beside the
    /// declaration — one row a publish, naming the bound address and the
    /// in-box port — and a box that published nothing prints no live section
    /// at all, so the declaration stands alone rather than beside an empty
    /// header.
    #[test]
    fn policy_shows_live_mappings() {
        let live = vec![minimald_rpc::LiveMapping {
            local: "127.0.64.21:3000".to_string(),
            internal_port: 3000,
            proto: IpProto::Tcp,
            pending: Some(false),
        }];

        // Beside the declaration: the declared dynamic surface first, then
        // the publish that used it.
        let policy = EffectiveBoxPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: Some(IngressPolicy {
                port_mappings: vec![],
                dynamic_allowed_range: Some((3000, 3999)),
                dynamic_ingress: Some(DynamicIngress::Allow),
            }),
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, &[]).unwrap();
        write_live_ingress(&mut out, &live).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        let (declared, live_rows) = rendered
            .split_once("live ingress (published at runtime)\n")
            .expect("the live section follows the declaration");
        assert!(
            declared.contains("  dynamic ports  3000–3999"),
            "the declared dynamic surface still renders: {rendered}"
        );
        assert!(
            live_rows.contains("  tcp  127.0.64.21:3000 → :3000\n"),
            "the live mapping names its bound address and in-box port: {rendered}"
        );

        // Every publish gets its row, in publish order.
        let mut out = Vec::new();
        write_live_ingress(
            &mut out,
            &[
                minimald_rpc::LiveMapping {
                    local: "127.0.64.21:3000".to_string(),
                    internal_port: 3000,
                    proto: IpProto::Tcp,
                    pending: Some(false),
                },
                minimald_rpc::LiveMapping {
                    local: "127.0.64.21:5353".to_string(),
                    internal_port: 5353,
                    proto: IpProto::Udp,
                    pending: Some(false),
                },
            ],
        )
        .unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  tcp  127.0.64.21:3000 → :3000\n")
                && rendered.contains("  udp  127.0.64.21:5353 → :5353\n"),
            "one row a publish: {rendered}"
        );

        // Nothing published: no section, not an empty header.
        let mut out = Vec::new();
        write_live_ingress(&mut out, &[]).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "",
            "a box that published nothing prints no live section"
        );
    }

    /// A listen-publish the audit log refused (NET-046) reaches the user
    /// as one warning line per port in `min session policy`, naming the
    /// log; an empty list prints nothing.
    #[test]
    fn unaudited_listen_ports_print_one_warning_per_port() {
        let mut out = Vec::new();
        write_unaudited_listen_ports(&mut out, &[3000, 3001], Some("/state/audit/decisions.log"))
            .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "warning: port 3000 is allowed but not reachable yet: Minimal could not write \
             the audit log /state/audit/decisions.log. The port is published once that log \
             can be written.\n\
             warning: port 3001 is allowed but not reachable yet: Minimal could not write \
             the audit log /state/audit/decisions.log. The port is published once that log \
             can be written.\n",
        );

        let mut out = Vec::new();
        write_unaudited_listen_ports(&mut out, &[], None).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "",
            "nothing refused, nothing said"
        );

        // The `-o json` document carries the same ports for a machine, and
        // leaves the key out when there are none.
        let policy = EffectiveBoxPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let document = |ports: &[u16]| {
            let mut out = Vec::new();
            write_policy_json_noting(
                &mut out,
                &policy,
                NetworkMode::OwnIp,
                Ok(Vec::new()),
                &[],
                ports,
            )
            .unwrap();
            serde_json_lenient::from_slice::<serde_json_lenient::Value>(&out).unwrap()
        };
        assert_eq!(
            document(&[3000])["unaudited_listen_ports"],
            serde_json_lenient::json!([3000])
        );
        assert!(
            document(&[]).get("unaudited_listen_ports").is_none(),
            "no refused listen, no key"
        );
    }

    /// NET-129: a declared port another box at the same shared loopback
    /// address holds is served by that box, so the declared row says whose
    /// it is rather than reading as this box's own. The mark names the
    /// holding box; a row whose port nobody else holds prints as before;
    /// an empty list marks nothing.
    #[test]
    fn policy_marks_a_yielded_shared_address_port() {
        let policy = EffectiveBoxPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: Some(IngressPolicy {
                port_mappings: vec![
                    PortMapping {
                        proto: IpProto::Tcp,
                        external_port: 8080,
                        internal_port: 8080,
                    },
                    PortMapping {
                        proto: IpProto::Udp,
                        external_port: 5353,
                        internal_port: 5353,
                    },
                ],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            credentialed_upstream: None,
        };
        let collisions = vec![minimald_rpc::SharedPortCollision {
            port: 8080,
            held_by: "first.min.internal".to_string(),
        }];

        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, &collisions).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  tcp  :8080 → :8080 (held by first.min.internal)\n"),
            "the yielded port's row names the box that holds it: {rendered}"
        );
        assert!(
            rendered.contains("  udp  :5353 → :5353\n"),
            "a port no other box holds prints unmarked: {rendered}"
        );

        // The `-o json` document carries the same rows, so a parser can tell
        // the yielded mapping from one this box serves; with none, the key
        // is absent.
        let mut out = Vec::new();
        write_policy_json(
            &mut out,
            &policy,
            NetworkMode::OwnIp,
            Ok(Vec::new()),
            &collisions,
        )
        .unwrap();
        let document = String::from_utf8(out).unwrap();
        assert!(
            document.contains(
                r#""shared_port_collisions":[{"port":8080,"held_by":"first.min.internal"}]"#
            ),
            "the document names the yielded port and its holder: {document}"
        );
        let mut out = Vec::new();
        write_policy_json(&mut out, &policy, NetworkMode::OwnIp, Ok(Vec::new()), &[]).unwrap();
        let document = String::from_utf8(out).unwrap();
        assert!(
            !document.contains("shared_port_collisions"),
            "no yields, no key: {document}"
        );

        // No collisions, no marks: the same declaration renders as before.
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, &[]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  tcp  :8080 → :8080\n"),
            "an empty collision list marks nothing: {rendered}"
        );
    }

    /// An older daemon bound a runtime mapping without admitting its port,
    /// so its row is a fact with a caveat. Both
    /// surfaces `min session policy` reads say it: the rendered text marks
    /// the row pending rather than letting it read as reachable, and the
    /// mapping's JSON — the shape any client of the RPC reads, and the data
    /// these rows render — carries the state with it.
    #[test]
    fn policy_shows_pending_live_mapping() {
        let pending = minimald_rpc::LiveMapping {
            local: "127.0.64.21:3000".to_string(),
            internal_port: 3000,
            proto: IpProto::Tcp,
            pending: Some(true),
        };
        let admitted = minimald_rpc::LiveMapping {
            local: "127.0.64.21:5353".to_string(),
            internal_port: 5353,
            proto: IpProto::Udp,
            pending: Some(false),
        };

        // The text: the pending row says so, bound but not admitted yet, and
        // the admitted row reads as reachable.
        let mut out = Vec::new();
        write_live_ingress(&mut out, &[pending.clone(), admitted.clone()]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  tcp  127.0.64.21:3000 → :3000  (pending; not yet reachable)\n"),
            "a mapping the gate has not admitted reads as pending: {rendered}"
        );
        assert!(
            rendered.contains("  udp  127.0.64.21:5353 → :5353\n"),
            "a mapping the gate admitted reads as reachable, with no caveat: {rendered}"
        );

        // The JSON: the mapping's own shape carries the state, so a client
        // reading the wire can tell the two apart without the renderer.
        let pending_json = serde_json_lenient::to_string(&pending).unwrap();
        assert!(
            pending_json.contains("\"pending\":true"),
            "the pending mapping's JSON says so: {pending_json}"
        );
        let admitted_json = serde_json_lenient::to_string(&admitted).unwrap();
        assert!(
            admitted_json.contains("\"pending\":false"),
            "the admitted mapping's JSON says so: {admitted_json}"
        );
    }

    /// A reply from a daemon that predates the `pending` field carries no
    /// `pending` key, and that absence must not fail open into the reachable
    /// reading: the row decodes as `None` — unknown — the text row says
    /// unknown and why, and the JSON document carries `null`, so nothing
    /// parsing either surface reads a runtime publish as reachable that the
    /// daemon could not classify.
    #[test]
    fn policy_marks_a_pre_field_pending_reply_unknown() {
        let encoded = serde_json_lenient::to_string(&minimald_rpc::LiveMapping {
            local: "127.0.64.21:3000".to_string(),
            internal_port: 3000,
            proto: IpProto::Tcp,
            pending: Some(false),
        })
        .unwrap();
        // The key, removed: the shape a daemon older than the field writes.
        let mut object: serde_json_lenient::Value = serde_json_lenient::from_str(&encoded).unwrap();
        object
            .as_object_mut()
            .expect("a mapping encodes as an object")
            .remove("pending");
        let pre_field = serde_json_lenient::to_string(&object).unwrap();
        let decoded: minimald_rpc::LiveMapping = serde_json_lenient::from_str(&pre_field).unwrap();
        assert_eq!(
            decoded.pending, None,
            "a reply from a pre-field daemon decodes as unknown: {pre_field}"
        );

        // The text row: unknown, and why — never the bare row of a
        // reachable mapping.
        let mut out = Vec::new();
        write_live_ingress(&mut out, std::slice::from_ref(&decoded)).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains(
                "  tcp  127.0.64.21:3000 → :3000  (reachability unknown: the running daemon \
                 is older than this min)\n"
            ),
            "a mapping the daemon could not classify reads as unknown, not as reachable: {rendered}"
        );

        // The JSON document: the unknown state rides as `null`, so a client
        // parsing it branches on absence of the fact, not on a guess.
        let json = serde_json_lenient::to_string(&decoded).unwrap();
        assert!(
            json.contains("\"pending\":null"),
            "the document carries the unknown state as null, not as a bool: {json}"
        );
    }

    /// The walk's failure kinds map onto the machine-mode error payload:
    /// the architecture's codes — `not_found` for a missing thing, with
    /// the kind of thing that was missing (a session) in the message and
    /// the hint, never a policy-specific spelling — beside the message and
    /// the hint the object carries. The one-object shape the payload
    /// becomes on stderr is pinned beside the emitter that writes it, in
    /// `main`'s own tests, since writing it is the emitter's job now.
    #[test]
    fn policy_json_failures_map_to_the_machine_mode_payload() {
        let missing =
            PolicyJsonFailure::SessionNotFound("No session found matching 'gone'".to_string())
                .machine_failure();
        assert_eq!(
            missing.code(),
            "not_found",
            "a missing session is the architecture's not-found code, not a \
             policy spelling"
        );
        assert!(
            missing.message().contains("session"),
            "the message names the kind of thing that was missing: {}",
            missing.message()
        );
        assert!(
            missing.hint().contains("session"),
            "the hint names the kind of thing that was missing: {}",
            missing.hint()
        );

        // The other two kinds keep their own codes, the same vocabulary.
        assert_eq!(
            PolicyJsonFailure::DaemonUnreachable(String::new())
                .machine_failure()
                .code(),
            "daemon_unreachable",
        );
        assert_eq!(
            PolicyJsonFailure::PolicyUnavailable(String::new())
                .machine_failure()
                .code(),
            "policy_unavailable",
        );
    }
}
