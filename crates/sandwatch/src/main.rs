//! `sandwatch`: flight recorder and tripwire for AI agents.

use anyhow::{Context, Result};
use catena::{Alert, Rule};
use clap::{Parser, Subcommand};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;
use swrec::Integrity;

#[derive(Parser)]
#[command(name = "sandwatch", version, about = "Flight recorder and tripwire for AI agents")]
struct Cli {
    /// Directory containing Catena rule files (*.yaml).
    #[arg(long, global = true, env = "SANDWATCH_RULES", default_value = "rules")]
    rules: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check the hash chain and structure of recordings.
    Verify { paths: Vec<PathBuf> },
    /// Replay a recording through Catena and show the alert timeline.
    Replay {
        path: PathBuf,
        /// Emit alerts as JSON lines instead of a timeline.
        #[arg(long)]
        json: bool,
    },
    /// Score the rules against labeled recordings (files or directories).
    Eval {
        paths: Vec<PathBuf>,
        /// Show every session, not only failures.
        #[arg(short, long)]
        verbose: bool,
    },
    /// List loaded rules.
    Rules,
    /// Launch a command in a fresh cgroup and watch it live (needs root).
    #[cfg(target_os = "linux")]
    Run {
        #[command(flatten)]
        live: LiveArgs,
        /// Command to run, after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Watch an existing container or cgroup live until interrupted (needs root).
    #[cfg(target_os = "linux")]
    Watch {
        #[command(flatten)]
        live: LiveArgs,
        /// Container id (or a prefix of at least 12 characters).
        #[arg(long, conflicts_with = "cgroup")]
        container: Option<String>,
        /// cgroup v2 directory, e.g. /sys/fs/cgroup/docker/<id>.
        #[arg(long)]
        cgroup: Option<PathBuf>,
    },
    /// Unfreeze a cgroup that Sandwatch froze.
    #[cfg(target_os = "linux")]
    Thaw {
        #[arg(long, conflicts_with = "cgroup")]
        container: Option<String>,
        #[arg(long)]
        cgroup: Option<PathBuf>,
    },
}

#[cfg(target_os = "linux")]
#[derive(clap::Args)]
struct LiveArgs {
    /// Recording to write (.swrec or .swrec.gz).
    #[arg(long, short)]
    out: Option<PathBuf>,
    #[arg(long)]
    session_id: Option<String>,
    /// Freeze the workload when any of these rules fire (comma-separated), e.g. `chain`.
    #[arg(long, value_delimiter = ',')]
    freeze_on: Vec<String>,
    /// Stop after this many seconds.
    #[arg(long)]
    duration: Option<f64>,
    /// `run` only: when the session stops (duration, Ctrl+C) the workload is sent SIGTERM,
    /// given this many seconds to exit, then its whole cgroup is killed.
    #[arg(long, default_value_t = 2.0)]
    grace: f64,
    /// Embed ground-truth labels from a lab manifest (for evaluation).
    #[arg(long, requires = "scenario")]
    manifest: Option<PathBuf>,
    #[arg(long)]
    scenario: Option<String>,
    #[arg(long, default_value_t = 1)]
    seed: u32,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Verify { paths } => verify(&paths),
        Cmd::Rules => {
            let rules = catena::load_dir(&cli.rules)?;
            for r in &rules {
                let stage = r.def.stage.as_deref().unwrap_or("-");
                println!("{:<20} {:<9} {:<18} {}", r.id(), r.def.severity.as_str(), stage, r.def.name);
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Replay { path, json } => {
            let rules = catena::load_dir(&cli.rules)?;
            replay(&rules, &path, json)
        }
        Cmd::Eval { paths, verbose } => {
            let rules = catena::load_dir(&cli.rules)?;
            eval(&rules, &paths, verbose)
        }
        #[cfg(target_os = "linux")]
        Cmd::Run { live: args, cmd } => {
            let rules = catena::load_dir(&cli.rules)?;
            live::run(rules, args, sandwatch_sensor::session::Target::Run(cmd))
        }
        #[cfg(target_os = "linux")]
        Cmd::Watch { live: args, container, cgroup } => {
            let rules = catena::load_dir(&cli.rules)?;
            let cg = live::resolve_cgroup(container, cgroup)?;
            live::run(rules, args, sandwatch_sensor::session::Target::Cgroup(cg))
        }
        #[cfg(target_os = "linux")]
        Cmd::Thaw { container, cgroup } => {
            let cg = live::resolve_cgroup(container, cgroup)?;
            sandwatch_sensor::session::freeze(&cg, false)?;
            println!("thawed {}", cg.display());
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[cfg(target_os = "linux")]
mod live {
    use super::{print_alert, LiveArgs};
    use anyhow::{bail, Context, Result};
    use catena::Rule;
    use sandwatch_sensor::session::{self, Options, Target};
    use serde_json::{json, Value};
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    pub fn resolve_cgroup(container: Option<String>, cgroup: Option<PathBuf>) -> Result<PathBuf> {
        match (container, cgroup) {
            (Some(id), _) => session::find_container_cgroup(&id),
            (_, Some(p)) => Ok(p),
            _ => bail!("give --container <id> or --cgroup <path>"),
        }
    }

    fn labels(manifest: &PathBuf, scenario: &str, seed: u32) -> Result<Value> {
        let m: Value = serde_json::from_str(&std::fs::read_to_string(manifest)?)
            .with_context(|| format!("parsing {}", manifest.display()))?;
        let s = m["scenarios"]
            .as_array()
            .and_then(|a| a.iter().find(|s| s["id"] == scenario))
            .with_context(|| format!("scenario {scenario} not in manifest"))?;
        let mut l = json!({
            "class": s["class"], "scenario": s["id"], "variant": seed,
            "pace": s.get("pace").cloned().unwrap_or(json!("natural")),
            "description": s["description"],
            "attack_techniques": s.get("attack_techniques").cloned().unwrap_or(json!([])),
            "expected_detections": s.get("expected_detections").cloned().unwrap_or(json!([])),
            "synthetic": true,
        });
        for k in ["forbidden_detections", "hard_negative", "notes"] {
            if let Some(v) = s.get(k) {
                l[k] = v.clone();
            }
        }
        Ok(l)
    }

    pub fn run(rules: Vec<Rule>, a: LiveArgs, target: Target) -> Result<ExitCode> {
        let session_id = a.session_id.clone().unwrap_or_else(|| {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!("live-{t}")
        });
        let out = a.out.clone().unwrap_or_else(|| PathBuf::from(format!("{session_id}.swrec.gz")));
        let labels = match (&a.manifest, &a.scenario) {
            (Some(m), Some(s)) => Some(labels(m, s, a.seed)?),
            _ => None,
        };
        let stop = Arc::new(AtomicBool::new(false));
        {
            let stop = stop.clone();
            ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
                .context("installing signal handler")?;
        }
        let opts = Options {
            session_id: session_id.clone(),
            out: out.clone(),
            labels,
            freeze_on: a.freeze_on.clone(),
            duration: a.duration.map(Duration::from_secs_f64),
            stop,
            stop_grace: Duration::try_from_secs_f64(a.grace)
                .context("--grace must be a non-negative number of seconds")?,
        };
        println!("SANDWATCH  live session {session_id}  →  {}\n", out.display());
        let mut on_alert = |al: &catena::Alert, _actor: Option<&str>| {
            print_alert(al);
            use std::io::Write;
            let _ = std::io::stdout().flush();
        };
        let o = session::run(opts, target, rules, &mut on_alert)?;
        println!();
        if o.alerts.is_empty() {
            println!("  no alerts");
        }
        println!(
            "  {} events recorded; {} alerts; sensor drops: ring {} / pending {}",
            o.events, o.alerts.len(), o.ring_drops, o.pending_drops
        );
        if o.order.reordered_events > 0 {
            println!(
                "  {} events arrived out of order (max {:.1} ms late); {} too late for a rule window",
                o.order.reordered_events,
                o.order.max_lateness_us as f64 / 1000.0,
                o.order.late_events_ignored
            );
        }
        if let Some(r) = &o.frozen_by {
            println!("  workload FROZEN by {r} ({})", o.cgroup.display());
        }
        if let Some(c) = o.exit_code {
            println!("  workload exit code {c}");
        }
        Ok(ExitCode::SUCCESS)
    }
}

fn verify(paths: &[PathBuf]) -> Result<ExitCode> {
    let files = swrec::discover(paths)?;
    let mut bad = 0;
    for f in &files {
        // Unreadable (truncated gzip, invalid JSON, …) is a verification failure, not an abort.
        let (rec, integrity) = match swrec::load(f, true) {
            Ok(r) => r,
            Err(e) => {
                bad += 1;
                println!("FAIL  {}  -- unreadable: {e:#}", f.display());
                continue;
            }
        };
        match integrity {
            Integrity::Verified => {
                println!("OK    {}  ({} events)", f.display(), rec.events.len())
            }
            Integrity::Broken(why) => {
                bad += 1;
                println!("FAIL  {}  -- {why}", f.display())
            }
            Integrity::NotChecked => unreachable!(),
        }
    }
    println!("\n{}/{} recordings verified", files.len() - bad, files.len());
    Ok(if bad == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn fmt_t(t_us: i64) -> String {
    let s = t_us as f64 / 1e6;
    let m = (s / 60.0).floor();
    format!("{:02}:{:06.3}", m as i64, s - m * 60.0)
}

fn replay(rules: &[Rule], path: &PathBuf, json: bool) -> Result<ExitCode> {
    let (rec, integrity) = swrec::load(path, true)?;
    let alerts = catena::run(rules, &rec.events);
    if json {
        for a in &alerts {
            println!("{}", serde_json::to_string(a)?);
        }
        return Ok(ExitCode::SUCCESS);
    }
    let h = &rec.header;
    let integrity_s = match &integrity {
        Integrity::Verified => "chain verified".to_string(),
        Integrity::Broken(w) => format!("CHAIN BROKEN: {w}"),
        Integrity::NotChecked => "not checked".into(),
    };
    println!("SANDWATCH  session {}  ({} events, {:.1}s, {integrity_s})",
        h.session.id, rec.events.len(), h.session.duration_ms as f64 / 1000.0);
    if let Some(l) = &h.labels {
        println!("           label: {}{}", l.class, if l.hard_negative { " (hard negative)" } else { "" });
    }
    println!();
    if alerts.is_empty() {
        println!("  no alerts");
    }
    for a in &alerts {
        print_alert(a);
    }
    let start = h.session.start_time;
    if !h.ground_truth.phases.is_empty() {
        println!("\n  ground truth phases:");
        for p in &h.ground_truth.phases {
            println!("    {}  {}", fmt_t((p.time - start) * 1000), p.name);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn print_alert(a: &Alert) {
    let sym = match a.severity {
        "critical" => "✖✖",
        "high" => "✖ ",
        _ => "⚠ ",
    };
    if a.rule_id == "chain" || !a.chain.is_empty() {
        let stages: Vec<String> = a.chain.iter().map(|l| l.stage.clone()).collect();
        println!("  {}  {sym} {:<18} {}  score {:.2}", fmt_t(a.t_us), a.rule_id.to_uppercase(),
            stages.join(" → "), a.score.unwrap_or(0.0));
        return;
    }
    let stage = a.stage.as_deref().map(|s| format!(" [{s}]")).unwrap_or_default();
    println!("  {}  {sym} {:<18} {}{stage}  — {} targets, {} failed",
        fmt_t(a.t_us), a.rule_id.to_uppercase(), a.rule_name, a.distinct, a.failures);
    if let Some(actor) = &a.actor {
        println!("              by: {}", truncate(actor, 90));
    }
    for e in a.evidence.iter().take(5) {
        println!("              · {}", truncate(e, 90));
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n - 1).collect::<String>() + "…" }
}

struct SessionResult {
    id: String,
    class: String,
    hard_negative: bool,
    fired: BTreeSet<String>,
    missing: Vec<String>,
    forbidden_hit: Vec<String>,
    extra: Vec<String>,
    latency_ms: Option<i64>,
    pass: bool,
}

fn eval(rules: &[Rule], paths: &[PathBuf], verbose: bool) -> Result<ExitCode> {
    let files = swrec::discover(paths)?;
    anyhow::ensure!(!files.is_empty(), "no .swrec / .swrec.gz recordings found");
    let mut results = Vec::new();
    for f in &files {
        let (rec, integrity) = swrec::load(f, true).with_context(|| f.display().to_string())?;
        if let Integrity::Broken(w) = &integrity {
            anyhow::bail!("{}: chain broken ({w}); refusing to evaluate tampered data", f.display());
        }
        let labels = rec.header.labels.clone().unwrap_or_default();
        let alerts = catena::run(rules, &rec.events);
        let fired: BTreeSet<String> = alerts.iter().map(|a| a.rule_id.clone()).collect();
        let expected: BTreeSet<String> = labels.expected_detections.iter().cloned().collect();
        let forbidden: BTreeSet<String> = labels.forbidden_detections.iter().cloned().collect();
        let is_attack = labels.class == "attack";
        let missing: Vec<String> = expected.difference(&fired).cloned().collect();
        let forbidden_hit: Vec<String> = if is_attack {
            fired.intersection(&forbidden).cloned().collect()
        } else {
            fired.iter().cloned().collect() // any alert on benign is a false positive
        };
        let extra: Vec<String> = if is_attack {
            fired.difference(&expected).filter(|r| !forbidden.contains(*r)).cloned().collect()
        } else {
            vec![]
        };
        let first_phase = rec.header.ground_truth.phases.first().map(|p| p.time);
        let latency_ms = match (is_attack, alerts.first(), first_phase) {
            (true, Some(a), Some(p)) => Some(a.time - p),
            _ => None,
        };
        let pass = missing.is_empty() && forbidden_hit.is_empty();
        results.push(SessionResult {
            id: rec.header.session.id.clone(),
            class: labels.class.clone(),
            hard_negative: labels.hard_negative,
            fired, missing, forbidden_hit, extra, latency_ms, pass,
        });
    }

    // ---- per-session table
    println!("{:<26} {:<9} {:<6} detail", "session", "class", "result");
    println!("{}", "-".repeat(96));
    for r in &results {
        if !verbose && r.pass {
            continue;
        }
        let class = format!("{}{}", r.class, if r.hard_negative { "*" } else { "" });
        let mut detail = Vec::new();
        if !r.missing.is_empty() { detail.push(format!("MISSED {}", r.missing.join(","))); }
        if !r.forbidden_hit.is_empty() {
            let what = if r.class == "attack" { "FORBIDDEN" } else { "FALSE POSITIVE" };
            detail.push(format!("{what} {}", r.forbidden_hit.join(",")));
        }
        if r.pass {
            detail.push(if r.fired.is_empty() { "no alerts".into() }
                        else { format!("fired {}", r.fired.iter().filter(|f| !r.extra.contains(f)).cloned().collect::<Vec<_>>().join(",")) });
        }
        if !r.extra.is_empty() { detail.push(format!("(+ {})", r.extra.join(","))); }
        if let Some(l) = r.latency_ms { detail.push(format!("first alert +{:.1}s", l as f64 / 1000.0)); }
        println!("{:<26} {:<9} {:<6} {}", r.id, class, if r.pass { "PASS" } else { "FAIL" }, detail.join("  "));
    }
    if !verbose {
        println!("(passing sessions hidden; use -v to show all)");
    }

    // ---- per-rule table
    println!("\n{:<20} {:>4} {:>4} {:>4} {:>6}   recall", "rule", "TP", "FN", "FP", "extra");
    println!("{}", "-".repeat(56));
    for rule in rules {
        let id = rule.id();
        let (mut tp, mut fnn, mut fp, mut extra) = (0, 0, 0, 0);
        for r in &results {
            let fired = r.fired.contains(id);
            if r.missing.iter().any(|m| m == id) { fnn += 1; }
            else if fired && r.class == "attack" && !r.forbidden_hit.iter().any(|f| f == id) {
                if r.extra.iter().any(|e| e == id) { extra += 1 } else { tp += 1 }
            }
            if r.forbidden_hit.iter().any(|f| f == id) { fp += 1; }
        }
        let recall = if tp + fnn == 0 { "-".to_string() } else { format!("{:.0}%", 100.0 * tp as f64 / (tp + fnn) as f64) };
        println!("{id:<20} {tp:>4} {fnn:>4} {fp:>4} {extra:>6}   {recall}");
    }

    // ---- summary
    let attacks: Vec<&SessionResult> = results.iter().filter(|r| r.class == "attack").collect();
    let benign: Vec<&SessionResult> = results.iter().filter(|r| r.class != "attack").collect();
    let detected = attacks.iter().filter(|r| !r.fired.is_empty()).count();
    let benign_fp = benign.iter().filter(|r| !r.fired.is_empty()).count();
    let passed = results.iter().filter(|r| r.pass).count();
    let mut lat: Vec<i64> = attacks.iter().filter_map(|r| r.latency_ms).collect();
    lat.sort();
    println!("\nattack sessions with ≥1 alert:   {detected}/{}", attacks.len());
    println!("benign sessions with any alert:  {benign_fp}/{}  (false positives)", benign.len());
    if !lat.is_empty() {
        println!("time to first alert (median):    {:.2}s after the attack began", lat[lat.len() / 2] as f64 / 1000.0);
    }
    println!("sessions passing all checks:     {passed}/{}", results.len());
    Ok(if passed == results.len() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}
