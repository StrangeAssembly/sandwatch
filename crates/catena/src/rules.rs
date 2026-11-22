//! Rule definitions (YAML) and their compiled form.

use anyhow::{bail, Context, Result};
use regex::RegexSet;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::Path;
use swrec::{Event, CLASS_FILE, CLASS_NETWORK, CLASS_PROCESS};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Contribution to a chain score.
    pub fn weight(self) -> f64 {
        match self {
            Severity::Low => 0.2,
            Severity::Medium => 0.4,
            Severity::High => 0.6,
            Severity::Critical => 0.8,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    #[default]
    Detect,
    Chain,
}

/// Rule file as written in YAML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub kind: RuleKind,
    pub severity: Severity,
    /// Attack stage this rule evidences; chain rules correlate distinct stages.
    pub stage: Option<String>,
    #[serde(default)]
    pub attack: Vec<String>,
    pub description: String,
    /// Why this rule should not fire on normal work (documentation for reviewers).
    pub false_positive_notes: Option<String>,
    #[serde(rename = "match")]
    pub matcher: Option<MatchDef>,
    pub aggregate: Option<AggregateDef>,
    pub chain: Option<ChainDef>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MatchDef {
    /// file | process | network
    pub class: Option<String>,
    #[serde(default)]
    pub activities: Vec<String>,
    /// File path must match at least one regex.
    #[serde(default)]
    pub path_any: Vec<String>,
    /// File path must match none of these regexes.
    #[serde(default)]
    pub path_none: Vec<String>,
    /// Acting process name (basename) must be one of these.
    #[serde(default)]
    pub actor_name_any: Vec<String>,
    /// Destination IP: exact address or IPv4/IPv6 CIDR.
    #[serde(default)]
    pub dst_ip_any: Vec<String>,
    #[serde(default)]
    pub dst_ip_none: Vec<String>,
    #[serde(default)]
    pub dst_port_any: Vec<u16>,
    #[serde(default)]
    pub dst_port_none: Vec<u16>,
    /// Raw syscall flags must contain one of these substrings (e.g. CLONE_NEWUSER).
    #[serde(default)]
    pub flags_any: Vec<String>,
    /// any | success | failure
    pub status: Option<String>,
    /// For opens: read | write (as recorded in `unmapped.access`).
    pub access: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateDef {
    /// Distinct targets (paths, ip:port, …) needed inside the window.
    #[serde(default = "one")]
    pub min_distinct: usize,
    pub window_s: f64,
    /// Distinct targets that FAILED (counting only `failure_errnos`) needed inside the window.
    #[serde(default)]
    pub min_failures: usize,
    /// Fraction of distinct targets that failed, 0.0–1.0.
    #[serde(default)]
    pub min_failure_ratio: f64,
    /// errnos that count as a "probe failed" signal. Others (e.g. ENODATA from xattr reads)
    /// are noise and are ignored for failure counting.
    #[serde(default = "default_errnos")]
    pub failure_errnos: Vec<String>,
    /// What counts as "distinct": `target` (full path / ip:port, default) or `basename`
    /// (so copies of the same file in different directories count once).
    #[serde(default)]
    pub distinct_by: DistinctBy,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DistinctBy {
    #[default]
    Target,
    Basename,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainDef {
    pub min_stages: usize,
    pub window_s: f64,
}

fn one() -> usize {
    1
}

fn default_errnos() -> Vec<String> {
    [
        "ENOENT", "EACCES", "EPERM", "ENOTDIR", "ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH",
        "ETIMEDOUT", "EROFS", "ENXIO",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Debug, Clone)]
enum IpMatcher {
    Exact(IpAddr),
    Cidr(IpAddr, u8),
}

impl IpMatcher {
    fn parse(s: &str) -> Result<Self> {
        if let Some((addr, bits)) = s.split_once('/') {
            Ok(IpMatcher::Cidr(addr.parse()?, bits.parse()?))
        } else {
            Ok(IpMatcher::Exact(s.parse()?))
        }
    }
    fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            IpMatcher::Exact(a) => a == ip,
            IpMatcher::Cidr(net, bits) => match (net, ip) {
                (IpAddr::V4(n), IpAddr::V4(i)) => {
                    let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - *bits as u32) };
                    (u32::from(*n) & mask) == (u32::from(*i) & mask)
                }
                (IpAddr::V6(n), IpAddr::V6(i)) => {
                    let mask = if *bits == 0 { 0 } else { u128::MAX << (128 - *bits as u32) };
                    (u128::from(*n) & mask) == (u128::from(*i) & mask)
                }
                _ => false,
            },
        }
    }
}

/// A rule ready to evaluate.
#[derive(Debug, Clone)]
pub struct Rule {
    pub def: RuleDef,
    class_uid: Option<u32>,
    path_any: Option<RegexSet>,
    path_none: Option<RegexSet>,
    dst_ip_any: Vec<IpMatcher>,
    dst_ip_none: Vec<IpMatcher>,
}

impl Rule {
    pub fn compile(def: RuleDef) -> Result<Self> {
        let ctx = || format!("rule {}", def.id);
        match def.kind {
            RuleKind::Detect => {
                if def.matcher.is_none() || def.aggregate.is_none() {
                    bail!("{}: detect rules need `match` and `aggregate`", ctx());
                }
            }
            RuleKind::Chain => {
                if def.chain.is_none() {
                    bail!("{}: chain rules need `chain`", ctx());
                }
            }
        }
        let m = def.matcher.clone().unwrap_or_default();
        let class_uid = match m.class.as_deref() {
            None => None,
            Some("file") => Some(CLASS_FILE),
            Some("process") => Some(CLASS_PROCESS),
            Some("network") => Some(CLASS_NETWORK),
            Some(other) => bail!("{}: unknown class {other:?}", ctx()),
        };
        let set = |v: &Vec<String>| -> Result<Option<RegexSet>> {
            if v.is_empty() {
                Ok(None)
            } else {
                Ok(Some(RegexSet::new(v).with_context(ctx)?))
            }
        };
        let ips = |v: &Vec<String>| -> Result<Vec<IpMatcher>> {
            v.iter().map(|s| IpMatcher::parse(s).with_context(ctx)).collect()
        };
        Ok(Rule {
            class_uid,
            path_any: set(&m.path_any)?,
            path_none: set(&m.path_none)?,
            dst_ip_any: ips(&m.dst_ip_any)?,
            dst_ip_none: ips(&m.dst_ip_none)?,
            def,
        })
    }

    pub fn id(&self) -> &str {
        &self.def.id
    }

    /// If the event matches, returns the target key it counts toward.
    pub fn match_event(&self, ev: &Event) -> Option<String> {
        let m = self.def.matcher.as_ref()?;
        if let Some(c) = self.class_uid {
            if ev.class_uid != c {
                return None;
            }
        }
        if !m.activities.is_empty() && !m.activities.iter().any(|a| a == &ev.activity_name) {
            return None;
        }
        match m.status.as_deref() {
            Some("success") if ev.status != "Success" => return None,
            Some("failure") if ev.status != "Failure" => return None,
            _ => {}
        }
        if let Some(want) = m.access.as_deref() {
            if ev.unmapped.access.as_deref() != Some(want) {
                return None;
            }
        }
        if !m.actor_name_any.is_empty() {
            let name = ev.actor_name()?;
            if !m.actor_name_any.iter().any(|n| n == name) {
                return None;
            }
        }
        if !m.flags_any.is_empty() {
            let flags = ev.unmapped.flags.as_deref()?;
            if !m.flags_any.iter().any(|f| flags.contains(f.as_str())) {
                return None;
            }
        }
        if self.path_any.is_some() || self.path_none.is_some() {
            let path = ev.path()?;
            if let Some(set) = &self.path_any {
                if !set.is_match(path) {
                    return None;
                }
            }
            if let Some(set) = &self.path_none {
                if set.is_match(path) {
                    return None;
                }
            }
        }
        let has_net_filter = !self.dst_ip_any.is_empty()
            || !self.dst_ip_none.is_empty()
            || !m.dst_port_any.is_empty()
            || !m.dst_port_none.is_empty();
        if has_net_filter {
            let ep = ev.dst_endpoint.as_ref()?;
            let ip: IpAddr = ep.ip.as_deref()?.parse().ok()?;
            if !self.dst_ip_any.is_empty() && !self.dst_ip_any.iter().any(|x| x.matches(&ip)) {
                return None;
            }
            if self.dst_ip_none.iter().any(|x| x.matches(&ip)) {
                return None;
            }
            let port = ep.port.unwrap_or(0);
            if !m.dst_port_any.is_empty() && !m.dst_port_any.contains(&port) {
                return None;
            }
            if m.dst_port_none.contains(&port) {
                return None;
            }
        }
        let key = target_key(ev);
        match self.def.aggregate.as_ref().map(|a| a.distinct_by) {
            Some(DistinctBy::Basename) => {
                Some(key.rsplit('/').next().unwrap_or(&key).to_string())
            }
            _ => Some(key),
        }
    }

    pub fn counts_as_failure(&self, ev: &Event) -> bool {
        let Some(agg) = &self.def.aggregate else { return false };
        ev.is_failure()
            && ev
                .status_detail
                .as_deref()
                .is_some_and(|e| agg.failure_errnos.iter().any(|x| x == e))
    }
}

/// What an event "touched": the unit rules count distinct values of.
pub fn target_key(ev: &Event) -> String {
    if let Some(p) = ev.path() {
        return p.to_string();
    }
    if let Some(ep) = &ev.dst_endpoint {
        if let Some(ip) = &ep.ip {
            return format!("{ip}:{}", ep.port.unwrap_or(0));
        }
        if let Some(p) = &ep.path {
            return format!("unix:{p}");
        }
    }
    let flags = ev.unmapped.flags.as_deref().unwrap_or("");
    format!("{}({flags})", ev.activity_name)
}

/// Load every `*.yaml` / `*.yml` rule in a directory, sorted by file name.
pub fn load_dir(dir: impl AsRef<Path>) -> Result<Vec<Rule>> {
    let dir = dir.as_ref();
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading rules directory {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yaml" | "yml")))
        .collect();
    files.sort();
    let mut rules = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f)?;
        let def: RuleDef =
            serde_yaml::from_str(&text).with_context(|| format!("parsing {}", f.display()))?;
        rules.push(Rule::compile(def).with_context(|| format!("compiling {}", f.display()))?);
    }
    let mut ids = std::collections::HashSet::new();
    for r in &rules {
        if !ids.insert(r.id().to_string()) {
            bail!("duplicate rule id {}", r.id());
        }
    }
    Ok(rules)
}
