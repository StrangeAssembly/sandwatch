//! Streaming evaluation: per-rule sliding windows plus stage-chain correlation.
//!
//! v0.1 correlation scope is one session (one monitored process tree). Each rule fires at
//! most once per session.

use crate::rules::{Rule, RuleKind, Severity};
use std::collections::{HashMap, HashSet, VecDeque};
use swrec::Event;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: &'static str,
    pub stage: Option<String>,
    pub attack: Vec<String>,
    /// Microseconds since session start.
    pub t_us: i64,
    /// Epoch milliseconds.
    pub time: i64,
    pub distinct: usize,
    pub failures: usize,
    /// Targets that contributed, failed ones first (truncated).
    pub evidence: Vec<String>,
    /// For chain alerts: stages and the rules that evidenced them, in order.
    pub chain: Vec<ChainLink>,
    /// For chain alerts: 1 - Π(1 - severity weight) over the best alert per stage.
    pub score: Option<f64>,
    /// Who did it (detect alerts): command line of the process behind the triggering event.
    pub actor: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainLink {
    pub stage: String,
    pub rule_id: String,
    pub t_us: i64,
}

#[derive(Default)]
struct Window {
    entries: VecDeque<(i64, String, bool)>,
    counts: HashMap<String, (usize, usize)>, // target -> (hits, failed hits)
}

impl Window {
    /// Insert keeping `entries` sorted by time, so front eviction stays exact even when an
    /// event arrives after newer ones (late events are rare and near the back: cheap).
    fn push(&mut self, t: i64, target: String, failed: bool) {
        let c = self.counts.entry(target.clone()).or_insert((0, 0));
        c.0 += 1;
        if failed {
            c.1 += 1;
        }
        if self.entries.back().is_none_or(|b| b.0 <= t) {
            self.entries.push_back((t, target, failed));
        } else {
            let at = self.entries.partition_point(|e| e.0 <= t);
            self.entries.insert(at, (t, target, failed));
        }
    }
    fn evict_before(&mut self, cutoff: i64) {
        while let Some((t, _, _)) = self.entries.front() {
            if *t >= cutoff {
                break;
            }
            let (_, target, failed) = self.entries.pop_front().unwrap();
            if let Some(c) = self.counts.get_mut(&target) {
                c.0 -= 1;
                if failed {
                    c.1 -= 1;
                }
                if c.0 == 0 {
                    self.counts.remove(&target);
                }
            }
        }
    }
    fn distinct(&self) -> usize {
        self.counts.len()
    }
    fn distinct_failed(&self) -> usize {
        self.counts.values().filter(|c| c.1 > 0).count()
    }
    fn evidence(&self, n: usize) -> Vec<String> {
        let mut v: Vec<(&String, &(usize, usize))> = self.counts.iter().collect();
        v.sort_by(|a, b| (b.1 .1 > 0).cmp(&(a.1 .1 > 0)).then(a.0.cmp(b.0)));
        v.into_iter()
            .take(n)
            .map(|(t, c)| if c.1 > 0 { format!("{t}  (failed)") } else { t.clone() })
            .collect()
    }
}

struct StageHit {
    t_us: i64,
    stage: String,
    rule_id: String,
    severity: Severity,
}

pub struct Engine {
    detect: Vec<Rule>,
    chains: Vec<Rule>,
    windows: Vec<Window>,
    fired: HashSet<String>,
    stage_hits: Vec<StageHit>,
    alerts: Vec<Alert>,
    /// Latest event time seen (µs): the "now" every window is anchored to.
    watermark: i64,
    stats: OrderStats,
}

/// How far event arrival order departed from timestamp order.
///
/// The live sensor timestamps a syscall at ENTRY but delivers it at EXIT, so with
/// concurrent threads a slow call arrives after faster, later ones. Catena's policy:
/// every window covers `[watermark - window_s, watermark]`, where the watermark is the
/// newest timestamp seen. A late event that still falls inside a rule's window is inserted
/// at its true time; one older than the window is ignored by that rule (it is still kept
/// in the recording). This makes results independent of arrival order except for events
/// later than the window itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct OrderStats {
    /// Events that arrived after an event with a newer timestamp.
    pub reordered_events: u64,
    /// Events ignored by at least one matching rule because they were older than its window.
    pub late_events_ignored: u64,
    /// Largest lateness seen, in microseconds.
    pub max_lateness_us: i64,
}

impl Engine {
    pub fn new(rules: Vec<Rule>) -> Self {
        let (chains, detect): (Vec<_>, Vec<_>) =
            rules.into_iter().partition(|r| r.def.kind == RuleKind::Chain);
        let windows = detect.iter().map(|_| Window::default()).collect();
        Engine {
            detect,
            chains,
            windows,
            fired: HashSet::new(),
            stage_hits: vec![],
            alerts: vec![],
            watermark: i64::MIN,
            stats: OrderStats::default(),
        }
    }

    /// Feed one event. Events may arrive somewhat out of timestamp order; see
    /// [`OrderStats`] for the policy. Returns alerts raised by it.
    pub fn process(&mut self, ev: &Event) -> Vec<Alert> {
        let t = ev.unmapped.t_us;
        if t < self.watermark {
            self.stats.reordered_events += 1;
            self.stats.max_lateness_us = self.stats.max_lateness_us.max(self.watermark - t);
        }
        self.watermark = self.watermark.max(t);
        let now = self.watermark;
        let mut ignored_late = false;
        let mut new_alerts = Vec::new();
        for (i, rule) in self.detect.iter().enumerate() {
            if self.fired.contains(rule.id()) {
                continue;
            }
            let Some(target) = rule.match_event(ev) else { continue };
            let agg = rule.def.aggregate.as_ref().expect("compiled detect rule has aggregate");
            let cutoff = now - (agg.window_s * 1e6) as i64;
            if t < cutoff {
                ignored_late = true; // older than this rule's window: cannot contribute
                continue;
            }
            let w = &mut self.windows[i];
            w.push(t, target, rule.counts_as_failure(ev));
            w.evict_before(cutoff);
            let distinct = w.distinct();
            let failed = w.distinct_failed();
            let ratio = if distinct == 0 { 0.0 } else { failed as f64 / distinct as f64 };
            if distinct >= agg.min_distinct && failed >= agg.min_failures && ratio >= agg.min_failure_ratio
            {
                self.fired.insert(rule.id().to_string());
                new_alerts.push(Alert {
                    rule_id: rule.id().to_string(),
                    rule_name: rule.def.name.clone(),
                    severity: rule.def.severity.as_str(),
                    stage: rule.def.stage.clone(),
                    attack: rule.def.attack.clone(),
                    t_us: t,
                    time: ev.time,
                    distinct,
                    failures: failed,
                    evidence: w.evidence(8),
                    chain: vec![],
                    score: None,
                    actor: ev.actor.process.cmd_line.clone(),
                });
                if let Some(stage) = &rule.def.stage {
                    self.stage_hits.push(StageHit {
                        t_us: t,
                        stage: stage.clone(),
                        rule_id: rule.id().to_string(),
                        severity: rule.def.severity,
                    });
                }
            }
        }
        if ignored_late {
            self.stats.late_events_ignored += 1;
        }
        if !new_alerts.is_empty() {
            new_alerts.extend(self.check_chains(now, ev.time));
        }
        self.alerts.extend(new_alerts.iter().cloned());
        new_alerts
    }

    fn check_chains(&mut self, t: i64, time: i64) -> Vec<Alert> {
        let mut out = Vec::new();
        for rule in &self.chains {
            if self.fired.contains(rule.id()) {
                continue;
            }
            let spec = rule.def.chain.as_ref().expect("compiled chain rule has chain");
            let cutoff = t - (spec.window_s * 1e6) as i64;
            // best (highest severity, earliest) hit per stage inside the window
            let mut best: HashMap<&str, &StageHit> = HashMap::new();
            for h in self.stage_hits.iter().filter(|h| h.t_us >= cutoff) {
                best.entry(h.stage.as_str())
                    .and_modify(|b| {
                        if h.severity > b.severity {
                            *b = h
                        }
                    })
                    .or_insert(h);
            }
            if best.len() < spec.min_stages {
                continue;
            }
            let mut links: Vec<&StageHit> = best.values().copied().collect();
            links.sort_by_key(|h| h.t_us);
            let score = 1.0 - links.iter().map(|h| 1.0 - h.severity.weight()).product::<f64>();
            self.fired.insert(rule.id().to_string());
            out.push(Alert {
                rule_id: rule.id().to_string(),
                rule_name: rule.def.name.clone(),
                severity: rule.def.severity.as_str(),
                stage: None,
                attack: rule.def.attack.clone(),
                t_us: t,
                time,
                distinct: links.len(),
                failures: 0,
                evidence: vec![],
                chain: links
                    .iter()
                    .map(|h| ChainLink { stage: h.stage.clone(), rule_id: h.rule_id.clone(), t_us: h.t_us })
                    .collect(),
                score: Some((score * 100.0).round() / 100.0),
                actor: None,
            });
        }
        out
    }

    pub fn alerts(&self) -> &[Alert] {
        &self.alerts
    }

    pub fn order_stats(&self) -> OrderStats {
        self.stats
    }

    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.detect.iter().chain(self.chains.iter())
    }
}

/// Convenience: run every event of a recording through a fresh engine.
pub fn run(rules: &[Rule], events: &[Event]) -> Vec<Alert> {
    let mut engine = Engine::new(rules.to_vec());
    for ev in events {
        engine.process(ev);
    }
    engine.alerts
}
