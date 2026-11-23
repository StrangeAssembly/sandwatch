use catena::{run, Rule, RuleDef};
use serde_json::json;
use swrec::Event;

fn rule(yaml: &str) -> Rule {
    let def: RuleDef = serde_yaml::from_str(yaml).expect("rule yaml");
    Rule::compile(def).expect("compile")
}

fn file_ev(seq: u64, t_us: i64, path: &str, errno: Option<&str>) -> Event {
    let mut v = json!({
        "seq": seq, "time": 1_000_000 + t_us / 1000, "class_uid": 1001, "activity_id": 14,
        "activity_name": "Open", "status": if errno.is_some() { "Failure" } else { "Success" },
        "actor": {"process": {"uid": "p1", "pid": 1, "name": "cat", "cmd_line": "cat x"}},
        "file": {"path": path}, "unmapped": {"t_us": t_us, "syscall": "openat"}
    });
    if let Some(e) = errno {
        v["status_detail"] = json!(e);
    }
    serde_json::from_value(v).unwrap()
}

const PROBE: &str = r#"
id: probe
name: probe
severity: high
stage: escape
description: test
match:
  class: file
  path_any: ['^/secret/']
aggregate:
  min_distinct: 3
  min_failures: 2
  window_s: 1
"#;

#[test]
fn fires_when_distinct_and_failures_met_inside_window() {
    let r = rule(PROBE);
    let evs = vec![
        file_ev(1, 0, "/secret/a", Some("ENOENT")),
        file_ev(2, 100_000, "/secret/b", Some("EACCES")),
        file_ev(3, 200_000, "/secret/c", None),
    ];
    let alerts = run(&[r], &evs);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].distinct, 3);
    assert_eq!(alerts[0].failures, 2);
}

#[test]
fn same_target_repeated_counts_once() {
    let r = rule(PROBE);
    let evs: Vec<Event> =
        (0..10).map(|i| file_ev(i, i as i64 * 1000, "/secret/a", Some("ENOENT"))).collect();
    assert!(run(&[r], &evs).is_empty());
}

#[test]
fn events_outside_window_are_evicted() {
    let r = rule(PROBE);
    let evs = vec![
        file_ev(1, 0, "/secret/a", Some("ENOENT")),
        file_ev(2, 600_000, "/secret/b", Some("ENOENT")),
        file_ev(3, 1_700_000, "/secret/c", None), // /secret/a is now > 1 s old
    ];
    assert!(run(&[r], &evs).is_empty());
}

#[test]
fn noise_errnos_do_not_count_as_failures() {
    let r = rule(PROBE);
    let evs = vec![
        file_ev(1, 0, "/secret/a", Some("ENODATA")),
        file_ev(2, 1000, "/secret/b", Some("EOPNOTSUPP")),
        file_ev(3, 2000, "/secret/c", Some("ENOENT")),
    ];
    assert!(run(&[r], &evs).is_empty(), "only 1 real failure");
}

#[test]
fn non_matching_paths_ignored() {
    let r = rule(PROBE);
    let evs = vec![
        file_ev(1, 0, "/app/a", Some("ENOENT")),
        file_ev(2, 1, "/app/b", Some("ENOENT")),
        file_ev(3, 2, "/app/c", Some("ENOENT")),
    ];
    assert!(run(&[r], &evs).is_empty());
}

#[test]
fn chain_links_distinct_stages_and_scores() {
    let stage = |id: &str, st: &str, prefix: &str| {
        rule(&format!(
            "id: {id}\nname: {id}\nseverity: high\nstage: {st}\ndescription: t\n\
             match:\n  class: file\n  path_any: ['^{prefix}']\naggregate:\n  min_distinct: 1\n  window_s: 10\n"
        ))
    };
    let chain = rule(
        "id: chain\nname: chain\nkind: chain\nseverity: critical\ndescription: t\n\
         chain:\n  min_stages: 3\n  window_s: 60\n",
    );
    let rules = vec![stage("a", "discovery", "/a"), stage("b", "escape", "/b"),
                     stage("c", "credential-access", "/c"), chain];
    let evs = vec![
        file_ev(1, 0, "/a/x", None),
        file_ev(2, 1_000_000, "/b/x", None),
        file_ev(3, 2_000_000, "/c/x", None),
    ];
    let alerts = run(&rules, &evs);
    let c = alerts.iter().find(|a| a.rule_id == "chain").expect("chain fired");
    assert_eq!(c.chain.len(), 3);
    // 1 - (0.4)^3 = 0.936 -> rounded 0.94
    assert_eq!(c.score, Some(0.94));
    assert_eq!(c.chain[0].stage, "discovery");
}

#[test]
fn chain_does_not_fire_with_two_stages() {
    let a = rule("id: a\nname: a\nseverity: high\nstage: s1\ndescription: t\nmatch:\n  path_any: ['^/a']\naggregate:\n  window_s: 10\n");
    let b = rule("id: b\nname: b\nseverity: high\nstage: s2\ndescription: t\nmatch:\n  path_any: ['^/b']\naggregate:\n  window_s: 10\n");
    let chain = rule("id: chain\nname: chain\nkind: chain\nseverity: critical\ndescription: t\nchain:\n  min_stages: 3\n  window_s: 60\n");
    let alerts = run(&[a, b, chain], &[file_ev(1, 0, "/a", None), file_ev(2, 5, "/b", None)]);
    assert!(alerts.iter().all(|x| x.rule_id != "chain"));
}

#[test]
fn shipped_rules_load() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules");
    let rules = catena::load_dir(dir).expect("rules/ loads");
    assert!(rules.len() >= 8);
}

// ---- out-of-order arrival (live sensor: timestamp at syscall entry, delivery at exit) ----

const THREE_IN_1S: &str = r#"
id: three
name: three
severity: high
stage: escape
description: test
match:
  class: file
  path_any: ['^/secret/']
aggregate:
  min_distinct: 3
  window_s: 1
"#;

fn sorted(mut evs: Vec<Event>) -> Vec<Event> {
    evs.sort_by_key(|e| e.unmapped.t_us);
    evs
}

fn fired(rules: &[Rule], evs: &[Event]) -> Vec<String> {
    run(rules, evs).into_iter().map(|a| a.rule_id).collect()
}

#[test]
fn late_event_inside_window_is_evicted_at_its_true_time() {
    // Needs 4 distinct in 1 s. b@0.3 s arrives after c@0.5 s. From e@1.4 s on the window
    // starts at 0.4 s, so a and b are out: {c, e, f} never reaches 4. Appending b at the
    // back (old behavior) left it stuck behind c, alive forever, and fired on {c, b, e, f}.
    let r = rule(&THREE_IN_1S.replace("min_distinct: 3", "min_distinct: 4"));
    let evs = vec![
        file_ev(1, 0, "/secret/a", None),
        file_ev(2, 500_000, "/secret/c", None),
        file_ev(3, 300_000, "/secret/b", None),
        file_ev(4, 1_400_000, "/secret/e", None),
        file_ev(5, 1_450_000, "/secret/f", None),
    ];
    assert!(fired(&[r.clone()], &evs).is_empty());
    assert_eq!(fired(&[r.clone()], &evs), fired(&[r], &sorted(evs)));
}

#[test]
fn event_older_than_window_is_ignored_and_counted() {
    // b@0.2 s arrives after c@1.5 s: already outside [0.5, 1.5], so it cannot count.
    let r = rule(THREE_IN_1S);
    let evs = vec![
        file_ev(1, 0, "/secret/a", None),
        file_ev(2, 1_500_000, "/secret/c", None),
        file_ev(3, 200_000, "/secret/b", None),
        file_ev(4, 1_600_000, "/secret/d", None),
    ];
    let mut eng = catena::Engine::new(vec![r.clone()]);
    for e in &evs {
        eng.process(e);
    }
    assert!(eng.alerts().is_empty());
    assert_eq!(fired(&[r], &sorted(evs)), Vec::<String>::new(), "same as timestamp order");
    let s = eng.order_stats();
    assert_eq!(s.reordered_events, 1);
    assert_eq!(s.late_events_ignored, 1);
    assert_eq!(s.max_lateness_us, 1_300_000);
}

#[test]
fn audit_case_0_2_1_seconds() {
    // Timestamps 0 s, 2 s, 1 s with a 1.5 s window: the late 1 s event is inside
    // [0.5, 2] and counts together with the 2 s one; the 0 s one is out.
    let r = rule(&THREE_IN_1S.replace("min_distinct: 3", "min_distinct: 2").replace("window_s: 1", "window_s: 1.5"));
    let evs = vec![
        file_ev(1, 0, "/secret/a", None),
        file_ev(2, 2_000_000, "/secret/c", None),
        file_ev(3, 1_000_000, "/secret/b", None),
    ];
    let alerts = run(&[r], &evs);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].distinct, 2);
    assert!(alerts[0].evidence.iter().all(|e| !e.contains("/secret/a")));
}

#[test]
fn shuffled_arrival_within_lateness_matches_timestamp_order() {
    // Deterministic pseudo-random jitter: each event delayed by < 50 ms. The stream spans
    // 1.8 s, inside every shipped window (>= 2 s), so nothing expires and counts only grow:
    // for rules with monotone thresholds the fired set must not depend on arrival order.
    // (A min_failure_ratio threshold is not monotone, so such rules are excluded.)
    let rules: Vec<Rule> = catena::load_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules"))
        .unwrap()
        .into_iter()
        .filter(|r| r.def.aggregate.as_ref().is_none_or(|a| a.min_failure_ratio == 0.0))
        .collect();
    let paths = ["/root/.ssh/id_rsa", "/root/.aws/credentials", "/root/.kube/config",
                 "/root/.docker/config.json", "/root/.git-credentials", "/root/.netrc",
                 "/var/run/docker.sock", "/proc/1/environ", "/proc/sys/kernel/core_pattern",
                 "/.dockerenv", "/proc/1/cgroup", "/app/main.py", "/etc/hosts"];
    let mut seed: u64 = 0x5eed;
    let mut next = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        seed >> 33
    };
    for round in 0..50 {
        let mut evs = Vec::new();
        for i in 0..60u64 {
            let p = paths[(next() as usize) % paths.len()];
            let t = (i as i64) * 30_000 + (round as i64) * 7;
            let err = if next() % 2 == 0 { Some("ENOENT") } else { None };
            evs.push((t + (next() % 50_000) as i64, file_ev(i + 1, t, p, err)));
        }
        let ts_order: Vec<Event> = evs.iter().map(|(_, e)| e.clone()).collect();
        evs.sort_by_key(|(arrival, _)| *arrival);
        let arrival_order: Vec<Event> = evs.into_iter().map(|(_, e)| e).collect();
        let mut a = fired(&rules, &arrival_order);
        let mut b = fired(&rules, &ts_order);
        a.sort();
        b.sort();
        assert_eq!(a, b, "round {round}");
    }
}

// ---- sensor-blinding: the sensor reports its own event loss as events ----

fn loss_ev(seq: u64, t_us: i64, report: u64, lost: u64) -> Event {
    let flags = if lost >= 10_000 {
        format!("EVENTS_LOST EVENTS_LOST_MAJOR report={report}")
    } else {
        format!("EVENTS_LOST report={report}")
    };
    serde_json::from_value(json!({
        "seq": seq, "time": 1_000_000 + t_us / 1000, "class_uid": 9001,
        "activity_id": 1, "activity_name": "Event Loss", "status": "Failure",
        "status_detail": "EVENTS_LOST",
        "actor": {"process": {"name": "sandwatch-sensor", "pid": 1}},
        "unmapped": {"t_us": t_us, "flags": flags,
                     "lost": {"ring_buffer": lost, "pending": 0, "burst_buffer": 0}}
    }))
    .unwrap()
}

fn shipped() -> Vec<Rule> {
    catena::load_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules")).unwrap()
}

#[test]
fn small_losses_are_recorded_but_do_not_alert() {
    let evs = [loss_ev(1, 0, 1, 500), loss_ev(2, 1_000_000, 2, 9_999)];
    let ids = fired(&shipped(), &evs);
    assert!(!ids.contains(&"sensor-blinding".to_string()), "{ids:?}");
}

#[test]
fn major_loss_fires_sensor_blinding() {
    let ids = fired(&shipped(), &[loss_ev(1, 0, 1, 10_000)]);
    assert!(ids.contains(&"sensor-blinding".to_string()), "{ids:?}");
}

#[test]
fn flooding_plus_two_attack_stages_completes_the_chain() {
    // discovery (fingerprint) + credential-access (cred-hunt) + defense-evasion (blinding)
    let fp = ["/.dockerenv", "/proc/1/cgroup", "/proc/1/sched"];
    let creds = ["/root/.ssh/id_rsa", "/root/.aws/credentials", "/root/.kube/config", "/root/.netrc"];
    let mut evs = Vec::new();
    let mut seq = 0;
    let mut next = || { seq += 1; seq };
    for (i, p) in fp.iter().enumerate() {
        evs.push(file_ev(next(), i as i64 * 1000, p, None));
    }
    for (i, p) in creds.iter().enumerate() {
        evs.push(file_ev(next(), 10_000 + i as i64 * 1000, p, Some("ENOENT")));
    }
    evs.push(loss_ev(next(), 20_000, 1, 250_000));
    let ids = fired(&shipped(), &evs);
    assert!(ids.contains(&"chain".to_string()), "{ids:?}");
}
