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
