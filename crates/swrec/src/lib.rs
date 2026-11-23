//! Reader and verifier for Sandwatch `.swrec` / `.swrec.gz` session recordings.
//!
//! Format spec: `docs/recording-format.md`. A recording is JSONL: one header, N events,
//! one footer, every line hash-chained to the previous one.

use anyhow::{anyhow, bail, Context, Result};
use flate2::read::MultiGzDecoder;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// OCSF class ids used by Sandwatch v0.1.
pub const CLASS_FILE: u32 = 1001;
pub const CLASS_PROCESS: u32 = 1007;
pub const CLASS_NETWORK: u32 = 4001;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Process {
    pub uid: Option<String>,
    pub pid: Option<i64>,
    pub name: Option<String>,
    pub path: Option<String>,
    pub cmd_line: Option<String>,
    pub parent_uid: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Actor {
    #[serde(default)]
    pub process: Process,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FileObj {
    pub path: Option<String>,
    pub new_path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Endpoint {
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Unmapped {
    /// Microseconds since session start.
    #[serde(default)]
    pub t_us: i64,
    pub syscall: Option<String>,
    pub flags: Option<String>,
    pub access: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub seq: u64,
    /// Epoch milliseconds.
    pub time: i64,
    pub class_uid: u32,
    pub activity_id: u32,
    pub activity_name: String,
    pub status: String,
    pub status_detail: Option<String>,
    #[serde(default)]
    pub actor: Actor,
    pub file: Option<FileObj>,
    pub dst_endpoint: Option<Endpoint>,
    pub process: Option<Process>,
    #[serde(default)]
    pub unmapped: Unmapped,
}

impl Event {
    pub fn is_failure(&self) -> bool {
        self.status == "Failure"
    }
    pub fn path(&self) -> Option<&str> {
        self.file.as_ref().and_then(|f| f.path.as_deref())
    }
    pub fn actor_name(&self) -> Option<&str> {
        self.actor.process.name.as_deref()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Labels {
    pub class: String,
    pub scenario: Option<String>,
    pub pace: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub attack_techniques: Vec<String>,
    #[serde(default)]
    pub expected_detections: Vec<String>,
    #[serde(default)]
    pub forbidden_detections: Vec<String>,
    #[serde(default)]
    pub hard_negative: bool,
    #[serde(default)]
    pub synthetic: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Phase {
    pub name: String,
    /// Epoch milliseconds.
    pub time: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GroundTruth {
    #[serde(default)]
    pub phases: Vec<Phase>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Session {
    pub id: String,
    #[serde(default)]
    pub start_time: i64,
    #[serde(default)]
    pub duration_ms: i64,
    #[serde(default)]
    pub event_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Header {
    pub format: String,
    pub format_version: String,
    pub session: Session,
    pub labels: Option<Labels>,
    #[serde(default)]
    pub ground_truth: GroundTruth,
}

#[derive(Debug, Clone)]
pub struct Recording {
    pub header: Header,
    pub events: Vec<Event>,
}

/// Outcome of chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Integrity {
    Verified,
    Broken(String),
    NotChecked,
}

fn open_reader(path: &Path) -> Result<Box<dyn BufRead>> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 2];
    let n = f.read(&mut magic)?;
    let f = File::open(path)?;
    if n == 2 && magic == [0x1f, 0x8b] {
        Ok(Box::new(BufReader::new(MultiGzDecoder::new(f))))
    } else {
        Ok(Box::new(BufReader::new(f)))
    }
}

/// Canonical JSON: sorted object keys, no whitespace, UTF-8 (matches the Python tools).
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("string serializes"));
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&serde_json::to_string(scalar).expect("scalar serializes")),
    }
}

pub fn line_hash(prev: &str, obj_without_hash: &Value) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(canonical(obj_without_hash).as_bytes());
    hex::encode(h.finalize())
}

/// Load a recording. With `verify`, the hash chain is checked while reading; a broken chain
/// is reported in the returned `Integrity` rather than aborting, so callers can decide.
pub fn load(path: impl AsRef<Path>, verify: bool) -> Result<(Recording, Integrity)> {
    let path = path.as_ref();
    let reader = open_reader(path)?;
    let mut prev = ZERO_HASH.to_string();
    let mut integrity = if verify { Integrity::Verified } else { Integrity::NotChecked };
    let mut header: Option<Header> = None;
    let mut events = Vec::new();
    let mut footer_count: Option<u64> = None;
    let mut footer_extra: Option<Value> = None;
    // First structural violation (same rules as tools/swrec_verify.py).
    let mut structure: Option<String> = None;
    fn flag(s: &mut Option<String>, msg: String) {
        s.get_or_insert(msg);
    }

    for (i, line) in reader.lines().enumerate() {
        let lineno = i + 1;
        let line = line.with_context(|| format!("reading line {lineno}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let mut v: Value =
            serde_json::from_str(&line).with_context(|| format!("line {lineno}: invalid JSON"))?;

        if verify && integrity == Integrity::Verified {
            let obj = v.as_object_mut().ok_or_else(|| anyhow!("line {lineno}: not an object"))?;
            let stored = obj.remove("hash").and_then(|h| h.as_str().map(String::from));
            let claimed_prev = obj.get("prev_hash").and_then(|p| p.as_str()).unwrap_or("");
            if claimed_prev != prev {
                integrity = Integrity::Broken(format!("line {lineno}: prev_hash does not match"));
            } else {
                let calc = line_hash(&prev, &v);
                match stored {
                    Some(s) if s == calc => prev = s,
                    _ => integrity = Integrity::Broken(format!("line {lineno}: hash mismatch")),
                }
            }
        }

        let rt = v.get("record_type").and_then(|r| r.as_str()).unwrap_or("").to_string();
        match rt.as_str() {
            "header" if lineno == 1 => {
                header = Some(serde_json::from_value(v).context("parsing header")?);
            }
            "event" => {
                let ev: Event = serde_json::from_value(v)
                    .with_context(|| format!("line {lineno}: parsing event"))?;
                if footer_extra.is_some() {
                    flag(&mut structure, format!("line {lineno}: event after footer"));
                }
                let expected = events.len() as u64 + 1;
                if ev.seq != expected {
                    flag(&mut structure, format!("line {lineno}: seq {} != expected {expected}", ev.seq));
                }
                events.push(ev);
            }
            "footer" => {
                if footer_extra.is_some() {
                    // Keep the first footer's metadata; a second one is a structural error.
                    flag(&mut structure, format!("line {lineno}: duplicate footer"));
                } else {
                    footer_count = v.get("event_count").and_then(|c| c.as_u64());
                    footer_extra = Some(v);
                }
            }
            other => bail!("line {lineno}: unexpected record_type {other:?}"),
        }
    }

    let mut header = header.ok_or_else(|| anyhow!("{}: missing header", path.display()))?;
    // Optional in the header (live recordings put it in the footer), but must agree if set.
    if header.session.event_count != 0 && header.session.event_count != events.len() as u64 {
        flag(&mut structure, "header event_count does not match".into());
    }
    if verify && integrity == Integrity::Verified {
        if let Some(s) = structure {
            integrity = Integrity::Broken(s);
        }
    }
    // Live recordings carry counts, duration and phases in the footer.
    if let Some(f) = &footer_extra {
        if header.ground_truth.phases.is_empty() {
            if let Some(gt) = f.get("ground_truth") {
                header.ground_truth = serde_json::from_value(gt.clone()).unwrap_or_default();
            }
        }
        if header.session.duration_ms == 0 {
            header.session.duration_ms = f.get("duration_ms").and_then(|d| d.as_i64()).unwrap_or(0);
        }
        if header.session.event_count == 0 {
            header.session.event_count = footer_count.unwrap_or(0);
        }
    }
    if verify && integrity == Integrity::Verified {
        match footer_count {
            None => integrity = Integrity::Broken("missing footer (truncated?)".into()),
            Some(c) if c != events.len() as u64 => {
                integrity = Integrity::Broken(format!(
                    "footer says {c} events, found {}",
                    events.len()
                ))
            }
            _ => {}
        }
    }
    Ok((Recording { header, events }, integrity))
}

/// Streaming writer: header first, events as they arrive, footer on `finish`.
///
/// Live recordings don't know their event count or ground-truth phases up front, so those go
/// in the footer (readers merge them into the header). A crash leaves a verifiable prefix
/// that `load` reports as truncated (missing footer).
pub struct Writer {
    out: Box<dyn std::io::Write + Send>,
    prev: String,
    seq: u64,
}

impl Writer {
    pub fn create(path: impl AsRef<Path>, mut header: Value) -> Result<Self> {
        let path = path.as_ref();
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
        let out: Box<dyn std::io::Write + Send> = if path.to_string_lossy().ends_with(".gz") {
            // fast level: compression was the largest per-event cost in the live sensor
            Box::new(flate2::write::GzEncoder::new(f, flate2::Compression::fast()))
        } else {
            Box::new(std::io::BufWriter::new(f))
        };
        let mut w = Writer { out, prev: ZERO_HASH.to_string(), seq: 0 };
        header["record_type"] = Value::from("header");
        w.write_line(header)?;
        Ok(w)
    }

    fn write_line(&mut self, mut obj: Value) -> Result<()> {
        let map = obj.as_object_mut().ok_or_else(|| anyhow!("record must be an object"))?;
        map.remove("hash");
        map.insert("prev_hash".into(), Value::from(self.prev.clone()));
        let h = line_hash(&self.prev, &obj);
        obj["hash"] = Value::from(h.clone());
        self.out.write_all(canonical(&obj).as_bytes())?;
        self.out.write_all(b"\n")?;
        self.prev = h;
        Ok(())
    }

    /// Append an event; assigns `seq` and `record_type`.
    pub fn event(&mut self, mut ev: Value) -> Result<()> {
        self.seq += 1;
        ev["record_type"] = Value::from("event");
        ev["seq"] = Value::from(self.seq);
        self.write_line(ev)
    }

    pub fn event_count(&self) -> u64 {
        self.seq
    }

    /// Write the footer (merging `extra` fields into it) and flush.
    pub fn finish(mut self, extra: Value) -> Result<()> {
        let mut footer = serde_json::json!({
            "record_type": "footer",
            "event_count": self.seq,
            "final_event_hash": self.prev,
        });
        if let Value::Object(m) = extra {
            for (k, v) in m {
                footer[k] = v;
            }
        }
        self.write_line(footer)?;
        self.out.flush()?;
        drop(self.out); // finishes the gzip stream
        Ok(())
    }
}

/// Find recordings under the given paths (files or directories, non-recursive into hidden dirs).
pub fn discover(paths: &[impl AsRef<Path>]) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        let p = p.as_ref();
        if p.is_dir() {
            let mut stack = vec![p.to_path_buf()];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(&dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    let name = entry.file_name().to_string_lossy().to_string();
                    if path.is_dir() && !name.starts_with('.') {
                        stack.push(path);
                    } else if name.ends_with(".swrec") || name.ends_with(".swrec.gz") {
                        out.push(path);
                    }
                }
            }
        } else {
            out.push(p.to_path_buf());
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_keys_recursively() {
        let v = json!({"b": 1, "a": {"d": [1, {"z": true, "y": null}], "c": "é"}});
        assert_eq!(canonical(&v), r#"{"a":{"c":"é","d":[1,{"y":null,"z":true}]},"b":1}"#);
    }

    #[test]
    fn hash_matches_python_reference() {
        // python3 -c 'import hashlib,json;o={"record_type":"footer","event_count":0,
        //   "final_event_hash":"0"*64,"prev_hash":"0"*64};
        //   print(hashlib.sha256(("0"*64+json.dumps(o,sort_keys=True,separators=(",",":"),
        //   ensure_ascii=False)).encode()).hexdigest())'
        let o = json!({"record_type": "footer", "event_count": 0,
                       "final_event_hash": ZERO_HASH, "prev_hash": ZERO_HASH});
        let canon = canonical(&o);
        assert_eq!(
            canon,
            format!(
                r#"{{"event_count":0,"final_event_hash":"{ZERO_HASH}","prev_hash":"{ZERO_HASH}","record_type":"footer"}}"#
            )
        );
        assert_eq!(line_hash(ZERO_HASH, &o).len(), 64);
    }

    // ---- structural contract: shared fixtures (also checked by tools/swrec_verify.py) ----

    fn fixtures_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    fn hdr(event_count: Option<u64>) -> Value {
        let mut h = json!({"format": "sandwatch-recording", "format_version": "0.2",
                           "session": {"id": "fixture"}});
        if let Some(c) = event_count {
            h["session"]["event_count"] = json!(c);
        }
        h
    }

    fn ev(seq: u64) -> Value {
        json!({"record_type": "event", "seq": seq, "time": 1000 + seq as i64,
               "class_uid": 1001, "activity_id": 14, "activity_name": "Open",
               "status": "Success", "file": {"path": format!("/f{seq}")},
               "unmapped": {"t_us": seq * 10}})
    }

    fn foot(count: u64) -> Value {
        json!({"record_type": "footer", "event_count": count})
    }

    /// Write records with a VALID hash chain (so only the structure is wrong).
    fn write_chain(name: &str, header: Value, records: &[Value]) -> std::path::PathBuf {
        let p = fixtures_dir().join(name);
        let mut w = Writer::create(&p, header).unwrap();
        for r in records {
            w.write_line(r.clone()).unwrap();
        }
        w.out.flush().unwrap();
        drop(w);
        p
    }

    fn edit_line(p: &std::path::Path, lineno: usize, f: impl Fn(&mut Value)) {
        let text = std::fs::read_to_string(p).unwrap();
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        let mut v: Value = serde_json::from_str(&lines[lineno - 1]).unwrap();
        f(&mut v);
        lines[lineno - 1] = canonical(&v);
        std::fs::write(p, lines.join("\n") + "\n").unwrap();
    }

    /// Regenerate tests/fixtures: `cargo test -p swrec -- --ignored regenerate_fixtures`
    #[test]
    #[ignore]
    fn regenerate_fixtures() {
        std::fs::create_dir_all(fixtures_dir()).unwrap();
        for gz in ["ok-minimal.swrec", "ok-minimal.swrec.gz"] {
            let mut w = Writer::create(fixtures_dir().join(gz), hdr(None)).unwrap();
            w.event(ev(0)).unwrap();
            w.event(ev(0)).unwrap();
            w.finish(json!({"duration_ms": 20})).unwrap();
        }
        write_chain("ok-header-count.swrec", hdr(Some(2)), &[ev(1), ev(2), foot(2)]);
        write_chain("bad-seq.swrec", hdr(None), &[ev(1), ev(3), foot(2)]);
        write_chain("bad-event-after-footer.swrec", hdr(None), &[ev(1), foot(1), ev(2)]);
        write_chain("bad-duplicate-footer.swrec", hdr(None), &[ev(1), foot(1), foot(1)]);
        write_chain("bad-missing-footer.swrec", hdr(None), &[ev(1), ev(2)]);
        write_chain("bad-footer-count.swrec", hdr(None), &[ev(1), ev(2), foot(3)]);
        write_chain("bad-header-count.swrec", hdr(Some(5)), &[ev(1), ev(2), foot(2)]);
        let p = write_chain("bad-hash.swrec", hdr(None), &[ev(1), ev(2), foot(2)]);
        edit_line(&p, 2, |v| v["file"]["path"] = json!("/edited"));
        let p = write_chain("bad-prev-hash.swrec", hdr(None), &[ev(1), ev(2), foot(2)]);
        edit_line(&p, 3, |v| v["prev_hash"] = json!(ZERO_HASH));
        // truncated gzip: cut the compressed stream in half
        let full = std::fs::read(fixtures_dir().join("ok-minimal.swrec.gz")).unwrap();
        std::fs::write(fixtures_dir().join("bad-truncated.swrec.gz"), &full[..full.len() / 2]).unwrap();
    }

    #[test]
    fn fixtures_follow_the_structural_contract() {
        let mut n = 0;
        for entry in std::fs::read_dir(fixtures_dir()).expect("tests/fixtures exists") {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if !name.contains(".swrec") {
                continue;
            }
            n += 1;
            let res = load(&p, true);
            if name.starts_with("ok-") {
                let (rec, integ) = res.unwrap_or_else(|e| panic!("{name}: {e:#}"));
                assert_eq!(integ, Integrity::Verified, "{name}");
                assert_eq!(rec.events.len(), 2, "{name}");
            } else {
                let ok = matches!(res, Ok((_, Integrity::Verified)));
                assert!(!ok, "{name} must fail verification");
            }
        }
        assert!(n >= 12, "expected the fixture corpus, found {n} files");
    }

    #[test]
    fn footer_metadata_is_merged_into_header() {
        let (rec, integ) = load(fixtures_dir().join("ok-minimal.swrec"), true).unwrap();
        assert_eq!(integ, Integrity::Verified);
        assert_eq!(rec.header.session.duration_ms, 20, "merged from footer");
    }
}
