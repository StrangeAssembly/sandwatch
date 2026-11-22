//! Catena: the Sandwatch correlation engine.
//!
//! Detect rules count distinct "targets" (paths, destinations, syscalls) matching a filter
//! inside a sliding time window, optionally requiring that many of them FAILED: probing for
//! things that are not there is the behavior that separates hunting from normal work.
//! Chain rules then link alerts from distinct attack stages into one escalating incident.

pub mod engine;
pub mod rules;

pub use engine::{run, Alert, ChainLink, Engine};
pub use rules::{load_dir, Rule, RuleDef, Severity};
