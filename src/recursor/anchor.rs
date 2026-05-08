//! DNSSEC trust-anchor lifecycle management.
//!
//! Two RFCs drive what this module does:
//!
//! * **RFC 5011** — automated trust-anchor rotation. Once we have one
//!   valid root KSK, we can watch the root's DNSKEY RRset for new
//!   keys (signed by the existing one) and walk them through a
//!   hold-down period before promoting them to active. Revoked keys
//!   (REVOKE bit set in DNSKEY flags) come out of the active set
//!   immediately. Without this, an operator's static `root.key` file
//!   will silently start failing validation when IANA rolls.
//!
//! * **RFC 7958** — first-boot anchor acquisition. When no anchor is
//!   on disk, fetch the IANA-signed `root-anchors.xml`, verify the
//!   detached CMS signature against ICANN's root cert chain, then
//!   look up `. DNSKEY` (no validation needed — the trust comes from
//!   the CMS signature) and persist the matching keys.
//!
//! This module owns the on-disk lifecycle: the active anchor file
//! (presentation format, BIND/Unbound style — readable by other
//! tools) and a sidecar JSON state file tracking pending-add
//! hold-downs and revocations. Phases:
//!
//! * Phase 1 (committed): `Validator` reads anchors via `ArcSwap`.
//! * Phase 2 (this file): in-memory state machine + atomic persist.
//!   No network code yet.
//! * Phase 3: refresh loop firing periodic `. DNSKEY +dnssec`.
//! * Phase 4: self-managed anchor directory (no operator file).
//! * Phase 5: RFC 7958 bootstrap.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use hickory_proto::op::Message;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, RRSIG};
use hickory_proto::dnssec::{Algorithm, PublicKey, PublicKeyBuf, Verifier};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde::{Deserialize, Serialize};

use super::dnssec::{build_dnskey_query, verify_rrset, TrustAnchorSwap, TrustAnchors};
use super::forwarder::UpstreamClient;

/// Default RFC 5011 hold-down: 30 days. New KSKs sit in PendingAdd
/// for at least this long before promoting to Active. RFC 5011 §2.4
/// permits longer; shorter would weaken the protocol.
pub const DEFAULT_HOLD_DOWN: Duration = Duration::from_secs(30 * 24 * 3600);

/// State file format. Always paired with the active anchor file —
/// the anchor file alone is what the validator reads (and what
/// external tooling can audit), the state file just tracks the
/// in-flight transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFile {
    /// Schema version. Bumped if the layout changes incompatibly.
    pub version: u32,
    /// Last successful refresh. Used to detect long outages where
    /// every key would have hold-down expire while we weren't
    /// listening.
    pub last_refresh: u64,
    /// Every key we know about — Active, PendingAdd, or Revoked.
    pub keys: Vec<ManagedKey>,
}

/// One managed trust-anchor key with its lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedKey {
    /// Owner zone (root is "."). Currently always root in practice
    /// but the format admits per-zone islands for future use.
    pub zone: String,
    pub key_tag: u16,
    pub algorithm: u8,
    pub flags: u16,
    /// Base64-encoded public key bytes (matches presentation format).
    pub public_key: String,
    pub status: KeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyStatus {
    /// Currently part of the validator's active anchor set.
    Active,
    /// Seen as a new KSK, not yet trusted. `added_at` is the unix
    /// timestamp when we first saw it in a validated DNSKEY response.
    /// Promotes to Active once `now - added_at >= hold_down`.
    PendingAdd { added_at: u64 },
    /// Was Active but came back with the REVOKE bit set in a
    /// validated response. Held in this state for housekeeping
    /// (logging, metrics) until the next refresh prunes it.
    Revoked { revoked_at: u64 },
}

impl ManagedKey {
    /// Re-derive the in-memory `DNSKEY` from the persisted form.
    pub fn to_dnskey(&self) -> Result<DNSKEY> {
        let public_key = BASE64_STANDARD
            .decode(self.public_key.as_bytes())
            .map_err(|e| anyhow!("base64 in stored public key: {e}"))?;
        let zone_flag = self.flags & 0x0100 != 0;
        let secure_entry_point = self.flags & 0x0001 != 0;
        let revoked = self.flags & 0x0080 != 0;
        let algorithm = Algorithm::from_u8(self.algorithm);
        Ok(DNSKEY::new(
            zone_flag,
            secure_entry_point,
            revoked,
            PublicKeyBuf::new(public_key, algorithm),
        ))
    }

    /// Build a `ManagedKey` from an observed DNSKEY (used when the
    /// refresh loop sees a key for the first time).
    pub fn from_observed(zone: &str, key: &DNSKEY, status: KeyStatus) -> Self {
        let flags = (if key.zone_key() { 0x0100 } else { 0 })
            | (if key.secure_entry_point() { 0x0001 } else { 0 })
            | (if key.revoke() { 0x0080 } else { 0 });
        Self {
            zone: zone.to_string(),
            key_tag: key.calculate_key_tag().unwrap_or(0),
            algorithm: u8::from(key.algorithm()),
            flags,
            public_key: BASE64_STANDARD.encode(key.public_key().public_bytes()),
            status,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, KeyStatus::Active)
    }
}

/// One refresh cycle's diff against the prior state — what we need
/// to log, fire metrics for, and persist.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RefreshDiff {
    pub added_pending: Vec<u16>,    // newly observed KSKs (key tags)
    pub promoted: Vec<u16>,         // PendingAdd → Active
    pub revoked: Vec<u16>,          // Active → Revoked (REVOKE bit + valid sig)
    pub dropped_pending: Vec<u16>,  // PendingAdd that disappeared (transient)
    pub pruned_revoked: Vec<u16>,   // Revoked entries cleaned up
}

impl RefreshDiff {
    pub fn is_empty(&self) -> bool {
        self.added_pending.is_empty()
            && self.promoted.is_empty()
            && self.revoked.is_empty()
            && self.dropped_pending.is_empty()
            && self.pruned_revoked.is_empty()
    }
}

/// Apply RFC 5011 §2 transitions.
///
/// Inputs:
/// * `state` — current managed keys (from disk, or in-memory state)
/// * `observed` — DNSKEYs from a freshly-validated `. DNSKEY` RRset
///   (the caller has already verified the RRSIG; if it didn't
///   validate we don't get here)
/// * `now`, `hold_down` — clock + RFC 5011 timer
///
/// Returns the new `Vec<ManagedKey>` and a `RefreshDiff`. Pure
/// function (no I/O), so unit-testable end-to-end with synthetic
/// keys + a fake clock.
pub fn apply_refresh(
    state: &[ManagedKey],
    observed: &[(String, DNSKEY)],
    now: SystemTime,
    hold_down: Duration,
) -> (Vec<ManagedKey>, RefreshDiff) {
    let now_unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut diff = RefreshDiff::default();
    let mut next: Vec<ManagedKey> = Vec::with_capacity(state.len() + observed.len());

    // RFC 5011 §2.1: matching must be by zone, algorithm, and public
    // key bytes — NOT key tag. The key tag includes the flags field
    // (RFC 4034 §B), so a key with REVOKE set has a different tag
    // than the same public key without it. Public key bytes don't
    // change across the revocation transition.
    let observed_idx: Vec<(String, u8, Vec<u8>, &DNSKEY)> = observed
        .iter()
        .map(|(z, k)| (z.clone(), u8::from(k.algorithm()), k.public_key().public_bytes().to_vec(), k))
        .collect();

    // Track which observed keys we've matched against existing
    // state entries; the rest become PendingAdd at the end.
    let mut matched = vec![false; observed_idx.len()];

    for entry in state {
        let entry_pubkey = BASE64_STANDARD
            .decode(entry.public_key.as_bytes())
            .unwrap_or_default();
        let observed_match = observed_idx.iter().position(|(z, alg, pk, _)| {
            z == &entry.zone && *alg == entry.algorithm && pk == &entry_pubkey
        });

        match (&entry.status, observed_match) {
            // PendingAdd reappears in the live RRset.
            (KeyStatus::PendingAdd { added_at }, Some(idx)) => {
                matched[idx] = true;
                let observed_key = observed_idx[idx].3;
                if observed_key.revoke() {
                    // Edge case: a key we were waiting to add comes
                    // back revoked. Drop it — never goes Active.
                    diff.dropped_pending.push(entry.key_tag);
                    continue;
                }
                if now_unix.saturating_sub(*added_at) >= hold_down.as_secs() {
                    diff.promoted.push(entry.key_tag);
                    next.push(ManagedKey {
                        status: KeyStatus::Active,
                        ..entry.clone()
                    });
                } else {
                    next.push(entry.clone());
                }
            }
            // PendingAdd vanished from the RRset before hold-down
            // expired. RFC 5011 §2.4 — drop it.
            (KeyStatus::PendingAdd { .. }, None) => {
                diff.dropped_pending.push(entry.key_tag);
            }
            // Active key still in the RRset.
            (KeyStatus::Active, Some(idx)) => {
                matched[idx] = true;
                let observed_key = observed_idx[idx].3;
                if observed_key.revoke() {
                    diff.revoked.push(entry.key_tag);
                    next.push(ManagedKey {
                        status: KeyStatus::Revoked {
                            revoked_at: now_unix,
                        },
                        flags: entry.flags | 0x0080,
                        ..entry.clone()
                    });
                } else {
                    next.push(entry.clone());
                }
            }
            // Active key is missing from the RRset. RFC 5011 §2.3 —
            // preserve it (could be a transient failure on our end
            // or a partial root response). Removal requires REVOKE.
            (KeyStatus::Active, None) => {
                next.push(entry.clone());
            }
            // Revoked entries: keep until the next refresh proves
            // they're gone. Then prune.
            (KeyStatus::Revoked { .. }, Some(idx)) => {
                matched[idx] = true;
                next.push(entry.clone());
            }
            (KeyStatus::Revoked { .. }, None) => {
                diff.pruned_revoked.push(entry.key_tag);
            }
        }
    }

    // Anything observed but not matched → a brand-new KSK. Start
    // it as PendingAdd unless it's already revoked (in which case
    // there's nothing to add).
    for (i, (zone, _alg, _pk, key)) in observed_idx.iter().enumerate() {
        if matched[i] || key.revoke() {
            continue;
        }
        // Only seed PendingAdd for KSKs (SEP=1). ZSKs don't go in
        // the trust anchor set.
        if !key.secure_entry_point() {
            continue;
        }
        let mk = ManagedKey::from_observed(
            zone,
            key,
            KeyStatus::PendingAdd { added_at: now_unix },
        );
        diff.added_pending.push(mk.key_tag);
        next.push(mk);
    }

    (next, diff)
}

/// Read the JSON state file. Missing-file → `Ok(None)`; other
/// errors propagate (parse error means the file is corrupt and the
/// caller needs to decide whether to start over).
pub fn load_state(path: &Path) -> Result<Option<StateFile>> {
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            let parsed: StateFile = serde_json::from_str(&raw)
                .with_context(|| format!("parsing state file {}", path.display()))?;
            if parsed.version != 1 {
                anyhow::bail!(
                    "unsupported state file version {} in {}",
                    parsed.version,
                    path.display()
                );
            }
            Ok(Some(parsed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading state file {}", path.display())),
    }
}

/// Atomically write the JSON state file: write to `<path>.tmp`,
/// fsync, rename. Survives crashes mid-write — the live file is
/// either the old version or the new one, never half-written.
pub fn save_state(path: &Path, state: &StateFile) -> Result<()> {
    let raw = serde_json::to_string_pretty(state)
        .context("serialising state file")?;
    atomic_write(path, raw.as_bytes())
}

/// Render the active anchor set in BIND/Unbound presentation
/// format. Matches what `parse_presentation_format` reads, so
/// `unbound-anchor`-style external tooling can audit the file.
pub fn render_anchor_file(active: &[ManagedKey], default_ttl: u32) -> String {
    let mut out = String::new();
    out.push_str("; automated trust-anchor file managed by dnsd\n");
    out.push_str("; format: presentation; consume with `dig +trust-anchor` or any RFC 1035 parser\n");
    for k in active.iter().filter(|k| k.is_active()) {
        // Strip the REVOKE bit if somehow set on an Active row —
        // active keys never carry REVOKE, but defence-in-depth.
        let flags = k.flags & !0x0080;
        out.push_str(&format!(
            "{owner}\t{ttl}\tIN\tDNSKEY\t{flags} 3 {alg} {key}\n",
            owner = if k.zone == "." { ".".to_string() } else { k.zone.clone() },
            ttl = default_ttl,
            flags = flags,
            alg = k.algorithm,
            key = k.public_key,
        ));
    }
    out
}

/// Atomically write the active anchor file in presentation format.
pub fn save_anchor_file(path: &Path, active: &[ManagedKey], default_ttl: u32) -> Result<()> {
    atomic_write(path, render_anchor_file(active, default_ttl).as_bytes())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    // Ensure the parent directory exists — fresh installs may not
    // have created `<data_dir>/anchor/` yet.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dir {}", parent.display()))?;
        }
    }

    let tmp_path = tmp_sibling(path);
    {
        let mut f = std::fs::File::create(&tmp_path)
            .with_context(|| format!("creating temp file {}", tmp_path.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("writing temp file {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync temp file {}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
    // Best-effort dir fsync so the rename is durable. Ignore failures
    // — tmpfs and some macOS configs don't support dir fsync.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    Ok(())
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// IANA root KSKs embedded at build time. When dnsd starts in
/// self-managed mode (no operator-supplied trust_anchor file) and
/// no anchor exists on disk yet, these get written as the initial
/// active set; the RFC 5011 refresh task takes over from there.
///
/// Source of truth: <https://data.iana.org/root-anchors/>.
/// Keep current — out-of-date embedded keys will eventually fail
/// to validate the live root once IANA fully revokes them. RFC 5011
/// rotation handles smooth in-place rolls, but only if dnsd was
/// running across the rollover; long-cold installs need a recent
/// build to bootstrap. Update on each dnsd release.
///
/// As of 2026-04: KSK-2017 (tag 20326) is active, KSK-2024 (tag
/// 38696) is active, no revocations yet.
pub const EMBEDDED_ROOT_KSKS: &str = "\
.\tIN\tDNSKEY\t257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=\n\
.\tIN\tDNSKEY\t257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=\n\
";

/// Default RFC 5011 refresh cadence: 1 hour. The RFC permits
/// "regular polling" without a hard floor; an hour is what BIND
/// and Unbound default to.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// Default TTL we emit when re-rendering the active anchor file.
/// 172800 (48h) is what IANA publishes for `. DNSKEY`.
pub const DEFAULT_ANCHOR_TTL: u32 = 172_800;

/// First-boot bootstrap for the self-managed anchor directory.
/// Materialises `EMBEDDED_ROOT_KSKS` to disk: the active anchor
/// file in presentation format, the state sidecar with all keys
/// marked Active, and returns the parsed `TrustAnchors` for
/// immediate use.
///
/// Pure local op — no network. The RFC 5011 refresh task that the
/// caller spawns afterwards handles ongoing rotation, including
/// picking up new IANA KSKs and revoking old ones once we observe
/// a signed root response that proves the change.
///
/// Idempotent: if `anchor_path` already exists with non-empty
/// contents the caller should skip this. We don't enforce that
/// here — the caller has more context.
pub fn bootstrap_self_managed(
    anchor_path: &Path,
    state_path: &Path,
) -> Result<TrustAnchors> {
    // Reuse the validator's presentation-format parser so the
    // embedded strings go through the exact same code path that
    // operator-supplied files do.
    let anchors = super::dnssec::parse_presentation_format_str(EMBEDDED_ROOT_KSKS)
        .context("parsing embedded root KSKs (build-time bug — please report)")?;

    // Convert to ManagedKey set so we can persist via the same
    // helpers the refresh task uses.
    let mut managed = Vec::new();
    for (name, key) in anchors.keys() {
        managed.push(ManagedKey::from_observed(
            &name.to_ascii(),
            key,
            KeyStatus::Active,
        ));
    }

    save_anchor_file(anchor_path, &managed, DEFAULT_ANCHOR_TTL)
        .with_context(|| format!("writing bootstrap anchor file {}", anchor_path.display()))?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    save_state(
        state_path,
        &StateFile {
            version: 1,
            last_refresh: now_unix,
            keys: managed,
        },
    )
    .with_context(|| format!("writing bootstrap state file {}", state_path.display()))?;

    Ok(anchors)
}

/// Periodic trust-anchor refresh task. Spawned once at handler
/// construction; lives for the daemon's lifetime. Each tick:
///
///   1. Snapshot current active anchors.
///   2. Query `. DNSKEY +dnssec` from a root NS.
///   3. Verify the response's RRSIG against the active anchors
///      (RFC 5011 §2.3 — the new RRset must be signed by a key we
///      already trust, otherwise we ignore it).
///   4. Run `apply_refresh` to compute next state.
///   5. Persist state file + anchor file (atomic).
///   6. Publish the new TrustAnchors into the validator's swap.
pub struct AnchorRefresh {
    pub anchors: TrustAnchorSwap,
    pub upstream: Arc<UpstreamClient>,
    pub roots: Arc<RwLock<Vec<IpAddr>>>,
    pub anchor_path: PathBuf,
    pub state_path: PathBuf,
    pub interval: Duration,
    pub hold_down: Duration,
}

impl AnchorRefresh {
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Stagger first tick by a few seconds so handler
            // construction completes and root hints are populated
            // before we hit the wire.
            tokio::time::sleep(Duration::from_secs(5)).await;
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // First fire is immediate; subsequent ticks honour `interval`.
            loop {
                ticker.tick().await;
                match self.tick().await {
                    Ok(diff) if !diff.is_empty() => {
                        tracing::info!(
                            added = diff.added_pending.len(),
                            promoted = diff.promoted.len(),
                            revoked = diff.revoked.len(),
                            dropped = diff.dropped_pending.len(),
                            pruned = diff.pruned_revoked.len(),
                            "trust anchor state changed"
                        );
                    }
                    Ok(_) => {
                        tracing::debug!("trust anchor refresh: no change");
                    }
                    Err(e) => {
                        tracing::warn!("trust anchor refresh failed: {e:#}");
                    }
                }
            }
        })
    }

    async fn tick(&self) -> Result<RefreshDiff> {
        let root_ips = {
            let g = self
                .roots
                .read()
                .map_err(|_| anyhow!("root hints lock poisoned"))?;
            g.clone()
        };
        if root_ips.is_empty() {
            anyhow::bail!("no root-hint NS IPs available");
        }

        let wire = build_dnskey_query(&Name::root())?;
        let bytes = self
            .upstream
            .query(&root_ips, &wire)
            .await
            .context("upstream . DNSKEY query")?;
        let resp = Message::from_bytes(&bytes).context("parsing . DNSKEY response")?;
        let (records, keys, sig) = extract_dnskey_response(&resp)?;
        let sig = sig.ok_or_else(|| anyhow!("no RRSIG on root DNSKEY response"))?;

        // Verify the RRset against our currently-active anchors.
        // RFC 5011 §2.3: a key transition requires the new RRset to
        // be signed by an existing trusted key. If nothing
        // validates, we keep the old state — better to alert on
        // "refresh failed" than to silently accept an unsigned
        // KSK rotation.
        let active = self.anchors.load_full();
        let any_valid = active
            .keys()
            .iter()
            .any(|(_, k)| verify_rrset(&records, &sig, k).is_ok());
        if !any_valid {
            anyhow::bail!(
                "DNSKEY RRSIG does not validate against any active trust anchor — \
                 refusing to update state"
            );
        }

        // Roll the state machine.
        let prior = load_state(&self.state_path)
            .context("loading prior anchor state")?
            .map(|s| s.keys)
            .unwrap_or_else(|| {
                // First refresh on a freshly-loaded operator file:
                // seed state from the active anchor set so we have
                // a baseline to compute transitions against.
                active
                    .keys()
                    .iter()
                    .map(|(name, k)| ManagedKey::from_observed(&name.to_ascii(), k, KeyStatus::Active))
                    .collect()
            });
        let observed: Vec<(String, DNSKEY)> = keys
            .into_iter()
            .map(|k| (".".to_string(), k))
            .collect();

        let (next, diff) = apply_refresh(&prior, &observed, SystemTime::now(), self.hold_down);
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        save_state(
            &self.state_path,
            &StateFile {
                version: 1,
                last_refresh: now_unix,
                keys: next.clone(),
            },
        )?;
        save_anchor_file(&self.anchor_path, &next, DEFAULT_ANCHOR_TTL)?;

        // Publish into the swap so live validations see the new set.
        let new_anchors =
            TrustAnchors::from_managed_keys(&next).context("building TrustAnchors from state")?;
        self.anchors.store(Arc::new(new_anchors));

        Ok(diff)
    }
}

/// Pull the DNSKEY records, the bare DNSKEY rdata, and the (single)
/// RRSIG covering the DNSKEY RRset from a `. DNSKEY` response.
fn extract_dnskey_response(
    resp: &Message,
) -> Result<(Vec<Record>, Vec<DNSKEY>, Option<RRSIG>)> {
    let mut records = Vec::new();
    let mut keys = Vec::new();
    let mut sig: Option<RRSIG> = None;
    let zone = Name::root();
    for r in &resp.answers {
        if r.name != zone {
            continue;
        }
        match &r.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(k)) => {
                records.push(r.clone());
                keys.push(k.clone());
            }
            RData::DNSSEC(DNSSECRData::RRSIG(s))
                if s.input().type_covered == RecordType::DNSKEY =>
            {
                sig = Some(s.clone());
            }
            _ => {}
        }
    }
    Ok((records, keys, sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::Algorithm;

    fn fake_key(byte: u8, sep: bool, revoke: bool) -> DNSKEY {
        // Pseudo-key; the validator never runs against these so
        // the bytes can be anything. Length 64 to look ECDSA-P256-ish.
        let public_key = vec![byte; 64];
        DNSKEY::new(
            true,
            sep,
            revoke,
            PublicKeyBuf::new(public_key, Algorithm::ECDSAP256SHA256),
        )
    }

    fn pending_with_age(secs: u64) -> ManagedKey {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        ManagedKey {
            zone: ".".into(),
            key_tag: 1,
            algorithm: 13,
            flags: 257,
            public_key: BASE64_STANDARD.encode([0x11; 64]),
            status: KeyStatus::PendingAdd {
                added_at: now.saturating_sub(secs),
            },
        }
    }

    #[test]
    fn new_ksk_starts_pending() {
        let key = fake_key(0xaa, true, false);
        let observed = vec![(".".to_string(), key.clone())];
        let (next, diff) = apply_refresh(&[], &observed, SystemTime::now(), DEFAULT_HOLD_DOWN);
        assert_eq!(next.len(), 1);
        assert_eq!(diff.added_pending.len(), 1);
        assert!(matches!(next[0].status, KeyStatus::PendingAdd { .. }));
    }

    #[test]
    fn zsk_in_response_does_not_become_anchor() {
        // SEP=0 means it's a zone-signing key, not a trust anchor.
        let zsk = fake_key(0xbb, false, false);
        let observed = vec![(".".to_string(), zsk)];
        let (next, diff) = apply_refresh(&[], &observed, SystemTime::now(), DEFAULT_HOLD_DOWN);
        assert!(next.is_empty());
        assert!(diff.added_pending.is_empty());
    }

    #[test]
    fn pending_promotes_after_holddown() {
        let key = fake_key(0x11, true, false);
        // Put it in PendingAdd 31 days ago.
        let mut existing = pending_with_age(31 * 24 * 3600);
        existing.key_tag = key.calculate_key_tag().unwrap_or(0);
        existing.public_key = BASE64_STANDARD.encode(key.public_key().public_bytes());

        let observed = vec![(".".to_string(), key)];
        let (next, diff) = apply_refresh(
            &[existing],
            &observed,
            SystemTime::now(),
            DEFAULT_HOLD_DOWN,
        );
        assert_eq!(next.len(), 1);
        assert!(matches!(next[0].status, KeyStatus::Active));
        assert_eq!(diff.promoted.len(), 1);
    }

    #[test]
    fn pending_under_holddown_stays_pending() {
        let key = fake_key(0x11, true, false);
        let mut existing = pending_with_age(5 * 24 * 3600); // 5 days
        existing.key_tag = key.calculate_key_tag().unwrap_or(0);
        existing.public_key = BASE64_STANDARD.encode(key.public_key().public_bytes());

        let observed = vec![(".".to_string(), key)];
        let (next, diff) =
            apply_refresh(&[existing], &observed, SystemTime::now(), DEFAULT_HOLD_DOWN);
        assert_eq!(next.len(), 1);
        assert!(matches!(next[0].status, KeyStatus::PendingAdd { .. }));
        assert!(diff.promoted.is_empty());
    }

    #[test]
    fn pending_disappearing_gets_dropped() {
        let existing = pending_with_age(2 * 24 * 3600);
        let (next, diff) = apply_refresh(&[existing], &[], SystemTime::now(), DEFAULT_HOLD_DOWN);
        assert!(next.is_empty());
        assert_eq!(diff.dropped_pending.len(), 1);
    }

    #[test]
    fn revoke_bit_moves_active_to_revoked() {
        let key = fake_key(0x22, true, false);
        let key_tag = key.calculate_key_tag().unwrap_or(0);
        let active = ManagedKey::from_observed(".", &key, KeyStatus::Active);
        // Same key, revoked.
        let revoked_key = fake_key(0x22, true, true);
        let observed = vec![(".".to_string(), revoked_key)];

        let (next, diff) =
            apply_refresh(&[active], &observed, SystemTime::now(), DEFAULT_HOLD_DOWN);
        assert_eq!(next.len(), 1);
        assert!(matches!(next[0].status, KeyStatus::Revoked { .. }));
        assert_eq!(diff.revoked, vec![key_tag]);
    }

    #[test]
    fn active_missing_from_response_is_kept() {
        // Transient root failure — preserve trust anchors.
        let key = fake_key(0x33, true, false);
        let active = ManagedKey::from_observed(".", &key, KeyStatus::Active);
        let (next, diff) = apply_refresh(&[active.clone()], &[], SystemTime::now(), DEFAULT_HOLD_DOWN);
        assert_eq!(next, vec![active]);
        assert!(diff.is_empty());
    }

    #[test]
    fn revoked_disappearing_gets_pruned() {
        let key = fake_key(0x44, true, true);
        let revoked = ManagedKey::from_observed(
            ".",
            &key,
            KeyStatus::Revoked {
                revoked_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        );
        let (next, diff) = apply_refresh(&[revoked], &[], SystemTime::now(), DEFAULT_HOLD_DOWN);
        assert!(next.is_empty());
        assert_eq!(diff.pruned_revoked.len(), 1);
    }

    #[test]
    fn state_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let s = StateFile {
            version: 1,
            last_refresh: 1735689600,
            keys: vec![ManagedKey {
                zone: ".".into(),
                key_tag: 20326,
                algorithm: 8,
                flags: 257,
                public_key: BASE64_STANDARD.encode([0xaa; 64]),
                status: KeyStatus::Active,
            }],
        };
        save_state(&path, &s).unwrap();
        let loaded = load_state(&path).unwrap().unwrap();
        assert_eq!(loaded.keys, s.keys);
        assert_eq!(loaded.last_refresh, s.last_refresh);
    }

    #[test]
    fn missing_state_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doesnt-exist.json");
        assert!(load_state(&path).unwrap().is_none());
    }

    #[test]
    fn anchor_file_renders_active_only() {
        let active = ManagedKey {
            zone: ".".into(),
            key_tag: 20326,
            algorithm: 8,
            flags: 257,
            public_key: BASE64_STANDARD.encode([0xaa; 64]),
            status: KeyStatus::Active,
        };
        let pending = ManagedKey {
            status: KeyStatus::PendingAdd { added_at: 0 },
            key_tag: 38696,
            ..active.clone()
        };
        let revoked = ManagedKey {
            status: KeyStatus::Revoked { revoked_at: 0 },
            key_tag: 12345,
            flags: 257 | 0x0080,
            ..active.clone()
        };
        let rendered = render_anchor_file(&[active, pending, revoked], 172800);
        let dnskey_lines: Vec<&str> = rendered
            .lines()
            .filter(|l| l.contains("DNSKEY"))
            .collect();
        assert_eq!(dnskey_lines.len(), 1, "only Active should render");
        assert!(dnskey_lines[0].contains("257 3 8"));
    }

    #[test]
    fn embedded_root_ksks_parse() {
        let parsed =
            super::super::dnssec::parse_presentation_format_str(EMBEDDED_ROOT_KSKS).unwrap();
        assert_eq!(parsed.len(), 2, "expected KSK-2017 + KSK-2024");
        for (name, key) in parsed.keys() {
            assert!(
                name.is_root(),
                "embedded keys must own the root zone, got {name}"
            );
            assert!(key.secure_entry_point(), "embedded keys must have SEP=1");
            assert!(!key.revoke(), "embedded keys must not have REVOKE set");
        }
    }

    #[test]
    fn bootstrap_writes_anchor_and_state() {
        let dir = tempfile::tempdir().unwrap();
        let anchor_path = dir.path().join("active.key");
        let state_path = dir.path().join("active.key.state");

        let anchors = bootstrap_self_managed(&anchor_path, &state_path).unwrap();
        assert_eq!(anchors.len(), 2);

        // Re-parse the file we just wrote to confirm it round-trips
        // through the same parser the operator-file path uses.
        let reread = super::super::dnssec::TrustAnchors::load_from_file(&anchor_path).unwrap();
        assert_eq!(reread.len(), 2);

        let state = load_state(&state_path).unwrap().unwrap();
        assert_eq!(state.keys.len(), 2);
        assert!(state.keys.iter().all(|k| k.is_active()));
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a");
        std::fs::write(&path, b"old").unwrap();
        atomic_write(&path, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        // No `.tmp` left behind.
        assert!(!path.with_extension("tmp").exists());
    }
}
