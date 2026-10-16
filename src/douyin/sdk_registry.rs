//! Offline-only SDK resource validation. Hash consistency is not publisher approval.
//! No downloads, JavaScript execution, or production adapters are provided here.

use std::collections::HashSet;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

pub const SCHEMA_VERSION: u32 = 1;
pub const ADAPTER_ABI: u32 = 1;
pub const MAX_RESOURCE_SIZE: u64 = 8 * 1024 * 1024;

/// Exact host and path boundaries, not a suffix match or a general CDN grant.
/// Being under this prefix does NOT establish an approved release or adapter.
const SOURCE_PREFIXES: &[(&str, &str)] = &[
    (
        "lf-douyin-pc-web.douyinstatic.com",
        "/obj/douyin-pc-web/ies/douyin_web/",
    ),
    (
        "lf-c-flwb.bytetos.com",
        "/obj/rc-client-security/c-webmssdk/",
    ),
    ("lf-c-flwb.bytetos.com", "/obj/rc-client-security/web/glue/"),
    ("p-pc-weboff.byteimg.com", "/tos-cn-i-9r5gewecjs/"),
];
const MAX_MANIFEST_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Unsupported,
    OfflineOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    dynamic_request: CapabilityStatus,
    ticket_guard: CapabilityStatus,
    renewal: CapabilityStatus,
}

impl Capabilities {
    pub fn dynamic_request(&self) -> CapabilityStatus {
        self.dynamic_request
    }

    pub fn ticket_guard(&self) -> CapabilityStatus {
        self.ticket_guard
    }

    pub fn renewal(&self) -> CapabilityStatus {
        self.renewal
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    adapter_abi: u32,
    resources: Vec<ResourceSpec>,
    capabilities: Capabilities,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceSpec {
    name: String,
    url: String,
    version: String,
    sha256: String,
    size: u64,
    entrypoint: String,
}

/// A structurally checked declaration, NOT an approved SDK or verified adapter.
#[derive(Debug)]
pub struct ValidatedManifest {
    manifest: Manifest,
}

impl ValidatedManifest {
    pub fn parse(json: &[u8]) -> Result<Self> {
        ensure!(
            json.len() <= MAX_MANIFEST_SIZE,
            "SDK manifest exceeds 1 MiB"
        );
        let manifest: Manifest = serde_json::from_slice(json).context("invalid SDK manifest")?;
        ensure!(
            manifest.schema_version == SCHEMA_VERSION,
            "unsupported SDK schema_version: {}",
            manifest.schema_version
        );
        ensure!(
            manifest.adapter_abi == ADAPTER_ABI,
            "unsupported SDK adapter_abi: {}",
            manifest.adapter_abi
        );
        ensure!(!manifest.resources.is_empty(), "empty SDK resource list");
        ensure!(!manifest.evidence.is_empty(), "empty SDK evidence list");
        ensure!(
            manifest.evidence.iter().all(|item| !item.trim().is_empty()),
            "empty SDK evidence string"
        );
        ensure!(manifest.resources.len() <= 16, "too many SDK resources");
        ensure!(
            manifest
                .resources
                .iter()
                .map(|r| r.size)
                .try_fold(0u64, |a, b| a.checked_add(b))
                .is_some_and(|n| n <= 32 * 1024 * 1024),
            "SDK candidate exceeds 32 MiB"
        );
        let mut names = HashSet::new();
        for resource in &manifest.resources {
            validate_spec(resource)?;
            ensure!(
                names.insert(&resource.name),
                "duplicate SDK resource name: {}",
                resource.name
            );
        }
        Ok(Self { manifest })
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.manifest.capabilities
    }

    pub fn resource_names(&self) -> impl Iterator<Item = &str> {
        self.manifest.resources.iter().map(|r| r.name.as_str())
    }

    pub fn resource_sources(&self) -> impl Iterator<Item = (&str, &str, u64)> {
        self.manifest
            .resources
            .iter()
            .map(|r| (r.name.as_str(), r.url.as_str(), r.size))
    }

    pub fn evidence(&self) -> &[String] {
        &self.manifest.evidence
    }

    /// Verify caller-supplied bytes only. This does not download or execute them.
    /// The returned metadata proves manifest consistency, not publisher identity.
    pub fn verify_resource(&self, name: &str, bytes: &[u8]) -> Result<ResourceMetadata> {
        let spec = self
            .manifest
            .resources
            .iter()
            .find(|item| item.name == name)
            .with_context(|| format!("undeclared SDK resource: {name}"))?;
        ensure!(
            bytes.len() as u64 == spec.size,
            "SDK resource size mismatch: {name}"
        );
        let actual = digest(bytes);
        ensure!(
            actual == spec.sha256,
            "SDK resource SHA-256 mismatch: {name}"
        );
        Ok(ResourceMetadata {
            name: spec.name.clone(),
            url: spec.url.clone(),
            version: spec.version.clone(),
            sha256: actual,
            size: spec.size,
            entrypoint: spec.entrypoint.clone(),
        })
    }

    /// All declared resources must be supplied exactly once. Candidate state is
    /// immutable and has no constructor/deserializer that could bypass checks.
    pub fn verify_candidate(&self, resources: &[(&str, &[u8])]) -> Result<ValidatedCandidate> {
        ensure!(
            resources.len() == self.manifest.resources.len(),
            "SDK candidate resource count mismatch"
        );
        let mut names = HashSet::new();
        let mut metadata = Vec::with_capacity(resources.len());
        for &(name, bytes) in resources {
            ensure!(names.insert(name), "duplicate candidate resource: {name}");
            metadata.push(self.verify_resource(name, bytes)?);
        }
        metadata.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(ValidatedCandidate {
            resources: metadata,
            capabilities: self.manifest.capabilities.clone(),
            evidence: self.manifest.evidence.clone(),
        })
    }
}

fn validate_spec(spec: &ResourceSpec) -> Result<()> {
    ensure!(
        !spec.name.is_empty()
            && spec.name != "."
            && !spec.name.contains("..")
            && spec
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "invalid SDK resource filename: {}",
        spec.name
    );
    ensure!(
        !spec.version.trim().is_empty(),
        "empty SDK resource version: {}",
        spec.name
    );
    ensure!(
        !spec.entrypoint.trim().is_empty(),
        "empty SDK resource entrypoint: {}",
        spec.name
    );
    ensure!(
        spec.size > 0 && spec.size <= MAX_RESOURCE_SIZE,
        "SDK resource exceeds 8 MiB: {}",
        spec.name
    );
    ensure!(
        spec.sha256.len() == 64
            && spec
                .sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "SDK SHA-256 must be 64 lowercase hexadecimal characters: {}",
        spec.name
    );
    validate_source(&spec.url).with_context(|| format!("invalid SDK source for {}", spec.name))
}

fn validate_source(raw: &str) -> Result<()> {
    let url = Url::parse(raw).context("invalid SDK source URL")?;
    ensure!(url.scheme() == "https", "SDK source must use HTTPS");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "SDK source userinfo forbidden"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "SDK source query/fragment forbidden"
    );
    ensure!(
        url.port_or_known_default() == Some(443),
        "SDK source nonstandard port forbidden"
    );

    // Check the original spelling too: URL parsers normalize dot segments,
    // backslashes, empty userinfo and whitespace before exposing their fields.
    let tail = raw
        .strip_prefix("https://")
        .context("noncanonical SDK source scheme")?;
    let (authority, path) = tail.split_once('/').context("SDK source path required")?;
    let raw_path = format!("/{path}");
    ensure!(
        !raw.bytes()
            .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
            && !raw.contains(['\\', '%', '@'])
            && raw_path == url.path()
            && !raw_path.split('/').any(|part| part == "." || part == "..")
            && !raw_path.ends_with('/'),
        "noncanonical SDK source path or authority"
    );
    ensure!(
        SOURCE_PREFIXES.iter().any(|&(host, prefix)| {
            url.host_str() == Some(host)
                && (authority == host || authority == format!("{host}:443"))
                && url.path().starts_with(prefix)
        }),
        "SDK source outside exact static prefix allowlist"
    );
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Read-only metadata for bytes actually checked against a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceMetadata {
    name: String,
    url: String,
    version: String,
    sha256: String,
    size: u64,
    entrypoint: String,
}

impl ResourceMetadata {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedCandidate {
    resources: Vec<ResourceMetadata>,
    capabilities: Capabilities,
    evidence: Vec<String>,
}

impl ValidatedCandidate {
    pub fn resources(&self) -> &[ResourceMetadata] {
        &self.resources
    }
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
    pub fn evidence(&self) -> &[String] {
        &self.evidence
    }
}

/// Reviewer-owned pins. Deliberately private: manifests/callers cannot add pins.
#[derive(Debug)]
struct KnownPin {
    name: &'static str,
    url: &'static str,
    version: &'static str,
    sha256: &'static str,
    size: u64,
    entrypoint: &'static str,
}

/// Compiled-in approval is distinct from a candidate's self-reported hash.
/// An approved resource still would NOT imply a working production adapter.
#[derive(Debug)]
pub struct KnownRelease {
    id: &'static str,
    pins: &'static [KnownPin],
}

impl KnownRelease {
    pub fn id(&self) -> &'static str {
        self.id
    }

    fn matches(&self, candidate: &ValidatedCandidate) -> bool {
        // The disabled fallback must never match as a wildcard.
        !self.pins.is_empty()
            && self.pins.len() == candidate.resources.len()
            && self.pins.iter().all(|pin| {
                candidate.resources.iter().any(|item| {
                    item.name == pin.name
                        && item.url == pin.url
                        && item.version == pin.version
                        && item.sha256 == pin.sha256
                        && item.size == pin.size
                        && item.entrypoint == pin.entrypoint
                })
            })
    }
}

// No official usable SDK release or production adapter has been verified.
// Keep this empty until independently reviewed pins exist; never learn pins
// from a manifest, observed bytes, local cache, or candidate evidence strings.
const KNOWN_RELEASES: &[KnownRelease] = &[];
static STABLE_FALLBACK: KnownRelease = KnownRelease {
    id: "disabled",
    pins: &[],
};

#[derive(Debug)]
pub enum CandidateEvaluation {
    UnverifiedCandidate,
    KnownRelease(&'static KnownRelease),
}

/// In-memory approval boundary. No API accepts caller-provided approved pins.
#[derive(Debug)]
pub struct SdkRegistry {
    current: &'static KnownRelease,
}

impl Default for SdkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SdkRegistry {
    pub fn new() -> Self {
        Self {
            current: &STABLE_FALLBACK,
        }
    }

    pub fn current_release(&self) -> &'static KnownRelease {
        self.current
    }

    /// Evaluates all resource identities and digests, without changing state.
    pub fn evaluate_candidate(&self, candidate: &ValidatedCandidate) -> CandidateEvaluation {
        evaluate_known(candidate, KNOWN_RELEASES, &STABLE_FALLBACK)
    }

    /// Fail closed even for a pinned resource: no verified adapter exists.
    /// Every failure leaves the current release/fallback untouched.
    pub fn activate_candidate(&mut self, candidate: &ValidatedCandidate) -> Result<()> {
        activation_error(self.evaluate_candidate(candidate))
    }
}

fn evaluate_known(
    candidate: &ValidatedCandidate,
    releases: &'static [KnownRelease],
    fallback: &'static KnownRelease,
) -> CandidateEvaluation {
    match releases
        .iter()
        .find(|release| release.matches(candidate))
        .or_else(|| fallback.matches(candidate).then_some(fallback))
    {
        Some(release) => CandidateEvaluation::KnownRelease(release),
        None => CandidateEvaluation::UnverifiedCandidate,
    }
}

fn activation_error(evaluation: CandidateEvaluation) -> Result<()> {
    match evaluation {
        CandidateEvaluation::UnverifiedCandidate => bail!(
            "unverified SDK candidate: no approved known pin; missing adapter (no verified production adapter)"
        ),
        CandidateEvaluation::KnownRelease(release) => bail!(
            "SDK release {}: missing adapter (no verified production adapter)",
            release.id
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const SOURCE: &str =
        "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/offline-test.js";
    const BYTES: &[u8] = b"abc";
    const HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn manifest_value() -> Value {
        json!({
            "schema_version": 1,
            "adapter_abi": 1,
            "resources": [{
                "name": "offline-test.js", "url": SOURCE,
                "version": "test-fixture-not-official", "sha256": HASH,
                "size": 3, "entrypoint": "offline_fixture"
            }],
            "capabilities": {
                "dynamic_request": "unsupported",
                "ticket_guard": "offline_only",
                "renewal": "unsupported"
            },
            "evidence": ["Synthetic offline test bytes; not a publisher assertion"]
        })
    }

    fn parse(value: &Value) -> Result<ValidatedManifest> {
        ValidatedManifest::parse(&serde_json::to_vec(value).unwrap())
    }

    fn candidate(value: &Value, bytes: &[u8]) -> ValidatedCandidate {
        parse(value)
            .unwrap()
            .verify_candidate(&[("offline-test.js", bytes)])
            .unwrap()
    }

    fn error_contains<T: std::fmt::Debug>(result: Result<T>, message: &str) {
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains(message), "unexpected error: {error}");
    }

    #[test]
    fn bundled_manifest_and_total_limits_are_checked() {
        assert!(ValidatedManifest::parse(include_bytes!("sdk/manifest.json")).is_ok());
        assert!(ValidatedManifest::parse(&vec![b' '; 1024 * 1024 + 1]).is_err());
        let mut value = manifest_value();
        let resource = value["resources"][0].clone();
        value["resources"] = Value::Array(
            (0..17)
                .map(|n| {
                    let mut r = resource.clone();
                    r["name"] = json!(format!("test-{n}.js"));
                    r
                })
                .collect(),
        );
        error_contains(parse(&value), "too many SDK resources");
        value["resources"] = Value::Array(
            (0..5)
                .map(|n| {
                    let mut r = resource.clone();
                    r["name"] = json!(format!("test-{n}.js"));
                    r["size"] = json!(MAX_RESOURCE_SIZE);
                    r
                })
                .collect(),
        );
        error_contains(parse(&value), "exceeds 32 MiB");
    }

    #[test]
    fn verifies_metadata_without_execution() {
        let manifest = parse(&manifest_value()).unwrap();
        let metadata = manifest.verify_resource("offline-test.js", BYTES).unwrap();
        assert_eq!(metadata.name(), "offline-test.js");
        assert_eq!(metadata.url(), SOURCE);
        assert_eq!(metadata.version(), "test-fixture-not-official");
        assert_eq!(metadata.sha256(), HASH);
        assert_eq!(metadata.size(), 3);
        assert_eq!(metadata.entrypoint(), "offline_fixture");
        assert_eq!(
            manifest.capabilities().ticket_guard(),
            CapabilityStatus::OfflineOnly
        );
        assert_eq!(
            manifest.capabilities().dynamic_request(),
            CapabilityStatus::Unsupported
        );
        assert_eq!(
            manifest.capabilities().renewal(),
            CapabilityStatus::Unsupported
        );
        assert_eq!(manifest.evidence().len(), 1);
    }

    #[test]
    fn content_changes_and_wrong_digest_are_detected() {
        let manifest = parse(&manifest_value()).unwrap();
        error_contains(
            manifest.verify_resource("offline-test.js", b"abd"),
            "SHA-256 mismatch",
        );
        let mut value = manifest_value();
        value["resources"][0]["sha256"] = json!("0".repeat(64));
        error_contains(
            parse(&value)
                .unwrap()
                .verify_resource("offline-test.js", BYTES),
            "SHA-256 mismatch",
        );
    }

    #[test]
    fn size_mismatch_and_limit_are_rejected() {
        let manifest = parse(&manifest_value()).unwrap();
        for bytes in [b"ab".as_slice(), b"abcd".as_slice()] {
            error_contains(
                manifest.verify_resource("offline-test.js", bytes),
                "size mismatch",
            );
        }
        let mut value = manifest_value();
        value["resources"][0]["size"] = json!(MAX_RESOURCE_SIZE + 1);
        error_contains(parse(&value), "exceeds 8 MiB");
        value["resources"][0]["size"] = json!(MAX_RESOURCE_SIZE);
        assert!(parse(&value).is_ok());
        value["resources"][0]["size"] = json!(0);
        assert!(parse(&value).is_err());
    }

    #[test]
    fn unsupported_schema_abi_and_unknown_fields_are_rejected() {
        for field in ["schema_version", "adapter_abi"] {
            for version in [0, 2] {
                let mut value = manifest_value();
                value[field] = json!(version);
                error_contains(parse(&value), &format!("unsupported SDK {field}"));
            }
        }
        let mut value = manifest_value();
        value["extra"] = json!(true);
        error_contains(parse(&value), "unknown field");
        let mut value = manifest_value();
        value["resources"][0]["extra"] = json!(true);
        error_contains(parse(&value), "unknown field");
        let mut value = manifest_value();
        value["capabilities"]["extra"] = json!(true);
        error_contains(parse(&value), "unknown field");
    }

    #[test]
    fn supported_capability_claims_cannot_enable_permissions() {
        for capability in ["dynamic_request", "ticket_guard", "renewal"] {
            for claim in ["supported", "available", "enabled"] {
                let mut value = manifest_value();
                value["capabilities"][capability] = json!(claim);
                error_contains(parse(&value), "unknown variant");
            }
        }
    }

    #[test]
    fn sources_require_the_exact_static_prefix() {
        for source in [
            SOURCE,
            "https://lf-c-flwb.bytetos.com:443/obj/rc-client-security/c-webmssdk/offline-test.js",
        ] {
            let mut value = manifest_value();
            value["resources"][0]["url"] = json!(source);
            assert!(parse(&value).is_ok(), "{source}");
        }
        for source in [
            "http://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/x.js",
            "https://lf-c-flwb.bytetos.com.evil.test/obj/rc-client-security/c-webmssdk/x.js",
            "https://evil.test/obj/rc-client-security/c-webmssdk/x.js",
            "https://lf-c-flwb.bytetos.com:8443/obj/rc-client-security/c-webmssdk/x.js",
            "https://user@lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/x.js",
            "https://user:pass@lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/x.js",
            "https://@lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/x.js",
            "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/x.js?",
            "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/x.js#",
            "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk-evil/x.js",
            "https://lf-c-flwb.bytetos.com/obj/rc-client-security/x.js",
            "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/",
            "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/../x.js",
            "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/./x.js",
            "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/%2e%2e/x.js",
            "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/x%2f.js",
            "https://lf-c-flwb.bytetos.com\\obj/rc-client-security/c-webmssdk/x.js",
            " https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/x.js",
            "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/x\n.js",
        ] {
            let mut value = manifest_value();
            value["resources"][0]["url"] = json!(source);
            assert!(
                parse(&value).is_err(),
                "accepted forbidden source: {source}"
            );
        }
    }

    #[test]
    fn path_escape_and_duplicate_names_are_rejected() {
        for name in [
            "",
            ".",
            "..",
            "../x.js",
            "/x.js",
            "a/b.js",
            "a\\b.js",
            "C:x.js",
            "%2e%2e.js",
            "a..js",
        ] {
            let mut value = manifest_value();
            value["resources"][0]["name"] = json!(name);
            error_contains(parse(&value), "invalid SDK resource filename");
        }
        let mut value = manifest_value();
        let duplicate = value["resources"][0].clone();
        value["resources"].as_array_mut().unwrap().push(duplicate);
        error_contains(parse(&value), "duplicate SDK resource name");
    }

    #[test]
    fn empty_fields_and_malformed_hashes_are_rejected() {
        let mut value = manifest_value();
        value["resources"] = json!([]);
        error_contains(parse(&value), "empty SDK resource list");
        for evidence in [json!([]), json!([""]), json!(["valid", "  "])] {
            let mut value = manifest_value();
            value["evidence"] = evidence;
            assert!(parse(&value).is_err());
        }
        for field in ["version", "entrypoint"] {
            let mut value = manifest_value();
            value["resources"][0][field] = json!(" \t");
            error_contains(parse(&value), &format!("empty SDK resource {field}"));
        }
        for hash in [
            HASH.to_uppercase(),
            "a".repeat(63),
            "g".repeat(64),
            "a".repeat(65),
        ] {
            let mut value = manifest_value();
            value["resources"][0]["sha256"] = json!(hash);
            error_contains(parse(&value), "64 lowercase hexadecimal");
        }
    }

    #[test]
    fn candidate_requires_every_resource_exactly_once() {
        let mut value = manifest_value();
        let mut second = value["resources"][0].clone();
        second["name"] = json!("second.js");
        value["resources"].as_array_mut().unwrap().push(second);
        let manifest = parse(&value).unwrap();
        error_contains(
            manifest.verify_candidate(&[("offline-test.js", BYTES)]),
            "count mismatch",
        );
        error_contains(
            manifest.verify_candidate(&[("offline-test.js", BYTES), ("offline-test.js", BYTES)]),
            "duplicate candidate",
        );
        error_contains(
            manifest.verify_candidate(&[("offline-test.js", BYTES), ("unknown.js", BYTES)]),
            "undeclared",
        );
        let checked = manifest
            .verify_candidate(&[("second.js", BYTES), ("offline-test.js", BYTES)])
            .unwrap();
        assert_eq!(checked.resources().len(), 2);
        assert_eq!(checked.resources()[0].name(), "offline-test.js");
    }

    #[test]
    fn self_reported_new_hash_never_becomes_approved() {
        let mut value = manifest_value();
        value["resources"][0]["sha256"] = json!(digest(b"abd"));
        let checked = candidate(&value, b"abd");
        let mut registry = SdkRegistry::new();
        assert!(matches!(
            registry.evaluate_candidate(&checked),
            CandidateEvaluation::UnverifiedCandidate
        ));
        error_contains(registry.activate_candidate(&checked), "missing adapter");
        assert_eq!(registry.current_release().id(), "disabled");
        assert_eq!(
            checked.capabilities().ticket_guard(),
            CapabilityStatus::OfflineOnly
        );
        assert_eq!(checked.evidence().len(), 1);
    }

    // Synthetic pins exist ONLY inside tests. These are neither official SDK
    // versions nor production approval, and cannot enter the public registry.
    const TEST_PINS: &[KnownPin] = &[KnownPin {
        name: "offline-test.js",
        url: SOURCE,
        version: "test-fixture-not-official",
        sha256: HASH,
        size: 3,
        entrypoint: "offline_fixture",
    }];
    const TEST_RELEASES: &[KnownRelease] = &[KnownRelease {
        id: "test-only-new",
        pins: TEST_PINS,
    }];
    static TEST_OLD: KnownRelease = KnownRelease {
        id: "test-only-old",
        pins: TEST_PINS,
    };

    #[test]
    fn fixed_pins_match_digests_and_fallback_without_trusting_claims() {
        let checked = candidate(&manifest_value(), BYTES);
        match evaluate_known(&checked, TEST_RELEASES, &TEST_OLD) {
            CandidateEvaluation::KnownRelease(release) => assert_eq!(release.id(), "test-only-new"),
            other => panic!("expected test pin match: {other:?}"),
        }
        match evaluate_known(&checked, &[], &TEST_OLD) {
            CandidateEvaluation::KnownRelease(release) => assert_eq!(release.id(), "test-only-old"),
            other => panic!("expected stable fallback match: {other:?}"),
        }
        let mut value = manifest_value();
        value["resources"][0]["sha256"] = json!(digest(b"abd"));
        let changed = candidate(&value, b"abd");
        assert!(matches!(
            evaluate_known(&changed, TEST_RELEASES, &TEST_OLD),
            CandidateEvaluation::UnverifiedCandidate
        ));
        // Same digest alone must not approve substituted release metadata.
        for (field, replacement) in [
            ("version", "other"),
            ("entrypoint", "other"),
            (
                "url",
                "https://lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/other.js",
            ),
        ] {
            let mut value = manifest_value();
            value["resources"][0][field] = json!(replacement);
            assert!(matches!(
                evaluate_known(&candidate(&value, BYTES), TEST_RELEASES, &TEST_OLD),
                CandidateEvaluation::UnverifiedCandidate
            ));
        }
    }

    #[test]
    fn missing_adapter_and_bad_candidates_preserve_old_pin() {
        let mut registry = SdkRegistry { current: &TEST_OLD };
        let checked = candidate(&manifest_value(), BYTES);
        error_contains(
            activation_error(evaluate_known(&checked, TEST_RELEASES, &TEST_OLD)),
            "missing adapter",
        );
        error_contains(registry.activate_candidate(&checked), "missing adapter");
        assert!(std::ptr::eq(registry.current_release(), &TEST_OLD));
        let mut value = manifest_value();
        value["resources"][0]["sha256"] = json!(digest(b"abd"));
        error_contains(
            registry.activate_candidate(&candidate(&value, b"abd")),
            "no approved known pin",
        );
        assert!(std::ptr::eq(registry.current_release(), &TEST_OLD));
        error_contains(
            parse(&manifest_value())
                .unwrap()
                .verify_resource("offline-test.js", b"bad"),
            "SHA-256 mismatch",
        );
        assert!(std::ptr::eq(registry.current_release(), &TEST_OLD));
    }
}
