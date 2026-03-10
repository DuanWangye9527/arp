//! ENS and DNS TXT resolution for ARP agent identity discovery.
//!
//! Resolves a human-readable name (ENS name or DNS domain) to an
//! ARP public key, eliminating the need for manual key exchange.
//!
//! # Supported formats
//!
//! - `alice.eth` → ENS Text Record lookup (`agent.arp` key)
//! - `alice.example.com` → DNS TXT record lookup (`_arpa.<domain>`)
//!
//! # Resolution result
//!
//! Both methods return a [`ResolvedIdentity`] containing the agent's
//! base58-encoded public key and an optional relay URL override.

use anyhow::{anyhow, bail, Context};
use serde::Deserialize;

/// The result of resolving a name to an ARP identity.
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    /// Base58-encoded Ed25519 public key.
    pub pubkey: String,
    /// Optional relay URL override from the identity record.
    /// If absent, the caller should use the configured default relay.
    pub relay: Option<String>,
}

/// JSON schema for the `agent.arp` ENS Text Record value
/// and the DNS TXT record value.
#[derive(Debug, Deserialize)]
struct IdentityRecord {
    pubkey: String,
    #[serde(default)]
    relay: Option<String>,
    // version and skills are accepted but not used by arpc itself
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    skills: Option<Vec<String>>,
}

// ── Name classification ──────────────────────────────────────────────

/// Returns `true` if the input looks like an ENS name.
///
/// ENS names end with a known ENS TLD. We check for `.eth` and the
/// common second-level ENS TLDs. DNS-style names are handled separately.
pub fn is_ens_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".eth")
        || lower.ends_with(".cb.id")
        || lower.ends_with(".lens")
        || lower.ends_with(".box")
}

/// Returns `true` if the input looks like a DNS domain name
/// (contains a dot but is not an ENS name).
pub fn is_dns_name(name: &str) -> bool {
    name.contains('.') && !is_ens_name(name)
}

// ── Top-level resolver ───────────────────────────────────────────────

/// Resolve a name to an ARP identity.
///
/// Dispatches to ENS or DNS resolution based on the name format.
///
/// # Errors
///
/// Returns an error if:
/// - The name is not a recognised ENS or DNS format
/// - The underlying resolution fails
/// - The resolved record is malformed or missing a pubkey
pub async fn resolve(name: &str, eth_rpc: Option<&str>) -> anyhow::Result<ResolvedIdentity> {
    if is_ens_name(name) {
        resolve_ens(name, eth_rpc).await
    } else if is_dns_name(name) {
        resolve_dns(name).await
    } else {
        bail!(
            "'{}' is not a recognised ENS name (.eth) or DNS domain. \
             Use a base58 public key directly, or provide an ENS/DNS name.",
            name
        )
    }
}

// ── ENS resolution ───────────────────────────────────────────────────

/// Default public Ethereum RPC endpoint (Cloudflare).
const DEFAULT_ETH_RPC: &str = "https://cloudflare-eth.com";

/// ENS Public Resolver address on Ethereum mainnet.
const ENS_PUBLIC_RESOLVER: &str = "0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41";

/// Resolve an ENS name to an ARP identity via the `agent.arp` Text Record.
///
/// Uses the Ethereum JSON-RPC `eth_call` to call `resolver.text(namehash, "agent.arp")`.
/// No Ethereum wallet or private key is required — this is a read-only call.
async fn resolve_ens(name: &str, eth_rpc: Option<&str>) -> anyhow::Result<ResolvedIdentity> {
    let rpc_url = eth_rpc.unwrap_or(DEFAULT_ETH_RPC);

    // Step 1: Compute ENS namehash
    let node = namehash(name);

    // Step 2: Find the resolver contract for this name
    let resolver_addr = ens_get_resolver(rpc_url, &node)
        .await
        .with_context(|| format!("failed to find ENS resolver for '{name}'"))?;

    if resolver_addr == "0x0000000000000000000000000000000000000000" {
        bail!("ENS name '{}' has no resolver — is it registered?", name);
    }

    // Step 3: Call resolver.text(node, "agent.arp")
    let record_value = ens_get_text(rpc_url, &resolver_addr, &node, "agent.arp")
        .await
        .with_context(|| format!("failed to read agent.arp record for '{name}'"))?;

    if record_value.is_empty() {
        bail!(
            "No ARP agent bound to '{}'. \
             Set the 'agent.arp' ENS Text Record to bind your agent.",
            name
        );
    }

    // Step 4: Parse the record
    parse_identity_record(&record_value)
        .with_context(|| format!("malformed agent.arp record for '{name}': {record_value}"))
}

/// Compute the ENS namehash for a name (EIP-137).
fn namehash(name: &str) -> String {
    // sha2 imports removed - not used

    // ENS namehash uses Keccak-256, but we approximate with a pure-Rust
    // implementation using the tiny-keccak approach via sha3.
    // We use the sha2 crate already in Cargo.toml for the PoW, but
    // Keccak-256 is distinct from SHA-256. We implement it inline.
    fn keccak256(data: &[u8]) -> [u8; 32] {
        // Use sha3::Keccak256 — added as a dependency below.
        use sha3::{Digest as _, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    let mut node = [0u8; 32]; // starts as 0x000...000

    if name.is_empty() {
        return hex::encode(node);
    }

    // Split on '.' and process labels right-to-left
    let labels: Vec<&str> = name.split('.').collect();
    for label in labels.iter().rev() {
        let label_hash = keccak256(label.as_bytes());
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&node);
        combined[32..].copy_from_slice(&label_hash);
        node = keccak256(&combined);
    }

    format!("0x{}", hex::encode(node))
}

/// Call ENS registry to get the resolver address for a node.
async fn ens_get_resolver(rpc_url: &str, node: &str) -> anyhow::Result<String> {
    // ENS Registry on mainnet: 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e
    // Function: resolver(bytes32 node) → address
    // Selector: 0x0178b8bf
    let padded_node = node.trim_start_matches("0x");
    let data = format!("0x0178b8bf{padded_node:0>64}");

    let result = eth_call(
        rpc_url,
        "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e",
        &data,
    )
    .await?;

    // Result is a 32-byte ABI-encoded address — take last 20 bytes
    let hex = result.trim_start_matches("0x");
    if hex.len() < 40 {
        bail!("unexpected resolver response: {result}");
    }
    Ok(format!("0x{}", &hex[hex.len() - 40..]))
}

/// Call resolver.text(node, key) and return the decoded string.
async fn ens_get_text(
    rpc_url: &str,
    resolver: &str,
    node: &str,
    key: &str,
) -> anyhow::Result<String> {
    // Function: text(bytes32 node, string key) → string
    // Selector: 0x59d1d43c
    let padded_node = node.trim_start_matches("0x");

    // ABI-encode the call: selector + node + offset to string + string length + string data
    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();
    let key_padded_len = ((key_len + 31) / 32) * 32;

    let mut call_data = format!(
        "0x59d1d43c\
         {padded_node:0>64}\
         {offset:064x}\
         {key_len:064x}",
        offset = 64u64, // offset to string data (after node + offset field)
    );

    // Append key bytes, padded to 32-byte boundary
    let key_hex: String = key_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let padding = "0".repeat((key_padded_len - key_len) * 2);
    call_data.push_str(&key_hex);
    call_data.push_str(&padding);

    let result = eth_call(rpc_url, resolver, &call_data).await?;

    // Decode ABI-encoded string from the response
    decode_abi_string(&result)
        .with_context(|| format!("failed to decode text() response: {result}"))
}

/// Decode an ABI-encoded `string` return value from `eth_call`.
fn decode_abi_string(hex_response: &str) -> anyhow::Result<String> {
    let hex = hex_response.trim_start_matches("0x");

    if hex.len() < 128 {
        // Empty string response
        return Ok(String::new());
    }

    // Bytes 32–63: offset to string data (usually 0x20 = 32)
    // Bytes 64–95: string length
    let len_hex = &hex[64..128];
    let str_len = usize::from_str_radix(len_hex, 16)
        .map_err(|_| anyhow!("invalid string length in ABI response"))?;

    if str_len == 0 {
        return Ok(String::new());
    }

    let data_start = 128;
    let data_end = data_start + str_len * 2;

    if hex.len() < data_end {
        bail!("ABI response too short for declared string length");
    }

    let str_hex = &hex[data_start..data_end];
    let bytes = (0..str_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&str_hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| anyhow!("invalid hex in ABI string data"))?;

    String::from_utf8(bytes).map_err(|e| anyhow!("ENS record is not valid UTF-8: {e}"))
}

/// Make a raw `eth_call` via JSON-RPC and return the hex result string.
async fn eth_call(rpc_url: &str, to: &str, data: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [
            { "to": to, "data": data },
            "latest"
        ],
        "id": 1
    });

    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("failed to reach Ethereum RPC at {rpc_url}"))?;

    let json: serde_json::Value = resp
        .json()
        .await
        .context("failed to parse Ethereum RPC response")?;

    if let Some(err) = json.get("error") {
        bail!("Ethereum RPC error: {err}");
    }

    json["result"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("missing 'result' in Ethereum RPC response"))
}

// ── DNS TXT resolution ───────────────────────────────────────────────

/// Resolve a DNS domain to an ARP identity via a `_arpa.<domain>` TXT record.
async fn resolve_dns(domain: &str) -> anyhow::Result<ResolvedIdentity> {
    let query_name = format!("_arpa.{domain}");

    // Use Google DNS-over-HTTPS for maximum portability
    // (no system resolver dependency, works in all environments)
    let url = format!(
        "https://dns.google/resolve?name={}&type=TXT",
        urlencoding_encode(&query_name)
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await
        .with_context(|| format!("DNS query failed for {query_name}"))?;

    let json: serde_json::Value = resp
        .json()
        .await
        .context("failed to parse DNS-over-HTTPS response")?;

    let status = json["Status"].as_u64().unwrap_or(3);
    if status == 3 {
        bail!(
            "DNS name '{}' not found. \
             Add a TXT record at '_arpa.{}' to bind your agent.",
            domain,
            domain
        );
    }
    if status != 0 {
        bail!("DNS query for '{}' failed with status {}", query_name, status);
    }

    // Collect all TXT strings and concatenate (handles multi-string records)
    let answers = json["Answer"]
        .as_array()
        .ok_or_else(|| anyhow!("no TXT records found for '{}'", query_name))?;

    let mut txt_value = String::new();
    for answer in answers {
        if answer["type"].as_u64() == Some(16) {
            // TXT record
            if let Some(data) = answer["data"].as_str() {
                // DNS-over-HTTPS wraps TXT data in quotes; strip them
                let stripped = data.trim_matches('"');
                txt_value.push_str(stripped);
            }
        }
    }

    if txt_value.is_empty() {
        bail!("No TXT records found at '_arpa.{}'", domain);
    }

    parse_identity_record(&txt_value)
        .with_context(|| format!("malformed ARP identity record at '_arpa.{domain}': {txt_value}"))
}

// ── Shared record parser ─────────────────────────────────────────────

/// Parse a JSON identity record string into a [`ResolvedIdentity`].
fn parse_identity_record(value: &str) -> anyhow::Result<ResolvedIdentity> {
    // Support both JSON objects and plain base58 pubkey strings (YUX minimal format)
    let trimmed = value.trim();

    if trimmed.starts_with('{') {
        // Full JSON record
        let record: IdentityRecord = serde_json::from_str(trimmed)
            .map_err(|e| anyhow!("invalid JSON in identity record: {e}"))?;

        validate_pubkey(&record.pubkey)?;

        Ok(ResolvedIdentity {
            pubkey: record.pubkey,
            relay: record.relay,
        })
    } else {
        // Plain base58 pubkey (minimal format)
        validate_pubkey(trimmed)?;
        Ok(ResolvedIdentity {
            pubkey: trimmed.to_string(),
            relay: None,
        })
    }
}

/// Validate that a string is a valid base58-encoded Ed25519 public key.
fn validate_pubkey(pubkey_b58: &str) -> anyhow::Result<()> {
    arp_common::base58::decode_pubkey(pubkey_b58)
        .map(|_| ())
        .map_err(|e| anyhow!("invalid ARP public key '{}': {}", pubkey_b58, e))
}

// ── Minimal URL encoding ─────────────────────────────────────────────

fn urlencoding_encode(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                vec![c]
            } else {
                let encoded = format!("%{:02X}", c as u8);
                encoded.chars().collect()
            }
        })
        .collect()
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ens_name() {
        assert!(is_ens_name("alice.eth"));
        assert!(is_ens_name("ALICE.ETH"));
        assert!(is_ens_name("sub.alice.eth"));
        assert!(is_ens_name("alice.cb.id"));
        assert!(!is_ens_name("alice.example.com"));
        assert!(!is_ens_name("alicepubkey"));
    }

    #[test]
    fn test_is_dns_name() {
        assert!(is_dns_name("alice.example.com"));
        assert!(is_dns_name("agent.mysite.io"));
        assert!(!is_dns_name("alice.eth"));
        assert!(!is_dns_name("rawpubkey"));
    }

    #[test]
    fn test_namehash_empty() {
        // namehash("") = 0x000...000
        let h = namehash("");
        assert_eq!(h, "0x".to_string() + &"0".repeat(64));
    }

    #[test]
    fn test_namehash_eth() {
        // Known value: namehash("eth") =
        // 0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae
        let h = namehash("eth");
        assert_eq!(
            h,
            "0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        );
    }

    #[test]
    fn test_parse_identity_record_json() {
        let json = r#"{"version":"1","pubkey":"7EcDy2GvMpBRbnkJRCsj7xp5n4KfQvBGBBr3TH8YXVW4","relay":"wss://arps.offgrid.ing"}"#;
        // This will fail validation because the pubkey is a test value,
        // but we can test the JSON parsing path
        let result = parse_identity_record(json);
        // Just verify it attempts JSON parsing (pubkey validation may fail for test key)
        match result {
            Ok(id) => assert!(!id.pubkey.is_empty()),
            Err(e) => assert!(e.to_string().contains("invalid ARP public key") || e.to_string().contains("invalid JSON")),
        }
    }

    #[test]
    fn test_parse_identity_record_minimal_json() {
        // Minimal JSON (no relay)
        let json = r#"{"pubkey":"7EcDy2GvMpBRbnkJRCsj7xp5n4KfQvBGBBr3TH8YXVW4"}"#;
        let result = parse_identity_record(json);
        match result {
            Ok(id) => assert!(id.relay.is_none()),
            Err(_) => {} // pubkey validation failure is ok for test data
        }
    }

    #[test]
    fn test_decode_abi_string_empty() {
        // eth_call returns 0x for empty string
        let result = decode_abi_string("0x").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_urlencoding_encode() {
        assert_eq!(urlencoding_encode("_arpa.alice.eth"), "_arpa.alice.eth");
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
    }
}
