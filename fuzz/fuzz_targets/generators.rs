//! Structure-aware byte sequence generators for SV2 protocol messages.
//!
//! Each generator builds a valid wire-format byte sequence from the spec field layout
//! giving the fuzzer meaningful starting points to mutate. The output bytes MUST be
//! parseable by the corresponding `from_bytes` implementation;
//!
//! Size bounds: payload sizes scale with remaining fuzz input via `u.len()`, capped at
//! the type's spec maximum. This keeps generation exhaustion-proof and corpus entries small.
#![allow(dead_code)]

use arbitrary::Unstructured;

// ---------------------------------------------------------------------------
// Core helper: build a variable-length payload capped by available input
// ---------------------------------------------------------------------------

fn gen_var_payload(u: &mut Unstructured, max: usize) -> arbitrary::Result<Vec<u8>> {
    let cap = u.len().min(max);
    let len = u.int_in_range(0..=cap)?;
    Ok(u.bytes(len)?.to_vec())
}

// ---------------------------------------------------------------------------
// Fixed-size primitive helpers (LE encoding)
// ---------------------------------------------------------------------------

pub fn gen_u8(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    Ok(u.arbitrary::<u8>()?.to_le_bytes().to_vec())
}

pub fn gen_u16(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    Ok(u.arbitrary::<u16>()?.to_le_bytes().to_vec())
}

pub fn gen_u32(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    Ok(u.arbitrary::<u32>()?.to_le_bytes().to_vec())
}

pub fn gen_u64(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    Ok(u.arbitrary::<u64>()?.to_le_bytes().to_vec())
}

pub fn gen_f32(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    Ok(u.arbitrary::<f32>()?.to_le_bytes().to_vec())
}

/// bool wire format: 1 byte, canonical 0 or 1 (any byte accepted by from_bytes;
/// we emit canonical values for deterministic roundtrips).
pub fn gen_bool(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    Ok(vec![u.arbitrary::<bool>()? as u8])
}

/// U24 wire format: 3 bytes LE. Valid range 0..=16_777_215.
pub fn gen_u24(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let raw = u.int_in_range(0u32..=0x00FF_FFFF)?;
    let b = raw.to_le_bytes();
    Ok(vec![b[0], b[1], b[2]])
}

// ---------------------------------------------------------------------------
// Fixed-size byte arrays (no header prefix)
// ---------------------------------------------------------------------------

pub fn gen_u256(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    Ok(u.bytes(32)?.to_vec())
}

pub fn gen_mac(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    Ok(u.bytes(16)?.to_vec())
}

pub fn gen_pubkey(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    Ok(u.bytes(32)?.to_vec())
}

pub fn gen_signature(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    Ok(u.bytes(64)?.to_vec())
}

// ---------------------------------------------------------------------------
// Variable-length byte arrays (length-prefixed)
// ---------------------------------------------------------------------------

/// B032: 1-byte LE length + 0..32 payload bytes
pub fn gen_b032(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let payload = gen_var_payload(u, 32)?;
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(payload.len() as u8);
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// B0255: 1-byte LE length + 0..255 payload bytes
pub fn gen_b0255(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let payload = gen_var_payload(u, 255)?;
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(payload.len() as u8);
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Str0255: 1-byte LE length + 0..255 payload bytes (identical wire format to B0255)
pub fn gen_str0255(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let payload = gen_var_payload(u, 255)?;
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(payload.len() as u8);
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// B064K: 2-byte LE length + 0..65535 payload bytes.
/// Capped at 512 bytes of payload for tractable fuzzer corpus sizes.
pub fn gen_b064k(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let payload = gen_var_payload(u, 512)?;
    let len = payload.len() as u16;
    let mut buf = Vec::with_capacity(2 + payload.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// B016M: 3-byte LE length + 0..16_777_215 payload bytes.
/// Capped at 100 bytes of payload for tractable fuzzer corpus sizes.
pub fn gen_b016m(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let payload = gen_var_payload(u, 100)?;
    let len = payload.len() as u32;
    let b = len.to_le_bytes();
    let mut buf = Vec::with_capacity(3 + payload.len());
    buf.extend_from_slice(&b[..3]); // 3 bytes LE
    buf.extend_from_slice(&payload);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Composite helpers
// ---------------------------------------------------------------------------

/// Sv2Option<T>: 1-byte header (0 = None, 1 = Some) + optional element.
/// Generator emits a bool-controlled header with element bytes if Some.
pub fn gen_sv2_option_u32(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    if u.arbitrary::<bool>()? {
        let mut buf = vec![1u8];
        buf.extend_from_slice(&u.arbitrary::<u32>()?.to_le_bytes());
        Ok(buf)
    } else {
        Ok(vec![0u8])
    }
}

/// Seq0255<U256>: 1-byte element count (0..255) + count × 32 raw bytes.
/// Element count capped by remaining input (at least 32 bytes each).
pub fn gen_seq0255_u256(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let elem_size = 32usize;
    let max_count = u.len() / elem_size;
    let count = u.int_in_range(0..=max_count.min(255))?;
    let mut buf = Vec::with_capacity(1 + count * elem_size);
    buf.push(count as u8);
    for _ in 0..count {
        buf.extend_from_slice(u.bytes(elem_size)?);
    }
    Ok(buf)
}

/// Seq064K<u16>: 2-byte LE element count + count × 2 raw bytes.
pub fn gen_seq064k_u16(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let elem_size = 2usize;
    let max_count = u.len() / elem_size;
    let count = u.int_in_range(0..=max_count.min(65535))?;
    let mut buf = Vec::with_capacity(2 + count * elem_size);
    buf.extend_from_slice(&(count as u16).to_le_bytes());
    for _ in 0..count {
        buf.extend_from_slice(u.bytes(elem_size)?);
    }
    Ok(buf)
}

/// Seq064K<u32>: 2-byte LE element count + count × 4 raw bytes.
pub fn gen_seq064k_u32(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let elem_size = 4usize;
    let max_count = u.len() / elem_size;
    let count = u.int_in_range(0..=max_count.min(65535))?;
    let mut buf = Vec::with_capacity(2 + count * elem_size);
    buf.extend_from_slice(&(count as u16).to_le_bytes());
    for _ in 0..count {
        buf.extend_from_slice(u.bytes(elem_size)?);
    }
    Ok(buf)
}

/// Seq064K<U256>: 2-byte LE element count + count × 32 raw bytes.
pub fn gen_seq064k_u256(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let elem_size = 32usize;
    let max_count = u.len() / elem_size;
    let count = u.int_in_range(0..=max_count.min(65535))?;
    let mut buf = Vec::with_capacity(2 + count * elem_size);
    buf.extend_from_slice(&(count as u16).to_le_bytes());
    for _ in 0..count {
        buf.extend_from_slice(u.bytes(elem_size)?);
    }
    Ok(buf)
}

/// Seq064K<B016M>: 2-byte LE element count + each element is B016M (3-byte len + payload).
/// Element count capped at 10 to keep corpus sizes tractable.
pub fn gen_seq064k_b016m(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let max_count = u.len() / 10; // conservative estimate per element
    let count = u.int_in_range(0..=max_count.min(10))?;
    let mut buf = Vec::with_capacity(2 + count * 32);
    buf.extend_from_slice(&(count as u16).to_le_bytes());
    for _ in 0..count {
        buf.extend_from_slice(&gen_b016m(u)?);
    }
    Ok(buf)
}

/// Seq0255<B016M>: 1-byte element count + each element is B016M (3-byte len + payload).
/// Element count capped at 10.
pub fn gen_seq0255_b016m(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let max_count = u.len() / 10;
    let count = u.int_in_range(0..=max_count.min(10))?;
    let mut buf = Vec::with_capacity(1 + count * 32);
    buf.push(count as u8);
    for _ in 0..count {
        buf.extend_from_slice(&gen_b016m(u)?);
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Generic composite helpers — used by datatype fuzz target
// ---------------------------------------------------------------------------

/// Seq0255<T>: 1-byte element count (0..=255) + count × element bytes.
/// The `gen_elem` callback produces one element's wire bytes.
/// `max_count` caps the element count (255 for small elements, lower for large ones).
pub fn gen_seq0255(
    u: &mut Unstructured,
    gen_elem: impl FnMut(&mut Unstructured) -> arbitrary::Result<Vec<u8>>,
    max_count: usize,
) -> arbitrary::Result<Vec<u8>> {
    let mut gen_elem = gen_elem;
    let count = u.int_in_range(0..=max_count.min(255))?;
    let mut buf = Vec::with_capacity(1 + count * 32);
    buf.push(count as u8);
    for _ in 0..count {
        buf.extend_from_slice(&gen_elem(u)?);
    }
    Ok(buf)
}

/// Seq064K<T>: 2-byte LE element count (0..=65535) + count × element bytes.
/// `max_count` caps the element count.
pub fn gen_seq064k(
    u: &mut Unstructured,
    gen_elem: impl FnMut(&mut Unstructured) -> arbitrary::Result<Vec<u8>>,
    max_count: usize,
) -> arbitrary::Result<Vec<u8>> {
    let mut gen_elem = gen_elem;
    let count = u.int_in_range(0..=max_count.min(65535))?;
    let mut buf = Vec::with_capacity(2 + count * 32);
    buf.extend_from_slice(&(count as u16).to_le_bytes());
    for _ in 0..count {
        buf.extend_from_slice(&gen_elem(u)?);
    }
    Ok(buf)
}

/// Sv2Option<T>: 1-byte header (0 = None, 1 = Some) + optional element bytes.
pub fn gen_sv2_option(
    u: &mut Unstructured,
    mut gen_elem: impl FnMut(&mut Unstructured) -> arbitrary::Result<Vec<u8>>,
) -> arbitrary::Result<Vec<u8>> {
    if u.arbitrary::<bool>()? {
        let mut buf = vec![1u8];
        buf.extend_from_slice(&gen_elem(u)?);
        Ok(buf)
    } else {
        Ok(vec![0u8])
    }
}

// ============================================================================
// Common Messages
// ============================================================================

/// SetupConnection: protocol(1B) + min_version(u16) + max_version(u16) + flags(u32)
/// + endpoint_host(Str0255) + endpoint_port(u16)
/// + vendor(Str0255) + hardware_version(Str0255)
/// + firmware(Str0255) + device_id(Str0255)
///
/// Protocol byte is restricted to valid discriminants 0..=2 per spec section 3.6.
pub fn gen_setup_connection(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(128);
    buf.push(u.int_in_range(0u8..=2)?); // protocol (valid discriminant only)
    buf.extend_from_slice(&u.arbitrary::<u16>()?.to_le_bytes()); // min_version
    buf.extend_from_slice(&u.arbitrary::<u16>()?.to_le_bytes()); // max_version
    buf.extend_from_slice(&u.arbitrary::<u32>()?.to_le_bytes()); // flags
    buf.extend_from_slice(&gen_str0255(u)?); // endpoint_host
    buf.extend_from_slice(&u.arbitrary::<u16>()?.to_le_bytes()); // endpoint_port
    buf.extend_from_slice(&gen_str0255(u)?); // vendor
    buf.extend_from_slice(&gen_str0255(u)?); // hardware_version
    buf.extend_from_slice(&gen_str0255(u)?); // firmware
    buf.extend_from_slice(&gen_str0255(u)?); // device_id
    Ok(buf)
}

/// SetupConnectionSuccess: used_version(u16) + flags(u32) = 6 bytes
pub fn gen_setup_connection_success(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(6);
    buf.extend_from_slice(&u.arbitrary::<u16>()?.to_le_bytes()); // used_version
    buf.extend_from_slice(&u.arbitrary::<u32>()?.to_le_bytes()); // flags
    Ok(buf)
}

/// SetupConnectionError: flags(u32) + error_code(Str0255)
pub fn gen_setup_connection_error(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&u.arbitrary::<u32>()?.to_le_bytes()); // flags
    buf.extend_from_slice(&gen_str0255(u)?); // error_code
    Ok(buf)
}

/// Reconnect: new_host(Str0255) + new_port(u16)
pub fn gen_reconnect(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&gen_str0255(u)?); // new_host
    buf.extend_from_slice(&u.arbitrary::<u16>()?.to_le_bytes()); // new_port
    Ok(buf)
}

/// ChannelEndpointChanged: channel_id(u32) = 4 bytes
pub fn gen_channel_endpoint_changed(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    gen_u32(u)
}

// ============================================================================
// Mining Messages
// ============================================================================

/// OpenStandardMiningChannel: request_id(u32) + user_identity(Str0255)
/// + nominal_hash_rate(f32) + max_target(U256)
pub fn gen_open_standard_mining_channel(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_str0255(u)?); // user_identity
    buf.extend_from_slice(&gen_f32(u)?); // nominal_hash_rate
    buf.extend_from_slice(&gen_u256(u)?); // max_target
    Ok(buf)
}

/// OpenStandardMiningChannelSuccess: request_id(u32) + channel_id(u32)
/// + target(U256) + extranonce_prefix(B032) + group_channel_id(u32)
pub fn gen_open_standard_mining_channel_success(
    u: &mut Unstructured,
) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(72);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u256(u)?); // target
    buf.extend_from_slice(&gen_b032(u)?); // extranonce_prefix
    buf.extend_from_slice(&gen_u32(u)?); // group_channel_id
    Ok(buf)
}

/// OpenMiningChannelError: request_id(u32) + error_code(Str0255)
pub fn gen_open_mining_channel_error(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_str0255(u)?); // error_code
    Ok(buf)
}

/// OpenExtendedMiningChannel: request_id(u32) + user_identity(Str0255)
/// + nominal_hash_rate(f32) + max_target(U256) + min_extranonce_size(u16)
pub fn gen_open_extended_mining_channel(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_str0255(u)?); // user_identity
    buf.extend_from_slice(&gen_f32(u)?); // nominal_hash_rate
    buf.extend_from_slice(&gen_u256(u)?); // max_target
    buf.extend_from_slice(&gen_u16(u)?); // min_extranonce_size
    Ok(buf)
}

/// OpenExtendedMiningChannelSuccess: request_id(u32) + channel_id(u32)
/// + target(U256) + extranonce_size(u16) + extranonce_prefix(B032)
/// + group_channel_id(u32)
pub fn gen_open_extended_mining_channel_success(
    u: &mut Unstructured,
) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(72);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u256(u)?); // target
    buf.extend_from_slice(&gen_u16(u)?); // extranonce_size
    buf.extend_from_slice(&gen_b032(u)?); // extranonce_prefix
    buf.extend_from_slice(&gen_u32(u)?); // group_channel_id
    Ok(buf)
}

/// NewMiningJob: channel_id(u32) + job_id(u32) + min_ntime(Sv2Option<u32>)
/// + version(u32) + merkle_root(U256)
pub fn gen_new_mining_job(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u32(u)?); // job_id
    buf.extend_from_slice(&gen_sv2_option_u32(u)?); // min_ntime
    buf.extend_from_slice(&gen_u32(u)?); // version
    buf.extend_from_slice(&gen_u256(u)?); // merkle_root
    Ok(buf)
}

/// NewExtendedMiningJob: channel_id(u32) + job_id(u32) + min_ntime(Sv2Option<u32>)
/// + version(u32) + version_rolling_allowed(bool)
/// + merkle_path(Seq0255<U256>) + coinbase_tx_prefix(B064K)
/// + coinbase_tx_suffix(B064K)
pub fn gen_new_extended_mining_job(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u32(u)?); // job_id
    buf.extend_from_slice(&gen_sv2_option_u32(u)?); // min_ntime
    buf.extend_from_slice(&gen_u32(u)?); // version
    buf.extend_from_slice(&gen_bool(u)?); // version_rolling_allowed
    buf.extend_from_slice(&gen_seq0255_u256(u)?); // merkle_path
    buf.extend_from_slice(&gen_b064k(u)?); // coinbase_tx_prefix
    buf.extend_from_slice(&gen_b064k(u)?); // coinbase_tx_suffix
    Ok(buf)
}

/// UpdateChannel: channel_id(u32) + nominal_hash_rate(f32) + maximum_target(U256)
pub fn gen_update_channel(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_f32(u)?); // nominal_hash_rate
    buf.extend_from_slice(&gen_u256(u)?); // maximum_target
    Ok(buf)
}

/// UpdateChannelError: channel_id(u32) + error_code(Str0255)
pub fn gen_update_channel_error(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_str0255(u)?); // error_code
    Ok(buf)
}

/// CloseChannel: channel_id(u32) + reason_code(Str0255)
pub fn gen_close_channel(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_str0255(u)?); // reason_code
    Ok(buf)
}

/// SetExtranoncePrefix: channel_id(u32) + extranonce_prefix(B032)
pub fn gen_set_extranonce_prefix(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_b032(u)?); // extranonce_prefix
    Ok(buf)
}

/// SetGroupChannel: group_channel_id(u32) + channel_ids(Seq064K<u32>)
pub fn gen_set_group_channel(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&gen_u32(u)?); // group_channel_id
    buf.extend_from_slice(&gen_seq064k_u32(u)?); // channel_ids
    Ok(buf)
}

/// SetNewPrevHash (mining): channel_id(u32) + job_id(u32) + prev_hash(U256)
/// + min_ntime(u32) + nbits(u32) = 48 bytes fixed
pub fn gen_set_new_prev_hash_mining(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u32(u)?); // job_id
    buf.extend_from_slice(&gen_u256(u)?); // prev_hash
    buf.extend_from_slice(&gen_u32(u)?); // min_ntime
    buf.extend_from_slice(&gen_u32(u)?); // nbits
    Ok(buf)
}

/// SetTarget: channel_id(u32) + maximum_target(U256)
pub fn gen_set_target(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(36);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u256(u)?); // maximum_target
    Ok(buf)
}

/// SubmitSharesStandard: channel_id(u32) + sequence_number(u32) + job_id(u32)
/// + nonce(u32) + ntime(u32) + version(u32) = 24 bytes fixed
pub fn gen_submit_shares_standard(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(24);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u32(u)?); // sequence_number
    buf.extend_from_slice(&gen_u32(u)?); // job_id
    buf.extend_from_slice(&gen_u32(u)?); // nonce
    buf.extend_from_slice(&gen_u32(u)?); // ntime
    buf.extend_from_slice(&gen_u32(u)?); // version
    Ok(buf)
}

/// SubmitSharesExtended: SubmitSharesStandard fields + extranonce(B032)
pub fn gen_submit_shares_extended(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = gen_submit_shares_standard(u)?;
    buf.extend_from_slice(&gen_b032(u)?); // extranonce
    Ok(buf)
}

/// SubmitSharesSuccess: channel_id(u32) + last_sequence_number(u32)
/// + new_submits_accepted_count(u32) + new_shares_sum(u64) = 16 bytes fixed
pub fn gen_submit_shares_success(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u32(u)?); // last_sequence_number
    buf.extend_from_slice(&gen_u32(u)?); // new_submits_accepted_count
    buf.extend_from_slice(&gen_u64(u)?); // new_shares_sum
    Ok(buf)
}

/// SubmitSharesError: channel_id(u32) + sequence_number(u32) + error_code(Str0255)
pub fn gen_submit_shares_error(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u32(u)?); // sequence_number
    buf.extend_from_slice(&gen_str0255(u)?); // error_code
    Ok(buf)
}

/// SetCustomMiningJob: channel_id(u32) + request_id(u32) + token(B0255)
/// + version(u32) + prev_hash(U256) + min_ntime(u32) + nbits(u32)
/// + coinbase_tx_version(u32) + coinbase_prefix(B0255)
/// + coinbase_tx_input_n_sequence(u32) + coinbase_tx_outputs(B064K)
/// + coinbase_tx_locktime(u32) + merkle_path(Seq0255<U256>)
pub fn gen_set_custom_mining_job(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_b0255(u)?); // token
    buf.extend_from_slice(&gen_u32(u)?); // version
    buf.extend_from_slice(&gen_u256(u)?); // prev_hash
    buf.extend_from_slice(&gen_u32(u)?); // min_ntime
    buf.extend_from_slice(&gen_u32(u)?); // nbits
    buf.extend_from_slice(&gen_u32(u)?); // coinbase_tx_version
    buf.extend_from_slice(&gen_b0255(u)?); // coinbase_prefix
    buf.extend_from_slice(&gen_u32(u)?); // coinbase_tx_input_n_sequence
    buf.extend_from_slice(&gen_b064k(u)?); // coinbase_tx_outputs
    buf.extend_from_slice(&gen_u32(u)?); // coinbase_tx_locktime
    buf.extend_from_slice(&gen_seq0255_u256(u)?); // merkle_path
    Ok(buf)
}

/// SetCustomMiningJobSuccess: channel_id(u32) + request_id(u32) + job_id(u32)
pub fn gen_set_custom_mining_job_success(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(12);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_u32(u)?); // job_id
    Ok(buf)
}

/// SetCustomMiningJobError: channel_id(u32) + request_id(u32) + error_code(Str0255)
pub fn gen_set_custom_mining_job_error(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&gen_u32(u)?); // channel_id
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_str0255(u)?); // error_code
    Ok(buf)
}

// ============================================================================
// Job Declaration Messages
// ============================================================================

/// AllocateMiningJobToken: user_identifier(Str0255) + request_id(u32)
pub fn gen_allocate_mining_job_token(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&gen_str0255(u)?); // user_identifier
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    Ok(buf)
}

/// AllocateMiningJobTokenSuccess: request_id(u32) + mining_job_token(B0255)
/// + coinbase_outputs(B064K)
pub fn gen_allocate_mining_job_token_success(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_b0255(u)?); // mining_job_token
    buf.extend_from_slice(&gen_b064k(u)?); // coinbase_outputs
    Ok(buf)
}

/// DeclareMiningJob: request_id(u32) + mining_job_token(B0255) + version(u32)
/// + coinbase_tx_prefix(B064K) + coinbase_tx_suffix(B064K)
/// + wtxid_list(Seq064K<U256>) + excess_data(B064K)
pub fn gen_declare_mining_job(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_b0255(u)?); // mining_job_token
    buf.extend_from_slice(&gen_u32(u)?); // version
    buf.extend_from_slice(&gen_b064k(u)?); // coinbase_tx_prefix
    buf.extend_from_slice(&gen_b064k(u)?); // coinbase_tx_suffix
    buf.extend_from_slice(&gen_seq064k_u256(u)?); // wtxid_list
    buf.extend_from_slice(&gen_b064k(u)?); // excess_data
    Ok(buf)
}

/// DeclareMiningJobSuccess: request_id(u32) + new_mining_job_token(B0255)
pub fn gen_declare_mining_job_success(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_b0255(u)?); // new_mining_job_token
    Ok(buf)
}

/// DeclareMiningJobError: request_id(u32) + error_code(Str0255)
/// + error_details(B064K)
pub fn gen_declare_mining_job_error(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_str0255(u)?); // error_code
    buf.extend_from_slice(&gen_b064k(u)?); // error_details
    Ok(buf)
}

/// ProvideMissingTransactions: request_id(u32)
/// + unknown_tx_position_list(Seq064K<u16>)
pub fn gen_provide_missing_transactions(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_seq064k_u16(u)?); // unknown_tx_position_list
    Ok(buf)
}

/// ProvideMissingTransactionsSuccess: request_id(u32)
/// + transaction_list(Seq0255<B016M>)
pub fn gen_provide_missing_transactions_success(
    u: &mut Unstructured,
) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&gen_u32(u)?); // request_id
    buf.extend_from_slice(&gen_seq064k_b016m(u)?); // transaction_list
    Ok(buf)
}

/// PushSolution: extranonce(B032) + prev_hash(U256) + nonce(u32)
/// + ntime(u32) + nbits(u32) + version(u32)
pub fn gen_push_solution(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(52);
    buf.extend_from_slice(&gen_b032(u)?); // extranonce
    buf.extend_from_slice(&gen_u256(u)?); // prev_hash
    buf.extend_from_slice(&gen_u32(u)?); // nonce
    buf.extend_from_slice(&gen_u32(u)?); // ntime
    buf.extend_from_slice(&gen_u32(u)?); // nbits
    buf.extend_from_slice(&gen_u32(u)?); // version
    Ok(buf)
}

// ============================================================================
// Template Distribution Messages
// ============================================================================

/// CoinbaseOutputConstraints: coinbase_output_max_additional_size(u32)
/// + coinbase_output_max_additional_sigops(u16) = 6 bytes fixed
pub fn gen_coinbase_output_constraints(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(6);
    buf.extend_from_slice(&gen_u32(u)?); // coinbase_output_max_additional_size
    buf.extend_from_slice(&gen_u16(u)?); // coinbase_output_max_additional_sigops
    Ok(buf)
}

/// NewTemplate: template_id(u64) + future_template(bool) + version(u32)
/// + coinbase_tx_version(u32) + coinbase_prefix(B0255)
/// + coinbase_tx_input_sequence(u32) + coinbase_tx_value_remaining(u64)
/// + coinbase_tx_outputs_count(u32) + coinbase_tx_outputs(B064K)
/// + coinbase_tx_locktime(u32) + merkle_path(Seq0255<U256>)
pub fn gen_new_template(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&gen_u64(u)?); // template_id
    buf.extend_from_slice(&gen_bool(u)?); // future_template
    buf.extend_from_slice(&gen_u32(u)?); // version
    buf.extend_from_slice(&gen_u32(u)?); // coinbase_tx_version
    buf.extend_from_slice(&gen_b0255(u)?); // coinbase_prefix
    buf.extend_from_slice(&gen_u32(u)?); // coinbase_tx_input_sequence
    buf.extend_from_slice(&gen_u64(u)?); // coinbase_tx_value_remaining
    buf.extend_from_slice(&gen_u32(u)?); // coinbase_tx_outputs_count
    buf.extend_from_slice(&gen_b064k(u)?); // coinbase_tx_outputs
    buf.extend_from_slice(&gen_u32(u)?); // coinbase_tx_locktime
    buf.extend_from_slice(&gen_seq0255_u256(u)?); // merkle_path
    Ok(buf)
}

/// SetNewPrevHash (template distribution): template_id(u64) + prev_hash(U256)
/// + header_timestamp(u32) + n_bits(u32) + target(U256) = 52 bytes fixed
pub fn gen_set_new_prev_hash_template(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(52);
    buf.extend_from_slice(&gen_u64(u)?); // template_id
    buf.extend_from_slice(&gen_u256(u)?); // prev_hash
    buf.extend_from_slice(&gen_u32(u)?); // header_timestamp
    buf.extend_from_slice(&gen_u32(u)?); // n_bits
    buf.extend_from_slice(&gen_u256(u)?); // target
    Ok(buf)
}

/// RequestTransactionData: template_id(u64) = 8 bytes fixed
pub fn gen_request_transaction_data(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    gen_u64(u)
}

/// RequestTransactionDataSuccess: template_id(u64) + excess_data(B064K)
/// + transaction_list(Seq0255<B016M>)
pub fn gen_request_transaction_data_success(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&gen_u64(u)?); // template_id
    buf.extend_from_slice(&gen_b064k(u)?); // excess_data
    buf.extend_from_slice(&gen_seq064k_b016m(u)?); // transaction_list
    Ok(buf)
}

/// RequestTransactionDataError: template_id(u64) + error_code(Str0255)
pub fn gen_request_transaction_data_error(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&gen_u64(u)?); // template_id
    buf.extend_from_slice(&gen_str0255(u)?); // error_code
    Ok(buf)
}

/// SubmitSolution: template_id(u64) + version(u32) + header_timestamp(u32)
/// + header_nonce(u32) + coinbase_tx(B064K)
pub fn gen_submit_solution(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&gen_u64(u)?); // template_id
    buf.extend_from_slice(&gen_u32(u)?); // version
    buf.extend_from_slice(&gen_u32(u)?); // header_timestamp
    buf.extend_from_slice(&gen_u32(u)?); // header_nonce
    buf.extend_from_slice(&gen_b064k(u)?); // coinbase_tx
    Ok(buf)
}
