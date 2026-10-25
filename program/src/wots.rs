//! Winternitz one-time signatures (WOTS) sized to fit a single Solana transaction.
//!
//! Parameters
//! - hash: SHA-256 truncated to N = 28 bytes (224 bits)
//! - Winternitz parameter w = 256, so every byte of the message digest is one digit
//! - message digits: 28 (a 224-bit digest)
//! - checksum digits: 2 (max checksum 28 * 255 = 7140 fits in a u16)
//! - chains: L = 30, signature size 30 * 28 = 840 bytes
//!
//! Chain step j (0..255) on chain i is `F(x, i, j) = SHA256(x || i || j)[..28]`.
//! The index tweak stops an attacker from reusing work across chains or steps.
//! A public key is the end of every chain (255 steps). Its 32-byte "root" is
//! `SHA256(pk_0 || .. || pk_29)` and is the seed of the vault address.

use solana_program::hash::hashv;

pub const N: usize = 28;
pub const MSG_DIGITS: usize = 28;
pub const CHECKSUM_DIGITS: usize = 2;
pub const CHAINS: usize = MSG_DIGITS + CHECKSUM_DIGITS;
pub const MAX_STEP: u8 = 255;
pub const SIGNATURE_LEN: usize = CHAINS * N;

pub type Element = [u8; N];

#[inline(always)]
fn truncate(h: &[u8; 32]) -> Element {
    let mut out = [0u8; N];
    out.copy_from_slice(&h[..N]);
    out
}

/// One step of chain `chain` at position `step`.
#[inline(always)]
pub fn chain_step(x: &Element, chain: u8, step: u8) -> Element {
    truncate(&hashv(&[x, &[chain, step]]).to_bytes())
}

/// Advance `x` (which sits at position `from`) up to position `to`.
pub fn chain(x: &Element, chain: u8, from: u8, to: u8) -> Element {
    let mut v = *x;
    let mut j = from;
    while j < to {
        v = chain_step(&v, chain, j);
        j += 1;
    }
    v
}

/// Message digest (28 digits) followed by the 2-digit big-endian checksum.
pub fn digits(message: &[u8; 32]) -> [u8; CHAINS] {
    let mut d = [0u8; CHAINS];
    let mut checksum: u16 = 0;
    for i in 0..MSG_DIGITS {
        d[i] = message[i];
        checksum += (MAX_STEP - message[i]) as u16;
    }
    d[MSG_DIGITS] = (checksum >> 8) as u8;
    d[MSG_DIGITS + 1] = (checksum & 0xff) as u8;
    d
}

/// Root of a public key: SHA256 of all chain ends.
pub fn root(public_key: &[Element; CHAINS]) -> [u8; 32] {
    let parts: [&[u8]; CHAINS] = core::array::from_fn(|i| &public_key[i][..]);
    hashv(&parts).to_bytes()
}

/// Recover the root a signature commits to for `message`. The caller checks it
/// against the vault address; a wrong signature yields an unrelated root.
pub fn recover_root(signature: &[u8], message: &[u8; 32]) -> Option<[u8; 32]> {
    if signature.len() != SIGNATURE_LEN {
        return None;
    }
    let d = digits(message);
    let mut pk = [[0u8; N]; CHAINS];
    for i in 0..CHAINS {
        let mut s = [0u8; N];
        s.copy_from_slice(&signature[i * N..(i + 1) * N]);
        pk[i] = chain(&s, i as u8, d[i], MAX_STEP);
    }
    Some(root(&pk))
}

/// Derive the one-time private key from a 32-byte seed.
pub fn private_key(seed: &[u8; 32]) -> [Element; CHAINS] {
    core::array::from_fn(|i| truncate(&hashv(&[b"quantities-wots-sk", seed, &[i as u8]]).to_bytes()))
}

pub fn public_key(sk: &[Element; CHAINS]) -> [Element; CHAINS] {
    core::array::from_fn(|i| chain(&sk[i], i as u8, 0, MAX_STEP))
}

pub fn sign(sk: &[Element; CHAINS], message: &[u8; 32]) -> [u8; SIGNATURE_LEN] {
    let d = digits(message);
    let mut out = [0u8; SIGNATURE_LEN];
    for i in 0..CHAINS {
        out[i * N..(i + 1) * N].copy_from_slice(&chain(&sk[i], i as u8, 0, d[i]));
    }
    out
}
