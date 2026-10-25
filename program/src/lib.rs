//! Quantities — quantum-resistant SOL vaults.
//!
//! A vault is a system-owned PDA derived from the root of a Winternitz one-time
//! public key: `["quantities", root, bump]`. Anyone can deposit with a plain
//! transfer. Funds move out only with a WOTS signature over the exact
//! destinations, and every spend drains the vault, because a one-time key must
//! never sign twice.
//!
//! Instructions (first byte):
//! - `0` Split: `[0, bump, amount: u64 LE, signature: 840 bytes]`
//!   accounts: vault (w), destination (w), refund (w), system program.
//!   Sends `amount` to destination and everything left to refund
//!   (normally the owner's next vault).
//! - `1` Close: `[1, bump, signature: 840 bytes]`
//!   accounts: vault (w), destination (w), system program.
//!   Sends the whole balance to destination.

pub mod wots;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    hash::hashv,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction, system_program,
};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub const VAULT_SEED: &[u8] = b"quantities";
pub const SPLIT_DOMAIN: &[u8] = b"quantities:split:v1";
pub const CLOSE_DOMAIN: &[u8] = b"quantities:close:v1";

#[repr(u32)]
pub enum QuantitiesError {
    BadInstruction = 1,
    BadVault = 2,
    BadSignature = 3,
    InsufficientFunds = 4,
    SelfTransfer = 5,
}

impl From<QuantitiesError> for ProgramError {
    fn from(e: QuantitiesError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

pub fn split_message(vault: &Pubkey, amount: u64, destination: &Pubkey, refund: &Pubkey) -> [u8; 32] {
    hashv(&[
        SPLIT_DOMAIN,
        vault.as_ref(),
        &amount.to_le_bytes(),
        destination.as_ref(),
        refund.as_ref(),
    ])
    .to_bytes()
}

pub fn close_message(vault: &Pubkey, destination: &Pubkey) -> [u8; 32] {
    hashv(&[CLOSE_DOMAIN, vault.as_ref(), destination.as_ref()]).to_bytes()
}

pub fn find_vault(root: &[u8; 32], program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[VAULT_SEED, root], program_id)
}

/// Check the signature recovers the root this vault was derived from.
fn verify(
    program_id: &Pubkey,
    vault: &AccountInfo,
    bump: u8,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    let root = wots::recover_root(signature, message).ok_or(QuantitiesError::BadInstruction)?;
    let expected = Pubkey::create_program_address(&[VAULT_SEED, &root, &[bump]], program_id)
        .map_err(|_| QuantitiesError::BadSignature)?;
    if expected != *vault.key {
        msg!("signature does not match vault");
        return Err(QuantitiesError::BadSignature.into());
    }
    Ok(root)
}

fn transfer<'a>(
    vault: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    lamports: u64,
    root: &[u8; 32],
    bump: u8,
) -> ProgramResult {
    if lamports == 0 {
        return Ok(());
    }
    invoke_signed(
        &system_instruction::transfer(vault.key, to.key, lamports),
        &[vault.clone(), to.clone(), system.clone()],
        &[&[VAULT_SEED, root, &[bump]]],
    )
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (&tag, rest) = data.split_first().ok_or(QuantitiesError::BadInstruction)?;
    let (&bump, rest) = rest.split_first().ok_or(QuantitiesError::BadInstruction)?;
    let iter = &mut accounts.iter();
    let vault = next_account_info(iter)?;
    let destination = next_account_info(iter)?;
    if destination.key == vault.key {
        return Err(QuantitiesError::SelfTransfer.into());
    }

    match tag {
        0 => {
            if rest.len() != 8 + wots::SIGNATURE_LEN {
                return Err(QuantitiesError::BadInstruction.into());
            }
            let amount = u64::from_le_bytes(rest[..8].try_into().unwrap());
            let refund = next_account_info(iter)?;
            let system = next_account_info(iter)?;
            if refund.key == vault.key {
                return Err(QuantitiesError::SelfTransfer.into());
            }
            if !system_program::check_id(system.key) {
                return Err(ProgramError::IncorrectProgramId);
            }
            let message = split_message(vault.key, amount, destination.key, refund.key);
            let root = verify(program_id, vault, bump, &rest[8..], &message)?;

            let balance = vault.lamports();
            if amount > balance {
                return Err(QuantitiesError::InsufficientFunds.into());
            }
            transfer(vault, destination, system, amount, &root, bump)?;
            transfer(vault, refund, system, balance - amount, &root, bump)?;
            msg!("split: {} to destination, {} to refund", amount, balance - amount);
        }
        1 => {
            if rest.len() != wots::SIGNATURE_LEN {
                return Err(QuantitiesError::BadInstruction.into());
            }
            let system = next_account_info(iter)?;
            if !system_program::check_id(system.key) {
                return Err(ProgramError::IncorrectProgramId);
            }
            let message = close_message(vault.key, destination.key);
            let root = verify(program_id, vault, bump, rest, &message)?;
            let balance = vault.lamports();
            transfer(vault, destination, system, balance, &root, bump)?;
            msg!("close: {} to destination", balance);
        }
        _ => return Err(QuantitiesError::BadInstruction.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn sign_and_recover() {
        let sk = wots::private_key(&seed(7));
        let pk = wots::public_key(&sk);
        let root = wots::root(&pk);
        let msg = hashv(&[b"hello"]).to_bytes();
        let sig = wots::sign(&sk, &msg);
        assert_eq!(wots::recover_root(&sig, &msg), Some(root));
    }

    #[test]
    fn wrong_message_fails() {
        let sk = wots::private_key(&seed(7));
        let root = wots::root(&wots::public_key(&sk));
        let sig = wots::sign(&sk, &hashv(&[b"a"]).to_bytes());
        assert_ne!(wots::recover_root(&sig, &hashv(&[b"b"]).to_bytes()), Some(root));
    }

    #[test]
    fn checksum_blocks_forward_forgery() {
        // Advancing one message chain raises that digit, so the checksum must
        // fall, which would require reversing a hash. Check the checksum moves.
        let mut m = [0u8; 32];
        let d0 = wots::digits(&m);
        m[0] = 1;
        let d1 = wots::digits(&m);
        let c0 = u16::from_be_bytes([d0[28], d0[29]]);
        let c1 = u16::from_be_bytes([d1[28], d1[29]]);
        assert_eq!(c0, 28 * 255);
        assert_eq!(c1, c0 - 1);
    }

    #[test]
    fn sizes_fit_one_transaction() {
        assert_eq!(wots::SIGNATURE_LEN, 840);
        // split instruction data: tag + bump + amount + signature
        assert!(1 + 1 + 8 + wots::SIGNATURE_LEN < 900);
    }

    /// Fixed vectors shared with the TypeScript SDK test.
    #[test]
    fn cross_language_vectors() {
        let sk = wots::private_key(&seed(1));
        let root = wots::root(&wots::public_key(&sk));
        let program = Pubkey::new_from_array([9u8; 32]);
        let (vault, bump) = find_vault(&root, &program);
        let dest = Pubkey::new_from_array([2u8; 32]);
        let refund = Pubkey::new_from_array([3u8; 32]);
        let msg = split_message(&vault, 1_000_000, &dest, &refund);
        let sig = wots::sign(&sk, &msg);
        let sig_hash = hashv(&[&sig]).to_bytes();
        println!("ROOT={}", hex::encode(root));
        println!("VAULT={} BUMP={}", vault, bump);
        println!("MSG={}", hex::encode(msg));
        println!("SIGHASH={}", hex::encode(sig_hash));
        assert_eq!(wots::recover_root(&sig, &msg), Some(root));
    }
}
