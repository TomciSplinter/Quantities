//! Runs the compiled program in LiteSVM: deposit, split, close, and a forgery attempt.
//! Build first: `cd ../program && cargo build-sbf`, then `cargo run --release`.

use litesvm::LiteSVM;
use quantities::{close_message, find_vault, split_message, wots};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

struct Vault {
    sk: [wots::Element; wots::CHAINS],
    address: Pubkey,
    bump: u8,
}

fn vault(seed: u8, program: &Pubkey) -> Vault {
    let sk = wots::private_key(&[seed; 32]);
    let root = wots::root(&wots::public_key(&sk));
    let (address, bump) = find_vault(&root, program);
    Vault { sk, address, bump }
}

fn split_ix(program: &Pubkey, v: &Vault, amount: u64, dest: &Pubkey, refund: &Pubkey, sig: Option<Vec<u8>>) -> Instruction {
    let sig = sig.unwrap_or_else(|| wots::sign(&v.sk, &split_message(&v.address, amount, dest, refund)).to_vec());
    let mut data = vec![0u8, v.bump];
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&sig);
    Instruction::new_with_bytes(*program, &data, vec![
        AccountMeta::new(v.address, false),
        AccountMeta::new(*dest, false),
        AccountMeta::new(*refund, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ])
}

fn close_ix(program: &Pubkey, v: &Vault, dest: &Pubkey) -> Instruction {
    let sig = wots::sign(&v.sk, &close_message(&v.address, dest));
    let mut data = vec![1u8, v.bump];
    data.extend_from_slice(&sig);
    Instruction::new_with_bytes(*program, &data, vec![
        AccountMeta::new(v.address, false),
        AccountMeta::new(*dest, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ])
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction) -> Result<(u64, usize), String> {
    let tx = Transaction::new_signed_with_payer(
        &[ComputeBudgetInstruction::set_compute_unit_limit(1_400_000), ix],
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    let size = bincode_len(&tx);
    svm.send_transaction(tx)
        .map(|m| (m.compute_units_consumed, size))
        .map_err(|e| format!("{:?}\n{}", e.err, e.meta.logs.join("\n")))
}

fn bincode_len(tx: &Transaction) -> usize {
    // Wire size: signatures + message, both short-vec encoded.
    1 + 64 * tx.signatures.len() + tx.message_data().len()
}

fn main() {
    let program = Pubkey::new_unique();
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program, "../program/target/deploy/quantities.so").expect("build the program first");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let v0 = vault(1, &program);
    let v1 = vault(2, &program);
    let alice = Pubkey::new_unique();
    let bal = |svm: &LiteSVM, k: &Pubkey| svm.get_balance(k).unwrap_or(0);

    // Deposit is a plain transfer.
    svm.airdrop(&v0.address, 2_000_000_000).unwrap();

    // Forgery: signature for a different amount must fail.
    let forged = wots::sign(&v0.sk, &split_message(&v0.address, 1, &alice, &v1.address)).to_vec();
    let r = send(&mut svm, &payer, split_ix(&program, &v0, 1_500_000_000, &alice, &v1.address, Some(forged)));
    assert!(r.is_err(), "forged split must fail");
    println!("forged signature rejected ✓");

    // Redirect: valid signature but a different destination must fail.
    let good = wots::sign(&v0.sk, &split_message(&v0.address, 500_000_000, &alice, &v1.address)).to_vec();
    let mallory = Pubkey::new_unique();
    let r = send(&mut svm, &payer, split_ix(&program, &v0, 500_000_000, &mallory, &v1.address, Some(good)));
    assert!(r.is_err(), "redirected split must fail");
    println!("redirected destination rejected ✓");

    // Real split.
    let (cu, size) = send(&mut svm, &payer, split_ix(&program, &v0, 500_000_000, &alice, &v1.address, None)).unwrap();
    assert_eq!(bal(&svm, &v0.address), 0);
    assert_eq!(bal(&svm, &alice), 500_000_000);
    assert_eq!(bal(&svm, &v1.address), 1_500_000_000);
    println!("split ✓  {cu} CU, {size} bytes");

    // Close the next vault.
    svm.expire_blockhash();
    let bob = Pubkey::new_unique();
    let (cu, size) = send(&mut svm, &payer, close_ix(&program, &v1, &bob)).unwrap();
    assert_eq!(bal(&svm, &v1.address), 0);
    assert_eq!(bal(&svm, &bob), 1_500_000_000);
    println!("close ✓  {cu} CU, {size} bytes");

    // Worst-case compute: search for a message with many low digits (lots of hashing).
    let mut worst = 0u64;
    for i in 0..40u8 {
        let v = vault(100 + i, &program);
        svm.airdrop(&v.address, 1_000_000_000).unwrap();
        let dest = Pubkey::new_unique();
        let (cu, _) = send(&mut svm, &payer, close_ix(&program, &v, &dest)).unwrap();
        worst = worst.max(cu);
    }
    println!("max CU over 40 random closes: {worst}");
    println!("all integration checks passed");
}
