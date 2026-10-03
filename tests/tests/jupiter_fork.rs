//! Jupiter v6 mainnet-fork tests: real routes and real mainnet state, run through the router in LiteSVM.
//!
//!   node live/jupiter-snapshot.mjs      (needs SOLANA_MAINNET_RPC_URL in .env)
//!   cargo test --test jupiter_fork -- --nocapture
//!
//! Each snapshot holds a real Jupiter swap instruction for a fresh test user plus every account it touches, taken
//! from mainnet at one slot: the Jupiter and DEX programs' code, pool state, mints and lookup tables. The test loads
//! them into LiteSVM at that slot, deploys the router (venues are permissionless; Jupiter is just the one used), and sends
//! `execute` wrapping Jupiter's instruction in a v0 transaction with Jupiter's lookup tables, exactly as the app
//! will. Checks: output >= Jupiter's minimum, the exact fee on the SOL side, the user's binding and authority
//! checks pass on a real route, transaction size and compute fit Solana's limits.
use alphabros_router::{self as router, Config};
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use base64::Engine;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
use solana_program_option::COption;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use spl_token_interface::state::{Account as TokenAccount, AccountState};
use std::str::FromStr;

const ROUTER_SO: &str = "../target/deploy/alphabros_router.so";
const SNAPSHOTS: &str = "../live/snapshots";
const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const NATIVE_LOADER: &str = "NativeLoader1111111111111111111111111111111";
const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
const MIN_FEE: u64 = 2_500_000;
const MAX_MIN_FEE: u64 = 50_000_000;
const TRADER_BPS: u16 = 15;
const MAX_TX_BYTES: usize = 1232;

fn pk(s: &str) -> Pubkey {
    Pubkey::from_str(s).unwrap()
}
fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}
fn pda(seeds: &[&[u8]], p: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(seeds, p).0
}
fn pct(a: u64, bps: u64) -> u64 {
    ((a as u128 * bps as u128).div_ceil(10_000)) as u64
}

struct Snap(serde_json::Value);

impl Snap {
    fn load(name: &str) -> Option<Snap> {
        let p = format!("{SNAPSHOTS}/{name}.json");
        let text = std::fs::read_to_string(&p).ok()?;
        Some(Snap(serde_json::from_str(&text).unwrap()))
    }
    fn s(&self, k: &str) -> &str {
        self.0[k].as_str().unwrap()
    }
}

fn token_account(svm: &mut LiteSVM, address: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64, token_program: Pubkey, native: bool) {
    let rent = svm.minimum_balance_for_rent_exemption(TokenAccount::LEN);
    let mut data = vec![0u8; TokenAccount::LEN];
    TokenAccount {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: AccountState::Initialized,
        is_native: if native { COption::Some(rent) } else { COption::None },
        delegated_amount: 0,
        close_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    let lamports = if native { rent + amount } else { rent };
    svm.set_account(address, Account { lamports, data, owner: token_program, executable: false, rent_epoch: 0 }).unwrap();
}

fn token_amount(svm: &LiteSVM, a: &Pubkey) -> u64 {
    TokenAccount::unpack(&svm.get_account(a).unwrap().data[..TokenAccount::LEN]).unwrap().amount
}

/// What a successful run measured.
struct Outcome {
    report: String,
    received: u64,
    quoted: u64,
}

/// Changes Jupiter's instruction (accounts, data) before it is wrapped, to test what the router refuses.
type Tamper = fn(&mut LiteSVM, &mut Vec<AccountMeta>, &mut Vec<u8>);

/// Runs one snapshot through the router; returns a one-line report.
fn run(name: &str) -> Option<String> {
    run_with(name, |_, _, _| {}).map(|r| r.unwrap_or_else(|e| panic!("{name}: execute failed: {e}")).report)
}

/// Runs one snapshot with Jupiter's instruction changed by `tamper`; `Err` carries the transaction error.
fn run_with(name: &str, tamper: Tamper) -> Option<Result<Outcome, String>> {
    let snap = match Snap::load(name) {
        Some(s) => s,
        None => {
            println!("SKIP {name}: no snapshot (run node live/jupiter-snapshot.mjs)");
            return None;
        }
    };
    let mut svm = LiteSVM::new();

    // 1. Mainnet state at the snapshot slot. Data accounts first (program-data before the programs that point at it),
    //    native programs and sysvars are LiteSVM's own.
    let slot = snap.0["slot"].as_u64().unwrap();
    svm.warp_to_slot(slot + 1);
    let mut clock: Clock = svm.get_sysvar();
    clock.unix_timestamp = snap.0["unixTime"].as_i64().unwrap();
    svm.set_sysvar(&clock);
    let accounts = snap.0["accounts"].as_object().unwrap();
    for pass in [false, true] {
        for (key, a) in accounts {
            let executable = a["executable"].as_bool().unwrap();
            let owner = a["owner"].as_str().unwrap();
            if executable != pass || owner == NATIVE_LOADER || owner.starts_with("Sysvar1") {
                continue;
            }
            let acc = Account {
                lamports: a["lamports"].as_u64().unwrap(),
                data: b64(a["data"].as_str().unwrap()),
                owner: pk(owner),
                executable,
                rent_epoch: 0,
            };
            if let Err(e) = svm.set_account(pk(key), acc) {
                println!("  note: could not load {key}: {e:?}");
            }
        }
    }

    // 2. The router.
    let admin = Keypair::new();
    let trader = Keypair::new();
    let protocol_wallet = Pubkey::new_unique();
    let trader_wallet = Pubkey::new_unique();
    svm.add_program_from_file(router::ID, ROUTER_SO).expect("build the router first");
    set_upgrade_authority(&mut svm, &router::ID, &admin.pubkey());
    for k in [&admin, &trader] {
        svm.airdrop(&k.pubkey(), 10_000_000_000).unwrap();
    }
    let config = pda(&[router::CONFIG_SEED], &router::ID);
    let vault = pda(&[router::VAULT_SEED], &router::ID);
    let credit = |w: &Pubkey| pda(&[router::CREDIT_SEED, w.as_ref()], &router::ID);
    let programdata = Pubkey::find_program_address(&[router::ID.as_ref()], &solana_sdk_ids::bpf_loader_upgradeable::ID).0;
    let init = Instruction {
        program_id: router::ID,
        accounts: router::accounts::Initialize {
            payer: admin.pubkey(),
            config,
            vault,
            protocol_credit: credit(&protocol_wallet),
            program: router::ID,
            program_data: programdata,
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None),
        data: router::instruction::Initialize {
            owner: admin.pubkey(),
            protocol_wallet,
            min_fee: MIN_FEE,
            max_min_fee: MAX_MIN_FEE,
        }
        .data(),
    };
    send_legacy(&mut svm, &[init], &admin).expect("initialize");
    let salt = [7u8; 32];
    let router_key = pda(&[router::ROUTER_SEED, trader.pubkey().as_ref(), &salt], &router::ID);
    let create = Instruction {
        program_id: router::ID,
        accounts: router::accounts::CreateRouter {
            owner: trader.pubkey(),
            router: router_key,
            vault,
            fee_credit: credit(&trader_wallet),
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None),
        data: router::instruction::CreateRouter { fee_wallet: trader_wallet, trader_fee_bps: TRADER_BPS, salt }.data(),
    };
    send_legacy(&mut svm, &[create], &trader).expect("create_router");

    // 3. The user Jupiter built the route for, with the input in their token account.
    let seed: [u8; 32] = b64(snap.s("userSeed")).try_into().unwrap();
    let user = Keypair::new_from_array(seed);
    assert_eq!(user.pubkey(), pk(snap.s("user")));
    svm.airdrop(&user.pubkey(), 5_000_000_000).unwrap();
    let (input, output) = (pk(snap.s("input")), pk(snap.s("output")));
    let (user_in, user_out) = (pk(snap.s("userIn")), pk(snap.s("userOut")));
    let amount: u64 = snap.s("amount").parse().unwrap();
    let wsol = router::WSOL_MINT;
    token_account(&mut svm, user_in, input, user.pubkey(), amount, pk(snap.s("inputTokenProgram")), input == wsol);
    token_account(&mut svm, user_out, output, user.pubkey(), 0, pk(snap.s("outputTokenProgram")), output == wsol);

    // 4. execute wrapping Jupiter's real instruction.
    let ix = &snap.0["swapIx"];
    let mut jup_metas: Vec<AccountMeta> = ix["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| AccountMeta {
            pubkey: pk(a["pubkey"].as_str().unwrap()),
            is_signer: a["isSigner"].as_bool().unwrap(),
            is_writable: a["isWritable"].as_bool().unwrap(),
        })
        .collect();
    let mut swap_data = b64(ix["data"].as_str().unwrap());
    tamper(&mut svm, &mut jup_metas, &mut swap_data);
    let min_out: u64 = snap.0["quote"]["otherAmountThreshold"].as_str().unwrap().parse().unwrap();
    let mut metas = router::accounts::Execute {
        user: user.pubkey(),
        config,
        router: router_key,
        vault,
        protocol_credit: credit(&protocol_wallet),
        trader_credit: credit(&trader_wallet),
        input_account: user_in,
        output_account: user_out,
        swap_program: pk(JUPITER),
        system_program: solana_system_interface::program::ID,
    }
    .to_account_metas(None);
    metas.extend(jup_metas);
    let execute = Instruction {
        program_id: router::ID,
        accounts: metas,
        data: router::instruction::Execute {
            min_out,
            max_fee: MAX_MIN_FEE,
            max_input: amount,
            deadline: i64::MAX,
            swap_data,
        }
        .data(),
    };
    let mut cu = vec![2u8];
    cu.extend_from_slice(&1_400_000u32.to_le_bytes());
    let budget = Instruction { program_id: pk(COMPUTE_BUDGET), accounts: vec![], data: cu };

    // v0 transaction with Jupiter's lookup tables (header 56 bytes, then 32-byte addresses).
    let alts: Vec<AddressLookupTableAccount> = snap.0["alts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            let key = pk(k.as_str().unwrap());
            let data = svm.get_account(&key).expect("lookup table loaded").data;
            let addresses = data[56..].chunks(32).map(|c| Pubkey::try_from(c).unwrap()).collect();
            AddressLookupTableAccount { key, addresses }
        })
        .collect();
    let msg = v0::Message::try_compile(&user.pubkey(), &[budget, execute], &alts, svm.latest_blockhash()).unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&user]).unwrap();
    let tx_bytes = bincode::serialize(&tx).unwrap().len();

    let cfg0 = read_config(&svm, &config).total_credited;
    let lamports0 = svm.get_account(&user.pubkey()).unwrap().lamports;
    let res = svm.send_transaction(tx);
    let meta = match res {
        Ok(m) => m,
        Err(f) => {
            println!("FAIL {name}: {:?}", f.err);
            for l in f.meta.logs.iter().rev().take(25).rev() {
                println!("    {l}");
            }
            return Some(Err(format!("{:?}", f.err)));
        }
    };

    // 5. Checks.
    let spent = amount - token_amount(&svm, &user_in);
    let received = token_amount(&svm, &user_out);
    let fee = read_config(&svm, &config).total_credited - cfg0;
    let sol_side = if input == wsol { spent } else { received };
    let expected = pct(sol_side, 25 + TRADER_BPS as u64).max(MIN_FEE);
    let user_sol = lamports0 - svm.get_account(&user.pubkey()).unwrap().lamports;
    assert!(received >= min_out, "{name}: received {received} < Jupiter's minimum {min_out}");
    assert_eq!(spent, amount, "{name}: the whole input was spent");
    assert_eq!(fee, expected, "{name}: exact fee");
    assert!(tx_bytes <= MAX_TX_BYTES, "{name}: transaction {tx_bytes} bytes > {MAX_TX_BYTES}");
    let quoted: u64 = snap.0["quote"]["outAmount"].as_str().unwrap().parse().unwrap();
    let route = snap.0["quote"]["route"].as_array().unwrap().iter().map(|r| r.as_str().unwrap()).collect::<Vec<_>>().join(" | ");
    let report = format!(
        "PASS {name}: {route}\n     spent {spent}, received {received} (Jupiter min {min_out}, quoted {}), fee {fee} lamports (= {:.4}% of the SOL side), \
         user SOL debit {user_sol} (fee + 5000 network fee), {} CU, {tx_bytes} of {MAX_TX_BYTES} bytes",
        snap.0["quote"]["outAmount"].as_str().unwrap(),
        fee as f64 * 100.0 / sol_side as f64,
        meta.compute_units_consumed
    );
    Some(Ok(Outcome { report, received, quoted }))
}

fn read_config(svm: &LiteSVM, config: &Pubkey) -> Config {
    Config::try_deserialize(&mut &svm.get_account(config).unwrap().data[..]).unwrap()
}

fn send_legacy(svm: &mut LiteSVM, ixs: &[Instruction], payer: &Keypair) -> Result<(), String> {
    let msg = solana_message::Message::new(ixs, Some(&payer.pubkey()));
    let tx = solana_transaction::Transaction::new(&[payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{:?} {:?}", e.err, e.meta.logs))
}

fn set_upgrade_authority(svm: &mut LiteSVM, program: &Pubkey, authority: &Pubkey) {
    let pd = Pubkey::find_program_address(&[program.as_ref()], &solana_sdk_ids::bpf_loader_upgradeable::ID).0;
    let mut acc = svm.get_account(&pd).unwrap();
    acc.data[12] = 1;
    acc.data[13..45].copy_from_slice(authority.as_ref());
    svm.set_account(pd, acc).unwrap();
}

#[test]
fn jupiter_sol_to_usdc() {
    if let Some(r) = run("sol_to_usdc") {
        println!("{r}");
    }
}

#[test]
fn jupiter_usdc_to_sol() {
    if let Some(r) = run("usdc_to_sol") {
        println!("{r}");
    }
}

#[test]
fn jupiter_sol_to_jup_multihop() {
    if let Some(r) = run("sol_to_jup_multihop") {
        println!("{r}");
    }
}

/// The first live snapshot: a proprietary market maker (Kipseli) route, kept as a fixed case.
#[test]
fn jupiter_usdc_to_sol_propamm() {
    if let Some(r) = run("usdc_to_sol_propamm") {
        println!("{r}");
    }
}

/// A genuine two-hop route: SOL -> USDC -> BONK, both legs on Raydium CLMM, with two lookup tables.
#[test]
fn jupiter_sol_to_bonk_two_hops() {
    if let Some(r) = run("sol_to_bonk_two_hops") {
        println!("{r}");
    }
}

/// Jupiter's platform fee, real route: `sol_to_usdc` is a `route` instruction, whose optional platform-fee account is
/// account 6. Pointing it at a fee collector's token account is refused before Jupiter runs.
#[test]
fn jupiter_platform_fee_account_refused() {
    let tamper: Tamper = |svm, metas, _| {
        let collector = Pubkey::new_unique();
        let usdc = pk("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        token_account(svm, collector, usdc, Pubkey::new_unique(), 0, spl_token_interface::ID, false);
        assert_eq!(metas[6].pubkey, pk(JUPITER), "fee slot is empty in the real route");
        metas[6] = AccountMeta::new(collector, false);
    };
    if let Some(r) = run_with("sol_to_usdc", tamper) {
        let want = format!("Custom({})", 6000 + router::RouterError::JupiterPlatformFee as u32);
        let err = r.err().expect("a route paying a platform fee must be refused");
        assert!(err.contains(&want), "refused with {err}, wanted {want}");
        println!("REFUSED sol_to_usdc with a platform-fee account: {err} (JupiterPlatformFee)");
    }
}

/// Jupiter's platform fee, real route: the fee byte set to 1% but no fee account. With nowhere to send a fee, Jupiter
/// takes none: the user receives exactly the quote, or Jupiter refuses the route (it does: InvalidTokenAccount, 6025).
/// Either way no fee leaves.
#[test]
fn jupiter_fee_bps_without_fee_account_takes_nothing() {
    let tamper: Tamper = |_, _, data| *data.last_mut().unwrap() = 100;
    if let Some(r) = run_with("sol_to_usdc", tamper) {
        match r {
            Ok(o) => {
                assert_eq!(o.received, o.quoted, "no platform fee taken");
                println!("{}\n     (platform_fee_bps = 100 with no fee account: received exactly the quote)", o.report);
            }
            Err(e) => println!("Jupiter refused platform_fee_bps = 100 with no fee account: {e}"),
        }
    }
}
