//! Alphabros router (Solana) — LiteSVM tests against the real compiled programs (target/deploy/*.so).
//!
//!   cargo-build-sbf (both programs)  then  cargo test -p alphabros-tests
//!
//! Every swap goes through `mock_swap`, a test venue that takes `amount_in` from the signer and pays `amount_out`
//! from its pool, so each test sets exact amounts. wSOL (So111…112) is the priced side. Venues are permissionless:
//! the router has never been told about `mock_swap`. Its `relay` instruction is a hostile venue that does whatever a
//! test asks with the user's signature.
use alphabros_router::{self as router, Config, Credit, Router, RouterError};
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_instruction::{error::InstructionError, Instruction};
use solana_message::Message;
use solana_program_option::COption;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::{Transaction, TransactionError};
use spl_token_interface::state::{Account as TokenAccount, AccountState, Mint, Multisig};

const ROUTER_SO: &str = "../target/deploy/alphabros_router.so";
const MOCK_SO: &str = "../target/deploy/mock_swap.so";
const SOL: u64 = 1_000_000_000;
const MIN_FEE: u64 = 2_500_000; // 0.0025 SOL
const MAX_MIN_FEE: u64 = 50_000_000; // 0.05 SOL
const TRADER_BPS: u16 = 15; // total 0.40%

fn wsol() -> Pubkey {
    router::WSOL_MINT
}
fn token_program() -> Pubkey {
    spl_token_interface::ID
}
fn pda(seeds: &[&[u8]], program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(seeds, program).0
}
fn config_pda() -> Pubkey {
    pda(&[router::CONFIG_SEED], &router::ID)
}
fn vault_pda() -> Pubkey {
    pda(&[router::VAULT_SEED], &router::ID)
}
fn credit_pda(wallet: &Pubkey) -> Pubkey {
    pda(&[router::CREDIT_SEED, wallet.as_ref()], &router::ID)
}
fn router_pda(owner: &Pubkey, salt: &[u8; 32]) -> Pubkey {
    pda(&[router::ROUTER_SEED, owner.as_ref(), salt], &router::ID)
}
fn pool_authority() -> Pubkey {
    pda(&[mock_swap::POOL_SEED], &mock_swap::ID)
}

/// The Anchor error code of `e` for instruction `ix_index`, if it is a custom program error.
fn custom_code(err: &TransactionError) -> Option<u32> {
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(*c),
        _ => None,
    }
}
fn code(e: RouterError) -> u32 {
    6000 + e as u32
}

struct Env {
    svm: LiteSVM,
    admin: Keypair,
    protocol_wallet: Pubkey,
    trader: Keypair,
    trader_wallet: Pubkey,
    user: Keypair,
    meme: Pubkey,
    router: Pubkey,
    pool_wsol: Pubkey,
    pool_meme: Pubkey,
    user_wsol: Pubkey,
    user_meme: Pubkey,
}

impl Env {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let admin = Keypair::new();
        svm.add_program_from_file(router::ID, ROUTER_SO).expect("build the router first: cargo-build-sbf");
        svm.add_program_from_file(mock_swap::ID, MOCK_SO).expect("build mock_swap first: cargo-build-sbf");
        set_upgrade_authority(&mut svm, &router::ID, Some(admin.pubkey()));

        let mut env = Env {
            svm,
            admin,
            protocol_wallet: Pubkey::new_unique(),
            trader: Keypair::new(),
            trader_wallet: Pubkey::new_unique(),
            user: Keypair::new(),
            meme: Pubkey::new_unique(),
            router: Pubkey::default(),
            pool_wsol: Pubkey::new_unique(),
            pool_meme: Pubkey::new_unique(),
            user_wsol: Pubkey::new_unique(),
            user_meme: Pubkey::new_unique(),
        };
        for kp in [&env.admin, &env.trader, &env.user] {
            env.svm.airdrop(&kp.pubkey(), 1_000 * SOL).unwrap();
        }
        env.mint(wsol(), 9);
        let meme = env.meme;
        env.mint(meme, 6);
        let pa = pool_authority();
        env.token_account(env.pool_wsol, wsol(), pa, 10_000 * SOL);
        env.token_account(env.pool_meme, meme, pa, 1_000_000_000_000);
        let user = env.user.pubkey();
        env.token_account(env.user_wsol, wsol(), user, 100 * SOL);
        env.token_account(env.user_meme, meme, user, 0);

        env.initialize(MIN_FEE, MAX_MIN_FEE).unwrap();
        env.router = env.create_router(&env.trader.insecure_clone(), env.trader_wallet, TRADER_BPS, [1; 32]).unwrap();
        env
    }

    fn mint(&mut self, address: Pubkey, decimals: u8) {
        let mut data = vec![0u8; Mint::LEN];
        Mint { mint_authority: COption::None, supply: 0, decimals, is_initialized: true, freeze_authority: COption::None }
            .pack_into_slice(&mut data);
        let lamports = self.svm.minimum_balance_for_rent_exemption(Mint::LEN);
        self.svm.set_account(address, Account { lamports, data, owner: token_program(), executable: false, rent_epoch: 0 }).unwrap();
    }

    /// A token account for `mint` owned by `owner` holding `amount` (a wSOL account also carries the lamports).
    fn token_account(&mut self, address: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
        let rent = self.svm.minimum_balance_for_rent_exemption(TokenAccount::LEN);
        let native = mint == wsol();
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
        self.svm.set_account(address, Account { lamports, data, owner: token_program(), executable: false, rent_epoch: 0 }).unwrap();
    }

    /// A wSOL account owned by `owner` with `delegate` approved for its whole balance.
    fn delegated_wsol(&mut self, address: Pubkey, owner: Pubkey, delegate: Pubkey, amount: u64) {
        let rent = self.svm.minimum_balance_for_rent_exemption(TokenAccount::LEN);
        let mut data = vec![0u8; TokenAccount::LEN];
        TokenAccount {
            mint: wsol(),
            owner,
            amount,
            delegate: COption::Some(delegate),
            state: AccountState::Initialized,
            is_native: COption::Some(rent),
            delegated_amount: amount,
            close_authority: COption::None,
        }
        .pack_into_slice(&mut data);
        self.svm.set_account(address, Account { lamports: rent + amount, data, owner: token_program(), executable: false, rent_epoch: 0 }).unwrap();
    }

    fn balance(&self, token_account: &Pubkey) -> u64 {
        TokenAccount::unpack(&self.svm.get_account(token_account).unwrap().data).unwrap().amount
    }
    fn lamports(&self, a: &Pubkey) -> u64 {
        self.svm.get_account(a).map(|x| x.lamports).unwrap_or(0)
    }
    fn config(&self) -> Config {
        Config::try_deserialize(&mut &self.svm.get_account(&config_pda()).unwrap().data[..]).unwrap()
    }
    fn router_state(&self, r: &Pubkey) -> Router {
        Router::try_deserialize(&mut &self.svm.get_account(r).unwrap().data[..]).unwrap()
    }
    fn credit(&self, wallet: &Pubkey) -> u64 {
        match self.svm.get_account(&credit_pda(wallet)) {
            Some(a) if a.owner == router::ID => Credit::try_deserialize(&mut &a.data[..]).unwrap().amount,
            _ => 0,
        }
    }
    fn vault_rent(&self) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(0)
    }

    fn send(&mut self, ixs: &[Instruction], payer: &Keypair, signers: &[&Keypair]) -> Result<(), TransactionError> {
        self.svm.expire_blockhash();
        let msg = Message::new(ixs, Some(&payer.pubkey()));
        let mut all: Vec<&Keypair> = vec![payer];
        all.extend_from_slice(signers);
        let tx = Transaction::new(&all, msg, self.svm.latest_blockhash());
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
    }

    fn initialize(&mut self, min_fee: u64, max_min_fee: u64) -> Result<(), TransactionError> {
        let admin = self.admin.insecure_clone();
        self.initialize_as(&admin, min_fee, max_min_fee)
    }

    fn initialize_as(&mut self, payer: &Keypair, min_fee: u64, max_min_fee: u64) -> Result<(), TransactionError> {
        let ix = Instruction {
            program_id: router::ID,
            accounts: router::accounts::Initialize {
                payer: payer.pubkey(),
                config: config_pda(),
                vault: vault_pda(),
                protocol_credit: credit_pda(&self.protocol_wallet),
                program: router::ID,
                program_data: programdata_address(&router::ID),
                system_program: solana_system_interface::program::ID,
            }
            .to_account_metas(None),
            data: router::instruction::Initialize {
                owner: self.admin.pubkey(),
                protocol_wallet: self.protocol_wallet,
                min_fee,
                max_min_fee,
            }
            .data(),
        };
        self.send(&[ix], payer, &[])
    }

    fn create_router(&mut self, owner: &Keypair, fee_wallet: Pubkey, bps: u16, salt: [u8; 32]) -> Result<Pubkey, TransactionError> {
        let r = router_pda(&owner.pubkey(), &salt);
        let ix = Instruction {
            program_id: router::ID,
            accounts: router::accounts::CreateRouter {
                owner: owner.pubkey(),
                router: r,
                vault: vault_pda(),
                fee_credit: credit_pda(&fee_wallet),
                system_program: solana_system_interface::program::ID,
            }
            .to_account_metas(None),
            data: router::instruction::CreateRouter { fee_wallet, trader_fee_bps: bps, salt }.data(),
        };
        self.send(&[ix], owner, &[]).map(|_| r)
    }

    /// The mock venue's swap instruction: `amount_in` of `user_in` from `user`, `amount_out` into `user_out`.
    fn venue_ix(&self, user: &Pubkey, user_in: Pubkey, user_out: Pubkey, mint_in: Pubkey, mint_out: Pubkey, amount_in: u64, amount_out: u64) -> Instruction {
        let (pool_in, pool_out) = if mint_in == wsol() { (self.pool_wsol, self.pool_meme) } else { (self.pool_meme, self.pool_wsol) };
        Instruction {
            program_id: mock_swap::ID,
            accounts: mock_swap::accounts::Swap {
                user: *user,
                user_in,
                user_out,
                pool_in,
                pool_out,
                pool_authority: pool_authority(),
                mint_in,
                mint_out,
                token_program_in: token_program(),
                token_program_out: token_program(),
            }
            .to_account_metas(None),
            data: mock_swap::instruction::Swap { amount_in, amount_out }.data(),
        }
    }

    /// `execute` wrapping `venue`: the venue's accounts become `remaining_accounts`.
    fn execute_ix(&self, user: &Pubkey, router_key: Pubkey, input: Pubkey, output: Pubkey, venue: Instruction, min_out: u64, max_fee: u64, deadline: i64) -> Instruction {
        self.execute_ix_full(user, router_key, input, output, venue, min_out, max_fee, u64::MAX, deadline)
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_ix_full(&self, user: &Pubkey, router_key: Pubkey, input: Pubkey, output: Pubkey, venue: Instruction, min_out: u64, max_fee: u64, max_input: u64, deadline: i64) -> Instruction {
        let cfg = self.config();
        let fee_wallet = self.router_state(&router_key).fee_wallet;
        let mut accounts = router::accounts::Execute {
            user: *user,
            config: config_pda(),
            router: router_key,
            vault: vault_pda(),
            protocol_credit: credit_pda(&cfg.protocol_wallet),
            trader_credit: credit_pda(&fee_wallet),
            input_account: input,
            output_account: output,
            swap_program: venue.program_id,
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None);
        accounts.extend(venue.accounts.iter().cloned());
        Instruction {
            program_id: router::ID,
            accounts,
            data: router::instruction::Execute { min_out, max_fee, max_input, deadline, swap_data: venue.data }.data(),
        }
    }

    /// The user buys meme with `sol_in` wSOL (venue pays `meme_out`), signing `max_fee`.
    fn buy(&mut self, sol_in: u64, meme_out: u64, min_out: u64, max_fee: u64) -> Result<(), TransactionError> {
        let u = self.user.pubkey();
        let venue = self.venue_ix(&u, self.user_wsol, self.user_meme, wsol(), self.meme, sol_in, meme_out);
        let ix = self.execute_ix_full(&u, self.router, self.user_wsol, self.user_meme, venue, min_out, max_fee, sol_in, i64::MAX);
        let user = self.user.insecure_clone();
        self.send(&[ix], &user, &[])
    }

    /// The user sells `meme_in` meme for `sol_out` wSOL, signing `max_fee`.
    fn sell(&mut self, meme_in: u64, sol_out: u64, min_out: u64, max_fee: u64) -> Result<(), TransactionError> {
        let u = self.user.pubkey();
        let venue = self.venue_ix(&u, self.user_meme, self.user_wsol, self.meme, wsol(), meme_in, sol_out);
        let ix = self.execute_ix_full(&u, self.router, self.user_meme, self.user_wsol, venue, min_out, max_fee, meme_in, i64::MAX);
        let user = self.user.insecure_clone();
        self.send(&[ix], &user, &[])
    }

    fn collect(&mut self, wallet: Pubkey, caller: &Keypair) -> Result<(), TransactionError> {
        let ix = Instruction {
            program_id: router::ID,
            accounts: router::accounts::Collect {
                config: config_pda(),
                vault: vault_pda(),
                credit: credit_pda(&wallet),
                wallet,
                system_program: solana_system_interface::program::ID,
            }
            .to_account_metas(None),
            data: router::instruction::Collect {}.data(),
        };
        self.send(&[ix], caller, &[])
    }

    fn assert_solvent(&self) {
        let cfg = self.config();
        assert_eq!(self.lamports(&vault_pda()) - self.vault_rent(), cfg.total_credited, "vault holds exactly the credits");
        assert_eq!(self.credit(&self.protocol_wallet) + self.credit(&self.trader_wallet), cfg.total_credited, "credits add up");
    }
}

fn programdata_address(program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[program.as_ref()], &solana_sdk_ids::bpf_loader_upgradeable::ID).0
}

/// LiteSVM deploys with no upgrade authority; tests set one so `initialize`'s authority check is real.
/// ProgramData metadata (bincode): u32 tag 3, u64 slot, Option<Pubkey> (1-byte tag + 32 bytes) = 45 bytes.
fn set_upgrade_authority(svm: &mut LiteSVM, program: &Pubkey, authority: Option<Pubkey>) {
    let pd = programdata_address(program);
    let mut acc = svm.get_account(&pd).unwrap();
    assert_eq!(u32::from_le_bytes(acc.data[0..4].try_into().unwrap()), 3, "not a ProgramData account");
    match authority {
        Some(a) => {
            acc.data[12] = 1;
            acc.data[13..45].copy_from_slice(a.as_ref());
        }
        None => {
            acc.data[12] = 0;
            acc.data[13..45].fill(0);
        }
    }
    svm.set_account(pd, acc).unwrap();
}

fn pct(amount: u64, bps: u64) -> u64 {
    ((amount as u128 * bps as u128 + 9_999) / 10_000) as u64
}

// ================================================================================ setup and admin

#[test]
fn initialize_only_by_upgrade_authority_and_once() {
    let mut env = Env::new();
    let cfg = env.config();
    assert_eq!(cfg.owner, env.admin.pubkey());
    assert_eq!(cfg.min_fee, MIN_FEE);
    assert_eq!(cfg.max_min_fee, MAX_MIN_FEE);
    assert_eq!(env.lamports(&vault_pda()), env.vault_rent(), "vault funded to rent exemption only");
    // A second initialize is impossible (the config already exists).
    assert!(env.initialize(MIN_FEE, MAX_MIN_FEE).is_err());
}

#[test]
fn initialize_refuses_strangers_and_bad_settings() {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(router::ID, ROUTER_SO).unwrap();
    let admin = Keypair::new();
    set_upgrade_authority(&mut svm, &router::ID, Some(admin.pubkey()));
    let mut env = Env { svm, ..Env::bare(admin) };
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), SOL).unwrap();
    let admin_key = env.admin.pubkey();
    env.svm.airdrop(&admin_key, SOL).unwrap();
    let e = env.initialize_as(&stranger, MIN_FEE, MAX_MIN_FEE).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::NotUpgradeAuthority)));
    let e = env.initialize(MAX_MIN_FEE + 1, MAX_MIN_FEE).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::AboveCap)));
}

impl Env {
    /// An environment with only the admin set (for initialize tests).
    fn bare(admin: Keypair) -> Self {
        Env {
            svm: LiteSVM::new(),
            admin,
            protocol_wallet: Pubkey::new_unique(),
            trader: Keypair::new(),
            trader_wallet: Pubkey::new_unique(),
            user: Keypair::new(),
            meme: Pubkey::new_unique(),
            router: Pubkey::default(),
            pool_wsol: Pubkey::new_unique(),
            pool_meme: Pubkey::new_unique(),
            user_wsol: Pubkey::new_unique(),
            user_meme: Pubkey::new_unique(),
        }
    }
}

#[test]
fn router_fee_capped_and_fixed() {
    let mut env = Env::new();
    let t = env.trader.insecure_clone();
    let e = env.create_router(&t, env.trader_wallet, 26, [2; 32]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::AboveCap)));
    let r = env.router_state(&env.router);
    assert_eq!(r.trader_fee_bps, TRADER_BPS);
    assert_eq!(r.owner, env.trader.pubkey());
    // There is no instruction that changes a router's fee: the program simply has none.
}

#[test]
fn owners_change_only_their_settings() {
    let mut env = Env::new();
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), SOL).unwrap();
    let admin = env.admin.insecure_clone();
    let set_min = |_env: &Env, who: &Pubkey, v: u64| Instruction {
        program_id: router::ID,
        accounts: router::accounts::ConfigOwnerOnly { owner: *who, config: config_pda() }.to_account_metas(None),
        data: router::instruction::SetMinFee { lamports: v }.data(),
    };
    let ix = set_min(&env, &stranger.pubkey(), 0);
    let e = env.send(&[ix], &stranger, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::NotOwner)));
    let ix = set_min(&env, &admin.pubkey(), MAX_MIN_FEE + 1);
    let e = env.send(&[ix], &admin, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::AboveCap)));
    let ix = set_min(&env, &admin.pubkey(), MAX_MIN_FEE);
    env.send(&[ix], &admin, &[]).unwrap();
    assert_eq!(env.config().min_fee, MAX_MIN_FEE);

    let set_wallet = |who: &Pubkey, router_key: Pubkey, w: Pubkey| Instruction {
        program_id: router::ID,
        accounts: router::accounts::SetFeeWallet {
            owner: *who,
            router: router_key,
            vault: vault_pda(),
            credit: credit_pda(&w),
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None),
        data: router::instruction::SetFeeWallet { wallet: w }.data(),
    };
    let ix = set_wallet(&stranger.pubkey(), env.router, stranger.pubkey());
    let e = env.send(&[ix], &stranger, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::NotOwner)));
    let trader = env.trader.insecure_clone();
    let ix = set_wallet(&trader.pubkey(), env.router, vault_pda());
    let e = env.send(&[ix], &trader, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::ZeroAddress)), "the vault is never a wallet");
}

#[test]
fn two_step_ownership_for_config_and_router() {
    let mut env = Env::new();
    let admin = env.admin.insecure_clone();
    let next = Keypair::new();
    env.svm.airdrop(&next.pubkey(), SOL).unwrap();
    let ix = Instruction {
        program_id: router::ID,
        accounts: router::accounts::ConfigOwnerOnly { owner: admin.pubkey(), config: config_pda() }.to_account_metas(None),
        data: router::instruction::TransferConfigOwnership { new_owner: next.pubkey() }.data(),
    };
    env.send(&[ix], &admin, &[]).unwrap();
    assert_eq!(env.config().owner, admin.pubkey(), "still the old owner until accepted");
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), SOL).unwrap();
    let accept = |who: &Pubkey| Instruction {
        program_id: router::ID,
        accounts: router::accounts::AcceptConfigOwnership { new_owner: *who, config: config_pda() }.to_account_metas(None),
        data: router::instruction::AcceptConfigOwnership {}.data(),
    };
    let e = env.send(&[accept(&stranger.pubkey())], &stranger, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::NotPendingOwner)));
    env.send(&[accept(&next.pubkey())], &next, &[]).unwrap();
    assert_eq!(env.config().owner, next.pubkey());

    let trader = env.trader.insecure_clone();
    let ix = Instruction {
        program_id: router::ID,
        accounts: router::accounts::RouterOwnerOnly { owner: trader.pubkey(), router: env.router }.to_account_metas(None),
        data: router::instruction::TransferRouterOwnership { new_owner: next.pubkey() }.data(),
    };
    env.send(&[ix], &trader, &[]).unwrap();
    let ix = Instruction {
        program_id: router::ID,
        accounts: router::accounts::AcceptRouterOwnership { new_owner: next.pubkey(), router: env.router }.to_account_metas(None),
        data: router::instruction::AcceptRouterOwnership {}.data(),
    };
    env.send(&[ix], &next, &[]).unwrap();
    assert_eq!(env.router_state(&env.router).owner, next.pubkey());
}

// ================================================================================ swaps and fees

#[test]
fn buy_charges_exact_percentage_of_sol_in() {
    let mut env = Env::new();
    let sol_in = 50 * SOL;
    let fee = pct(sol_in, 40); // 0.2 SOL
    let v0 = env.lamports(&vault_pda());
    env.buy(sol_in, 1_000_000, 1_000_000, fee + SOL).unwrap();
    assert_eq!(env.lamports(&vault_pda()) - v0, fee, "exactly 0.40% of 50 SOL, not the signed max");
    assert_eq!(env.balance(&env.user_wsol), 50 * SOL);
    assert_eq!(env.balance(&env.user_meme), 1_000_000);
    assert_eq!(env.credit(&env.protocol_wallet), fee * 25 / 40);
    assert_eq!(env.credit(&env.trader_wallet), fee - fee * 25 / 40);
    env.assert_solvent();
}

#[test]
fn sell_charges_percentage_of_sol_out() {
    let mut env = Env::new();
    env.buy(SOL, 5_000_000, 1, SOL).unwrap();
    let before = env.config().total_credited;
    let sol_out = 10 * SOL;
    env.sell(5_000_000, sol_out, sol_out, SOL).unwrap();
    assert_eq!(env.config().total_credited - before, pct(sol_out, 40), "0.40% of the 10 SOL received");
    env.assert_solvent();
}

#[test]
fn small_trade_pays_the_floor() {
    let mut env = Env::new();
    env.buy(SOL / 5, 1, 1, MIN_FEE).unwrap(); // 0.40% of 0.2 SOL = 0.0008 < 0.0025
    assert_eq!(env.config().total_credited, MIN_FEE);
    env.assert_solvent();
}

#[test]
fn fee_above_max_reverts_whole_swap() {
    let mut env = Env::new();
    let w0 = env.balance(&env.user_wsol);
    let e = env.buy(50 * SOL, 1_000_000, 1, pct(50 * SOL, 40) - 1).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::FeeTooLow)));
    assert_eq!(env.balance(&env.user_wsol), w0, "nothing moved");
    assert_eq!(env.balance(&env.user_meme), 0);
}

#[test]
fn better_fill_costs_more_fee_within_max() {
    let mut env = Env::new();
    env.buy(SOL, 5_000_000, 1, SOL).unwrap();
    let before = env.config().total_credited;
    // The app quoted 8 SOL out and signed a 25% headroom; the sale fills at 9 SOL.
    let max_fee = pct(8 * SOL, 40) * 5 / 4;
    env.sell(5_000_000, 9 * SOL, 8 * SOL, max_fee).unwrap();
    assert_eq!(env.config().total_credited - before, pct(9 * SOL, 40));
}

#[test]
fn fee_follows_what_actually_left_the_wsol_account() {
    // The venue takes 30 SOL even though nothing in the instruction names an amount: the fee follows the 30 SOL.
    let mut env = Env::new();
    env.buy(30 * SOL, 1, 1, SOL).unwrap();
    assert_eq!(env.config().total_credited, pct(30 * SOL, 40));
}

#[test]
fn min_out_enforced() {
    let mut env = Env::new();
    let e = env.buy(SOL, 999, 1_000, SOL).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::InsufficientOutput)));
}

#[test]
fn unpriced_pair_and_same_token_refused() {
    let mut env = Env::new();
    let other = Pubkey::new_unique();
    env.mint(other, 6);
    let user_other = Pubkey::new_unique();
    let u = env.user.pubkey();
    env.token_account(user_other, other, u, 0);
    env.token_account(env.user_meme, env.meme, u, 1_000);
    let venue = env.venue_ix(&u, env.user_meme, user_other, env.meme, other, 1_000, 0);
    let ix = env.execute_ix(&u, env.router, env.user_meme, user_other, venue, 1, SOL, i64::MAX);
    let user = env.user.insecure_clone();
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::UnpricedPair)));

    let second_wsol = Pubkey::new_unique();
    env.token_account(second_wsol, wsol(), u, 0);
    let venue = env.venue_ix(&u, env.user_wsol, second_wsol, wsol(), wsol(), SOL, 0);
    let ix = env.execute_ix(&u, env.router, env.user_wsol, second_wsol, venue, 1, SOL, i64::MAX);
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::SameToken)));
}

#[test]
fn expired_and_zero_min_out_refused() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let mut clock = env.svm.get_sysvar::<solana_clock::Clock>();
    clock.unix_timestamp = 1_000_000;
    env.svm.set_sysvar(&clock);
    let venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, SOL, 10);
    let ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue.clone(), 1, SOL, 999_999);
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::Expired)));
    let ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 0, SOL, i64::MAX);
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::ZeroMinOut)));
}

/// Programs that are never venues: the router itself (a nested `execute`) and the native programs.
#[test]
fn blocked_venues_refused() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    for blocked in [router::ID, router::NATIVE_PROGRAMS[0], solana_sdk_ids::bpf_loader_upgradeable::ID, solana_sdk_ids::stake::ID] {
        let mut venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, SOL, 10);
        venue.program_id = blocked;
        let ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
        let e = env.send(&[ix], &user, &[]).unwrap_err();
        assert_eq!(custom_code(&e), Some(code(RouterError::VenueNotAllowed)), "{blocked}");
    }
}

// ================================================================================ permissionless venues: hostile venue

impl Env {
    /// The hostile venue: `mock_swap::relay` calls `inner` with the user's signature and every permission it was given.
    fn relay(&self, inner: Instruction) -> Instruction {
        let mut accounts = vec![solana_instruction::AccountMeta::new_readonly(inner.program_id, false)];
        accounts.extend(inner.accounts);
        Instruction { program_id: mock_swap::ID, accounts, data: mock_swap::instruction::Relay { data: inner.data }.data() }
    }

    /// A buy of `sol_in` wSOL routed through the hostile venue doing `inner`, expecting at least `min_out` meme.
    fn hostile_buy(&mut self, inner: Instruction, sol_in: u64, min_out: u64) -> Result<(), TransactionError> {
        let u = self.user.pubkey();
        let venue = self.relay(inner);
        let ix = self.execute_ix_full(&u, self.router, self.user_wsol, self.user_meme, venue, min_out, SOL, sol_in, i64::MAX);
        let user = self.user.insecure_clone();
        self.send(&[ix], &user, &[])
    }

    fn untouched(&self) {
        assert_eq!(self.balance(&self.user_wsol), 100 * SOL, "user's wSOL untouched");
        assert_eq!(self.lamports(&vault_pda()), self.vault_rent(), "vault untouched");
        self.assert_solvent();
    }
}

/// The hostile venue spends the user's input with the user's signature but sends it to the attacker and pays nothing
/// back: the output check refuses it.
#[test]
fn hostile_venue_taking_input_without_paying_refused() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let thief = Pubkey::new_unique();
    let thief_wsol = Pubkey::new_unique();
    env.token_account(thief_wsol, wsol(), thief, 0);
    let steal = spl_token_interface::instruction::transfer(&token_program(), &env.user_wsol, &thief_wsol, &u, &[], 10 * SOL).unwrap();
    let e = env.hostile_buy(steal, 10 * SOL, 1).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::InsufficientOutput)));
    assert_eq!(env.balance(&thief_wsol), 0);
    env.untouched();
}

/// The hostile venue calls back into the router (collect, then a nested execute): the runtime refuses re-entry.
#[test]
fn hostile_venue_reentering_the_router_refused() {
    let mut env = Env::new();
    env.buy(10 * SOL, 1_000, 1, SOL).unwrap();
    let credited = env.config().total_credited;
    let collect = Instruction {
        program_id: router::ID,
        accounts: router::accounts::Collect {
            config: config_pda(),
            vault: vault_pda(),
            credit: credit_pda(&env.protocol_wallet),
            wallet: env.protocol_wallet,
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None),
        data: router::instruction::Collect {}.data(),
    };
    let e = env.hostile_buy(collect, SOL, 1).unwrap_err();
    assert_eq!(e, TransactionError::InstructionError(0, InstructionError::ReentrancyNotAllowed));
    let u = env.user.pubkey();
    let inner = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, SOL, 10);
    let nested = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, inner, 1, SOL, i64::MAX);
    let e = env.hostile_buy(nested, SOL, 1).unwrap_err();
    assert_eq!(e, TransactionError::InstructionError(0, InstructionError::ReentrancyNotAllowed));
    assert_eq!(env.config().total_credited, credited, "no credit moved");
    env.assert_solvent();
}

/// The hostile venue tries to pay itself from the vault: the vault is a PDA only the router can sign for, and the
/// router never signs for it during a swap.
#[test]
fn hostile_venue_cannot_touch_the_vault() {
    let mut env = Env::new();
    env.buy(10 * SOL, 1_000, 1, SOL).unwrap();
    let before = env.lamports(&vault_pda());
    let thief = Pubkey::new_unique();
    let mut drain = solana_system_interface::instruction::transfer(&vault_pda(), &thief, 1);
    drain.accounts[0].is_signer = false; // nobody in the transaction can sign for the vault
    let e = env.hostile_buy(drain, SOL, 1).unwrap_err();
    assert_eq!(e, TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature));
    assert_eq!(env.lamports(&vault_pda()), before);
    env.assert_solvent();
}

/// Accounts a native program owns can name the user as their authority (stake, vote, program upgrade, lookup table,
/// durable nonce): none may be writable in the swap. Read-only they are harmless and allowed.
#[test]
fn native_program_accounts_refused_when_writable() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let cases = [
        (solana_sdk_ids::stake::ID, 200usize),
        (solana_sdk_ids::vote::ID, 3_762),
        (solana_sdk_ids::bpf_loader_upgradeable::ID, 64),
        (solana_sdk_ids::address_lookup_table::ID, 56),
        (solana_sdk_ids::system_program::ID, 80), // a durable nonce account
    ];
    for (owner, len) in cases {
        let acc = Pubkey::new_unique();
        let lamports = env.svm.minimum_balance_for_rent_exemption(len);
        env.svm.set_account(acc, Account { lamports, data: vec![1; len], owner, executable: false, rent_epoch: 0 }).unwrap();
        let mut venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, SOL, 1_000);
        venue.accounts.push(solana_instruction::AccountMeta::new(acc, false));
        let ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
        let e = env.send(&[ix], &user, &[]).unwrap_err();
        assert_eq!(custom_code(&e), Some(code(RouterError::ProtectedAccount)), "{owner}");

        let mut venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, SOL, 1_000);
        venue.accounts.push(solana_instruction::AccountMeta::new_readonly(acc, false));
        let ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
        env.send(&[ix], &user, &[]).unwrap();
    }
    env.assert_solvent();
}

// ================================================================================ Jupiter v6: platform fee must be off

impl Env {
    /// Puts the mock venue's code at Jupiter v6's address (the router checks Jupiter's instruction before calling it,
    /// so any program there will do) and sends `data` with `accounts` to it through `execute`.
    fn to_jupiter(&mut self, data: Vec<u8>, accounts: Vec<solana_instruction::AccountMeta>) -> Result<(), TransactionError> {
        if self.svm.get_account(&router::JUPITER_V6).is_none() {
            self.svm.add_program_from_file(router::JUPITER_V6, MOCK_SO).unwrap();
        }
        let u = self.user.pubkey();
        let venue = Instruction { program_id: router::JUPITER_V6, accounts, data };
        let ix = self.execute_ix(&u, self.router, self.user_wsol, self.user_meme, venue, 1, SOL, i64::MAX);
        let user = self.user.insecure_clone();
        self.send(&[ix], &user, &[])
    }
}

/// Anchor discriminator of a Jupiter v6 instruction: sha256("global:<name>")[..8], computed independently of the
/// router's own table.
fn disc(name: &str) -> Vec<u8> {
    let hex = match name {
        "route" => "e517cb977ae3ad2a",
        "route_with_token_ledger" => "96564774a75d0e68",
        "exact_out_route" => "d033ef977b2bed5c",
        "shared_accounts_route" => "c1209b3341d69c81",
        "shared_accounts_route_with_token_ledger" => "e6798f50779f6aaa",
        "shared_accounts_exact_out_route" => "b0d169a89a7d453e",
        "route_v2" => "bb64facc31c4af14",
        "exact_out_route_v2" => "9d8ab85215f4f324",
        "shared_accounts_route_v2" => "d19853937cfed8e9",
        "shared_accounts_exact_out_route_v2" => "3560e5cad8bbfa18",
        "claim" => "3ec6d6c1d59f6cd2",
        "close_token" => "1a4aec976840b7f9",
        "create_token_account" => "93f17b64f484ae76",
        "set_token_ledger" => "e455b9704e4f4d02",
        "withdraw_token_account_excess_lamports" => "927c0e00b5717293",
        _ => panic!("unknown {name}"),
    };
    (0..8).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// The six original routes: the optional platform-fee account must be absent (Jupiter's own id in its slot), whatever
/// the fee byte at the end of the data says. Fourteen readonly accounts, so every route's fee slot exists.
#[test]
fn jupiter_v1_route_needs_no_platform_fee_account() {
    let mut env = Env::new();
    let routes = [
        ("route", 6),
        ("route_with_token_ledger", 6),
        ("exact_out_route", 7),
        ("shared_accounts_route", 9),
        ("shared_accounts_route_with_token_ledger", 9),
        ("shared_accounts_exact_out_route", 9),
    ];
    let fee_account = Pubkey::new_unique();
    for (name, slot) in routes {
        let mut data = disc(name);
        data.extend_from_slice(&[0u8; 30]);
        let mut accounts: Vec<_> = (0..14).map(|_| solana_instruction::AccountMeta::new_readonly(Pubkey::new_unique(), false)).collect();
        accounts[slot].pubkey = fee_account;
        let e = env.to_jupiter(data.clone(), accounts.clone()).unwrap_err();
        assert_eq!(custom_code(&e), Some(code(RouterError::JupiterPlatformFee)), "{name} with a fee account");
        // A trailing zero cannot hide a fee: the account decides.
        let mut padded = data.clone();
        padded.push(0);
        let e = env.to_jupiter(padded, accounts.clone()).unwrap_err();
        assert_eq!(custom_code(&e), Some(code(RouterError::JupiterPlatformFee)), "{name} padded");
        // Fee account absent: the router's check passes and Jupiter is called (here the mock refuses the data).
        accounts[slot].pubkey = router::JUPITER_V6;
        let e = env.to_jupiter(data, accounts).unwrap_err();
        assert!(![code(RouterError::JupiterPlatformFee), code(RouterError::JupiterNotARoute)].contains(&custom_code(&e).unwrap_or(0)), "{name}");
    }
    env.untouched();
}

/// The four v2 routes: platform_fee_bps (u16) and positive_slippage_bps (u16) sit at a fixed offset before the route
/// plan and must both be zero.
#[test]
fn jupiter_v2_route_fee_fields_must_be_zero() {
    let mut env = Env::new();
    let accounts: Vec<_> = (0..12).map(|_| solana_instruction::AccountMeta::new_readonly(Pubkey::new_unique(), false)).collect();
    for (name, lead) in [("route_v2", 0usize), ("exact_out_route_v2", 0), ("shared_accounts_route_v2", 1), ("shared_accounts_exact_out_route_v2", 1)] {
        let at = 8 + lead + 18;
        let mut data = disc(name);
        data.extend_from_slice(&[7u8; 40]); // amounts, slippage and plan bytes are nonzero noise
        for (field, value) in [(at, [50u8, 0]), (at + 2, [1u8, 0])] {
            let mut d = data.clone();
            d[at..at + 4].fill(0);
            d[field..field + 2].copy_from_slice(&value);
            let e = env.to_jupiter(d, accounts.clone()).unwrap_err();
            assert_eq!(custom_code(&e), Some(code(RouterError::JupiterPlatformFee)), "{name} field at {field}");
        }
        let mut d = data.clone();
        d[at..at + 4].fill(0);
        let e = env.to_jupiter(d, accounts.clone()).unwrap_err();
        assert!(![code(RouterError::JupiterPlatformFee), code(RouterError::JupiterNotARoute)].contains(&custom_code(&e).unwrap_or(0)), "{name}");
        let e = env.to_jupiter(data[..at + 3].to_vec(), accounts.clone()).unwrap_err();
        assert_eq!(custom_code(&e), Some(code(RouterError::JupiterNotARoute)), "{name} truncated");
    }
    env.untouched();
}

/// Any other Jupiter instruction (claim, close_token, create_token_account, ...) is refused.
#[test]
fn jupiter_non_route_instruction_refused() {
    let mut env = Env::new();
    let accounts: Vec<_> = (0..12).map(|_| solana_instruction::AccountMeta::new_readonly(Pubkey::new_unique(), false)).collect();
    for name in ["claim", "close_token", "create_token_account", "set_token_ledger", "withdraw_token_account_excess_lamports"] {
        let mut data = disc(name);
        data.extend_from_slice(&[0u8; 8]);
        let e = env.to_jupiter(data, accounts.clone()).unwrap_err();
        assert_eq!(custom_code(&e), Some(code(RouterError::JupiterNotARoute)), "{name}");
    }
    let e = env.to_jupiter(vec![1, 2, 3], accounts).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::JupiterNotARoute)), "short data");
    env.untouched();
}

// ================================================================================ exploits

#[test]
fn foreign_token_accounts_refused() {
    let mut env = Env::new();
    let attacker = Keypair::new();
    env.svm.airdrop(&attacker.pubkey(), 10 * SOL).unwrap();
    let a = attacker.pubkey();
    let a_meme = Pubkey::new_unique();
    env.token_account(a_meme, env.meme, a, 0);
    // The attacker names the victim's wSOL account as the input.
    let venue = env.venue_ix(&a, env.user_wsol, a_meme, wsol(), env.meme, SOL, 10);
    let ix = env.execute_ix(&a, env.router, env.user_wsol, a_meme, venue, 1, SOL, i64::MAX);
    let e = env.send(&[ix], &attacker, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::NotUsersAccount)));
    assert_eq!(env.balance(&env.user_wsol), 100 * SOL, "victim untouched");
}

#[test]
fn venue_cannot_spend_a_victims_tokens() {
    // The attacker's own accounts pass the checks, but the venue is told to pull from the victim: the token program
    // refuses, because only the victim's signature could move them.
    let mut env = Env::new();
    let attacker = Keypair::new();
    env.svm.airdrop(&attacker.pubkey(), 10 * SOL).unwrap();
    let a = attacker.pubkey();
    let (a_wsol, a_meme) = (Pubkey::new_unique(), Pubkey::new_unique());
    env.token_account(a_wsol, wsol(), a, 0);
    env.token_account(a_meme, env.meme, a, 0);
    let mut venue = env.venue_ix(&a, env.user_wsol, a_meme, wsol(), env.meme, SOL, 10);
    venue.accounts[0].pubkey = a; // signer = attacker, source = victim's account
    let ix = env.execute_ix(&a, env.router, a_wsol, a_meme, venue, 1, SOL, i64::MAX);
    assert!(env.send(&[ix], &attacker, &[]).is_err());
    assert_eq!(env.balance(&env.user_wsol), 100 * SOL, "victim untouched");
}

#[test]
fn wrong_credit_account_refused() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, SOL, 10);
    let mut ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
    ix.accounts[4].pubkey = credit_pda(&u); // protocol_credit pointed at the user's own credit
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::WrongCreditAccount)));
}

#[test]
fn fake_router_account_refused() {
    // A router-shaped account owned by someone else's program is rejected by the owner check.
    let mut env = Env::new();
    let real = env.svm.get_account(&env.router).unwrap();
    let fake = Pubkey::new_unique();
    env.svm.set_account(fake, Account { owner: mock_swap::ID, ..real }).unwrap();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, SOL, 10);
    let mut ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
    ix.accounts[2].pubkey = fake;
    assert!(env.send(&[ix], &user, &[]).is_err());
}

// ================================================================================ credits and collection

#[test]
fn collect_pays_only_the_wallet_and_keeps_the_vault_solvent() {
    let mut env = Env::new();
    env.buy(50 * SOL, 1_000_000, 1, SOL).unwrap();
    let fee = pct(50 * SOL, 40);
    let p = fee * 25 / 40;
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), SOL).unwrap();
    let w0 = env.lamports(&env.protocol_wallet);
    let s0 = env.lamports(&stranger.pubkey());
    let pw = env.protocol_wallet;
    env.collect(pw, &stranger).unwrap(); // anyone can trigger it
    assert_eq!(env.lamports(&env.protocol_wallet) - w0, p, "paid to the protocol wallet");
    assert!(env.lamports(&stranger.pubkey()) < s0, "the caller only paid the transaction fee");
    assert_eq!(env.credit(&env.protocol_wallet), 0);
    let tw = env.trader_wallet;
    env.collect(tw, &stranger).unwrap();
    assert_eq!(env.lamports(&env.trader_wallet), fee - p);
    assert_eq!(env.config().total_credited, 0);
    assert_eq!(env.lamports(&vault_pda()), env.vault_rent(), "the vault keeps exactly its rent reserve");
    // Collecting again pays nothing.
    env.collect(pw, &stranger).unwrap();
    assert_eq!(env.lamports(&env.protocol_wallet) - w0, p);
}

#[test]
fn collect_with_a_mismatched_wallet_refused() {
    let mut env = Env::new();
    env.buy(SOL, 10, 1, SOL).unwrap();
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), SOL).unwrap();
    let ix = Instruction {
        program_id: router::ID,
        accounts: router::accounts::Collect {
            config: config_pda(),
            vault: vault_pda(),
            credit: credit_pda(&env.protocol_wallet),
            wallet: stranger.pubkey(),
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None),
        data: router::instruction::Collect {}.data(),
    };
    assert!(env.send(&[ix], &stranger, &[]).is_err());
    assert_eq!(env.credit(&env.protocol_wallet), pct(SOL, 40) * 25 / 40, "credit untouched");
}

#[test]
fn protocol_and_trader_wallet_may_be_the_same() {
    let mut env = Env::new();
    let t = env.trader.insecure_clone();
    let pw = env.protocol_wallet;
    env.router = env.create_router(&t, pw, TRADER_BPS, [9; 32]).unwrap();
    env.buy(50 * SOL, 10, 1, SOL).unwrap();
    assert_eq!(env.credit(&pw), pct(50 * SOL, 40), "both shares credited, none lost");
    assert_eq!(env.config().total_credited, pct(50 * SOL, 40));
}

#[test]
fn many_swaps_stay_solvent() {
    let mut env = Env::new();
    for i in 1..=12u64 {
        if i % 2 == 0 {
            env.buy(i * SOL / 3, 1_000 * i, 1, SOL).unwrap();
        } else {
            env.buy(SOL, 2_000 * i, 1, SOL).unwrap();
            env.sell(1_000 * i, i * SOL / 4, 1, SOL).unwrap();
        }
        env.assert_solvent();
        if i % 5 == 0 {
            let s = env.user.insecure_clone();
            let pw = env.protocol_wallet;
            env.collect(pw, &s).unwrap();
            env.assert_solvent();
        }
    }
}

// ================================================================================ review findings (proofs)

/// Review finding 1 (fixed): the swap pulls from a SECOND wSOL account while an empty decoy is measured. Before
/// the fix this paid the 0.0025 SOL floor on a 50 SOL swap; now the unmeasured source is refused.
#[test]
fn review_f1_decoy_input_refused() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let decoy = Pubkey::new_unique();
    env.token_account(decoy, wsol(), u, 0);
    let venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, 50 * SOL, 1_000_000);
    let ix = env.execute_ix(&u, env.router, decoy, env.user_meme, venue, 1, SOL, i64::MAX);
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::SwapAccountNotBound)));
    assert_eq!(env.balance(&env.user_wsol), 100 * SOL, "nothing moved");
}

/// The same trick through a DELEGATED account: someone approved the user to spend their wSOL. Refused too.
#[test]
fn review_f1_delegated_source_refused() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let lender = Pubkey::new_unique();
    let delegated = Pubkey::new_unique();
    env.delegated_wsol(delegated, lender, u, 50 * SOL);
    let venue = env.venue_ix(&u, delegated, env.user_meme, wsol(), env.meme, 50 * SOL, 1_000_000);
    let ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::SwapAccountNotBound)));
}

/// Nothing spent from the measured input (a route that takes nothing, or pays from elsewhere): refused.
#[test]
fn zero_input_refused() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, 0, 1_000_000);
    let ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::ZeroInput)));
}

/// Review finding 2: the user's signed max_input caps what the route may take.
#[test]
fn max_input_enforced() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, 5 * SOL, 1_000);
    let ix = env.execute_ix_full(&u, env.router, env.user_wsol, env.user_meme, venue.clone(), 1, SOL, 5 * SOL - 1, i64::MAX);
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::InputTooHigh)));
    let ix = env.execute_ix_full(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, 5 * SOL, i64::MAX);
    env.send(&[ix], &user, &[]).unwrap();
}

/// Second review: a second signer in the same transaction (another key the caller controls) is NOT passed to the
/// swap. The venue tries to take 50 SOL from that key's wSOL account while the user's account is measured: the
/// swap fails for lack of that signature (before the fix it would have run and only `ZeroInput` stopped this case).
#[test]
fn second_signer_is_not_forwarded_to_the_swap() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let other = Keypair::new();
    env.svm.airdrop(&other.pubkey(), SOL).unwrap();
    let other_wsol = Pubkey::new_unique();
    env.token_account(other_wsol, wsol(), other.pubkey(), 50 * SOL);
    let mut venue = env.venue_ix(&other.pubkey(), other_wsol, env.user_meme, wsol(), env.meme, 50 * SOL, 1_000_000);
    venue.accounts[0].is_signer = true;
    let ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
    let e = env.send(&[ix], &user, &[&other]).unwrap_err();
    assert_ne!(custom_code(&e), Some(code(RouterError::ZeroInput)), "stopped at the swap, not after it");
    assert_eq!(env.balance(&other_wsol), 50 * SOL, "the second signer's tokens never moved");
}

/// Second review: an SPL multisig handed to the swap is refused before the swap runs.
#[test]
fn multisig_account_refused() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let ms = Pubkey::new_unique();
    let mut signers = [Pubkey::default(); 11];
    signers[0] = u;
    let mut data = vec![0u8; Multisig::LEN];
    Multisig { m: 1, n: 1, is_initialized: true, signers }.pack_into_slice(&mut data);
    let lamports = env.svm.minimum_balance_for_rent_exemption(Multisig::LEN);
    env.svm.set_account(ms, Account { lamports, data, owner: token_program(), executable: false, rent_epoch: 0 }).unwrap();
    let mut venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, SOL, 1_000);
    venue.accounts.push(solana_instruction::AccountMeta::new_readonly(ms, false));
    let ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::MultisigNotAllowed)));
}

/// Review finding 3: a user's whole SOL cost is the fee, even on the very first swap (credit accounts already exist,
/// paid when the wallets were set). A separate fee payer covers the transaction fee, so the user's delta is exact.
#[test]
fn user_pays_exactly_the_fee_and_nothing_else() {
    let mut env = Env::new();
    assert!(env.svm.get_account(&credit_pda(&env.protocol_wallet)).is_some(), "created at initialize");
    assert!(env.svm.get_account(&credit_pda(&env.trader_wallet)).is_some(), "created at create_router");
    let relayer = Keypair::new();
    env.svm.airdrop(&relayer.pubkey(), SOL).unwrap();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let l0 = env.lamports(&u);
    let venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, 50 * SOL, 1_000);
    let ix = env.execute_ix_full(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, 50 * SOL, i64::MAX);
    env.send(&[ix], &relayer, &[&user]).unwrap();
    assert_eq!(l0 - env.lamports(&u), pct(50 * SOL, 40), "SOL cost = exactly 0.40% of 50 SOL");
}

/// A pre-funded credit address (someone sent lamports there first) does not block creating it.
#[test]
fn prefunded_credit_address_still_works() {
    let mut env = Env::new();
    let wallet = Pubkey::new_unique();
    env.svm.airdrop(&credit_pda(&wallet), 1_000_000).unwrap();
    let t = env.trader.insecure_clone();
    let r = env.create_router(&t, wallet, TRADER_BPS, [7; 32]).unwrap();
    env.router = r;
    env.buy(50 * SOL, 1_000, 1, SOL).unwrap();
    assert_eq!(env.credit(&wallet), pct(50 * SOL, 40) - pct(50 * SOL, 40) * 25 / 40);
}

/// A failed fee check rolls back the swap AND leaves every credit untouched.
#[test]
fn failed_fee_check_rolls_back_everything() {
    let mut env = Env::new();
    env.buy(SOL, 10, 1, SOL).unwrap();
    let (p0, t0, tot0, w0) = (env.credit(&env.protocol_wallet), env.credit(&env.trader_wallet), env.config().total_credited, env.balance(&env.user_wsol));
    assert!(env.buy(50 * SOL, 10, 1, pct(50 * SOL, 40) - 1).is_err());
    assert_eq!((env.credit(&env.protocol_wallet), env.credit(&env.trader_wallet), env.config().total_credited, env.balance(&env.user_wsol)), (p0, t0, tot0, w0));
}

/// Changing the protocol wallet creates its credit account (paid by the owner); new fees go there, old ones stay.
#[test]
fn protocol_wallet_change_creates_credit_and_redirects_new_fees() {
    let mut env = Env::new();
    env.buy(SOL, 10, 1, SOL).unwrap();
    let old = env.protocol_wallet;
    let old_credit = env.credit(&old);
    let new_wallet = Pubkey::new_unique();
    let admin = env.admin.insecure_clone();
    let ix = Instruction {
        program_id: router::ID,
        accounts: router::accounts::SetProtocolWallet {
            owner: admin.pubkey(),
            config: config_pda(),
            vault: vault_pda(),
            credit: credit_pda(&new_wallet),
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None),
        data: router::instruction::SetProtocolWallet { wallet: new_wallet }.data(),
    };
    env.send(&[ix], &admin, &[]).unwrap();
    env.protocol_wallet = new_wallet;
    env.buy(50 * SOL, 10, 1, SOL).unwrap();
    assert_eq!(env.credit(&old), old_credit, "old credit stays with the old wallet");
    assert_eq!(env.credit(&new_wallet), pct(50 * SOL, 40) * 25 / 40);
}

// ================================================================================ security checklist (verification)

/// Type confusion: a Router account handed to `collect` as the credit account. Anchor's account discriminator and
/// seeds reject it; nothing is paid.
#[test]
fn router_account_cannot_pose_as_credit() {
    let mut env = Env::new();
    env.buy(SOL, 10, 1, SOL).unwrap();
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), SOL).unwrap();
    let ix = Instruction {
        program_id: router::ID,
        accounts: router::accounts::Collect {
            config: config_pda(),
            vault: vault_pda(),
            credit: env.router,
            wallet: stranger.pubkey(),
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None),
        data: router::instruction::Collect {}.data(),
    };
    let v0 = env.lamports(&vault_pda());
    assert!(env.send(&[ix], &stranger, &[]).is_err());
    assert_eq!(env.lamports(&vault_pda()), v0, "vault untouched");
}

/// A look-alike config (same bytes, but owned by another program, at another address) is rejected by `execute`.
#[test]
fn fake_config_refused() {
    let mut env = Env::new();
    let real = env.svm.get_account(&config_pda()).unwrap();
    let fake = Pubkey::new_unique();
    env.svm.set_account(fake, Account { owner: mock_swap::ID, ..real }).unwrap();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, SOL, 10);
    let mut ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
    ix.accounts[1].pubkey = fake;
    assert!(env.send(&[ix], &user, &[]).is_err());
}

/// Fee math, 20,000 deterministic pseudo-random cases including the extremes: the fee is max(floor, ceil(x * bps /
/// 10,000)), never overflows, and the protocol and trader shares always add up to it exactly.
#[test]
fn fee_math_property() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let edges = [0u64, 1, 9_999, 10_000, MIN_FEE, u64::MAX / 50, u64::MAX];
    for i in 0..20_000u64 {
        let amount = if (i as usize) < edges.len() { edges[i as usize] } else { next() >> (next() % 40) };
        let trader = (next() % 26) as u64;
        let bps = 25 + trader;
        let p = router::pct(amount, bps).expect("never overflows u64 for bps <= 50");
        assert_eq!(p as u128, (amount as u128 * bps as u128).div_ceil(10_000));
        let fee = p.max(MIN_FEE);
        let protocol = (fee as u128 * 25 / bps as u128) as u64;
        let trader_share = fee - protocol;
        assert_eq!(protocol + trader_share, fee);
        assert!(protocol as u128 * bps as u128 <= fee as u128 * 25, "protocol never over-paid");
    }
}

/// V-1 (security verification): a venue that uses the user's signature to approve a delegate on the user's input
/// account during the swap. The router refuses it, so no approval can outlive the transaction.
#[test]
fn venue_cannot_leave_an_approval_behind() {
    let mut env = Env::new();
    let u = env.user.pubkey();
    let user = env.user.insecure_clone();
    let thief = Pubkey::new_unique();
    let mut venue = env.venue_ix(&u, env.user_wsol, env.user_meme, wsol(), env.meme, SOL, 1_000);
    venue.data = mock_swap::instruction::SwapAndApprove { amount_in: SOL, amount_out: 1_000, delegate: thief }.data();
    venue.accounts.push(solana_instruction::AccountMeta::new_readonly(thief, false));
    let ix = env.execute_ix(&u, env.router, env.user_wsol, env.user_meme, venue, 1, SOL, i64::MAX);
    let e = env.send(&[ix], &user, &[]).unwrap_err();
    assert_eq!(custom_code(&e), Some(code(RouterError::AccountAuthorityChanged)));
    let acc = TokenAccount::unpack(&env.svm.get_account(&env.user_wsol).unwrap().data).unwrap();
    assert_eq!(acc.delegate, COption::None, "no approval survived");
    assert_eq!(acc.amount, 100 * SOL, "nothing moved");
}
